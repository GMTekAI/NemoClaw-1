// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const DOCKER_DRIVER_GATEWAY_CONFIG_NAME = "openshell-gateway.toml";
export const DOCKER_DRIVER_GATEWAY_JWT_TTL_SECS = 3600;
const GATEWAY_JWT_DIR_NAME = "jwt";

export type DockerDriverGatewayJwtBundle = {
  signingKeyPath: string;
  publicKeyPath: string;
  kidPath: string;
};

function tomlString(value: string): string {
  return JSON.stringify(value);
}

function existingFileCount(paths: string[]): number {
  return paths.filter((candidate) => fs.existsSync(candidate)).length;
}

function writeRestrictedFile(filePath: string, value: string, mode = 0o600): void {
  fs.writeFileSync(filePath, value, { encoding: "utf-8", mode });
  fs.chmodSync(filePath, mode);
}

function dockerDriverGatewayJwtBundleIsValid(bundle: DockerDriverGatewayJwtBundle): boolean {
  try {
    const kid = fs.readFileSync(bundle.kidPath, "utf-8").trim();
    if (!kid) return false;
    const privateKey = createPrivateKey(fs.readFileSync(bundle.signingKeyPath, "utf-8"));
    const publicKey = createPublicKey(fs.readFileSync(bundle.publicKeyPath, "utf-8"));
    if (privateKey.asymmetricKeyType !== "ed25519" || publicKey.asymmetricKeyType !== "ed25519") {
      return false;
    }
    const payload = Buffer.from("nemoclaw-openshell-gateway-jwt-bundle-check", "utf-8");
    const signature = sign(null, payload, privateKey);
    return verify(null, payload, publicKey, signature);
  } catch {
    return false;
  }
}

export function ensureDockerDriverGatewayJwtBundle(stateDir: string): DockerDriverGatewayJwtBundle {
  const jwtDir = path.join(stateDir, GATEWAY_JWT_DIR_NAME);
  const bundle = {
    signingKeyPath: path.join(jwtDir, "signing.pem"),
    publicKeyPath: path.join(jwtDir, "public.pem"),
    kidPath: path.join(jwtDir, "kid"),
  };
  const files = [bundle.signingKeyPath, bundle.publicKeyPath, bundle.kidPath];

  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(stateDir, 0o700);

  const present = existingFileCount(files);
  if (present === files.length) {
    fs.chmodSync(jwtDir, 0o700);
    fs.chmodSync(bundle.signingKeyPath, 0o600);
    fs.chmodSync(bundle.publicKeyPath, 0o600);
    fs.chmodSync(bundle.kidPath, 0o600);
    if (dockerDriverGatewayJwtBundleIsValid(bundle)) {
      return bundle;
    }
    // Complete-but-invalid local auth material is unsafe to reuse because
    // OpenShell loads these files as one Ed25519 gateway_jwt bundle.
    fs.rmSync(jwtDir, { recursive: true, force: true });
  } else if (present > 0) {
    // Invalid state boundary: this directory is NemoClaw-owned local gateway
    // state, and a manual edit or interrupted prior write can leave only part
    // of the OpenShell v0.0.67 gateway_jwt bundle. OpenShell requires all three
    // files to agree, so the safe source of truth is a freshly generated local
    // bundle. Remove this recovery only if bundle creation becomes atomic.
    fs.rmSync(jwtDir, { recursive: true, force: true });
  }
  fs.mkdirSync(jwtDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(jwtDir, 0o700);

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  writeRestrictedFile(
    bundle.signingKeyPath,
    String(privateKey.export({ format: "pem", type: "pkcs8" })),
  );
  writeRestrictedFile(
    bundle.publicKeyPath,
    String(publicKey.export({ format: "pem", type: "spki" })),
  );
  writeRestrictedFile(bundle.kidPath, `${randomBytes(16).toString("hex")}\n`);

  return bundle;
}

function gatewayIdForStateDir(stateDir: string): string {
  const leaf = path.basename(path.resolve(stateDir)).replace(/[^A-Za-z0-9_.-]/g, "-");
  return leaf ? `nemoclaw-${leaf}` : "nemoclaw";
}

function gatewayLocalTlsDir(gatewayEnv: Record<string, string>): string {
  const localTlsDir = gatewayEnv.OPENSHELL_LOCAL_TLS_DIR?.trim();
  if (!localTlsDir) {
    throw new Error("OpenShell Docker-driver gateway mTLS requires OPENSHELL_LOCAL_TLS_DIR");
  }
  return localTlsDir;
}

export function buildDockerDriverGatewayConfigToml(
  gatewayEnv: Record<string, string>,
  sandboxBin?: string | null,
  jwtBundle?: DockerDriverGatewayJwtBundle | null,
  gatewayId = "nemoclaw",
): string {
  const localTlsDir = jwtBundle ? gatewayLocalTlsDir(gatewayEnv) : undefined;
  const dockerEntries: [string, string | undefined][] = [
    ["grpc_endpoint", gatewayEnv.OPENSHELL_GRPC_ENDPOINT],
    ["network_name", gatewayEnv.OPENSHELL_DOCKER_NETWORK_NAME],
    ["supervisor_image", gatewayEnv.OPENSHELL_DOCKER_SUPERVISOR_IMAGE],
    ["supervisor_bin", sandboxBin ?? undefined],
    ["guest_tls_ca", localTlsDir ? path.join(localTlsDir, "ca.crt") : undefined],
    ["guest_tls_cert", localTlsDir ? path.join(localTlsDir, "client", "tls.crt") : undefined],
    ["guest_tls_key", localTlsDir ? path.join(localTlsDir, "client", "tls.key") : undefined],
  ];
  const dockerConfig = dockerEntries
    .filter(
      (entry): entry is [string, string] => typeof entry[1] === "string" && entry[1].trim() !== "",
    )
    .map(([key, value]) => `${key} = ${tomlString(value)}`)
    .join("\n");

  const sections = [
    "[openshell]",
    "version = 1",
    "",
    "[openshell.gateway]",
    'compute_drivers = ["docker"]',
    "disable_tls = false",
    "",
  ];

  if (jwtBundle) {
    const tlsDir = localTlsDir ?? gatewayLocalTlsDir(gatewayEnv);
    sections.push(
      "[openshell.gateway.tls]",
      `cert_path = ${tomlString(path.join(tlsDir, "server", "tls.crt"))}`,
      `key_path = ${tomlString(path.join(tlsDir, "server", "tls.key"))}`,
      `client_ca_path = ${tomlString(path.join(tlsDir, "ca.crt"))}`,
      "require_client_auth = true",
      "",
      "[openshell.gateway.mtls_auth]",
      "enabled = true",
      "",
      "[openshell.gateway.gateway_jwt]",
      `signing_key_path = ${tomlString(jwtBundle.signingKeyPath)}`,
      `public_key_path = ${tomlString(jwtBundle.publicKeyPath)}`,
      `kid_path = ${tomlString(jwtBundle.kidPath)}`,
      `gateway_id = ${tomlString(gatewayId)}`,
      `ttl_secs = ${DOCKER_DRIVER_GATEWAY_JWT_TTL_SECS}`,
      "",
      "[openshell.gateway.auth]",
      "allow_unauthenticated_users = false",
      "",
    );
  }

  sections.push("[openshell.drivers.docker]");
  if (dockerConfig) sections.push(dockerConfig);
  sections.push("");

  return sections.join("\n");
}

export function writeDockerDriverGatewayConfig(
  stateDir: string,
  gatewayEnv: Record<string, string>,
  sandboxBin?: string | null,
): string {
  const configPath = path.join(stateDir, DOCKER_DRIVER_GATEWAY_CONFIG_NAME);
  const jwtBundle = ensureDockerDriverGatewayJwtBundle(stateDir);
  fs.writeFileSync(
    configPath,
    buildDockerDriverGatewayConfigToml(
      gatewayEnv,
      sandboxBin,
      jwtBundle,
      gatewayIdForStateDir(stateDir),
    ),
    {
      encoding: "utf-8",
      mode: 0o600,
    },
  );
  fs.chmodSync(configPath, 0o600);
  return configPath;
}

export function prepareDockerDriverGatewayConfigEnv(
  gatewayEnv: Record<string, string>,
  stateDir: string,
  sandboxBin?: string | null,
): Record<string, string> {
  gatewayEnv.OPENSHELL_GATEWAY_CONFIG = writeDockerDriverGatewayConfig(
    stateDir,
    gatewayEnv,
    sandboxBin,
  );
  return gatewayEnv;
}
