// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { generateKeyPairSync, randomBytes } from "node:crypto";
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
    return bundle;
  }

  if (present > 0) {
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

export function buildDockerDriverGatewayConfigToml(
  gatewayEnv: Record<string, string>,
  sandboxBin?: string | null,
  jwtBundle?: DockerDriverGatewayJwtBundle | null,
  gatewayId = "nemoclaw",
): string {
  const dockerEntries: [string, string | undefined][] = [
    ["grpc_endpoint", gatewayEnv.OPENSHELL_GRPC_ENDPOINT],
    ["network_name", gatewayEnv.OPENSHELL_DOCKER_NETWORK_NAME],
    ["supervisor_image", gatewayEnv.OPENSHELL_DOCKER_SUPERVISOR_IMAGE],
    ["supervisor_bin", sandboxBin ?? undefined],
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
    "",
  ];

  if (jwtBundle) {
    // OpenShell v0.0.67 loads these tables from OPENSHELL_GATEWAY_CONFIG, with
    // OPENSHELL_* env vars taking precedence. The upstream config contract
    // recognizes gateway_jwt for sandbox callbacks and classifies
    // allow_unauthenticated_users as a local/trusted-proxy escape hatch that
    // affects user-facing CLI/API calls, not sandbox supervisor callbacks.
    // NemoClaw's package-managed gateway still registers providers through
    // local CLI/API calls without a user auth header, so keep that local user
    // path compatible while the supervisor channel authenticates with the
    // generated gateway_jwt bundle below. The normal package-managed gateway
    // remains loopback-bound; the separate Docker compatibility wrapper may
    // bind 0.0.0.0 only so Docker sandbox callbacks can reach the host-network
    // gateway container.
    //
    // Removal condition: set this back to false once NemoClaw supplies
    // OpenShell user auth for local provider registration/CLI calls, or once
    // OpenShell exposes an equivalent trusted local-user auth path.
    sections.push(
      "[openshell.gateway.gateway_jwt]",
      `signing_key_path = ${tomlString(jwtBundle.signingKeyPath)}`,
      `public_key_path = ${tomlString(jwtBundle.publicKeyPath)}`,
      `kid_path = ${tomlString(jwtBundle.kidPath)}`,
      `gateway_id = ${tomlString(gatewayId)}`,
      `ttl_secs = ${DOCKER_DRIVER_GATEWAY_JWT_TTL_SECS}`,
      "",
      "[openshell.gateway.auth]",
      "allow_unauthenticated_users = true",
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
