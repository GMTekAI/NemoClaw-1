// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  createPrivateKey,
  createPublicKey,
  sign as signPayload,
  verify as verifyPayload,
} from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  DOCKER_DRIVER_GATEWAY_JWT_TTL_SECS,
  prepareDockerDriverGatewayConfigEnv,
} from "./docker-driver-gateway-config";

const REPO_ROOT = path.resolve(import.meta.dirname, "../../..");
const GATEWAY_AUTH_REVIEW_NOTE = path.join(
  REPO_ROOT,
  "docs",
  "security",
  "openshell-0.0.67-gateway-auth-review.md",
);
const SANDBOX_JWT_SUBJECT_PREFIX = "spiffe://openshell/sandbox/";

function baseGatewayEnv(stateDir: string): Record<string, string> {
  return {
    OPENSHELL_GRPC_ENDPOINT: "https://127.0.0.1:8080",
    OPENSHELL_LOCAL_TLS_DIR: path.join(stateDir, "tls"),
    OPENSHELL_DOCKER_NETWORK_NAME: "openshell-docker",
    OPENSHELL_DOCKER_SUPERVISOR_IMAGE: "ghcr.io/nvidia/openshell/supervisor:0.0.67",
  };
}

function writeGatewayConfig(stateDir: string): Record<string, string> {
  return prepareDockerDriverGatewayConfigEnv(
    baseGatewayEnv(stateDir),
    stateDir,
    "/usr/bin/openshell-sandbox",
  );
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf-8").toString("base64url");
}

function parseTomlString(toml: string, key: string): string {
  const match = toml.match(new RegExp(`^${key} = "([^"]+)"$`, "m"));
  expect(match, `missing TOML string key ${key}`).not.toBeNull();
  return match?.[1] ?? "";
}

function parseTomlInteger(toml: string, key: string): number {
  const match = toml.match(new RegExp(`^${key} = (\\d+)$`, "m"));
  expect(match, `missing TOML integer key ${key}`).not.toBeNull();
  return Number(match?.[1] ?? "0");
}

function jwtBundlePaths(stateDir: string): {
  signingKeyPath: string;
  publicKeyPath: string;
  kidPath: string;
} {
  return {
    signingKeyPath: path.join(stateDir, "jwt", "signing.pem"),
    publicKeyPath: path.join(stateDir, "jwt", "public.pem"),
    kidPath: path.join(stateDir, "jwt", "kid"),
  };
}

function expectEd25519BundleSignsAndVerifies(paths: {
  signingKeyPath: string;
  publicKeyPath: string;
  kidPath: string;
}): void {
  const privateKey = createPrivateKey(fs.readFileSync(paths.signingKeyPath, "utf-8"));
  const publicKey = createPublicKey(fs.readFileSync(paths.publicKeyPath, "utf-8"));
  const payload = Buffer.from("nemoclaw-openshell-gateway-jwt-bundle-check", "utf-8");
  expect(privateKey.asymmetricKeyType).toBe("ed25519");
  expect(publicKey.asymmetricKeyType).toBe("ed25519");
  expect(fs.readFileSync(paths.kidPath, "utf-8").trim()).not.toBe("");
  expect(verifyPayload(null, payload, publicKey, signPayload(null, payload, privateKey))).toBe(
    true,
  );
}

function decodeJwtPart(part: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf-8")) as Record<string, unknown>;
}

function mintOpenShellStyleSandboxJwt(options: {
  signingKeyPath: string;
  kid: string;
  gatewayId: string;
  sandboxId: string;
  exp: number;
  iat: number;
}): string {
  const header = base64UrlJson({ alg: "EdDSA", kid: options.kid, typ: "JWT" });
  const identity = `openshell-gateway:${options.gatewayId}`;
  const payload = base64UrlJson({
    sub: `${SANDBOX_JWT_SUBJECT_PREFIX}${options.sandboxId}`,
    iss: identity,
    aud: identity,
    iat: options.iat,
    exp: options.exp,
    sandbox_id: options.sandboxId,
  });
  const signingInput = `${header}.${payload}`;
  const privateKey = createPrivateKey(fs.readFileSync(options.signingKeyPath, "utf-8"));
  const signature = signPayload(null, Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

function validateOpenShellStyleSandboxJwt(options: {
  token: string;
  publicKeyPath: string;
  kid: string;
  gatewayId: string;
  now: number;
}): Record<string, unknown> | null {
  const [headerPart, payloadPart, signaturePart] = options.token.split(".");
  expect(headerPart, "JWT header segment").toBeTruthy();
  expect(payloadPart, "JWT payload segment").toBeTruthy();
  expect(signaturePart, "JWT signature segment").toBeTruthy();

  const header = decodeJwtPart(headerPart ?? "");
  return header.kid === options.kid && header.alg === "EdDSA"
    ? validateOpenShellStyleSandboxJwtSignature({
        headerPart: headerPart ?? "",
        payloadPart: payloadPart ?? "",
        signaturePart: signaturePart ?? "",
        publicKeyPath: options.publicKeyPath,
        gatewayId: options.gatewayId,
        now: options.now,
      })
    : null;
}

function validateOpenShellStyleSandboxJwtSignature(options: {
  headerPart: string;
  payloadPart: string;
  signaturePart: string;
  publicKeyPath: string;
  gatewayId: string;
  now: number;
}): Record<string, unknown> {
  const signingInput = `${options.headerPart}.${options.payloadPart}`;
  const publicKey = createPublicKey(fs.readFileSync(options.publicKeyPath, "utf-8"));
  const signatureOk = verifyPayload(
    null,
    Buffer.from(signingInput),
    publicKey,
    Buffer.from(options.signaturePart, "base64url"),
  );
  expect(signatureOk, "OpenShell-style sandbox JWT signature").toBe(true);

  const payload = decodeJwtPart(options.payloadPart);
  const identity = `openshell-gateway:${options.gatewayId}`;
  expect(payload.iss).toBe(identity);
  expect(payload.aud).toBe(identity);
  expect(String(payload.sub)).toBe(`${SANDBOX_JWT_SUBJECT_PREFIX}${payload.sandbox_id}`);
  const exp = typeof payload.exp === "number" ? payload.exp : Number.NaN;
  expect(exp === 0 || exp >= options.now - 60, "OpenShell-style sandbox JWT expiry").toBe(true);
  return payload;
}

describe("docker-driver-gateway-config", () => {
  it("keeps the OpenShell gateway auth source review aligned with the generated config", () => {
    const reviewNote = fs.readFileSync(GATEWAY_AUTH_REVIEW_NOTE, "utf-8");

    expect(reviewNote).toContain("NVIDIA/OpenShell@v0.0.67");
    expect(reviewNote).toContain("ce788b50f9b1f977a4327e4484c5b663013dd9a5");
    expect(reviewNote).toContain("openshell-gateway-auth-source-contract.test.ts");
    expect(reviewNote).toContain("openshell_server::config_file::load()");
    expect(reviewNote).toContain("allow_unauthenticated_users");
    expect(reviewNote).toContain("gateway_jwt");
    expect(reviewNote).toContain("mTLS user authentication");
    expect(reviewNote).toContain("SandboxJwtAuthenticator");
    expect(reviewNote).toContain("user principals are rejected from sandbox-only methods");
    expect(reviewNote).toContain(
      "gateway_listener_addresses_include_driver_address_on_distinct_ip",
    );
    expect(reviewNote).toContain("container_visible_endpoint_rewrites_loopback_hosts");
    expect(reviewNote).toContain("docker_gateway_route_uses_bridge_gateway_for_linux_docker");
    expect(reviewNote).toContain("keeps the main OpenShell listener on `127.0.0.1`");
    expect(reviewNote).toContain(
      "NEMOCLAW_OPENSHELL_GATEWAY_COMPAT_BIND_ADDRESS=0.0.0.0` is rejected",
    );
    expect(reviewNote).toContain("reject `NEMOCLAW_GATEWAY_BIND_ADDRESS=0.0.0.0`");
    expect(reviewNote).toContain("host-side OpenShell CLI user calls use local mTLS");
    expect(reviewNote).toContain("Source-of-Truth Boundaries");
    expect(reviewNote).toContain("OpenShell gateway auth source contract");
    expect(reviewNote).toContain("Markerless sandbox gateway recovery output");
    expect(reviewNote).toContain("Sessions admin gateway RPC helper");
    expect(reviewNote).toContain("Issue #5591 is the dependency-update umbrella");
    expect(reviewNote).toContain("this PR pins and validates OpenShell `0.0.67`");
    expect(reviewNote).toContain("Issue #2478 is not an acceptance target");
    expect(reviewNote).toContain("valid sandbox JWT access from Docker origin");
  });

  it("writes OpenShell 0.0.67 gateway JWT config into the managed state dir", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-config-"));
    try {
      const env = writeGatewayConfig(stateDir);
      const configPath = path.join(stateDir, "openshell-gateway.toml");
      const signingKeyPath = path.join(stateDir, "jwt", "signing.pem");
      const publicKeyPath = path.join(stateDir, "jwt", "public.pem");
      const kidPath = path.join(stateDir, "jwt", "kid");
      const toml = fs.readFileSync(configPath, "utf-8");

      expect(env.OPENSHELL_GATEWAY_CONFIG).toBe(configPath);
      expect(env.OPENSHELL_GRPC_ENDPOINT).toBe("https://127.0.0.1:8080");
      expect(toml).toContain("[openshell.gateway.gateway_jwt]");
      expect(toml).toContain(`signing_key_path = "${signingKeyPath}"`);
      expect(toml).toContain(`public_key_path = "${publicKeyPath}"`);
      expect(toml).toContain(`kid_path = "${kidPath}"`);
      expect(toml).toContain('gateway_id = "nemoclaw-');
      expect(toml).toContain(`ttl_secs = ${DOCKER_DRIVER_GATEWAY_JWT_TTL_SECS}`);
      expect(toml).toContain("disable_tls = false");
      expect(toml).toContain("[openshell.gateway.tls]");
      expect(toml).toContain(`cert_path = "${path.join(stateDir, "tls", "server", "tls.crt")}"`);
      expect(toml).toContain(`key_path = "${path.join(stateDir, "tls", "server", "tls.key")}"`);
      expect(toml).toContain(`client_ca_path = "${path.join(stateDir, "tls", "ca.crt")}"`);
      expect(toml).toContain("[openshell.gateway.mtls_auth]");
      expect(toml).toContain("enabled = true");
      expect(toml).toContain("[openshell.gateway.auth]");
      expect(toml).toContain("allow_unauthenticated_users = false");
      expect(toml).toContain('compute_drivers = ["docker"]');
      expect(toml).toContain('grpc_endpoint = "https://127.0.0.1:8080"');
      expect(toml).toContain(`guest_tls_ca = "${path.join(stateDir, "tls", "ca.crt")}"`);
      expect(toml).toContain(
        `guest_tls_cert = "${path.join(stateDir, "tls", "client", "tls.crt")}"`,
      );
      expect(toml).toContain(
        `guest_tls_key = "${path.join(stateDir, "tls", "client", "tls.key")}"`,
      );
      expect(toml).toContain('supervisor_bin = "/usr/bin/openshell-sandbox"');
      expect(env.OPENSHELL_DISABLE_GATEWAY_AUTH).toBeUndefined();
      expect(fs.statSync(stateDir).mode & 0o777).toBe(0o700);
      expect(fs.statSync(path.join(stateDir, "jwt")).mode & 0o777).toBe(0o700);
      expect(fs.statSync(configPath).mode & 0o777).toBe(0o600);
      expect(fs.statSync(signingKeyPath).mode & 0o777).toBe(0o600);
      expect(fs.statSync(publicKeyPath).mode & 0o777).toBe(0o600);
      expect(fs.statSync(kidPath).mode & 0o777).toBe(0o600);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("preserves a complete gateway JWT bundle across config rewrites", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-config-"));
    try {
      writeGatewayConfig(stateDir);
      const paths = jwtBundlePaths(stateDir);
      const firstSigningKey = fs.readFileSync(paths.signingKeyPath, "utf-8");
      expectEd25519BundleSignsAndVerifies(paths);

      writeGatewayConfig(stateDir);

      expect(fs.readFileSync(paths.signingKeyPath, "utf-8")).toBe(firstSigningKey);
      expectEd25519BundleSignsAndVerifies(paths);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it.each([
    {
      name: "malformed signing key",
      corrupt: (paths: ReturnType<typeof jwtBundlePaths>) => {
        fs.writeFileSync(paths.signingKeyPath, "not a private key\n", { mode: 0o600 });
      },
    },
    {
      name: "empty kid",
      corrupt: (paths: ReturnType<typeof jwtBundlePaths>) => {
        fs.writeFileSync(paths.kidPath, "\n", { mode: 0o600 });
      },
    },
    {
      name: "mismatched public key",
      corrupt: (paths: ReturnType<typeof jwtBundlePaths>) => {
        const otherStateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-config-"));
        try {
          writeGatewayConfig(otherStateDir);
          fs.copyFileSync(jwtBundlePaths(otherStateDir).publicKeyPath, paths.publicKeyPath);
        } finally {
          fs.rmSync(otherStateDir, { recursive: true, force: true });
        }
      },
    },
  ])("regenerates a complete gateway JWT bundle when $name", ({ corrupt }) => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-config-"));
    try {
      writeGatewayConfig(stateDir);
      const paths = jwtBundlePaths(stateDir);
      const firstSigningKey = fs.readFileSync(paths.signingKeyPath, "utf-8");

      corrupt(paths);
      writeGatewayConfig(stateDir);

      expect(fs.readFileSync(paths.signingKeyPath, "utf-8")).not.toBe(firstSigningKey);
      expectEd25519BundleSignsAndVerifies(paths);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("regenerates an incomplete gateway JWT bundle before writing config", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-config-"));
    try {
      const jwtDir = path.join(stateDir, "jwt");
      fs.mkdirSync(jwtDir, { recursive: true, mode: 0o700 });
      const signingKeyPath = path.join(jwtDir, "signing.pem");
      const publicKeyPath = path.join(jwtDir, "public.pem");
      const kidPath = path.join(jwtDir, "kid");
      fs.writeFileSync(signingKeyPath, "stale partial key\n", { mode: 0o600 });

      writeGatewayConfig(stateDir);

      const toml = fs.readFileSync(path.join(stateDir, "openshell-gateway.toml"), "utf-8");
      expect(fs.readFileSync(signingKeyPath, "utf-8")).not.toBe("stale partial key\n");
      expect(fs.existsSync(publicKeyPath)).toBe(true);
      expect(fs.existsSync(kidPath)).toBe(true);
      expect(fs.statSync(jwtDir).mode & 0o777).toBe(0o700);
      expect(fs.statSync(signingKeyPath).mode & 0o777).toBe(0o600);
      expect(fs.statSync(publicKeyPath).mode & 0o777).toBe(0o600);
      expect(fs.statSync(kidPath).mode & 0o777).toBe(0o600);
      expect(toml).toContain(`signing_key_path = "${signingKeyPath}"`);
      expect(toml).toContain(`public_key_path = "${publicKeyPath}"`);
      expect(toml).toContain(`kid_path = "${kidPath}"`);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("emits an OpenShell 0.0.67-compatible sandbox JWT bundle and TTL contract", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-config-"));
    try {
      const env = writeGatewayConfig(stateDir);
      const toml = fs.readFileSync(env.OPENSHELL_GATEWAY_CONFIG, "utf-8");
      const signingKeyPath = parseTomlString(toml, "signing_key_path");
      const publicKeyPath = parseTomlString(toml, "public_key_path");
      const kidPath = parseTomlString(toml, "kid_path");
      const gatewayId = parseTomlString(toml, "gateway_id");
      const ttlSecs = parseTomlInteger(toml, "ttl_secs");
      const kid = fs.readFileSync(kidPath, "utf-8").trim();
      const now = Math.floor(Date.now() / 1000);
      const sandboxId = "sandbox-contract";

      expect(toml).toContain("[openshell.gateway.gateway_jwt]");
      expect(toml).toContain("[openshell.gateway.auth]");
      expect(toml).toContain("allow_unauthenticated_users = false");
      expect(env.OPENSHELL_DISABLE_GATEWAY_AUTH).toBeUndefined();
      expect(ttlSecs).toBe(DOCKER_DRIVER_GATEWAY_JWT_TTL_SECS);

      const token = mintOpenShellStyleSandboxJwt({
        signingKeyPath,
        kid,
        gatewayId,
        sandboxId,
        iat: now,
        exp: now + ttlSecs,
      });

      const payload = validateOpenShellStyleSandboxJwt({
        token,
        publicKeyPath,
        kid,
        gatewayId,
        now,
      });
      expect(payload).toMatchObject({
        sandbox_id: sandboxId,
        iss: `openshell-gateway:${gatewayId}`,
        aud: `openshell-gateway:${gatewayId}`,
      });
      expect(payload?.exp).toBe(now + ttlSecs);

      expect(
        validateOpenShellStyleSandboxJwt({
          token,
          publicKeyPath,
          kid: "wrong-kid",
          gatewayId,
          now,
        }),
      ).toBeNull();
      expect(() =>
        validateOpenShellStyleSandboxJwt({
          token,
          publicKeyPath,
          kid,
          gatewayId: "wrong-gateway",
          now,
        }),
      ).toThrow("expected");

      const expired = mintOpenShellStyleSandboxJwt({
        signingKeyPath,
        kid,
        gatewayId,
        sandboxId,
        iat: now - ttlSecs * 2,
        exp: now - ttlSecs,
      });
      expect(() =>
        validateOpenShellStyleSandboxJwt({
          token: expired,
          publicKeyPath,
          kid,
          gatewayId,
          now,
        }),
      ).toThrow("OpenShell-style sandbox JWT expiry");
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });
});
