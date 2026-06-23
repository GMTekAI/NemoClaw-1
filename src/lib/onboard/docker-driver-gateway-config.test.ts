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

const SANDBOX_JWT_SUBJECT_PREFIX = "spiffe://openshell/sandbox/";

function baseGatewayEnv(): Record<string, string> {
  return {
    OPENSHELL_GRPC_ENDPOINT: "http://127.0.0.1:8080",
    OPENSHELL_DOCKER_NETWORK_NAME: "openshell-docker",
    OPENSHELL_DOCKER_SUPERVISOR_IMAGE: "ghcr.io/nvidia/openshell/supervisor:0.0.67",
  };
}

function writeGatewayConfig(stateDir: string): Record<string, string> {
  return prepareDockerDriverGatewayConfigEnv(
    baseGatewayEnv(),
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
      expect(toml).toContain("[openshell.gateway.gateway_jwt]");
      expect(toml).toContain(`signing_key_path = "${signingKeyPath}"`);
      expect(toml).toContain(`public_key_path = "${publicKeyPath}"`);
      expect(toml).toContain(`kid_path = "${kidPath}"`);
      expect(toml).toContain('gateway_id = "nemoclaw-');
      expect(toml).toContain(`ttl_secs = ${DOCKER_DRIVER_GATEWAY_JWT_TTL_SECS}`);
      expect(toml).toContain("[openshell.gateway.auth]");
      expect(toml).toContain("allow_unauthenticated_users = true");
      expect(toml).toContain('compute_drivers = ["docker"]');
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
      const signingKeyPath = path.join(stateDir, "jwt", "signing.pem");
      const firstSigningKey = fs.readFileSync(signingKeyPath, "utf-8");

      writeGatewayConfig(stateDir);

      expect(fs.readFileSync(signingKeyPath, "utf-8")).toBe(firstSigningKey);
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
      expect(toml).toContain("allow_unauthenticated_users = true");
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
