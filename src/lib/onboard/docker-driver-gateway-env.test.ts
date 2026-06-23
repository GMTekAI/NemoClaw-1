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

import { describe, expect, it, vi } from "vitest";

import {
  buildDockerDriverGatewayEnv,
  buildDockerGatewayDebEnvFile,
  startPackageManagedDockerDriverGatewayWithEnvOverride,
  writeDockerGatewayDebEnvOverride,
} from "./docker-driver-gateway-env";

const SANDBOX_JWT_SUBJECT_PREFIX = "spiffe://openshell/sandbox/";

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf-8").toString("base64url");
}

function parseTomlString(toml: string, key: string): string {
  const match = toml.match(new RegExp(`^${key} = "([^"]+)"$`, "m"));
  if (!match) throw new Error(`missing TOML string key ${key}`);
  return match[1];
}

function parseTomlInteger(toml: string, key: string): number {
  const match = toml.match(new RegExp(`^${key} = (\\d+)$`, "m"));
  if (!match) throw new Error(`missing TOML integer key ${key}`);
  return Number(match[1]);
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
  if (!headerPart || !payloadPart || !signaturePart) throw new Error("malformed JWT");

  const header = decodeJwtPart(headerPart);
  if (header.kid !== options.kid || header.alg !== "EdDSA") return null;

  const signingInput = `${headerPart}.${payloadPart}`;
  const publicKey = createPublicKey(fs.readFileSync(options.publicKeyPath, "utf-8"));
  const signatureOk = verifyPayload(
    null,
    Buffer.from(signingInput),
    publicKey,
    Buffer.from(signaturePart, "base64url"),
  );
  if (!signatureOk) throw new Error("invalid JWT signature");

  const payload = decodeJwtPart(payloadPart);
  const identity = `openshell-gateway:${options.gatewayId}`;
  expect(payload.iss).toBe(identity);
  expect(payload.aud).toBe(identity);
  expect(String(payload.sub)).toBe(`${SANDBOX_JWT_SUBJECT_PREFIX}${payload.sandbox_id}`);
  if (typeof payload.exp === "number" && payload.exp !== 0 && payload.exp < options.now - 60) {
    throw new Error("expired JWT");
  }
  return payload;
}

describe("buildDockerDriverGatewayEnv", () => {
  it("sets Docker-driver gateway networking from NemoClaw configuration", () => {
    const env = buildDockerDriverGatewayEnv({
      platform: "linux",
      stateDir: "/tmp/nemoclaw-gateway",
      getDockerSupervisorImage: () => "ghcr.io/nvidia/openshell/supervisor:0.0.37",
      resolveSandboxBin: () => "/usr/bin/openshell-sandbox",
    });

    expect(env).toMatchObject({
      OPENSHELL_DRIVERS: "docker",
      OPENSHELL_BIND_ADDRESS: "127.0.0.1",
      OPENSHELL_SERVER_PORT: "8080",
      OPENSHELL_GRPC_ENDPOINT: "http://127.0.0.1:8080",
      OPENSHELL_SSH_GATEWAY_HOST: "127.0.0.1",
      OPENSHELL_SSH_GATEWAY_PORT: "8080",
      OPENSHELL_DOCKER_NETWORK_NAME: "openshell-docker",
      OPENSHELL_DOCKER_SUPERVISOR_IMAGE: "ghcr.io/nvidia/openshell/supervisor:0.0.37",
      OPENSHELL_DOCKER_SUPERVISOR_BIN: "/usr/bin/openshell-sandbox",
      OPENSHELL_GATEWAY_CONFIG: "/tmp/nemoclaw-gateway/openshell-gateway.toml",
    });
    expect(env.OPENSHELL_DISABLE_GATEWAY_AUTH).toBeUndefined();
  });

  it("uses the Docker driver on macOS without VM helper state", () => {
    const env = buildDockerDriverGatewayEnv({
      platform: "darwin",
      stateDir: "/tmp/nemoclaw-gateway",
      getDockerSupervisorImage: () => "ghcr.io/nvidia/openshell/supervisor:0.0.37",
      resolveSandboxBin: () => "/usr/local/bin/openshell-sandbox",
    });

    expect(env).toMatchObject({
      OPENSHELL_DRIVERS: "docker",
      OPENSHELL_BIND_ADDRESS: "127.0.0.1",
      OPENSHELL_SERVER_PORT: "8080",
      OPENSHELL_GRPC_ENDPOINT: "http://127.0.0.1:8080",
      OPENSHELL_DOCKER_NETWORK_NAME: "openshell-docker",
      OPENSHELL_DOCKER_SUPERVISOR_IMAGE: "ghcr.io/nvidia/openshell/supervisor:0.0.37",
      OPENSHELL_GATEWAY_CONFIG: "/tmp/nemoclaw-gateway/openshell-gateway.toml",
    });
    expect(env.OPENSHELL_DOCKER_SUPERVISOR_BIN).toBeUndefined();
    expect(env.OPENSHELL_VM_DRIVER_STATE_DIR).toBeUndefined();
    expect(env.OPENSHELL_DRIVER_DIR).toBeUndefined();
  });

  it("writes OpenShell 0.0.67 gateway JWT config into the managed state dir", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-env-config-"));
    try {
      const env = buildDockerDriverGatewayEnv({
        platform: "linux",
        stateDir,
        getDockerSupervisorImage: () => "ghcr.io/nvidia/openshell/supervisor:0.0.67",
        resolveSandboxBin: () => "/usr/bin/openshell-sandbox",
      });
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
      expect(toml).toContain("ttl_secs = 3600");
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
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-env-config-"));
    try {
      buildDockerDriverGatewayEnv({
        platform: "linux",
        stateDir,
        getDockerSupervisorImage: () => "ghcr.io/nvidia/openshell/supervisor:0.0.67",
        resolveSandboxBin: () => "/usr/bin/openshell-sandbox",
      });
      const signingKeyPath = path.join(stateDir, "jwt", "signing.pem");
      const firstSigningKey = fs.readFileSync(signingKeyPath, "utf-8");

      buildDockerDriverGatewayEnv({
        platform: "linux",
        stateDir,
        getDockerSupervisorImage: () => "ghcr.io/nvidia/openshell/supervisor:0.0.67",
        resolveSandboxBin: () => "/usr/bin/openshell-sandbox",
      });

      expect(fs.readFileSync(signingKeyPath, "utf-8")).toBe(firstSigningKey);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("regenerates an incomplete gateway JWT bundle before writing config", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-env-config-"));
    try {
      const jwtDir = path.join(stateDir, "jwt");
      fs.mkdirSync(jwtDir, { recursive: true, mode: 0o700 });
      const signingKeyPath = path.join(jwtDir, "signing.pem");
      const publicKeyPath = path.join(jwtDir, "public.pem");
      const kidPath = path.join(jwtDir, "kid");
      fs.writeFileSync(signingKeyPath, "stale partial key\n", { mode: 0o600 });

      buildDockerDriverGatewayEnv({
        platform: "linux",
        stateDir,
        getDockerSupervisorImage: () => "ghcr.io/nvidia/openshell/supervisor:0.0.67",
        resolveSandboxBin: () => "/usr/bin/openshell-sandbox",
      });

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
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-env-config-"));
    try {
      const env = buildDockerDriverGatewayEnv({
        platform: "linux",
        stateDir,
        getDockerSupervisorImage: () => "ghcr.io/nvidia/openshell/supervisor:0.0.67",
        resolveSandboxBin: () => "/usr/bin/openshell-sandbox",
      });
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
      expect(ttlSecs).toBe(3600);

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
      ).toThrow("expired JWT");
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });
});

describe("buildDockerGatewayDebEnvFile", () => {
  it("replaces all managed gateway env keys and preserves unrelated values", () => {
    const next = buildDockerGatewayDebEnvFile(
      [
        "KEEP_ME=1",
        "OPENSHELL_BIND_ADDRESS=127.0.0.1",
        "OPENSHELL_SERVER_PORT=8080",
        "OPENSHELL_DOCKER_SUPERVISOR_IMAGE=old",
      ].join("\n"),
      {
        OPENSHELL_DRIVERS: "docker",
        OPENSHELL_BIND_ADDRESS: "0.0.0.0",
        OPENSHELL_SERVER_PORT: "8990",
        OPENSHELL_DISABLE_TLS: "true",
        OPENSHELL_DISABLE_GATEWAY_AUTH: "true",
        OPENSHELL_DB_URL: "sqlite:/tmp/openshell.db",
        OPENSHELL_GRPC_ENDPOINT: "http://127.0.0.1:8990",
        OPENSHELL_SSH_GATEWAY_HOST: "127.0.0.1",
        OPENSHELL_SSH_GATEWAY_PORT: "8990",
        OPENSHELL_DOCKER_NETWORK_NAME: "openshell-docker",
        OPENSHELL_DOCKER_SUPERVISOR_IMAGE: "new",
        OPENSHELL_GATEWAY_CONFIG: "/tmp/openshell-gateway.toml",
        OPENSHELL_VM_DRIVER_STATE_DIR: "/tmp/old-vm-driver",
      },
    );

    expect(next).toContain("KEEP_ME=1\n");
    expect(next).toContain("OPENSHELL_BIND_ADDRESS=0.0.0.0\n");
    expect(next).toContain("OPENSHELL_SERVER_PORT=8990\n");
    expect(next).toContain("OPENSHELL_DOCKER_SUPERVISOR_IMAGE=new\n");
    expect(next).toContain("OPENSHELL_GATEWAY_CONFIG=/tmp/openshell-gateway.toml\n");
    expect(next).toContain("OPENSHELL_VM_DRIVER_STATE_DIR=/tmp/old-vm-driver\n");
    expect(next).not.toContain("OPENSHELL_BIND_ADDRESS=127.0.0.1");
    expect(next).not.toContain("OPENSHELL_DOCKER_SUPERVISOR_IMAGE=old");
  });

  it("removes stale VM driver env keys when writing a Docker-driver env file", () => {
    const next = buildDockerGatewayDebEnvFile(
      [
        "OPENSHELL_DRIVERS=vm",
        "OPENSHELL_VM_DRIVER_STATE_DIR=/tmp/old-vm-driver",
        "OPENSHELL_DRIVER_DIR=/tmp/old-driver-dir",
      ].join("\n"),
      {
        OPENSHELL_DRIVERS: "docker",
      },
    );

    expect(next).toBe("OPENSHELL_DRIVERS=docker\n");
  });

  it("removes stale auth-disable env so OpenShell 0.0.67 TOML auth policy stays authoritative", () => {
    const next = buildDockerGatewayDebEnvFile(
      [
        "KEEP_ME=1",
        "OPENSHELL_DISABLE_GATEWAY_AUTH=true",
        "OPENSHELL_GATEWAY_CONFIG=/tmp/old-gateway.toml",
      ].join("\n"),
      {
        OPENSHELL_DRIVERS: "docker",
        OPENSHELL_GATEWAY_CONFIG: "/tmp/new-gateway.toml",
      },
    );

    expect(next).toContain("KEEP_ME=1\n");
    expect(next).toContain("OPENSHELL_DRIVERS=docker\n");
    expect(next).toContain("OPENSHELL_GATEWAY_CONFIG=/tmp/new-gateway.toml\n");
    expect(next).not.toContain("OPENSHELL_DISABLE_GATEWAY_AUTH");
    expect(next).not.toContain("OPENSHELL_GATEWAY_CONFIG=/tmp/old-gateway.toml");
  });

  it("rejects multiline managed values", () => {
    expect(() =>
      buildDockerGatewayDebEnvFile("", {
        OPENSHELL_BIND_ADDRESS: "127.0.0.1\nINJECTED=1",
      }),
    ).toThrow("line break");
  });
});

describe("writeDockerGatewayDebEnvOverride", () => {
  it("enforces restrictive permissions on an existing env directory and file", () => {
    const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-env-"));
    const envDir = path.join(tempHome, ".config", "openshell");
    const envFile = path.join(envDir, "gateway.env");
    fs.mkdirSync(envDir, { recursive: true, mode: 0o755 });
    fs.chmodSync(envDir, 0o755);
    fs.writeFileSync(envFile, "KEEP_ME=1\n", { mode: 0o644 });
    fs.chmodSync(envFile, 0o644);

    const existsSpy = vi
      .spyOn(fs, "existsSync")
      .mockImplementation(
        (candidate) => candidate === "/usr/lib/systemd/user/openshell-gateway.service",
      );
    const homedirSpy = vi.spyOn(os, "homedir").mockReturnValue(tempHome);

    try {
      const wrote = writeDockerGatewayDebEnvOverride(
        () => ({
          OPENSHELL_BIND_ADDRESS: "127.0.0.1",
        }),
        { platform: "linux" },
      );

      const envFileContent = fs.readFileSync(envFile, "utf-8");
      expect(wrote).toBe(true);
      expect(fs.statSync(envDir).mode & 0o777).toBe(0o700);
      expect(fs.statSync(envFile).mode & 0o777).toBe(0o600);
      expect(envFileContent).toContain("KEEP_ME=1\n");
      expect(envFileContent).toContain("OPENSHELL_BIND_ADDRESS=127.0.0.1\n");
    } finally {
      existsSpy.mockRestore();
      homedirSpy.mockRestore();
      fs.rmSync(tempHome, { recursive: true, force: true });
    }
  });

  it("does not write service env for standalone gateway binaries", () => {
    const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-env-"));
    const existsSpy = vi
      .spyOn(fs, "existsSync")
      .mockImplementation((candidate) => candidate === "/usr/bin/openshell-gateway");
    const homedirSpy = vi.spyOn(os, "homedir").mockReturnValue(tempHome);

    try {
      const wrote = writeDockerGatewayDebEnvOverride(
        () => ({
          OPENSHELL_BIND_ADDRESS: "127.0.0.1",
        }),
        { platform: "linux" },
      );

      expect(wrote).toBe(false);
      expect(fs.existsSync(path.join(tempHome, ".config", "openshell", "gateway.env"))).toBe(false);
    } finally {
      existsSpy.mockRestore();
      homedirSpy.mockRestore();
      fs.rmSync(tempHome, { recursive: true, force: true });
    }
  });

  it("writes the service env only when package-managed startup prepares the service", async () => {
    const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-env-"));
    const envFile = path.join(tempHome, ".config", "openshell", "gateway.env");
    const existsSpy = vi
      .spyOn(fs, "existsSync")
      .mockImplementation(
        (candidate) => candidate === "/usr/lib/systemd/user/openshell-gateway.service",
      );
    const homedirSpy = vi.spyOn(os, "homedir").mockReturnValue(tempHome);

    try {
      await expect(
        startPackageManagedDockerDriverGatewayWithEnvOverride({
          clearDockerDriverGatewayRuntimeFiles: vi.fn(),
          exitOnFailure: false,
          gatewayEnv: { OPENSHELL_BIND_ADDRESS: "127.0.0.1" },
          gatewayName: "nemoclaw",
          hasOpenShellGatewayUserService: () => true,
          isDockerDriverGatewayReady: async () => true,
          registerDockerDriverGatewayEndpoint: () => true,
          runCaptureOpenshell: (args) =>
            args[0] === "status"
              ? "Gateway: nemoclaw\nConnected"
              : "Gateway: nemoclaw\nGateway endpoint: https://127.0.0.1:8080/",
          skipSandboxBridgeReachability: false,
          startOpenShellGatewayUserService: (opts) => {
            opts?.prepareServiceEnv?.();
            return { attempted: true, fallbackAllowed: false, started: true };
          },
          verifySandboxBridgeGatewayReachableOrExit: async () => undefined,
        }),
      ).resolves.toBe(true);

      expect(fs.readFileSync(envFile, "utf-8")).toContain("OPENSHELL_BIND_ADDRESS=127.0.0.1\n");
    } finally {
      existsSpy.mockRestore();
      homedirSpy.mockRestore();
      fs.rmSync(tempHome, { recursive: true, force: true });
    }
  });
});
