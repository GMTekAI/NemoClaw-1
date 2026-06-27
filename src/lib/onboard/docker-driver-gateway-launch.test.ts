// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  buildDockerDriverGatewayConfigToml,
  buildDockerDriverGatewayLaunch,
  buildDockerDriverGatewayRuntimeIdentity,
  parseGlibcVersionsFromBinaryText,
  prepareAndLogDockerDriverGatewayLaunch,
  resolveDriftGatewayBin,
  shouldUseContainerizedGateway,
} from "../../../dist/lib/onboard/docker-driver-gateway-launch";

function withTempBinaries<T>(
  fn: (paths: { dir: string; gatewayBin: string; sandboxBin: string }) => T,
): T {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-launch-"));
  const gatewayBin = path.join(dir, "openshell-gateway");
  const sandboxBin = path.join(dir, "openshell-sandbox");
  try {
    fs.writeFileSync(gatewayBin, "GLIBC_2.39\n", { mode: 0o755 });
    fs.writeFileSync(sandboxBin, "#!/bin/sh\n", { mode: 0o755 });
    return fn({ dir, gatewayBin, sandboxBin });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("docker-driver-gateway-launch", () => {
  it("extracts GLIBC versions from binary text", () => {
    expect(parseGlibcVersionsFromBinaryText("GLIBC_2.35\0GLIBC_2.39\0GLIBC_2.39")).toEqual([
      "2.35",
      "2.39",
    ]);
  });

  it("selects the containerized gateway only for affected Linux hosts or explicit force", () => {
    expect(
      shouldUseContainerizedGateway({
        gatewayBin: "/tmp/openshell-gateway",
        platform: "linux",
        env: {},
        hostGlibcVersion: "2.35",
        requiredGlibcVersions: ["2.38", "2.39"],
      }),
    ).toMatchObject({ useContainer: true });
    expect(
      shouldUseContainerizedGateway({
        gatewayBin: "/tmp/openshell-gateway",
        platform: "linux",
        env: {},
        hostGlibcVersion: "2.39",
        requiredGlibcVersions: ["2.38", "2.39"],
      }),
    ).toEqual({ useContainer: false });
    expect(
      shouldUseContainerizedGateway({
        gatewayBin: "/tmp/openshell-gateway",
        platform: "darwin",
        env: { NEMOCLAW_OPENSHELL_GATEWAY_CONTAINER_PATCH: "1" },
        hostGlibcVersion: "2.35",
        requiredGlibcVersions: ["2.39"],
      }),
    ).toEqual({ useContainer: false });
    expect(
      shouldUseContainerizedGateway({
        gatewayBin: "/tmp/openshell-gateway",
        platform: "linux",
        env: { NEMOCLAW_OPENSHELL_GATEWAY_CONTAINER_PATCH: "0" },
        hostGlibcVersion: "2.35",
        requiredGlibcVersions: ["2.39"],
      }),
    ).toEqual({ useContainer: false });
  });

  it("builds a Docker-hosted gateway launch that preserves Docker-driver env", () => {
    withTempBinaries(({ dir, gatewayBin, sandboxBin }) => {
      const stateDir = path.join(dir, "state");
      const dockerSocket = path.join(dir, "docker.sock");
      fs.mkdirSync(stateDir);
      fs.writeFileSync(dockerSocket, "");
      const launch = buildDockerDriverGatewayLaunch({
        gatewayBin,
        sandboxBin,
        stateDir,
        platform: "linux",
        env: {
          DOCKER_HOST: `unix://${dockerSocket}`,
          NEMOCLAW_OPENSHELL_GATEWAY_CONTAINER_PATCH: "1",
        },
        gatewayEnv: {
          OPENSHELL_DB_URL: `sqlite:${path.join(stateDir, "openshell.db")}`,
          OPENSHELL_DRIVERS: "docker",
        },
      });

      expect(launch.mode).toBe("container");
      expect(launch.command).toBe("docker");
      expect(launch.processGatewayBin).toBeNull();
      expect(launch.args).toEqual(
        expect.arrayContaining([
          "run",
          "--rm",
          "--name",
          "nemoclaw-openshell-gateway",
          "--network",
          "host",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges",
          "--volume",
          `${gatewayBin}:/opt/nemoclaw/openshell-gateway:ro`,
          "--volume",
          `${stateDir}:${stateDir}:rw`,
          "--volume",
          `${dir}:${dir}:ro`,
          "--volume",
          `${dockerSocket}:${dockerSocket}:ro`,
          "--env",
          "OPENSHELL_DRIVERS",
          "--env",
          "OPENSHELL_DOCKER_SUPERVISOR_BIN",
          "--env",
          "OPENSHELL_GATEWAY_CONFIG",
          "ubuntu:24.04@sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54",
          "/opt/nemoclaw/openshell-gateway",
        ]),
      );
      expect(launch.args).not.toContain("ubuntu:24.04");
      expect(launch.args).not.toContain("--publish");
      expect(launch.args).not.toContain("-p");
      expect(launch.env.OPENSHELL_DOCKER_SUPERVISOR_BIN).toBe(sandboxBin);
      expect(launch.env.OPENSHELL_BIND_ADDRESS).toBe("127.0.0.1");
      const configPath = launch.env.OPENSHELL_GATEWAY_CONFIG;
      expect(configPath).toBe(path.join(stateDir, "openshell-gateway.toml"));
      expect(configPath).toBeDefined();
      if (!configPath) throw new Error("expected generated gateway config path");
      const toml = fs.readFileSync(configPath, "utf-8");
      expect(toml).toContain(`supervisor_bin = "${sandboxBin}"`);
      expect(toml).toContain("disable_tls = false");
      expect(toml).toContain("[openshell.gateway.tls]");
      expect(toml).toContain(`cert_path = "${path.join(stateDir, "tls", "server", "tls.crt")}"`);
      expect(toml).toContain(`client_ca_path = "${path.join(stateDir, "tls", "ca.crt")}"`);
      expect(toml).toContain("[openshell.gateway.mtls_auth]");
      expect(toml).toContain("enabled = true");
      expect(toml).toContain("[openshell.gateway.gateway_jwt]");
      expect(toml).toContain(`signing_key_path = "${path.join(stateDir, "jwt", "signing.pem")}"`);
      expect(toml).toContain("[openshell.gateway.auth]");
      expect(toml).toContain("allow_unauthenticated_users = false");
      expect(toml).toContain(`guest_tls_ca = "${path.join(stateDir, "tls", "ca.crt")}"`);
      expect(toml).toContain(
        `guest_tls_cert = "${path.join(stateDir, "tls", "client", "tls.crt")}"`,
      );
      expect(launch.env.OPENSHELL_DISABLE_GATEWAY_AUTH).toBeUndefined();
      expect(launch.args).not.toContain("OPENSHELL_DISABLE_GATEWAY_AUTH");
      expect(fs.existsSync(path.join(stateDir, "jwt", "public.pem"))).toBe(true);
    });
  });

  it("scrubs stale auth-disable env from compatibility gateway launches", () => {
    withTempBinaries(({ dir, gatewayBin, sandboxBin }) => {
      const stateDir = path.join(dir, "state");
      fs.mkdirSync(stateDir);
      const launch = buildDockerDriverGatewayLaunch({
        gatewayBin,
        sandboxBin,
        stateDir,
        platform: "linux",
        env: {
          NEMOCLAW_OPENSHELL_GATEWAY_CONTAINER_PATCH: "1",
          OPENSHELL_DISABLE_GATEWAY_AUTH: "true",
        },
        gatewayEnv: {
          OPENSHELL_DRIVERS: "docker",
        },
      });

      expect(launch.mode).toBe("container");
      expect(launch.env.OPENSHELL_DISABLE_GATEWAY_AUTH).toBeUndefined();
      expect(launch.args).not.toContain("OPENSHELL_DISABLE_GATEWAY_AUTH");
    });
  });

  it("logs the loopback main bind, Docker bridge listener contract, and auth boundary", () => {
    const messages: string[] = [];
    prepareAndLogDockerDriverGatewayLaunch(
      {
        command: "docker",
        args: [],
        env: {
          OPENSHELL_BIND_ADDRESS: "127.0.0.1",
          OPENSHELL_GATEWAY_CONFIG: "/tmp/openshell-gateway.toml",
        },
        mode: "container",
        processGatewayBin: null,
        reason: "forced by test",
      },
      (message) => messages.push(message),
    );

    expect(messages).toContain(
      "  Compatibility gateway bind: 127.0.0.1 main listener plus OpenShell Docker-driver bridge reachability.",
    );
    expect(messages).toContain(
      "  Compatibility container trust boundary: host networking plus Docker API access; disable with NEMOCLAW_OPENSHELL_GATEWAY_CONTAINER_PATCH=0 on untrusted hosts.",
    );
    expect(messages).toContain(
      "  Gateway auth boundary: host-side OpenShell CLI uses local mTLS; sandbox callbacks use mTLS plus OpenShell gateway JWT.",
    );
  });

  it("writes Docker driver settings in gateway TOML because OpenShell driver config is not env-backed", () => {
    const toml = buildDockerDriverGatewayConfigToml(
      {
        OPENSHELL_GRPC_ENDPOINT: "https://127.0.0.1:8080",
        OPENSHELL_LOCAL_TLS_DIR: "/tmp/openshell-tls",
        OPENSHELL_DOCKER_NETWORK_NAME: "openshell-docker",
        OPENSHELL_DOCKER_SUPERVISOR_IMAGE: "ghcr.io/nvidia/openshell/supervisor:0.0.44",
      },
      "/home/shadeform/.local/bin/openshell-sandbox",
    );

    expect(toml).toContain('compute_drivers = ["docker"]');
    expect(toml).toContain('grpc_endpoint = "https://127.0.0.1:8080"');
    expect(toml).toContain('network_name = "openshell-docker"');
    expect(toml).toContain('supervisor_image = "ghcr.io/nvidia/openshell/supervisor:0.0.44"');
    expect(toml).toContain('supervisor_bin = "/home/shadeform/.local/bin/openshell-sandbox"');
  });

  it("rejects wildcard binds for the compatibility gateway", () => {
    expect(() => {
      withTempBinaries(({ dir, gatewayBin, sandboxBin }) => {
        const stateDir = path.join(dir, "state");
        fs.mkdirSync(stateDir);
        buildDockerDriverGatewayLaunch({
          gatewayBin,
          sandboxBin,
          stateDir,
          platform: "linux",
          env: {
            NEMOCLAW_OPENSHELL_GATEWAY_CONTAINER_PATCH: "1",
            NEMOCLAW_OPENSHELL_GATEWAY_COMPAT_BIND_ADDRESS: "0.0.0.0",
          },
          gatewayEnv: {
            OPENSHELL_BIND_ADDRESS: "127.0.0.1",
            OPENSHELL_DRIVERS: "docker",
          },
        });
      });
    }).toThrow(/only supports 127\.0\.0\.1/);
  });

  it("rejects wildcard binds for direct host gateway launches", () => {
    expect(() => {
      withTempBinaries(({ dir, gatewayBin }) => {
        const stateDir = path.join(dir, "state");
        fs.mkdirSync(stateDir);
        buildDockerDriverGatewayLaunch({
          gatewayBin,
          stateDir,
          platform: "linux",
          env: {},
          hostGlibcVersion: "2.39",
          requiredGlibcVersions: ["2.39"],
          gatewayEnv: {
            OPENSHELL_BIND_ADDRESS: "0.0.0.0",
            OPENSHELL_DRIVERS: "docker",
          },
        });
      });
    }).toThrow(/not supported for the OpenShell 0\.0\.67 Docker-driver gateway/);
  });

  it("keeps the drift gateway binary null for the containerized compatibility gateway (#4520)", () => {
    withTempBinaries(({ dir, gatewayBin, sandboxBin }) => {
      const stateDir = path.join(dir, "state");
      fs.mkdirSync(stateDir);
      const identity = buildDockerDriverGatewayRuntimeIdentity({
        gatewayBin,
        sandboxBin,
        stateDir,
        platform: "linux",
        env: { NEMOCLAW_OPENSHELL_GATEWAY_CONTAINER_PATCH: "1" },
        gatewayEnv: { OPENSHELL_DRIVERS: "docker" },
      });

      expect(identity.launch?.mode).toBe("container");
      // The compat gateway parent process is `/usr/bin/docker`, not the host
      // binary, so the executable check must be skipped via a null drift bin.
      expect(identity.driftGatewayBin).toBeNull();
      // The identity bin still falls back to the host binary for listener PID
      // matching, where the cmdline contains the gateway path.
      expect(identity.identityGatewayBin).toBe(gatewayBin);

      // Callers must preserve that deliberate null rather than coalescing it
      // back to the host binary (the #4520 false-stale bug).
      expect(resolveDriftGatewayBin(identity, gatewayBin)).toBeNull();
      // `?? gatewayBin` would have wrongly restored the host path:
      expect(identity.driftGatewayBin ?? gatewayBin).toBe(gatewayBin);
    });
  });

  it("uses the host binary as the drift binary outside compatibility mode", () => {
    withTempBinaries(({ dir, gatewayBin }) => {
      const identity = buildDockerDriverGatewayRuntimeIdentity({
        gatewayBin,
        stateDir: dir,
        platform: "linux",
        env: {},
        hostGlibcVersion: "2.39",
        requiredGlibcVersions: ["2.39"],
        gatewayEnv: { OPENSHELL_DRIVERS: "docker" },
      });

      expect(identity.launch?.mode).toBe("host");
      expect(identity.driftGatewayBin).toBe(gatewayBin);
      expect(identity.desiredEnv.OPENSHELL_GATEWAY_CONFIG).toBe(
        path.join(dir, "openshell-gateway.toml"),
      );
      expect(resolveDriftGatewayBin(identity, gatewayBin)).toBe(gatewayBin);
    });
  });

  it("falls back to the host binary when no runtime identity is available", () => {
    expect(resolveDriftGatewayBin(null, "/opt/openshell/openshell-gateway")).toBe(
      "/opt/openshell/openshell-gateway",
    );
    expect(resolveDriftGatewayBin(null, null)).toBeNull();
  });

  it("uses the host binary when the gateway ABI is compatible", () => {
    withTempBinaries(({ dir, gatewayBin }) => {
      const launch = buildDockerDriverGatewayLaunch({
        gatewayBin,
        stateDir: dir,
        platform: "linux",
        env: {},
        hostGlibcVersion: "2.39",
        requiredGlibcVersions: ["2.39"],
        gatewayEnv: { OPENSHELL_DRIVERS: "docker" },
      });

      expect(launch).toMatchObject({
        command: gatewayBin,
        args: [],
        mode: "host",
        processGatewayBin: gatewayBin,
      });
    });
  });

  it("scrubs stale auth-disable env from direct host gateway launches", () => {
    withTempBinaries(({ dir, gatewayBin }) => {
      const launch = buildDockerDriverGatewayLaunch({
        gatewayBin,
        stateDir: dir,
        platform: "linux",
        env: { OPENSHELL_DISABLE_GATEWAY_AUTH: "true" },
        hostGlibcVersion: "2.39",
        requiredGlibcVersions: ["2.39"],
        gatewayEnv: { OPENSHELL_DRIVERS: "docker" },
      });

      expect(launch.mode).toBe("host");
      expect(launch.env.OPENSHELL_DISABLE_GATEWAY_AUTH).toBeUndefined();
    });
  });
});
