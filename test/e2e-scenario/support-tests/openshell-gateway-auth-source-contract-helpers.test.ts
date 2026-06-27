// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import path from "node:path";

import { describe, expect, it, vi } from "vitest";

import {
  buildSandboxTokenContainerProbeDockerArgs,
  skipUnavailableProbeImage,
} from "../live/openshell-gateway-auth-source-contract-helpers.ts";

function valuesAfterFlag(args: string[], flag: string): string[] {
  return args.flatMap((arg, index) => (arg === flag ? [args[index + 1] ?? ""] : []));
}

describe("OpenShell gateway auth source contract helpers", () => {
  it("mounts only TLS material into the sandbox JWT Docker probe", () => {
    const stateDir = path.resolve("/tmp/nemoclaw-auth-source-state");
    const args = buildSandboxTokenContainerProbeDockerArgs({
      authorization: "Bearer sandbox-token",
      dockerBin: "docker",
      networkName: "nemoclaw-auth-source-net",
      payload: Buffer.from("sandbox request"),
      port: 47321,
      stateDir,
    });

    expect(valuesAfterFlag(args, "--volume")).toEqual([
      `${path.join(stateDir, "tls", "ca.crt")}:/tmp/nemoclaw-probe-ca.crt:ro`,
      `${path.join(stateDir, "tls", "client", "tls.crt")}:/tmp/nemoclaw-probe-client.crt:ro`,
      `${path.join(stateDir, "tls", "client", "tls.key")}:/tmp/nemoclaw-probe-client.key:ro`,
    ]);
    expect(valuesAfterFlag(args, "--env")).toEqual(
      expect.arrayContaining([
        "PROBE_AUTHORIZATION=Bearer sandbox-token",
        "PROBE_CA_PATH=/tmp/nemoclaw-probe-ca.crt",
        "PROBE_CLIENT_CERT_PATH=/tmp/nemoclaw-probe-client.crt",
        "PROBE_CLIENT_KEY_PATH=/tmp/nemoclaw-probe-client.key",
      ]),
    );
    expect(args).not.toContain(`${stateDir}:${stateDir}:ro`);

    const serializedArgs = args.join("\n");
    expect(serializedArgs).not.toContain("jwt/signing.pem");
    expect(serializedArgs).not.toContain("jwt/kid");
    expect(serializedArgs).not.toContain("openshell-gateway.toml");
  });

  it("omits sandbox JWT material from the mTLS-only Docker probe", () => {
    const args = buildSandboxTokenContainerProbeDockerArgs({
      dockerBin: "docker",
      networkName: "nemoclaw-auth-source-net",
      payload: Buffer.from("sandbox request"),
      port: 47321,
      stateDir: path.resolve("/tmp/nemoclaw-auth-source-state"),
    });

    expect(
      valuesAfterFlag(args, "--env").some((value) => value.startsWith("PROBE_AUTHORIZATION=")),
    ).toBe(false);
  });

  it("uses host networking to reach a loopback-only Linux gateway", () => {
    const args = buildSandboxTokenContainerProbeDockerArgs({
      dockerBin: "docker",
      networkName: "nemoclaw-auth-source-net",
      payload: Buffer.from("sandbox request"),
      port: 47321,
      stateDir: path.resolve("/tmp/nemoclaw-auth-source-state"),
      useHostNetwork: true,
    });

    expect(valuesAfterFlag(args, "--network")).toEqual(["host"]);
    expect(valuesAfterFlag(args, "--add-host")).toEqual(["host.openshell.internal:127.0.0.1"]);
  });

  it("hard-fails unavailable Docker probe images on GitHub Actions", () => {
    const skip = vi.fn();

    expect(() =>
      skipUnavailableProbeImage(
        { status: 125, stdout: "", stderr: "toomanyrequests: rate limit exceeded" },
        skip,
        true,
      ),
    ).toThrow(/Docker probe image was unavailable.*toomanyrequests/);
    expect(skip).not.toHaveBeenCalled();
  });

  it("allows local runs to skip when the Docker probe image is unavailable", () => {
    const skip = vi.fn();

    skipUnavailableProbeImage({ status: 125, stdout: "", stderr: "manifest unknown" }, skip, false);

    expect(skip).toHaveBeenCalledWith("Docker probe image was unavailable: manifest unknown");
  });
});
