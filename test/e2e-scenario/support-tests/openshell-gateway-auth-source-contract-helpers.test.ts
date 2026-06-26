// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import path from "node:path";

import { describe, expect, it } from "vitest";

import { buildSandboxTokenContainerProbeDockerArgs } from "../live/openshell-gateway-auth-source-contract-helpers.ts";

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
});
