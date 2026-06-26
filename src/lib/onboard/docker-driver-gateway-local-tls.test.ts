// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  ensureDockerDriverGatewayLocalTlsBundle,
  getDockerDriverGatewayLocalTlsBundle,
} from "./docker-driver-gateway-local-tls";

function writeCompleteBundle(stateDir: string): Record<string, string> {
  const paths = getDockerDriverGatewayLocalTlsBundle(stateDir);
  const contents = {
    [paths.caPath]: "ca\n",
    [paths.serverCertPath]: "server cert\n",
    [paths.serverKeyPath]: "server key\n",
    [paths.clientCertPath]: "client cert\n",
    [paths.clientKeyPath]: "client key\n",
  };
  for (const [filePath, content] of Object.entries(contents)) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  return contents;
}

describe("docker-driver-gateway-local-tls", () => {
  it("runs OpenShell certgen into the NemoClaw-owned gateway TLS directory", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-tls-"));
    const calls: Array<{ command: string; args: string[]; env?: NodeJS.ProcessEnv }> = [];
    try {
      const bundle = ensureDockerDriverGatewayLocalTlsBundle({
        env: { PATH: "/usr/bin" },
        gatewayBin: "/opt/openshell/openshell-gateway",
        stateDir,
        spawnSyncImpl: ((
          command: string,
          args: string[],
          options?: { env?: NodeJS.ProcessEnv },
        ) => {
          calls.push({ command, args, env: options?.env });
          const paths = getDockerDriverGatewayLocalTlsBundle(stateDir);
          for (const filePath of [
            paths.caPath,
            paths.serverCertPath,
            paths.serverKeyPath,
            paths.clientCertPath,
            paths.clientKeyPath,
          ]) {
            fs.mkdirSync(path.dirname(filePath), { recursive: true });
            fs.writeFileSync(filePath, "pem\n");
          }
          return { status: 0, stdout: "", stderr: "" };
        }) as never,
      });

      expect(bundle.localTlsDir).toBe(path.join(stateDir, "tls"));
      expect(calls).toHaveLength(1);
      expect(calls[0]).toMatchObject({
        command: "/opt/openshell/openshell-gateway",
        args: [
          "generate-certs",
          "--output-dir",
          path.join(stateDir, "tls"),
          "--server-san",
          "host.openshell.internal",
        ],
      });
      expect(calls[0]?.env?.OPENSHELL_LOCAL_TLS_DIR).toBe(path.join(stateDir, "tls"));
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("preserves an existing complete mTLS bundle without regenerating certs", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-tls-"));
    const contents = writeCompleteBundle(stateDir);
    let certgenCalls = 0;
    try {
      const bundle = ensureDockerDriverGatewayLocalTlsBundle({
        env: { PATH: "/usr/bin" },
        gatewayBin: "/opt/openshell/openshell-gateway",
        stateDir,
        spawnSyncImpl: (() => {
          certgenCalls += 1;
          return { status: 0, stdout: "", stderr: "" };
        }) as never,
      });

      expect(bundle.localTlsDir).toBe(path.join(stateDir, "tls"));
      expect(certgenCalls).toBe(0);
      for (const [filePath, content] of Object.entries(contents)) {
        expect(fs.readFileSync(filePath, "utf-8")).toBe(content);
      }
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });
});
