// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import { chmod } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { buildAvailabilityProbeEnv } from "../fixtures/availability-env.ts";
import type { HostCliClient } from "../fixtures/clients/host.ts";
import { trustedSandboxShellScript, type SandboxClient } from "../fixtures/clients/sandbox.ts";
import { expect, test } from "../fixtures/e2e-test.ts";
import type { CleanupRegistry } from "../fixtures/cleanup.ts";
import type { ArtifactSink } from "../fixtures/artifacts.ts";
import type { ShellProbeResult } from "../fixtures/shell-probe.ts";

const SANDBOX_NAME = "e2e-mcp-bridge";
const SERVER_NAME = "fake";
const HOST_SECRET = "fake-host-mcp-secret-value";
const REGISTRY_FILE = path.join(process.env.HOME ?? os.homedir(), ".nemoclaw", "sandboxes.json");
const liveTest = process.env.NEMOCLAW_RUN_E2E_SCENARIOS === "1" ? test : test.skip;

function resultText(result: ShellProbeResult): string {
  return [result.stdout, result.stderr].filter(Boolean).join("\n");
}

function expectExitZero(result: ShellProbeResult, label: string): void {
  expect(result.exitCode, `${label}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`).toBe(0);
}

async function bestEffortRemoveBridge(host: HostCliClient): Promise<void> {
  await host.nemoclaw([SANDBOX_NAME, "mcp", "remove", SERVER_NAME, "--force"], {
    artifactName: "cleanup-mcp-remove",
    env: buildAvailabilityProbeEnv(),
    timeoutMs: 60_000,
  });
}

async function cleanupSandbox(host: HostCliClient): Promise<void> {
  await host.bestEffortCleanupSandbox(SANDBOX_NAME, {
    artifactName: "cleanup-destroy-sandbox",
    timeoutMs: 15 * 60_000,
  });
}

async function createFakeMcpServer(artifacts: ArtifactSink): Promise<string> {
  const script = await artifacts.writeText(
    "fake-mcp-server.js",
    `let buffer = "";
process.stdin.on("data", (chunk) => {
  buffer += chunk.toString("utf8");
  const lines = buffer.split("\\n");
  buffer = lines.pop() || "";
  for (const line of lines.filter((value) => value.trim())) {
    const request = JSON.parse(line);
    const method = request.method;
    const result = method === "initialize"
      ? { protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "fake", version: "1.0.0" } }
      : method === "tools/list"
        ? { tools: [{ name: "fake_echo", description: "fake echo", inputSchema: { type: "object", properties: {} } }] }
        : { ok: true };
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }) + "\\n");
  }
});
setInterval(() => {}, 1000);
`,
  );
  await chmod(script, 0o755);
  return script;
}

async function onboardOpenClaw(host: HostCliClient, cleanup: CleanupRegistry): Promise<void> {
  cleanup.add("destroy MCP bridge sandbox", () => cleanupSandbox(host));
  await host.bestEffortCleanupSandbox(SANDBOX_NAME, {
    artifactName: "precleanup-destroy-sandbox",
    timeoutMs: 15 * 60_000,
  });
  const apiKey = process.env.NVIDIA_INFERENCE_API_KEY ?? "";
  const result = await host.nemoclaw(
    ["onboard", "--non-interactive", "--yes", "--yes-i-accept-third-party-software"],
    {
      artifactName: "onboard-openclaw-mcp-bridge",
      env: {
        ...buildAvailabilityProbeEnv(),
        NEMOCLAW_AGENT: "openclaw",
        NEMOCLAW_PROVIDER: "cloud",
        NEMOCLAW_SANDBOX_NAME: SANDBOX_NAME,
        NEMOCLAW_RECREATE_SANDBOX: "1",
        NVIDIA_INFERENCE_API_KEY: apiKey,
      },
      redactionValues: [apiKey],
      timeoutMs: 20 * 60_000,
    },
  );
  expectExitZero(result, "onboard OpenClaw sandbox for MCP bridge");
}

async function assertSecretAbsentFromSandbox(sandbox: SandboxClient): Promise<void> {
  const result = await sandbox.execShell(
    SANDBOX_NAME,
    trustedSandboxShellScript(
      [
        "set -eu",
        `if grep -R ${JSON.stringify(HOST_SECRET)} /sandbox/.openclaw /sandbox/.mcp.json /sandbox/.hermes 2>/dev/null; then`,
        "  exit 1",
        "fi",
      ].join("\n"),
    ),
    {
      artifactName: "assert-secret-absent-from-sandbox",
      env: buildAvailabilityProbeEnv(),
      timeoutMs: 60_000,
    },
  );
  expectExitZero(result, "host MCP secret must not appear in sandbox files");
}

liveTest("mcp-bridge", { timeout: 45 * 60_000 }, async ({ artifacts, cleanup, host, sandbox }) => {
  await artifacts.writeJson("scenario.json", {
    id: "mcp-bridge",
    sandbox: SANDBOX_NAME,
    server: SERVER_NAME,
  });
  const fakeServer = await createFakeMcpServer(artifacts);
  await onboardOpenClaw(host, cleanup);
  cleanup.add("remove MCP bridge", () => bestEffortRemoveBridge(host));

  const add = await host.nemoclaw(
    [
      SANDBOX_NAME,
      "mcp",
      "add",
      SERVER_NAME,
      "--env",
      "FAKE_MCP_SECRET",
      "--",
      process.execPath,
      fakeServer,
    ],
    {
      artifactName: "mcp-add-fake-server",
      env: {
        ...buildAvailabilityProbeEnv(),
        FAKE_MCP_SECRET: HOST_SECRET,
      },
      redactionValues: [HOST_SECRET],
      timeoutMs: 2 * 60_000,
    },
  );
  expectExitZero(add, "mcp add fake server");

  const status = await host.nemoclaw([SANDBOX_NAME, "mcp", "status", SERVER_NAME, "--json"], {
    artifactName: "mcp-status-json",
    env: {
      ...buildAvailabilityProbeEnv(),
      FAKE_MCP_SECRET: HOST_SECRET,
    },
    redactionValues: [HOST_SECRET],
    timeoutMs: 60_000,
  });
  expectExitZero(status, "mcp status --json");
  const statusJson = JSON.parse(status.stdout) as {
    support: { supported: boolean; adapter: string };
    bridges: Array<{
      server: string;
      token: string;
      env: { names: string[]; ready: boolean; missing: string[] };
      proxy: { running: boolean };
      policy: { gatewayPresent: boolean | null };
      adapter: { registered: boolean | null };
    }>;
  };
  expect(statusJson.support).toMatchObject({ supported: true, adapter: "mcporter" });
  expect(statusJson.bridges).toHaveLength(1);
  expect(statusJson.bridges[0]).toMatchObject({
    server: SERVER_NAME,
    token: "[REDACTED]",
    env: { names: ["FAKE_MCP_SECRET"], ready: true, missing: [] },
    proxy: { running: true },
    policy: { gatewayPresent: true },
    adapter: { registered: true },
  });
  expect(status.stdout).not.toContain(HOST_SECRET);

  const policy = await sandbox.openshell(["policy", "get", "--full", SANDBOX_NAME], {
    artifactName: "openshell-policy-get-mcp",
    env: buildAvailabilityProbeEnv(),
    timeoutMs: 60_000,
  });
  expectExitZero(policy, "openshell policy get --full");
  expect(resultText(policy)).toContain("mcp-bridge-fake");
  expect(resultText(policy)).toContain("protocol: mcp");
  expect(resultText(policy)).toContain("allow_all_known_mcp_methods: true");
  expect(resultText(policy)).toContain("host.docker.internal");

  const registryRaw = fs.existsSync(REGISTRY_FILE) ? fs.readFileSync(REGISTRY_FILE, "utf8") : "";
  expect(registryRaw).toContain("enc:v1:");
  expect(registryRaw).not.toContain(HOST_SECRET);
  await assertSecretAbsentFromSandbox(sandbox);

  const remove = await host.nemoclaw([SANDBOX_NAME, "mcp", "remove", SERVER_NAME], {
    artifactName: "mcp-remove-fake-server",
    env: buildAvailabilityProbeEnv(),
    timeoutMs: 60_000,
  });
  expectExitZero(remove, "mcp remove fake server");

  const list = await host.nemoclaw([SANDBOX_NAME, "mcp", "list", "--json"], {
    artifactName: "mcp-list-after-remove",
    env: buildAvailabilityProbeEnv(),
    timeoutMs: 60_000,
  });
  expectExitZero(list, "mcp list after remove");
  expect(JSON.parse(list.stdout).bridges).toEqual([]);
});
