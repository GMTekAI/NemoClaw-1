// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { buildAvailabilityProbeEnv } from "../fixtures/availability-env.ts";
import type { HostCliClient } from "../fixtures/clients/host.ts";
import { trustedSandboxShellScript, type SandboxClient } from "../fixtures/clients/sandbox.ts";
import { expect, test } from "../fixtures/e2e-test.ts";
import type { CleanupRegistry } from "../fixtures/cleanup.ts";
import type { ShellProbeResult } from "../fixtures/shell-probe.ts";
import { startCompatibleMock, startFakeMcpHttpServer } from "./mcp-bridge-servers.ts";

const SANDBOX_NAME = "e2e-mcp-bridge";
const SERVER_NAME = "fake";
const HOST_SECRET = "fake-host-mcp-secret-value";
const COMPATIBLE_KEY = "fake-compatible-mcp-bridge-key";
const COMPATIBLE_MODEL = "mock/mcp-bridge";
const REGISTRY_FILE = path.join(process.env.HOME ?? os.homedir(), ".nemoclaw", "sandboxes.json");
const liveTest = process.env.NEMOCLAW_RUN_E2E_SCENARIOS === "1" ? test : test.skip;

function resultText(result: ShellProbeResult): string {
  return [result.stdout, result.stderr].filter(Boolean).join("\n");
}

function expectExitZero(result: ShellProbeResult, label: string): void {
  expect(result.exitCode, `${label}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`).toBe(0);
}

async function hostAddressForSandbox(host: HostCliClient): Promise<string> {
  const probe = await host.command(
    "bash",
    [
      "-lc",
      [
        'ip_addr="$(ip route get 1.1.1.1 2>/dev/null | awk \'{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}\')"',
        'if [ -n "$ip_addr" ]; then echo "$ip_addr"; exit 0; fi',
        "ip_addr=\"$(hostname -I 2>/dev/null | awk '{print $1}')\"",
        'if [ -n "$ip_addr" ]; then echo "$ip_addr"; exit 0; fi',
        "echo 127.0.0.1",
      ].join("\n"),
    ],
    {
      artifactName: "host-ip-for-mcp-compatible-endpoint",
      env: buildAvailabilityProbeEnv(),
      timeoutMs: 30_000,
    },
  );
  return probe.stdout.trim().split(/\s+/)[0] || "127.0.0.1";
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

async function onboardOpenClaw(
  host: HostCliClient,
  cleanup: CleanupRegistry,
  endpointUrl: string,
): Promise<void> {
  cleanup.add("destroy MCP bridge sandbox", () => cleanupSandbox(host));
  await host.bestEffortCleanupSandbox(SANDBOX_NAME, {
    artifactName: "precleanup-destroy-sandbox",
    timeoutMs: 15 * 60_000,
  });
  const result = await host.nemoclaw(
    ["onboard", "--non-interactive", "--yes", "--yes-i-accept-third-party-software"],
    {
      artifactName: "onboard-openclaw-mcp-bridge",
      env: {
        ...buildAvailabilityProbeEnv(),
        COMPATIBLE_API_KEY: COMPATIBLE_KEY,
        NEMOCLAW_AGENT: "openclaw",
        NEMOCLAW_ENDPOINT_URL: endpointUrl,
        NEMOCLAW_MODEL: COMPATIBLE_MODEL,
        NEMOCLAW_PREFERRED_API: "openai-completions",
        NEMOCLAW_PROVIDER: "custom",
        NEMOCLAW_SANDBOX_NAME: SANDBOX_NAME,
        NEMOCLAW_RECREATE_SANDBOX: "1",
      },
      redactionValues: [COMPATIBLE_KEY],
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
  const compatibleMock = await startCompatibleMock({
    apiKey: COMPATIBLE_KEY,
    model: COMPATIBLE_MODEL,
  });
  cleanup.add("stop MCP bridge compatible endpoint mock", () => compatibleMock.close());
  const fakeMcp = await startFakeMcpHttpServer({ secret: HOST_SECRET });
  cleanup.add("stop fake MCP HTTP server", () => fakeMcp.close());
  const hostAddress = await hostAddressForSandbox(host);
  const endpointUrl = `http://${hostAddress}:${compatibleMock.port}/v1`;
  const mcpUrl = `http://host.openshell.internal:${fakeMcp.port}/mcp`;
  await onboardOpenClaw(host, cleanup, endpointUrl);
  cleanup.add("remove MCP bridge", () => bestEffortRemoveBridge(host));

  const add = await host.nemoclaw(
    [SANDBOX_NAME, "mcp", "add", SERVER_NAME, "--url", mcpUrl, "--env", "FAKE_MCP_SECRET"],
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
    server: string;
    url: string;
    env: { names: string[]; ready: boolean; missing: string[] };
    provider: { name: string; gatewayPresent: boolean | null; attached: boolean | null };
    policy: { gatewayPresent: boolean | null };
    adapter: { registered: boolean | null };
  };
  expect(statusJson.support).toMatchObject({ supported: true, adapter: "mcporter" });
  expect(statusJson).toMatchObject({
    server: SERVER_NAME,
    url: mcpUrl,
    env: { names: ["FAKE_MCP_SECRET"], ready: true, missing: [] },
    provider: { gatewayPresent: true, attached: true },
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
  expect(resultText(policy)).toContain("tools/list");
  expect(resultText(policy)).toContain("tools/call");
  expect(resultText(policy)).toContain("host.openshell.internal");

  const provider = await host.command(
    "openshell",
    ["provider", "get", `${SANDBOX_NAME}-mcp-fake`],
    {
      artifactName: "openshell-provider-get-mcp",
      env: buildAvailabilityProbeEnv(),
      timeoutMs: 60_000,
    },
  );
  expectExitZero(provider, "openshell provider get mcp provider");
  expect(resultText(provider)).toContain("FAKE_MCP_SECRET");
  expect(resultText(provider)).not.toContain(HOST_SECRET);

  const mcpCallScript = `const http = require("node:http");
const url = new URL(process.argv[2]);
const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });
const req = http.request({
  hostname: url.hostname,
  port: url.port,
  path: url.pathname,
  method: "POST",
  headers: {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "authorization": "Bearer openshell:resolve:env:FAKE_MCP_SECRET"
  }
}, (res) => {
  let data = "";
  res.setEncoding("utf8");
  res.on("data", (chunk) => { data += chunk; });
  res.on("end", () => {
    console.log(JSON.stringify({ status: res.statusCode, body: data }));
    process.exit(res.statusCode === 200 && data.includes("fake_echo") ? 0 : 1);
  });
});
req.on("error", (error) => {
  console.error(error.message);
  process.exit(1);
});
req.end(body);
`;
  await artifacts.writeText("mcp-provider-rewrite-proof.mjs", mcpCallScript);
  const mcpCallScriptB64 = Buffer.from(mcpCallScript, "utf8").toString("base64");
  const mcpCall = await sandbox.execShell(
    SANDBOX_NAME,
    trustedSandboxShellScript(
      [
        "set -eu",
        `printf '%s' ${JSON.stringify(mcpCallScriptB64)} | base64 -d > /tmp/nemoclaw-mcp-provider-rewrite-proof.mjs`,
        `nemoclaw-start node /tmp/nemoclaw-mcp-provider-rewrite-proof.mjs ${JSON.stringify(mcpUrl)}`,
      ].join("\n"),
    ),
    {
      artifactName: "mcp-provider-rewrite-tools-list",
      env: buildAvailabilityProbeEnv(),
      timeoutMs: 90_000,
    },
  );
  expectExitZero(mcpCall, "OpenShell provider rewrites MCP authorization placeholder");
  expect(fakeMcp.requests.some((request) => request.auth === `Bearer ${HOST_SECRET}`)).toBe(true);
  expect(fakeMcp.requests.every((request) => !request.auth.includes("openshell:resolve:env"))).toBe(
    true,
  );

  const registryRaw = fs.existsSync(REGISTRY_FILE) ? fs.readFileSync(REGISTRY_FILE, "utf8") : "";
  expect(registryRaw).toContain(mcpUrl);
  expect(registryRaw).toContain(`${SANDBOX_NAME}-mcp-fake`);
  expect(registryRaw).not.toContain("enc:v1:");
  expect(registryRaw).not.toContain("proxy.pid");
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
