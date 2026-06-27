// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { buildAvailabilityProbeEnv } from "../fixtures/availability-env.ts";
import type { CleanupRegistry } from "../fixtures/cleanup.ts";
import type { HostCliClient } from "../fixtures/clients/host.ts";
import { type SandboxClient, trustedSandboxShellScript } from "../fixtures/clients/sandbox.ts";
import { expect, test } from "../fixtures/e2e-test.ts";
import type { ShellProbeResult } from "../fixtures/shell-probe.ts";
import { startCompatibleMock, startFakeMcpHttpServer } from "./mcp-bridge-servers.ts";

const OPENCLAW_SANDBOX_NAME = process.env.NEMOCLAW_SANDBOX_NAME ?? "e2e-mcp-bridge";
const HERMES_SANDBOX_NAME = process.env.NEMOCLAW_MCP_HERMES_SANDBOX_NAME ?? "e2e-mcp-hermes";
const DEEPAGENTS_SANDBOX_NAME = process.env.NEMOCLAW_MCP_DEEPAGENTS_SANDBOX_NAME ?? "e2e-mcp-dcode";
const SERVER_NAME = "fake";
const HOST_SECRET = "fake-host-mcp-secret-value";
const COMPATIBLE_KEY = "fake-compatible-mcp-bridge-key";
const COMPATIBLE_MODEL = "mock/mcp-bridge";
const REGISTRY_FILE = path.join(process.env.HOME ?? os.homedir(), ".nemoclaw", "sandboxes.json");
const liveTest = process.env.NEMOCLAW_RUN_E2E_SCENARIOS === "1" ? test : test.skip;
const liveAgentMatrixTest =
  process.env.NEMOCLAW_RUN_E2E_SCENARIOS === "1" &&
  process.env.NEMOCLAW_MCP_BRIDGE_AGENT_MATRIX === "1"
    ? test
    : test.skip;

type McpAgent = "openclaw" | "hermes" | "langchain-deepagents-code";
type McpAdapter = "mcporter" | "hermes-config" | "deepagents-config";

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

async function bestEffortRemoveBridge(host: HostCliClient, sandboxName: string): Promise<void> {
  await host.nemoclaw([sandboxName, "mcp", "remove", SERVER_NAME, "--force"], {
    artifactName: "cleanup-mcp-remove",
    env: buildAvailabilityProbeEnv(),
    timeoutMs: 60_000,
  });
}

async function cleanupSandbox(host: HostCliClient, sandboxName: string): Promise<void> {
  await host.bestEffortCleanupSandbox(sandboxName, {
    artifactName: "cleanup-destroy-sandbox",
    timeoutMs: 15 * 60_000,
  });
}

async function onboardAgent(
  host: HostCliClient,
  cleanup: CleanupRegistry,
  endpointUrl: string,
  options: { agent: McpAgent; sandboxName: string; artifactName: string },
): Promise<void> {
  cleanup.add(`destroy MCP bridge ${options.agent} sandbox`, () =>
    cleanupSandbox(host, options.sandboxName),
  );
  await host.bestEffortCleanupSandbox(options.sandboxName, {
    artifactName: "precleanup-destroy-sandbox",
    timeoutMs: 15 * 60_000,
  });
  const result = await host.nemoclaw(
    ["onboard", "--non-interactive", "--yes", "--yes-i-accept-third-party-software"],
    {
      artifactName: options.artifactName,
      env: {
        ...buildAvailabilityProbeEnv(),
        COMPATIBLE_API_KEY: COMPATIBLE_KEY,
        NVIDIA_INFERENCE_API_KEY: COMPATIBLE_KEY,
        NEMOCLAW_AGENT: options.agent,
        NEMOCLAW_ENDPOINT_URL: endpointUrl,
        NEMOCLAW_MODEL: COMPATIBLE_MODEL,
        NEMOCLAW_COMPAT_MODEL: COMPATIBLE_MODEL,
        NEMOCLAW_PREFERRED_API: "openai-completions",
        NEMOCLAW_PROVIDER: "custom",
        NEMOCLAW_SANDBOX_NAME: options.sandboxName,
        NEMOCLAW_RECREATE_SANDBOX: "1",
      },
      redactionValues: [COMPATIBLE_KEY],
      timeoutMs: 20 * 60_000,
    },
  );
  expectExitZero(result, `onboard ${options.agent} sandbox for MCP bridge`);
}

async function assertSecretAbsentFromSandbox(
  sandbox: SandboxClient,
  sandboxName: string,
  paths: string[],
): Promise<void> {
  const result = await sandbox.execShell(
    sandboxName,
    trustedSandboxShellScript(
      ["set -eu", `! grep -R ${JSON.stringify(HOST_SECRET)} ${paths.join(" ")} 2>/dev/null`].join(
        "\n",
      ),
    ),
    {
      artifactName: "assert-secret-absent-from-sandbox",
      env: buildAvailabilityProbeEnv(),
      timeoutMs: 60_000,
    },
  );
  expectExitZero(result, "host MCP secret must not appear in sandbox files");
}

async function addBridgeAndReadStatus(
  host: HostCliClient,
  options: {
    sandboxName: string;
    mcpUrl: string;
    expectedAdapter: McpAdapter;
    artifactPrefix: string;
  },
): Promise<void> {
  const add = await host.nemoclaw(
    [
      options.sandboxName,
      "mcp",
      "add",
      SERVER_NAME,
      "--url",
      options.mcpUrl,
      "--env",
      "FAKE_MCP_SECRET",
    ],
    {
      artifactName: `${options.artifactPrefix}-mcp-add-fake-server`,
      env: {
        ...buildAvailabilityProbeEnv(),
        FAKE_MCP_SECRET: HOST_SECRET,
      },
      redactionValues: [HOST_SECRET],
      timeoutMs: 2 * 60_000,
    },
  );
  expectExitZero(add, `${options.artifactPrefix} mcp add fake server`);

  const status = await host.nemoclaw(
    [options.sandboxName, "mcp", "status", SERVER_NAME, "--json"],
    {
      artifactName: `${options.artifactPrefix}-mcp-status-json`,
      env: {
        ...buildAvailabilityProbeEnv(),
        FAKE_MCP_SECRET: HOST_SECRET,
      },
      redactionValues: [HOST_SECRET],
      timeoutMs: 60_000,
    },
  );
  expectExitZero(status, `${options.artifactPrefix} mcp status --json`);
  const statusJson = JSON.parse(status.stdout) as {
    support: { supported: boolean; adapter: string };
    server: string;
    url: string;
    env: { names: string[]; ready: boolean; missing: string[] };
    provider: {
      name: string;
      gatewayPresent: boolean | null;
      attached: boolean | null;
    };
    policy: { gatewayPresent: boolean | null };
    adapter: { registered: boolean | null };
  };
  expect(statusJson.support).toMatchObject({
    supported: true,
    adapter: options.expectedAdapter,
  });
  expect(statusJson).toMatchObject({
    server: SERVER_NAME,
    url: options.mcpUrl,
    env: { names: ["FAKE_MCP_SECRET"], ready: true, missing: [] },
    provider: { gatewayPresent: true, attached: true },
    policy: { gatewayPresent: true },
    adapter: { registered: true },
  });
  expect(status.stdout).not.toContain(HOST_SECRET);
}

async function assertBridgeInfrastructure(
  host: HostCliClient,
  sandbox: SandboxClient,
  options: { sandboxName: string; artifactPrefix: string },
): Promise<void> {
  const policy = await sandbox.openshell(["policy", "get", "--full", options.sandboxName], {
    artifactName: `${options.artifactPrefix}-openshell-policy-get-mcp`,
    env: buildAvailabilityProbeEnv(),
    timeoutMs: 60_000,
  });
  expectExitZero(policy, `${options.artifactPrefix} openshell policy get --full`);
  expect(resultText(policy)).toContain("mcp-bridge-fake");
  expect(resultText(policy)).toContain("protocol: mcp");
  expect(resultText(policy)).toContain("allow_all_known_mcp_methods");
  expect(resultText(policy)).toContain("host.openshell.internal");

  const provider = await host.command(
    "openshell",
    ["provider", "get", `${options.sandboxName}-mcp-fake`],
    {
      artifactName: `${options.artifactPrefix}-openshell-provider-get-mcp`,
      env: buildAvailabilityProbeEnv(),
      timeoutMs: 60_000,
    },
  );
  expectExitZero(provider, `${options.artifactPrefix} openshell provider get mcp provider`);
  expect(resultText(provider)).toContain("FAKE_MCP_SECRET");
  expect(resultText(provider)).not.toContain(HOST_SECRET);
}

async function removeBridgeAndAssertEmpty(
  host: HostCliClient,
  options: { sandboxName: string; artifactPrefix: string },
): Promise<void> {
  const remove = await host.nemoclaw([options.sandboxName, "mcp", "remove", SERVER_NAME], {
    artifactName: `${options.artifactPrefix}-mcp-remove-fake-server`,
    env: buildAvailabilityProbeEnv(),
    timeoutMs: 60_000,
  });
  expectExitZero(remove, `${options.artifactPrefix} mcp remove fake server`);

  const list = await host.nemoclaw([options.sandboxName, "mcp", "list", "--json"], {
    artifactName: `${options.artifactPrefix}-mcp-list-after-remove`,
    env: buildAvailabilityProbeEnv(),
    timeoutMs: 60_000,
  });
  expectExitZero(list, `${options.artifactPrefix} mcp list after remove`);
  expect(JSON.parse(list.stdout).bridges).toEqual([]);
}

async function assertHermesConfig(
  sandbox: SandboxClient,
  sandboxName: string,
  mcpUrl: string,
): Promise<void> {
  const result = await sandbox.execShell(
    sandboxName,
    trustedSandboxShellScript(
      [
        "set -eu",
        "/opt/hermes/.venv/bin/python - <<'PY'",
        "import pathlib, yaml",
        "path = pathlib.Path('/sandbox/.hermes/config.yaml')",
        "text = path.read_text(encoding='utf-8')",
        "data = yaml.safe_load(text) or {}",
        `entry = data['mcp_servers'][${JSON.stringify(SERVER_NAME)}]`,
        `assert entry['url'] == ${JSON.stringify(mcpUrl)}`,
        "assert entry['headers']['Authorization'] == 'Bearer openshell:resolve:env:FAKE_MCP_SECRET'",
        `assert ${JSON.stringify(HOST_SECRET)} not in text`,
        "PY",
      ].join("\n"),
    ),
    {
      artifactName: "hermes-mcp-config-assertions",
      env: buildAvailabilityProbeEnv(),
      timeoutMs: 60_000,
    },
  );
  expectExitZero(result, "Hermes MCP config contains placeholder and no raw host secret");
}

async function assertDeepAgentsConfig(
  sandbox: SandboxClient,
  sandboxName: string,
  mcpUrl: string,
): Promise<void> {
  const result = await sandbox.execShell(
    sandboxName,
    trustedSandboxShellScript(
      [
        "set -eu",
        "python3 - <<'PY'",
        "import json, pathlib",
        "path = pathlib.Path('/sandbox/.mcp.json')",
        "text = path.read_text(encoding='utf-8')",
        "data = json.loads(text)",
        `entry = data['mcpServers'][${JSON.stringify(SERVER_NAME)}]`,
        "assert entry['type'] == 'http'",
        `assert entry['url'] == ${JSON.stringify(mcpUrl)}`,
        "assert entry['headers']['Authorization'] == 'Bearer openshell:resolve:env:FAKE_MCP_SECRET'",
        `assert ${JSON.stringify(HOST_SECRET)} not in text`,
        "PY",
      ].join("\n"),
    ),
    {
      artifactName: "deepagents-mcp-config-assertions",
      env: buildAvailabilityProbeEnv(),
      timeoutMs: 60_000,
    },
  );
  expectExitZero(result, "Deep Agents MCP config contains placeholder and no raw host secret");
}

liveTest("mcp-bridge", { timeout: 45 * 60_000 }, async ({ artifacts, cleanup, host, sandbox }) => {
  await artifacts.writeJson("scenario.json", {
    id: "mcp-bridge",
    sandbox: OPENCLAW_SANDBOX_NAME,
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
  await onboardAgent(host, cleanup, endpointUrl, {
    agent: "openclaw",
    sandboxName: OPENCLAW_SANDBOX_NAME,
    artifactName: "onboard-openclaw-mcp-bridge",
  });
  cleanup.add("remove MCP bridge", () => bestEffortRemoveBridge(host, OPENCLAW_SANDBOX_NAME));

  await addBridgeAndReadStatus(host, {
    sandboxName: OPENCLAW_SANDBOX_NAME,
    mcpUrl,
    expectedAdapter: "mcporter",
    artifactPrefix: "openclaw",
  });
  await assertBridgeInfrastructure(host, sandbox, {
    sandboxName: OPENCLAW_SANDBOX_NAME,
    artifactPrefix: "openclaw",
  });

  const mcporterList = await sandbox.execShell(
    OPENCLAW_SANDBOX_NAME,
    trustedSandboxShellScript(
      ["set -eu", `nemoclaw-start mcporter list ${SERVER_NAME} --json`].join("\n"),
    ),
    {
      artifactName: "mcp-mcporter-list-tools",
      env: buildAvailabilityProbeEnv(),
      timeoutMs: 90_000,
    },
  );
  expectExitZero(mcporterList, "mcporter lists tools through OpenShell MCP policy");
  expect(resultText(mcporterList)).toContain("fake_echo");
  expect(fakeMcp.requests.some((request) => request.auth === `Bearer ${HOST_SECRET}`)).toBe(true);
  expect(fakeMcp.requests.every((request) => !request.auth.includes("openshell:resolve:env"))).toBe(
    true,
  );

  const requestCountAfterAdapterProof = fakeMcp.requests.length;
  const deniedCurl = await sandbox.execShell(
    OPENCLAW_SANDBOX_NAME,
    trustedSandboxShellScript(
      [
        "set -eu",
        `body='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`,
        "set +e",
        `curl -sS -X POST ${JSON.stringify(mcpUrl)} -H 'content-type: application/json' -H 'authorization: Bearer openshell:resolve:env:FAKE_MCP_SECRET' --data "$body" > /tmp/nemoclaw-mcp-denied.out`,
        "rc=$?",
        "set -e",
        'if [ "$rc" -eq 0 ] && grep -q fake_echo /tmp/nemoclaw-mcp-denied.out; then',
        "  cat /tmp/nemoclaw-mcp-denied.out",
        "  exit 1",
        "fi",
        "cat /tmp/nemoclaw-mcp-denied.out 2>/dev/null || true",
      ].join("\n"),
    ),
    {
      artifactName: "mcp-non-allowlisted-curl-denied",
      env: buildAvailabilityProbeEnv(),
      timeoutMs: 60_000,
    },
  );
  expectExitZero(deniedCurl, "non-allowlisted curl cannot call MCP endpoint");
  expect(fakeMcp.requests.length).toBe(requestCountAfterAdapterProof);

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
    OPENCLAW_SANDBOX_NAME,
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
  expect(registryRaw).toContain(`${OPENCLAW_SANDBOX_NAME}-mcp-fake`);
  expect(registryRaw).not.toContain("enc:v1:");
  expect(registryRaw).not.toContain("proxy.pid");
  expect(registryRaw).not.toContain(HOST_SECRET);
  await assertSecretAbsentFromSandbox(sandbox, OPENCLAW_SANDBOX_NAME, [
    "/sandbox/.openclaw",
    "/sandbox/.mcp.json",
  ]);

  await removeBridgeAndAssertEmpty(host, {
    sandboxName: OPENCLAW_SANDBOX_NAME,
    artifactPrefix: "openclaw",
  });
});

liveAgentMatrixTest(
  "mcp-bridge-hermes",
  { timeout: 45 * 60_000 },
  async ({ artifacts, cleanup, host, sandbox }) => {
    await artifacts.writeJson("scenario.json", {
      id: "mcp-bridge-hermes",
      sandbox: HERMES_SANDBOX_NAME,
      server: SERVER_NAME,
    });
    const compatibleMock = await startCompatibleMock({
      apiKey: COMPATIBLE_KEY,
      model: COMPATIBLE_MODEL,
    });
    cleanup.add("stop Hermes MCP bridge compatible endpoint mock", () => compatibleMock.close());
    const fakeMcp = await startFakeMcpHttpServer({ secret: HOST_SECRET });
    cleanup.add("stop fake Hermes MCP HTTP server", () => fakeMcp.close());
    const hostAddress = await hostAddressForSandbox(host);
    const endpointUrl = `http://${hostAddress}:${compatibleMock.port}/v1`;
    const mcpUrl = `http://host.openshell.internal:${fakeMcp.port}/mcp`;
    await onboardAgent(host, cleanup, endpointUrl, {
      agent: "hermes",
      sandboxName: HERMES_SANDBOX_NAME,
      artifactName: "onboard-hermes-mcp-bridge",
    });
    cleanup.add("remove Hermes MCP bridge", () =>
      bestEffortRemoveBridge(host, HERMES_SANDBOX_NAME),
    );

    await addBridgeAndReadStatus(host, {
      sandboxName: HERMES_SANDBOX_NAME,
      mcpUrl,
      expectedAdapter: "hermes-config",
      artifactPrefix: "hermes",
    });
    await assertBridgeInfrastructure(host, sandbox, {
      sandboxName: HERMES_SANDBOX_NAME,
      artifactPrefix: "hermes",
    });
    await assertHermesConfig(sandbox, HERMES_SANDBOX_NAME, mcpUrl);
    await assertSecretAbsentFromSandbox(sandbox, HERMES_SANDBOX_NAME, ["/sandbox/.hermes"]);
    await removeBridgeAndAssertEmpty(host, {
      sandboxName: HERMES_SANDBOX_NAME,
      artifactPrefix: "hermes",
    });
  },
);

liveAgentMatrixTest(
  "mcp-bridge-deepagents",
  { timeout: 45 * 60_000 },
  async ({ artifacts, cleanup, host, sandbox }) => {
    await artifacts.writeJson("scenario.json", {
      id: "mcp-bridge-deepagents",
      sandbox: DEEPAGENTS_SANDBOX_NAME,
      server: SERVER_NAME,
    });
    const compatibleMock = await startCompatibleMock({
      apiKey: COMPATIBLE_KEY,
      model: COMPATIBLE_MODEL,
    });
    cleanup.add("stop Deep Agents MCP bridge compatible endpoint mock", () =>
      compatibleMock.close(),
    );
    const fakeMcp = await startFakeMcpHttpServer({ secret: HOST_SECRET });
    cleanup.add("stop fake Deep Agents MCP HTTP server", () => fakeMcp.close());
    const hostAddress = await hostAddressForSandbox(host);
    const endpointUrl = `http://${hostAddress}:${compatibleMock.port}/v1`;
    const mcpUrl = `http://host.openshell.internal:${fakeMcp.port}/mcp`;
    await onboardAgent(host, cleanup, endpointUrl, {
      agent: "langchain-deepagents-code",
      sandboxName: DEEPAGENTS_SANDBOX_NAME,
      artifactName: "onboard-deepagents-mcp-bridge",
    });
    cleanup.add("remove Deep Agents MCP bridge", () =>
      bestEffortRemoveBridge(host, DEEPAGENTS_SANDBOX_NAME),
    );

    await addBridgeAndReadStatus(host, {
      sandboxName: DEEPAGENTS_SANDBOX_NAME,
      mcpUrl,
      expectedAdapter: "deepagents-config",
      artifactPrefix: "deepagents",
    });
    await assertBridgeInfrastructure(host, sandbox, {
      sandboxName: DEEPAGENTS_SANDBOX_NAME,
      artifactPrefix: "deepagents",
    });
    await assertDeepAgentsConfig(sandbox, DEEPAGENTS_SANDBOX_NAME, mcpUrl);
    await assertSecretAbsentFromSandbox(sandbox, DEEPAGENTS_SANDBOX_NAME, [
      "/sandbox/.deepagents",
      "/sandbox/.mcp.json",
    ]);
    await removeBridgeAndAssertEmpty(host, {
      sandboxName: DEEPAGENTS_SANDBOX_NAME,
      artifactPrefix: "deepagents",
    });
  },
);
