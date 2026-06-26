// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import YAML from "yaml";
import { describe, expect, it } from "vitest";

import {
  buildMcpBridgePolicyName,
  buildMcpBridgePolicyYaml,
  buildOpenClawMcporterRegisterCommand,
  cleanupStalePidFile,
  MCP_BRIDGE_POLICY_MAX_BODY_BYTES,
  MCP_HOST,
  MCP_PORT_END,
  MCP_PORT_START,
  MCPORTER_VERSION,
  parseMcpAddArgs,
  readLivePid,
  redactBridgeSecretsForDisplay,
  resolveLaunchEnv,
  waitForProxyReady,
} from "../../../../dist/lib/actions/sandbox/mcp-bridge";
import type { McpBridgeEntry } from "../../../../dist/lib/state/registry";

const DEAD_PID = 2_147_483_646;

function seedProxyRuntime(
  sandboxName: string,
  server: string,
  logContents: string,
  pid: number,
): { dir: string; pidFile: string } {
  const dir = path.join(
    process.env.HOME || os.homedir(),
    ".nemoclaw",
    "runtime",
    "mcp",
    sandboxName,
    server,
  );
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(dir, "proxy.log"), logContents, { mode: 0o600 });
  const pidFile = path.join(dir, "proxy.pid");
  fs.writeFileSync(pidFile, `${String(pid)}\n${new Date().toISOString()}\n`, { mode: 0o600 });
  return { dir, pidFile };
}

describe("MCP bridge CLI parsing", () => {
  it("parses server, env references, and command args", () => {
    const parsed = parseMcpAddArgs([
      "github",
      "--env",
      "GITHUB_TOKEN",
      "--",
      "npx",
      "-y",
      "@modelcontextprotocol/server-github",
    ]);

    expect(parsed).toEqual({
      server: "github",
      env: [{ name: "GITHUB_TOKEN" }],
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-github"],
    });
  });

  it("rejects inline env values so bridges stay restart-safe", () => {
    expect(() => parseMcpAddArgs(["srv", "--env=TOKEN=a=b=c", "--", "node", "server.js"])).toThrow(
      /KEY=VALUE is not supported/,
    );
    expect(() =>
      parseMcpAddArgs(["srv", "--env", "TOKEN=secret", "--", "node", "server.js"]),
    ).toThrow(/KEY=VALUE is not supported/);
  });

  it("rejects missing command separators", () => {
    expect(() => parseMcpAddArgs(["github", "npx"])).toThrow(/Command must follow '--'/);
  });

  it("rejects the bridge's reserved token env name", () => {
    expect(() =>
      parseMcpAddArgs(["github", "--env", "NEMOCLAW_MCP_BRIDGE_TOKEN", "--", "node", "server.js"]),
    ).toThrow(/reserved/);
  });

  it("resolves host env references without persisting values", () => {
    const prior = process.env.MCP_BRIDGE_TEST_TOKEN;
    process.env.MCP_BRIDGE_TEST_TOKEN = "secret-value";
    try {
      expect(resolveLaunchEnv([{ name: "MCP_BRIDGE_TEST_TOKEN" }])).toEqual({
        MCP_BRIDGE_TEST_TOKEN: "secret-value",
      });
    } finally {
      prior === undefined
        ? delete process.env.MCP_BRIDGE_TEST_TOKEN
        : (process.env.MCP_BRIDGE_TEST_TOKEN = prior);
    }
  });

  it("rejects programmatic inline env values before launch", () => {
    const prior = process.env.MCP_BRIDGE_INLINE_TOKEN;
    try {
      process.env.MCP_BRIDGE_INLINE_TOKEN = "secret-value";
      expect(() =>
        resolveLaunchEnv([{ name: "MCP_BRIDGE_INLINE_TOKEN", value: "secret-value" }]),
      ).toThrow(/VALUE is not supported/);
    } finally {
      prior === undefined
        ? delete process.env.MCP_BRIDGE_INLINE_TOKEN
        : (process.env.MCP_BRIDGE_INLINE_TOKEN = prior);
    }
  });
});

describe("MCP bridge policy", () => {
  it("generates an OpenShell MCP L7 policy for the bridge endpoint", () => {
    const policyName = buildMcpBridgePolicyName("GitHub_Server");
    const policy = YAML.parse(buildMcpBridgePolicyYaml("GitHub_Server", 3104)) as {
      preset: { name: string };
      network_policies: Record<
        string,
        {
          endpoints: Array<{
            host: string;
            port: number;
            path: string;
            protocol: string;
            mcp: { max_body_bytes: number; allow_all_known_mcp_methods: boolean };
            rules: Array<{ allow: Record<string, never> }>;
          }>;
          binaries: Array<{ path: string }>;
        }
      >;
    };
    const entry = policy.network_policies.mcp_bridge_github_server;

    expect(policyName).toBe("mcp-bridge-github-server");
    expect(policy.preset.name).toBe(policyName);
    expect(entry.endpoints).toEqual([
      {
        host: MCP_HOST,
        port: 3104,
        path: "/",
        protocol: "mcp",
        enforcement: "enforce",
        mcp: {
          max_body_bytes: MCP_BRIDGE_POLICY_MAX_BODY_BYTES,
          allow_all_known_mcp_methods: true,
        },
        rules: [{ allow: {} }],
      },
    ]);
    expect(entry.binaries.map((binary) => binary.path)).toEqual([
      "/usr/local/bin/mcporter",
      "/usr/bin/mcporter",
      "/usr/local/bin/openclaw",
      "/usr/bin/node",
      "/usr/local/bin/node",
    ]);
  });
});

describe("MCP bridge runtime helpers", () => {
  it("uses the reserved 3100-3199 bridge range and pins mcporter", () => {
    expect(MCP_PORT_START).toBe(3100);
    expect(MCP_PORT_END).toBe(3199);
    expect(MCP_PORT_END - MCP_PORT_START + 1).toBe(100);
    expect(MCPORTER_VERSION).toBe("0.7.3");
  });

  it("cleans up stale pid files", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-pid-"));
    const pidFile = path.join(tmp, "proxy.pid");
    fs.writeFileSync(pidFile, `${String(DEAD_PID)}\n`, { mode: 0o600 });

    expect(readLivePid(pidFile)).toBeNull();
    expect(cleanupStalePidFile(pidFile)).toBe(true);
    expect(fs.existsSync(pidFile)).toBe(false);
  });

  it("waits for proxy readiness using only fresh log content", async () => {
    const priorHome = process.env.HOME;
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-ready-home-"));
    process.env.HOME = home;
    const sandbox = `mcp-ready-${String(process.pid)}`;
    const server = "github";
    const stale = "[mcp-proxy] listening on 127.0.0.1:3100\n";
    const { dir } = seedProxyRuntime(sandbox, server, stale, DEAD_PID);
    try {
      await expect(
        waitForProxyReady(sandbox, server, 3100, Buffer.byteLength(stale), 500),
      ).resolves.toBe("failed");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      priorHome === undefined ? delete process.env.HOME : (process.env.HOME = priorHome);
    }
  });
});

describe("OpenClaw MCP adapter", () => {
  it("constructs a mcporter HTTP registration without external env values", () => {
    const entry: McpBridgeEntry = {
      server: "github",
      agent: "openclaw",
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-github"],
      env: ["GITHUB_TOKEN"],
      port: 3100,
      token: "bridge-token",
      policyName: "mcp-bridge-github",
      addedAt: new Date(0).toISOString(),
    };

    const command = buildOpenClawMcporterRegisterCommand(entry);

    expect(command).toContain("'mcporter' 'config' 'add' 'github'");
    expect(command).toContain("'--url' 'http://host.docker.internal:3100'");
    expect(command).toContain("'--header' 'Authorization=Bearer bridge-token'");
    expect(command).toContain("'--scope' 'home'");
    expect(command).not.toContain("GITHUB_TOKEN");
  });

  it("redacts bridge bearer tokens from adapter display output", () => {
    const redacted = redactBridgeSecretsForDisplay(
      "failed header Authorization=Bearer bridge-token raw bridge-token",
      { token: "bridge-token" },
    );

    expect(redacted).toBe("failed header Authorization=Bearer ***REDACTED*** raw ***REDACTED***");
  });
});

describe("unsupported agents", () => {
  it("reports disabled support in status JSON without requiring bridges", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-status-"));
    const script = `
process.env.HOME = ${JSON.stringify(home)};
const registry = require("./dist/lib/state/registry.js");
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
registry.registerSandbox({ name: "hermes-sandbox", agent: "hermes" });
bridge.dispatchMcpBridgeCommand("hermes-sandbox", ["status", "--json"]).then(
  () => {},
  (error) => {
    console.error(error);
    process.exit(1);
  },
);
`;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, HOME: home },
    });

    expect(result.status).toBe(0);
    const payload = JSON.parse(result.stdout.trim()) as {
      sandbox: string;
      agent: string;
      support: { supported: boolean; mode: string; reason?: string };
      bridges: unknown[];
    };
    expect(payload.sandbox).toBe("hermes-sandbox");
    expect(payload.agent).toBe("hermes");
    expect(payload.support).toMatchObject({ supported: false, mode: "disabled" });
    expect(payload.support.reason).toContain("NVIDIA/NemoClaw#566");
    expect(payload.bridges).toEqual([]);
  });

  it("rejects before proxy, policy, or bridge registry side effects", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-unsupported-"));
    const script = `
const fs = require("node:fs");
const path = require("node:path");
process.env.HOME = ${JSON.stringify(home)};
process.env.MCP_BRIDGE_TEST_TOKEN = "secret";
const registry = require("./dist/lib/state/registry.js");
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
registry.registerSandbox({ name: "hermes-sandbox", agent: "hermes" });
bridge.addMcpBridge("hermes-sandbox", {
  server: "github",
  env: [{ name: "MCP_BRIDGE_TEST_TOKEN" }],
  command: "node",
  args: ["-e", "process.exit(0)"],
}).then(
  () => {
    console.log(JSON.stringify({ ok: true }));
  },
  (error) => {
    const sandbox = registry.getSandbox("hermes-sandbox");
    const runtimeRoot = path.join(process.env.HOME, ".nemoclaw", "runtime", "mcp");
    console.log(JSON.stringify({
      ok: false,
      message: error.message,
      mcp: sandbox.mcp || null,
      runtimeExists: fs.existsSync(runtimeRoot),
      policies: sandbox.policies || [],
      customPolicies: sandbox.customPolicies || [],
    }));
  },
);
`;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, HOME: home },
    });

    expect(result.status).toBe(0);
    const payload = JSON.parse(result.stdout.trim()) as {
      ok: boolean;
      message: string;
      mcp: unknown;
      runtimeExists: boolean;
      policies: string[];
      customPolicies: unknown[];
    };
    expect(payload.ok).toBe(false);
    expect(payload.message).toContain("Hermes Agent does not support MCP bridges yet");
    expect(payload.mcp).toBeNull();
    expect(payload.runtimeExists).toBe(false);
    expect(payload.policies).toEqual([]);
    expect(payload.customPolicies).toEqual([]);
  });
});
