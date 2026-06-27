// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import YAML from "yaml";
import { describe, expect, it, vi } from "vitest";

import {
  buildDeepAgentsMcpRegisterCommand,
  buildDeepAgentsMcpRemoveCommand,
  buildHermesMcpRegisterCommand,
  buildMcpBridgePolicyName,
  buildMcpBridgePolicyYaml,
  buildMcpBridgeProviderArgs,
  buildMcpBridgeProviderName,
  buildOpenClawMcporterRegisterCommand,
  dispatchMcpBridgeCommand,
  MCP_BRIDGE_ALLOWED_METHODS,
  MCP_BRIDGE_POLICY_MAX_BODY_BYTES,
  MCPORTER_VERSION,
  normalizeMcpServerUrl,
  parseMcpAddArgs,
  redactBridgeSecretsForDisplay,
  redactCredentialValuesForDisplay,
  resolveCredentialEnv,
} from "../../../../dist/lib/actions/sandbox/mcp-bridge";
import type { McpBridgeEntry } from "../../../../dist/lib/state/registry";

describe("MCP CLI parsing", () => {
  it("parses server, URL, and env references", () => {
    const parsed = parseMcpAddArgs([
      "github",
      "--url",
      "https://api.githubcopilot.com/mcp/",
      "--env",
      "GITHUB_TOKEN",
    ]);

    expect(parsed).toEqual({
      server: "github",
      url: "https://api.githubcopilot.com/mcp/",
      env: [{ name: "GITHUB_TOKEN" }],
    });
  });

  it("allows inline env values for provider registration but persists only names", () => {
    const parsed = parseMcpAddArgs([
      "srv",
      "--url=http://mcp.example.test/rpc",
      "--env=TOKEN=a=b=c",
    ]);

    expect(parsed.env).toEqual([{ name: "TOKEN", value: "a=b=c" }]);
    expect(resolveCredentialEnv(parsed.env)).toEqual({ TOKEN: "a=b=c" });
    expect(parsed.env.map((entry) => entry.name)).toEqual(["TOKEN"]);
  });

  it("rejects host stdio commands", () => {
    expect(() =>
      parseMcpAddArgs([
        "github",
        "--env",
        "GITHUB_TOKEN",
        "--",
        "npx",
        "@modelcontextprotocol/server-github",
      ]),
    ).toThrow(/Host stdio MCP commands are not supported/);
  });

  it("requires an HTTP MCP URL", () => {
    expect(() => parseMcpAddArgs(["github"])).toThrow(/--url/);
    expect(() => parseMcpAddArgs(["github", "--url", "stdio://github"])).toThrow(/http/);
  });

  it("normalizes URLs without persisting credentials", () => {
    expect(normalizeMcpServerUrl("https://mcp.example.test")).toBe("https://mcp.example.test/");
    expect(() => normalizeMcpServerUrl("https://user:pass@mcp.example.test/mcp")).toThrow(
      /must not embed credentials/,
    );
  });

  it("rejects local and private URL targets except OpenShell host aliases", () => {
    expect(() => normalizeMcpServerUrl("http://localhost:31337/mcp")).toThrow(
      /private, local, or special-use IP/,
    );
    expect(() => normalizeMcpServerUrl("http://127.0.0.1:31337/mcp")).toThrow(
      /private, local, or special-use IP/,
    );
    expect(() => normalizeMcpServerUrl("http://169.254.169.254/latest")).toThrow(
      /private, local, or special-use IP/,
    );
    expect(() => normalizeMcpServerUrl("http://[::1]:31337/mcp")).toThrow(
      /private, local, or special-use IP/,
    );
    expect(normalizeMcpServerUrl("https://192.0.1.1/mcp")).toBe("https://192.0.1.1/mcp");
    expect(normalizeMcpServerUrl("https://[2606:4700::1]/mcp")).toBe("https://[2606:4700::1]/mcp");
    expect(normalizeMcpServerUrl("http://host.openshell.internal:31337/mcp")).toBe(
      "http://host.openshell.internal:31337/mcp",
    );
  });

  it("resolves host env values without requiring them for provider reuse", () => {
    const prior = process.env.MCP_BRIDGE_TEST_TOKEN;
    process.env.MCP_BRIDGE_TEST_TOKEN = "secret-value";
    try {
      expect(resolveCredentialEnv([{ name: "MCP_BRIDGE_TEST_TOKEN" }])).toEqual({
        MCP_BRIDGE_TEST_TOKEN: "secret-value",
      });
    } finally {
      prior === undefined
        ? delete process.env.MCP_BRIDGE_TEST_TOKEN
        : (process.env.MCP_BRIDGE_TEST_TOKEN = prior);
    }
    expect(resolveCredentialEnv([{ name: "MCP_BRIDGE_TEST_TOKEN_NOT_SET" }])).toEqual({});
  });

  it("redacts inline credential values from provider failure output", () => {
    const output = redactCredentialValuesForDisplay(
      "provider failed for --credential TOKEN=inline-secret-value",
      { TOKEN: "inline-secret-value" },
    );
    expect(output).toContain("provider failed for --credential");
    expect(output).not.toContain("inline-secret-value");
  });

  it("passes MCP provider credentials by environment name, not argv value", () => {
    const args = buildMcpBridgeProviderArgs(
      "create",
      "alpha-mcp-github",
      [{ name: "TOKEN", value: "inline-secret-value" }],
      { TOKEN: "inline-secret-value" },
    );

    expect(args).toEqual([
      "provider",
      "create",
      "--name",
      "alpha-mcp-github",
      "--type",
      "generic",
      "--credential",
      "TOKEN",
    ]);
    expect(args.join(" ")).not.toContain("inline-secret-value");
    expect(args.join(" ")).not.toContain("TOKEN=inline-secret-value");
  });

  it("rejects surplus positional arguments before sandbox side effects", async () => {
    const priorExitCode = process.exitCode;
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      process.exitCode = undefined;
      await dispatchMcpBridgeCommand("missing-sandbox", ["list", "extra"]);
      expect(process.exitCode).toBe(2);
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Usage: nemoclaw <sandbox> mcp list [--json]"),
      );

      process.exitCode = undefined;
      await dispatchMcpBridgeCommand("missing-sandbox", ["remove", "one", "two"]);
      expect(process.exitCode).toBe(2);
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Usage: nemoclaw <sandbox> mcp remove <server> [--force]"),
      );
    } finally {
      errorSpy.mockRestore();
      process.exitCode = priorExitCode;
    }
  });
});

describe("MCP OpenShell policy", () => {
  it("generates a protocol:mcp policy for the target endpoint and adapter binaries", () => {
    const policyName = buildMcpBridgePolicyName("GitHub_Server");
    const policy = YAML.parse(
      buildMcpBridgePolicyYaml(
        "GitHub_Server",
        "https://api.githubcopilot.com/mcp?transport=streamable",
        "mcporter",
      ),
    ) as {
      preset: { name: string };
      network_policies: Record<
        string,
        {
          endpoints: Array<{
            host: string;
            port: number;
            path: string;
            protocol: string;
            mcp: { max_body_bytes: number; strict_tool_names?: boolean };
            rules?: Array<{ allow: { method: string; path: string } }>;
          }>;
          binaries: Array<{ path: string }>;
        }
      >;
    };
    const entry = policy.network_policies.mcp_bridge_github_server;

    expect(policyName).toBe("mcp-bridge-github-server");
    expect(policy.preset.name).toBe(policyName);
    expect(entry.endpoints[0]).toMatchObject({
      host: "api.githubcopilot.com",
      port: 443,
      path: "/mcp",
      protocol: "mcp",
      enforcement: "enforce",
      mcp: {
        max_body_bytes: MCP_BRIDGE_POLICY_MAX_BODY_BYTES,
        strict_tool_names: true,
      },
    });
    expect(entry.endpoints[0].rules).toEqual(
      MCP_BRIDGE_ALLOWED_METHODS.map((method) => ({
        allow: { method, path: "/mcp" },
      })),
    );
    expect(entry.binaries.map((binary) => binary.path)).toEqual([
      "/usr/local/bin/mcporter",
      "/usr/bin/mcporter",
      "/usr/local/bin/openclaw",
      "/usr/local/bin/node",
      "/usr/bin/node",
    ]);
  });

  it("allows the OpenShell host alias with private-network SSRF guards", () => {
    const policy = YAML.parse(
      buildMcpBridgePolicyYaml("local", "http://host.openshell.internal:31337/mcp", "mcporter"),
    ) as { network_policies: Record<string, { endpoints: Array<{ allowed_ips: string[] }> }> };

    expect(policy.network_policies.mcp_bridge_local.endpoints[0].allowed_ips).toEqual([
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "fc00::/7",
    ]);
  });

  it("scopes binaries to the selected agent adapter", () => {
    const hermes = YAML.parse(
      buildMcpBridgePolicyYaml("srv", "http://mcp.example.test/mcp", "hermes-config"),
    ) as { network_policies: Record<string, { binaries: Array<{ path: string }> }> };
    const deepAgents = YAML.parse(
      buildMcpBridgePolicyYaml("srv", "http://mcp.example.test/mcp", "deepagents-config"),
    ) as { network_policies: Record<string, { binaries: Array<{ path: string }> }> };

    expect(hermes.network_policies.mcp_bridge_srv.binaries.map((b) => b.path)).toEqual([
      "/usr/local/bin/hermes",
      "/opt/hermes/.venv/bin/python*",
    ]);
    expect(deepAgents.network_policies.mcp_bridge_srv.binaries.map((b) => b.path)).toEqual([
      "/usr/local/bin/dcode",
      "/opt/venv/bin/python3*",
    ]);
  });

  it("uses stable provider names with a length guard", () => {
    expect(buildMcpBridgeProviderName("alpha", "GitHub_Server")).toBe("alpha-mcp-github-server");
    const long = buildMcpBridgeProviderName(
      "sandbox-name-with-a-long-prefix",
      "ServerNameThatWouldOtherwiseExceedTheProviderNameLimit",
    );
    expect(long.length).toBeLessThanOrEqual(63);
    expect(long).toMatch(/^sandbox-name-with-a-long-prefix-mcp-servername-[a-f0-9]{16}$/);
  });
});

describe("MCP adapters", () => {
  const baseEntry: McpBridgeEntry = {
    server: "github",
    agent: "openclaw",
    adapter: "mcporter",
    url: "https://api.githubcopilot.com/mcp/",
    env: ["GITHUB_TOKEN"],
    providerName: "alpha-mcp-github",
    policyName: "mcp-bridge-github",
    addedAt: new Date(0).toISOString(),
  };

  it("constructs a mcporter HTTP registration with OpenShell env placeholders", () => {
    const command = buildOpenClawMcporterRegisterCommand(baseEntry);

    expect(command).toContain("'mcporter' 'config' 'add' 'github'");
    expect(command).toContain("'--url' 'https://api.githubcopilot.com/mcp/'");
    expect(command).toContain(
      "'--header' 'Authorization=Bearer openshell:resolve:env:GITHUB_TOKEN'",
    );
    expect(command).toContain("'--scope' 'home'");
    expect(command).not.toContain("fake-secret");
  });

  it("constructs a Hermes config registration with placeholders", () => {
    const command = buildHermesMcpRegisterCommand({
      ...baseEntry,
      agent: "hermes",
      adapter: "hermes-config",
    });

    expect(command).toContain("/sandbox/.hermes/config.yaml");
    expect(command).toContain("mcp_servers");
    expect(command).toContain("https://api.githubcopilot.com/mcp/");
    expect(command).toContain("openshell:resolve:env:GITHUB_TOKEN");
  });

  it("constructs a Deep Agents .mcp.json registration with placeholders", () => {
    const command = buildDeepAgentsMcpRegisterCommand({
      ...baseEntry,
      agent: "langchain-deepagents-code",
      adapter: "deepagents-config",
    });

    expect(command).toContain("/sandbox/.mcp.json");
    expect(command).toContain("mcpServers");
    expect(command).toContain("'type': 'http'");
    expect(command).toContain("https://api.githubcopilot.com/mcp/");
    expect(command).toContain("openshell:resolve:env:GITHUB_TOKEN");
    expect(command).toContain("Invalid /sandbox/.mcp.json");
    expect(command).toContain("mcpServers must be an object");
  });

  it("fails Deep Agents removal on corrupt config unless forced", () => {
    const normal = buildDeepAgentsMcpRemoveCommand("github");
    const forced = buildDeepAgentsMcpRemoveCommand("github", true);

    expect(normal).toContain("Invalid /sandbox/.mcp.json");
    expect(normal).toContain('\\"force\\":false');
    expect(normal).toContain("raise SystemExit(2)");
    expect(forced).toContain('\\"force\\":true');
  });

  it("keeps unauthenticated servers free of Authorization headers", () => {
    const command = buildOpenClawMcporterRegisterCommand({ ...baseEntry, env: [] });

    expect(command).not.toContain("Authorization=");
    expect(command).toContain("'--url' 'https://api.githubcopilot.com/mcp/'");
  });

  it("redacts credential values from adapter display output", () => {
    const prior = process.env.GITHUB_TOKEN;
    process.env.GITHUB_TOKEN = "real-host-secret";
    try {
      const redacted = redactBridgeSecretsForDisplay(
        "failed header Authorization=Bearer real-host-secret raw real-host-secret",
        baseEntry,
      );

      expect(redacted).toBe("failed header Authorization=Bearer ***REDACTED*** raw ***REDACTED***");
    } finally {
      prior === undefined ? delete process.env.GITHUB_TOKEN : (process.env.GITHUB_TOKEN = prior);
    }
  });

  it("redacts inline credential values that were not exported in host env", () => {
    const prior = process.env.GITHUB_TOKEN;
    delete process.env.GITHUB_TOKEN;
    try {
      const redacted = redactBridgeSecretsForDisplay(
        "adapter echoed Authorization=Bearer inline-provider-secret and inline-provider-secret",
        baseEntry,
        { GITHUB_TOKEN: "inline-provider-secret" },
      );

      expect(redacted).toBe(
        "adapter echoed Authorization=Bearer ***REDACTED*** and ***REDACTED***",
      );
    } finally {
      prior === undefined ? delete process.env.GITHUB_TOKEN : (process.env.GITHUB_TOKEN = prior);
    }
  });
});

describe("cross-agent MCP status", () => {
  it("reports Hermes bridge support in status JSON without requiring servers", () => {
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
    expect(payload.support).toMatchObject({
      supported: true,
      mode: "bridge",
      adapter: "hermes-config",
    });
    expect(payload.bridges).toEqual([]);
  });
});

describe("MCP image/runtime constants", () => {
  it("keeps the mcporter runtime pin visible for image tests", () => {
    expect(MCPORTER_VERSION).toBe("0.7.3");
  });
});
