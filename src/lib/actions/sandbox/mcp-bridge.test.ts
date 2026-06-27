// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import YAML from "yaml";

import {
  addMcpBridge,
  buildDeepAgentsMcpRegisterCommand,
  buildDeepAgentsMcpRemoveCommand,
  buildDeepAgentsMcpStatusCommand,
  buildHermesMcpLifecycleExecArgs,
  buildHermesMcpRegisterCommand,
  buildMcpBridgePolicyName,
  buildMcpBridgePolicyYaml,
  buildMcpBridgeProviderArgs,
  buildMcpBridgeProviderName,
  buildMcpCredentialReadinessCommand,
  buildMcpCredentialRevisionSnapshotCommand,
  buildOpenClawMcporterInspectCommand,
  buildOpenClawMcporterRegisterCommand,
  buildOpenClawMcporterRemoveCommand,
  DEEPAGENTS_MCP_CONFIG_PATH,
  dispatchMcpBridgeCommand,
  MCP_BRIDGE_ALLOWED_METHODS,
  MCP_BRIDGE_POLICY_MAX_BODY_BYTES,
  MCP_SERVER_URL_MAX_LENGTH,
  MCPORTER_VERSION,
  mcporterHeadersMatchExpected,
  normalizeMcpServerUrl,
  parseMcpAddArgs,
  parseMcpProviderMetadata,
  providerDetachChangedState,
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

  it("rejects inline env values that would leak through process arguments", () => {
    expect(() =>
      parseMcpAddArgs(["srv", "--url=https://mcp.example.test/rpc", "--env=TOKEN=a=b=c"]),
    ).toThrow(/process arguments and shell history/);
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
    expect(() => normalizeMcpServerUrl("https://mcp.example.test/mcp?token=secret")).toThrow(
      /must not include a query string/,
    );
    expect(() => normalizeMcpServerUrl("https://mcp.example.test/mcp#credential")).toThrow(
      /must not include a fragment/,
    );
    expect(() => normalizeMcpServerUrl("https://*.example.test/mcp")).toThrow(
      /hosts must be literal/,
    );
    expect(() => normalizeMcpServerUrl("https://mcp.example.test:0/mcp")).toThrow(
      /port must be between 1 and 65535/,
    );
    for (const path of [
      "/mcp/**",
      "/mcp/%2A%2A",
      "/a/%2e%2e/mcp",
      "/mcp/%2fadmin",
      "/mcp;version=1",
      "/mcp/[admin]",
      "/mcp\\admin",
    ]) {
      expect(() => normalizeMcpServerUrl(`https://mcp.example.test${path}`)).toThrow(
        /literal and canonical/,
      );
    }
  });

  it("bounds persisted MCP endpoint URLs consistently across adapters", () => {
    const prefix = "https://mcp.example.test/";
    const maxLengthUrl = prefix.padEnd(MCP_SERVER_URL_MAX_LENGTH, "a");
    expect(normalizeMcpServerUrl(maxLengthUrl)).toBe(maxLengthUrl);
    expect(() => normalizeMcpServerUrl(`${maxLengthUrl}a`)).toThrow(/at most 2048 characters/);
  });

  it("requires exactly one bearer credential reference", () => {
    expect(() => parseMcpAddArgs(["github", "--url", "https://mcp.example.test/mcp"])).toThrow(
      /requires exactly one --env KEY/,
    );
    expect(() =>
      parseMcpAddArgs([
        "github",
        "--url",
        "https://mcp.example.test/mcp",
        "--env",
        "TOKEN_ONE",
        "--env",
        "TOKEN_TWO",
      ]),
    ).toThrow(/requires exactly one --env KEY/);
  });

  it("rejects unauthenticated direct add callers before sandbox or network side effects", async () => {
    await expect(
      addMcpBridge("missing-sandbox", {
        server: "github",
        url: "https://mcp.example.test/mcp",
        env: [],
      }),
    ).rejects.toThrow(/requires exactly one --env KEY/);
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
      /IPv6-literal MCP server URLs are not supported/,
    );
    expect(() => normalizeMcpServerUrl("http://[::ffff:a00:1]:31337/mcp")).toThrow(
      /IPv6-literal MCP server URLs are not supported/,
    );
    expect(() => normalizeMcpServerUrl("http://mcp.example.test/mcp")).toThrow(/must use https/);
    expect(normalizeMcpServerUrl("https://8.8.8.8/mcp")).toBe("https://8.8.8.8/mcp");
    expect(() => normalizeMcpServerUrl("https://[2606:4700::1]/mcp")).toThrow(
      /IPv6-literal MCP server URLs are not supported/,
    );
    expect(normalizeMcpServerUrl("http://host.openshell.internal:31337/mcp")).toBe(
      "http://host.openshell.internal:31337/mcp",
    );
    expect(normalizeMcpServerUrl("http://host.openshell.internal.:31337/mcp")).toBe(
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

  it("documents force cleanup without promising residual registry removal", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      await dispatchMcpBridgeCommand("missing-sandbox", ["remove", "--help"]);
      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "Best-effort owned cleanup; preserves registry state when residuals remain",
        ),
      );
      expect(logSpy).not.toHaveBeenCalledWith(expect.stringContaining("stale registry removal"));
    } finally {
      logSpy.mockRestore();
    }
  });
});

describe("OpenShell MCP provider state", () => {
  it("parses provider type and credential keys without values", () => {
    expect(
      parseMcpProviderMetadata(`
Provider:

  Name: alpha-mcp-github
  Type: generic
  Credential keys: GITHUB_TOKEN
  Config keys: <none>
`),
    ).toEqual({ type: "generic", credentialKeys: ["GITHUB_TOKEN"] });
    expect(parseMcpProviderMetadata("Type: generic\nCredential keys: <none>\n")).toEqual({
      type: "generic",
      credentialKeys: [],
    });
  });

  it("distinguishes a real detach from OpenShell's idempotent success", () => {
    expect(
      providerDetachChangedState(0, "✓ Detached provider alpha-mcp-github from sandbox alpha"),
    ).toBe(true);
    expect(
      providerDetachChangedState(0, "Provider alpha-mcp-github was not attached to sandbox alpha."),
    ).toBe(false);
  });

  it("accepts current revision-scoped placeholders without exposing their value", () => {
    const command = buildMcpCredentialReadinessCommand("GITHUB_TOKEN");
    for (const value of [
      "openshell:resolve:env:GITHUB_TOKEN",
      "openshell:resolve:env:v11_GITHUB_TOKEN",
      "openshell:resolve:env:v0_GITHUB_TOKEN",
    ]) {
      const result = spawnSync("/bin/sh", ["-c", command], {
        encoding: "utf8",
        env: { GITHUB_TOKEN: value },
      });
      expect(result.status, value).toBe(0);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe("");
    }

    for (const value of [
      "raw-secret",
      "openshell:resolve:env:v_GITHUB_TOKEN",
      "openshell:resolve:env:v11_OTHER_TOKEN",
      "openshell:resolve:env:v11x_GITHUB_TOKEN",
    ]) {
      const result = spawnSync("/bin/sh", ["-c", command], {
        encoding: "utf8",
        env: { GITHUB_TOKEN: value },
      });
      expect(result.status, value).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe("");
    }
  });

  it("captures only validated OpenShell credential placeholders without printing values", () => {
    const snapshotPath = `/tmp/nemoclaw-mcp-provider-sync-${randomUUID()}`;
    const command = buildMcpCredentialRevisionSnapshotCommand("GITHUB_TOKEN", snapshotPath);

    try {
      for (const value of [
        "openshell:resolve:env:GITHUB_TOKEN",
        "openshell:resolve:env:v11_GITHUB_TOKEN",
      ]) {
        fs.rmSync(snapshotPath, { force: true });
        const result = spawnSync("/bin/sh", ["-c", command], {
          encoding: "utf8",
          env: { GITHUB_TOKEN: value },
        });
        expect(result.status, value).toBe(0);
        expect(result.stdout).toBe("");
        expect(result.stderr).toBe("");
        expect(fs.readFileSync(snapshotPath, "utf8")).toBe(value);
      }

      const rawSecret = "never-write-or-print-this-secret";
      fs.rmSync(snapshotPath, { force: true });
      const rawResult = spawnSync("/bin/sh", ["-c", command], {
        encoding: "utf8",
        env: { GITHUB_TOKEN: rawSecret },
      });
      expect(rawResult.status).not.toBe(0);
      expect(rawResult.stdout).toBe("");
      expect(rawResult.stderr).toBe("");
      expect(fs.readFileSync(snapshotPath, "utf8")).toBe("");
      expect(
        `${rawResult.stdout}${rawResult.stderr}${fs.readFileSync(snapshotPath, "utf8")}`,
      ).not.toContain(rawSecret);

      fs.rmSync(snapshotPath, { force: true });
      const absentResult = spawnSync("/bin/sh", ["-c", command], {
        encoding: "utf8",
        env: {},
      });
      expect(absentResult.status).toBe(0);
      expect(absentResult.stdout).toBe("");
      expect(absentResult.stderr).toBe("");
      expect(fs.readFileSync(snapshotPath, "utf8")).toBe("");
    } finally {
      fs.rmSync(snapshotPath, { force: true });
    }
  });

  it("does not overwrite a pre-existing credential revision snapshot", () => {
    const snapshotPath = `/tmp/nemoclaw-mcp-provider-sync-${randomUUID()}`;
    const sentinel = "pre-existing-snapshot";
    fs.writeFileSync(snapshotPath, sentinel, { mode: 0o600 });

    try {
      const result = spawnSync(
        "/bin/sh",
        ["-c", buildMcpCredentialRevisionSnapshotCommand("GITHUB_TOKEN", snapshotPath)],
        {
          encoding: "utf8",
          env: {
            GITHUB_TOKEN: "openshell:resolve:env:v11_GITHUB_TOKEN",
          },
        },
      );
      expect(result.status).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(fs.readFileSync(snapshotPath, "utf8")).toBe(sentinel);
    } finally {
      fs.rmSync(snapshotPath, { force: true });
    }
  });

  it("requires a changed credential revision after provider updates", () => {
    const snapshotPath = `/tmp/nemoclaw-mcp-provider-sync-${randomUUID()}`;
    const runReadiness = (value: string) =>
      spawnSync(
        "/bin/sh",
        ["-c", buildMcpCredentialReadinessCommand("GITHUB_TOKEN", snapshotPath)],
        { encoding: "utf8", env: { GITHUB_TOKEN: value } },
      );

    try {
      for (const [prior, stale, refreshed] of [
        [
          "openshell:resolve:env:v11_GITHUB_TOKEN",
          "openshell:resolve:env:v11_GITHUB_TOKEN",
          "openshell:resolve:env:v12_GITHUB_TOKEN",
        ],
        [
          "openshell:resolve:env:GITHUB_TOKEN",
          "openshell:resolve:env:GITHUB_TOKEN",
          "openshell:resolve:env:v1_GITHUB_TOKEN",
        ],
      ]) {
        fs.writeFileSync(snapshotPath, prior, { mode: 0o600 });
        const staleResult = runReadiness(stale);
        expect(staleResult.status, prior).not.toBe(0);
        expect(staleResult.stdout).toBe("");
        expect(staleResult.stderr).toBe("");

        const refreshedResult = runReadiness(refreshed);
        expect(refreshedResult.status, prior).toBe(0);
        expect(refreshedResult.stdout).toBe("");
        expect(refreshedResult.stderr).toBe("");
      }
    } finally {
      fs.rmSync(snapshotPath, { force: true });
    }
  });

  it("treats an empty pre-update snapshot as presence-only and rejects malformed prior state", () => {
    const snapshotPath = `/tmp/nemoclaw-mcp-provider-sync-${randomUUID()}`;
    const command = buildMcpCredentialReadinessCommand("GITHUB_TOKEN", snapshotPath);
    const run = (value: string) =>
      spawnSync("/bin/sh", ["-c", command], {
        encoding: "utf8",
        env: { GITHUB_TOKEN: value },
      });

    try {
      fs.writeFileSync(snapshotPath, "", { mode: 0o600 });
      for (const value of [
        "openshell:resolve:env:GITHUB_TOKEN",
        "openshell:resolve:env:v1_GITHUB_TOKEN",
      ]) {
        const result = run(value);
        expect(result.status, value).toBe(0);
        expect(result.stdout).toBe("");
        expect(result.stderr).toBe("");
      }

      fs.writeFileSync(snapshotPath, "raw-or-corrupt-prior-value", {
        mode: 0o600,
      });
      const malformedResult = run("openshell:resolve:env:v2_GITHUB_TOKEN");
      expect(malformedResult.status).not.toBe(0);
      expect(malformedResult.stdout).toBe("");
      expect(malformedResult.stderr).toBe("");

      fs.rmSync(snapshotPath, { force: true });
      const missingResult = run("openshell:resolve:env:v2_GITHUB_TOKEN");
      expect(missingResult.status).not.toBe(0);
      expect(missingResult.stdout).toBe("");
      expect(missingResult.stderr).toBe("");
    } finally {
      fs.rmSync(snapshotPath, { force: true });
    }
  });
});

describe("MCP OpenShell policy", () => {
  it("generates a protocol:mcp policy for the target endpoint and adapter binaries", () => {
    const policyName = buildMcpBridgePolicyName("GitHub_Server");
    const policy = YAML.parse(
      buildMcpBridgePolicyYaml("GitHub_Server", "https://api.githubcopilot.com/mcp", "mcporter", [
        "8.8.8.8",
        "2606:4700:4700::1111",
      ]),
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
            mcp: {
              max_body_bytes: number;
              strict_tool_names?: boolean;
              allow_all_known_mcp_methods?: boolean;
            };
            allowed_ips?: string[];
            rules?: Array<{ allow: { method: string } }>;
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
        allow_all_known_mcp_methods: false,
      },
    });
    expect(entry.endpoints[0].rules).toEqual(
      MCP_BRIDGE_ALLOWED_METHODS.map((method) => ({
        allow: { method },
      })),
    );
    expect(entry.endpoints[0].allowed_ips).toEqual(["8.8.8.8", "2606:4700:4700::1111"]);
    expect(entry.binaries.map((binary) => binary.path)).toEqual([
      "/usr/local/bin/mcporter",
      "/usr/bin/mcporter",
      "/usr/local/bin/openclaw",
      "/usr/local/bin/node",
      "/usr/bin/node",
    ]);
    expect(entry.endpoints[0].mcp).toEqual({
      max_body_bytes: MCP_BRIDGE_POLICY_MAX_BODY_BYTES,
      strict_tool_names: true,
      allow_all_known_mcp_methods: false,
    });
  });

  it("pins the current OpenShell main client-to-server MCP method profile", () => {
    expect(MCP_BRIDGE_ALLOWED_METHODS).toEqual([
      "initialize",
      "notifications/initialized",
      "ping",
      "tools/list",
      "tools/call",
      "resources/list",
      "resources/read",
      "resources/templates/list",
      "resources/subscribe",
      "resources/unsubscribe",
      "prompts/list",
      "prompts/get",
      "tasks/list",
      "tasks/get",
      "tasks/update",
      "tasks/result",
      "tasks/cancel",
      "completion/complete",
      "logging/setLevel",
      "server/discover",
      "messages/listen",
      "notifications/cancelled",
      "notifications/progress",
      "notifications/roots/list_changed",
      "notifications/elicitation/complete",
    ]);
  });

  it("allows the OpenShell host alias with private-network SSRF guards", () => {
    const policy = YAML.parse(
      buildMcpBridgePolicyYaml("local", "http://host.openshell.internal:31337/mcp", "mcporter"),
    ) as {
      network_policies: Record<string, { endpoints: Array<{ allowed_ips: string[] }> }>;
    };

    expect(policy.network_policies.mcp_bridge_local.endpoints[0].allowed_ips).toEqual([
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "fc00::/7",
    ]);
  });

  it("scopes binaries to the selected agent adapter", () => {
    const hermes = YAML.parse(
      buildMcpBridgePolicyYaml("srv", "https://mcp.example.test/mcp", "hermes-config"),
    ) as {
      network_policies: Record<string, { binaries: Array<{ path: string }> }>;
    };
    const deepAgents = YAML.parse(
      buildMcpBridgePolicyYaml("srv", "https://mcp.example.test/mcp", "deepagents-config"),
    ) as {
      network_policies: Record<string, { binaries: Array<{ path: string }> }>;
    };

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

  function runDeepAgentsConfigCommand(
    command: string,
    initialConfig: Record<string, unknown>,
  ): {
    status: number | null;
    stdout: string;
    stderr: string;
    configExists: boolean;
    config: Record<string, unknown> | null;
  } {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-deepagents-mcp-"));
    const configPath = path.join(tmp, ".deepagents", ".mcp.json");
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, `${JSON.stringify(initialConfig, null, 2)}\n`, {
      mode: 0o600,
    });
    try {
      const result = spawnSync(
        "bash",
        ["-c", command.replaceAll(DEEPAGENTS_MCP_CONFIG_PATH, configPath)],
        { encoding: "utf-8", timeout: 5000 },
      );
      const configExists = fs.existsSync(configPath);
      return {
        status: result.status,
        stdout: result.stdout,
        stderr: result.stderr,
        configExists,
        config: configExists
          ? (JSON.parse(fs.readFileSync(configPath, "utf-8")) as Record<string, unknown>)
          : null,
      };
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }

  it("constructs a mcporter HTTP registration with OpenShell env placeholders", () => {
    const command = buildOpenClawMcporterRegisterCommand(baseEntry);

    expect(command).toContain("'mcporter' 'config' 'add' 'github'");
    expect(command).toContain("'--url' 'https://api.githubcopilot.com/mcp/'");
    expect(command).toContain(
      "'--header' 'Authorization=Bearer openshell:resolve:env:GITHUB_TOKEN'",
    );
    expect(command).toContain("'--scope' 'home'");
    expect(command).toContain("already exists in mcporter config");
    expect(command).not.toContain("fake-secret");
  });

  it("accepts only mcporter's synthesized HTTP Accept header in ownership checks", () => {
    const expected = {
      Authorization: "Bearer openshell:resolve:env:GITHUB_TOKEN",
    };

    expect(
      mcporterHeadersMatchExpected(
        {
          ...expected,
          accept: "application/json, text/event-stream",
        },
        expected,
      ),
    ).toBe(true);
    expect(mcporterHeadersMatchExpected(expected, expected)).toBe(true);
    expect(
      mcporterHeadersMatchExpected(
        {
          ...expected,
          accept: "application/json",
        },
        expected,
      ),
    ).toBe(false);
    expect(
      mcporterHeadersMatchExpected(
        {
          ...expected,
          accept: "application/json, text/event-stream",
          "x-unowned": "drift",
        },
        expected,
      ),
    ).toBe(false);
    expect(
      mcporterHeadersMatchExpected(
        {
          Authorization: "Bearer changed",
          accept: "application/json, text/event-stream",
        },
        expected,
      ),
    ).toBe(false);
  });

  it("uses the normalized-header ownership rule in mcporter inspect and remove commands", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcporter-owner-"));
    const fakeMcporter = path.join(temp, "mcporter");
    const removeMarker = path.join(temp, "removed");
    fs.writeFileSync(
      fakeMcporter,
      [
        "#!/usr/bin/env node",
        'const fs = require("node:fs");',
        'const headers = JSON.parse(process.env.FAKE_MCPORTER_HEADERS || "{}");',
        'if (process.argv[3] === "get") {',
        "  process.stdout.write(JSON.stringify({",
        '    name: "github", transport: "http",',
        '    baseUrl: "https://api.githubcopilot.com/mcp/", headers,',
        "  }));",
        "  process.exit(0);",
        "}",
        'if (process.argv[3] === "remove") {',
        '  fs.writeFileSync(process.env.FAKE_MCPORTER_REMOVE_MARKER, "removed");',
        "  process.exit(0);",
        "}",
        "process.exit(3);",
      ].join("\n"),
      { mode: 0o755 },
    );
    const run = (command: string, headers: Record<string, string>) =>
      spawnSync("/bin/sh", ["-c", command], {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${temp}:${process.env.PATH ?? ""}`,
          FAKE_MCPORTER_HEADERS: JSON.stringify(headers),
          FAKE_MCPORTER_REMOVE_MARKER: removeMarker,
        },
      });
    const normalizedHeaders = {
      Authorization: "Bearer openshell:resolve:env:GITHUB_TOKEN",
      accept: "application/json, text/event-stream",
    };

    const inspect = run(buildOpenClawMcporterInspectCommand(baseEntry, true), normalizedHeaders);
    expect(inspect.status).toBe(0);
    expect(inspect.stdout.trim()).toBe("registered");

    const remove = run(buildOpenClawMcporterRemoveCommand(baseEntry), normalizedHeaders);
    expect(remove.status).toBe(0);
    expect(fs.readFileSync(removeMarker, "utf8")).toBe("removed");

    fs.rmSync(removeMarker, { force: true });
    const drifted = run(buildOpenClawMcporterRemoveCommand(baseEntry), {
      ...normalizedHeaders,
      "x-unowned": "drift",
    });
    expect(drifted.status).toBe(2);
    expect(drifted.stderr).toContain("Refusing to remove modified mcporter MCP server");
    expect(fs.existsSync(removeMarker)).toBe(false);
  });

  it("constructs a Hermes config registration with placeholders", () => {
    const command = buildHermesMcpRegisterCommand({
      ...baseEntry,
      agent: "hermes",
      adapter: "hermes-config",
    });

    expect(command.slice(0, 4)).toEqual([
      "/opt/hermes/.venv/bin/python",
      "/usr/local/lib/nemoclaw/hermes-mcp-config-transaction.py",
      "add",
      "--payload",
    ]);
    expect(JSON.parse(command[4] ?? "{}")).toEqual({
      server: "github",
      url: "https://api.githubcopilot.com/mcp/",
      headers: { Authorization: "Bearer openshell:resolve:env:GITHUB_TOKEN" },
      replace_existing: false,
    });
    expect(buildHermesMcpLifecycleExecArgs("hermes-box", command)).toEqual([
      "sandbox",
      "exec",
      "--name",
      "hermes-box",
      "--no-tty",
      "--",
      ...command,
    ]);
  });

  it("constructs a Deep Agents .mcp.json registration with placeholders", () => {
    const command = buildDeepAgentsMcpRegisterCommand({
      ...baseEntry,
      agent: "langchain-deepagents-code",
      adapter: "deepagents-config",
    });

    expect(DEEPAGENTS_MCP_CONFIG_PATH).toBe("/sandbox/.deepagents/.mcp.json");
    expect(command).toContain(DEEPAGENTS_MCP_CONFIG_PATH);
    expect(command).not.toContain('pathlib.Path("/sandbox/.mcp.json")');
    expect(command).toContain("mcpServers");
    expect(command).toContain('\\"type\\":\\"http\\"');
    expect(command).toContain("https://api.githubcopilot.com/mcp/");
    expect(command).toContain("openshell:resolve:env:GITHUB_TOKEN");
    expect(command).toContain("Invalid /sandbox/.deepagents/.mcp.json");
    expect(command).toContain("mcpServers must be an object");
    expect(command).toContain("already exists in /sandbox/.deepagents/.mcp.json");
  });

  it("fails Deep Agents removal on corrupt config unless forced", () => {
    const normal = buildDeepAgentsMcpRemoveCommand(baseEntry);
    const forced = buildDeepAgentsMcpRemoveCommand(baseEntry, true);

    expect(normal).toContain("Invalid /sandbox/.deepagents/.mcp.json");
    expect(normal).toContain('\\"force\\":false');
    expect(normal).toContain("raise SystemExit(2)");
    expect(normal).toContain("Refusing to remove modified MCP server");
    expect(forced).toContain('\\"force\\":true');
  });

  it("treats every extra Deep Agents server field as ownership drift", () => {
    const managedServer = {
      type: "http",
      url: baseEntry.url,
      headers: {
        Authorization: "Bearer openshell:resolve:env:GITHUB_TOKEN",
      },
    };
    const driftedConfig = {
      mcpServers: {
        github: {
          ...managedServer,
          allowedTools: ["get_issue"],
        },
      },
    };

    const status = runDeepAgentsConfigCommand(
      buildDeepAgentsMcpStatusCommand(baseEntry),
      driftedConfig,
    );
    expect(status.status, status.stderr).toBe(0);
    expect(status.stdout.trim()).toBe("mismatch");

    const remove = runDeepAgentsConfigCommand(
      buildDeepAgentsMcpRemoveCommand(baseEntry),
      driftedConfig,
    );
    expect(remove.status).toBe(2);
    expect(remove.stderr).toContain("Refusing to remove modified MCP server 'github'");
    expect(remove.config).toEqual(driftedConfig);
  });

  it("deletes an empty managed file but preserves unrelated Deep Agents config", () => {
    const managedServer = {
      type: "http",
      url: baseEntry.url,
      headers: {
        Authorization: "Bearer openshell:resolve:env:GITHUB_TOKEN",
      },
    };
    const onlyManagedServer = runDeepAgentsConfigCommand(
      buildDeepAgentsMcpRemoveCommand(baseEntry),
      { mcpServers: { github: managedServer } },
    );
    expect(onlyManagedServer.status, onlyManagedServer.stderr).toBe(0);
    expect(onlyManagedServer.configExists).toBe(false);

    const withUnrelatedConfig = runDeepAgentsConfigCommand(
      buildDeepAgentsMcpRemoveCommand(baseEntry),
      {
        mcpServers: { github: managedServer },
        ui: { theme: "dark" },
      },
    );
    expect(withUnrelatedConfig.status, withUnrelatedConfig.stderr).toBe(0);
    expect(withUnrelatedConfig.configExists).toBe(true);
    expect(withUnrelatedConfig.config).toEqual({ ui: { theme: "dark" } });
  });

  it("does not fabricate Authorization headers for legacy entries without credentials", () => {
    const command = buildOpenClawMcporterRegisterCommand({
      ...baseEntry,
      env: [],
    });

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

  it("redacts resolved Authorization bearer values even without host env access", () => {
    const prior = process.env.GITHUB_TOKEN;
    delete process.env.GITHUB_TOKEN;
    try {
      const redacted = redactBridgeSecretsForDisplay(
        '{"headers":{"Authorization":"Bearer resolved-provider-secret"},"raw":"Authorization: Bearer another-secret"}',
        baseEntry,
      );

      expect(redacted).not.toContain("resolved-provider-secret");
      expect(redacted).not.toContain("another-secret");
      expect(redacted).toContain("Bearer ***REDACTED***");
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
  () => process.exit(0),
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

  it("removes a persisted bridge without requiring the current agent to support MCP", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-remove-"));
    const script = `
process.env.HOME = ${JSON.stringify(home)};
const registry = require("./dist/lib/state/registry.js");
const agentDefs = require("./dist/lib/agent/defs.js");
const gatewayRuntime = require("./dist/lib/gateway-runtime-action.js");
const policies = require("./dist/lib/policy/index.js");
const processRecovery = require("./dist/lib/actions/sandbox/process-recovery.js");
agentDefs.loadAgent = () => { throw new Error("current agent must not be consulted"); };
gatewayRuntime.recoverNamedGatewayRuntime = async () => ({
  recovered: true,
  attempted: false,
  before: { state: "healthy_named" },
  after: { state: "healthy_named" },
});
policies.removePreset = () => true;
policies.getPresetContentGatewayState = () => "absent";
processRecovery.executeSandboxCommand = () => ({ status: 0, stdout: "", stderr: "" });
registry.registerSandbox({
  name: "legacy-sandbox",
  agent: "legacy-disabled",
  mcp: { bridges: { github: {
    server: "github",
    url: "https://mcp.example.test/mcp",
    env: [],
    policyName: "mcp-bridge-github",
    adapter: "mcporter",
    createdAt: "2026-06-01T00:00:00.000Z",
    updatedAt: "2026-06-01T00:00:00.000Z",
  } } },
});
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
bridge.removeMcpBridge("legacy-sandbox", "github").then(
  () => {
    process.stdout.write(JSON.stringify(registry.getSandbox("legacy-sandbox")));
    process.exit(0);
  },
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
    const jsonStart = result.stdout.indexOf("{");
    const sandbox = JSON.parse(result.stdout.slice(jsonStart)) as {
      mcp?: unknown;
    };
    expect(sandbox.mcp).toBeUndefined();
  });

  it("preserves the registry entry when force cleanup leaves residual policy state", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-residual-"));
    const script = `
process.env.HOME = ${JSON.stringify(home)};
const registry = require("./dist/lib/state/registry.js");
const agentDefs = require("./dist/lib/agent/defs.js");
const gatewayRuntime = require("./dist/lib/gateway-runtime-action.js");
const policies = require("./dist/lib/policy/index.js");
const processRecovery = require("./dist/lib/actions/sandbox/process-recovery.js");
agentDefs.loadAgent = () => { throw new Error("current agent must not be consulted"); };
gatewayRuntime.recoverNamedGatewayRuntime = async () => ({
  recovered: true,
  attempted: false,
  before: { state: "healthy_named" },
  after: { state: "healthy_named" },
});
policies.removePreset = () => false;
policies.getPresetContentGatewayState = () => "match";
processRecovery.executeSandboxCommand = () => ({ status: 0, stdout: "", stderr: "" });
registry.registerSandbox({
  name: "legacy-sandbox",
  agent: "legacy-disabled",
  mcp: { bridges: { github: {
    server: "github",
    url: "https://mcp.example.test/mcp",
    env: [],
    policyName: "mcp-bridge-github",
    adapter: "mcporter",
    createdAt: "2026-06-01T00:00:00.000Z",
    updatedAt: "2026-06-01T00:00:00.000Z",
  } } },
});
registry.addCustomPolicy("legacy-sandbox", {
  name: "mcp-bridge-github",
  content: "network_policies:\\n  mcp_bridge_github:\\n    name: managed\\n    endpoints: []\\n",
  sourcePath: "generated:nemoclaw-mcp-bridge",
  appliedAt: "2026-06-01T00:00:00.000Z",
});
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
bridge.removeMcpBridge("legacy-sandbox", "github", { force: true }).then(
  () => process.exit(1),
  (error) => {
    process.stdout.write(JSON.stringify({
      message: error.message,
      sandbox: registry.getSandbox("legacy-sandbox"),
    }));
    process.exit(0);
  },
);
`;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, HOME: home },
    });

    expect(result.status).toBe(0);
    const jsonStart = result.stdout.indexOf("{");
    const payload = JSON.parse(result.stdout.slice(jsonStart)) as {
      message: string;
      sandbox: { mcp?: { bridges?: Record<string, unknown> } };
    };
    expect(payload.message).toContain("registry entry was preserved");
    expect(payload.sandbox.mcp?.bridges).toHaveProperty("github");
  });

  it("rejects duplicate static credential keys across bridges in one sandbox", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-env-key-"));
    const script = `
process.env.HOME = ${JSON.stringify(home)};
const registry = require("./dist/lib/state/registry.js");
registry.registerSandbox({
  name: "openclaw-sandbox",
  agent: "openclaw",
  mcp: { bridges: { first: {
    server: "first",
    url: "https://8.8.8.8/mcp",
    env: ["SHARED_MCP_TOKEN"],
    providerName: "nemoclaw-mcp-openclaw-sandbox-first",
    policyName: "mcp-bridge-first",
    adapter: "mcporter",
    createdAt: "2026-06-01T00:00:00.000Z",
    updatedAt: "2026-06-01T00:00:00.000Z",
  } } },
});
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
bridge.addMcpBridge("openclaw-sandbox", {
  server: "second",
  url: "https://8.8.8.8/mcp",
  env: [{ name: "SHARED_MCP_TOKEN" }],
}).then(
  () => process.exit(1),
  (error) => {
    process.stdout.write(error.message);
    process.exit(0);
  },
);
`;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, HOME: home },
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("already attached through MCP server 'first'");
  });
});

describe("MCP image/runtime constants", () => {
  it("keeps the mcporter runtime pin visible for image tests", () => {
    expect(MCPORTER_VERSION).toBe("0.7.3");
  });
});
