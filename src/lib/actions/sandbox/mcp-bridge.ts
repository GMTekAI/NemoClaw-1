// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import YAML from "yaml";

import { type AgentDefinition, type AgentMcpAdapter, loadAgent } from "../../agent/defs";
import { runOpenshellProviderCommand } from "../../actions/global";
import { recoverNamedGatewayRuntime } from "../../gateway-runtime-action";
import * as policies from "../../policy";
import { redact } from "../../security/redact";
import * as registry from "../../state/registry";
import type { McpBridgeEntry, SandboxEntry } from "../../state/registry";
import { shellQuote } from "../../runner";
import {
  deleteProviderWithRecovery,
  type SandboxProviderRunOpenshell,
} from "../../onboard/sandbox-provider-cleanup";
import { executeSandboxCommand } from "./process-recovery";
import { getSandboxTargetGatewayName } from "./gateway-target";

export const MCPORTER_VERSION = "0.7.3";
export const MCP_BRIDGE_POLICY_SOURCE = "generated:nemoclaw-mcp-bridge";
export const MCP_BRIDGE_POLICY_MAX_BODY_BYTES = 131_072;

const VALID_SERVER_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const VALID_ENV_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const VALID_SANDBOX_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const DEFAULT_AUTH_HEADER = "Authorization";
const DEFAULT_AUTH_SCHEME = "Bearer";
const MCP_PROVIDER_HASH_BYTES = 5;

export class McpBridgeError extends Error {
  constructor(
    message: string,
    readonly exitCode = 1,
  ) {
    super(message);
    this.name = "McpBridgeError";
  }
}

export interface ParsedEnvReference {
  name: string;
  value?: string;
}

export interface ParsedMcpAddArgs {
  server: string;
  url: string;
  env: ParsedEnvReference[];
}

export interface McpBridgeAddOptions extends ParsedMcpAddArgs {}

export interface McpBridgeStatus {
  server: string;
  agent: string;
  support: {
    supported: boolean;
    mode: "bridge" | "disabled";
    adapter?: AgentMcpAdapter;
    reason?: string;
  };
  url?: string;
  env: {
    names: string[];
    missing: string[];
    ready: boolean;
  };
  provider: {
    name?: string;
    registryPresent: boolean;
    gatewayPresent: boolean | null;
    attached: boolean | null;
  };
  policy: {
    name?: string;
    registryPresent: boolean;
    gatewayPresent: boolean | null;
  };
  adapter: {
    registered: boolean | null;
    detail?: string;
  };
  addedAt?: string;
  updatedAt?: string;
}

interface McpBridgeJsonSummary {
  sandbox: string;
  agent: string;
  support: McpBridgeStatus["support"];
  bridges: McpBridgeStatus[];
}

type OpenShellCommandResult = {
  status: number | null;
  stdout?: string | Buffer | null;
  stderr?: string | Buffer | null;
};

function nowIso(): string {
  return new Date().toISOString();
}

function validateSandboxName(name: string): void {
  if (!name || name.length > 63 || !VALID_SANDBOX_RE.test(name)) {
    throw new McpBridgeError(
      `Invalid sandbox name '${name}'. Names must be 1-63 lowercase alphanumeric characters with optional internal hyphens.`,
      2,
    );
  }
}

export function validateMcpServerName(name: string): void {
  if (!VALID_SERVER_RE.test(name)) {
    throw new McpBridgeError(
      `Invalid MCP server name '${name}'. Names must start with a letter and contain only letters, digits, hyphens, and underscores.`,
      2,
    );
  }
}

function validateEnvName(name: string): void {
  if (!VALID_ENV_RE.test(name)) {
    throw new McpBridgeError(
      `Invalid environment variable name '${name}'. Names must match [A-Za-z_][A-Za-z0-9_]*.`,
      2,
    );
  }
}

export function normalizeMcpServerUrl(rawUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new McpBridgeError(`Invalid MCP server URL '${rawUrl}'.`, 2);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new McpBridgeError("MCP server URL must use http:// or https://.", 2);
  }
  if (!parsed.hostname) {
    throw new McpBridgeError("MCP server URL must include a hostname.", 2);
  }
  if (parsed.username || parsed.password) {
    throw new McpBridgeError(
      "MCP server URL must not embed credentials. Use --env KEY so OpenShell resolves host-only credentials.",
      2,
    );
  }
  if (parsed.hash) parsed.hash = "";
  if (!parsed.pathname) parsed.pathname = "/";
  return parsed.toString();
}

function parseMcpUrl(rawUrl: string): URL {
  return new URL(normalizeMcpServerUrl(rawUrl));
}

function getSandboxOrThrow(sandboxName: string): SandboxEntry {
  const sandbox = registry.getSandbox(sandboxName);
  if (!sandbox) {
    throw new McpBridgeError(`Sandbox '${sandboxName}' not found.`, 1);
  }
  return sandbox;
}

function getSandboxAgentName(sandbox: SandboxEntry): string {
  return sandbox.agent || "openclaw";
}

function getSandboxAgent(sandbox: SandboxEntry): AgentDefinition {
  return loadAgent(getSandboxAgentName(sandbox));
}

function unsupportedMessage(agent: AgentDefinition): string {
  const reason = agent.mcpCapability.reason
    ? ` ${agent.mcpCapability.reason}`
    : " MCP support is disabled for this agent.";
  return `${agent.displayName} does not support managed MCP servers yet.${reason} Issue #566 tracks future design.`;
}

function assertBridgeSupported(agent: AgentDefinition): void {
  if (agent.mcpCapability.support === "bridge") return;
  throw new McpBridgeError(unsupportedMessage(agent), 1);
}

function getBridgeAdapter(agent: AgentDefinition): AgentMcpAdapter {
  assertBridgeSupported(agent);
  const adapter = agent.mcpCapability.adapter;
  if (!adapter) {
    throw new McpBridgeError(
      `${agent.displayName} declares MCP support but does not declare an adapter.`,
      1,
    );
  }
  return adapter;
}

function isAgentMcpAdapter(value: unknown): value is AgentMcpAdapter {
  return value === "mcporter" || value === "hermes-config" || value === "deepagents-config";
}

function getEntryAdapter(
  entry: Pick<McpBridgeEntry, "adapter"> | undefined,
  agent: AgentDefinition,
): AgentMcpAdapter | null {
  if (entry && isAgentMcpAdapter(entry.adapter)) return entry.adapter;
  return agent.mcpCapability.support === "bridge" && agent.mcpCapability.adapter
    ? agent.mcpCapability.adapter
    : null;
}

function bridgeState(sandbox: SandboxEntry): Record<string, McpBridgeEntry> {
  return sandbox.mcp?.bridges ?? {};
}

function setBridgeState(sandboxName: string, bridges: Record<string, McpBridgeEntry>): void {
  registry.updateSandbox(sandboxName, {
    mcp: Object.keys(bridges).length > 0 ? { bridges } : undefined,
  });
}

export function parseMcpAddArgs(argv: string[]): ParsedMcpAddArgs {
  const env: ParsedEnvReference[] = [];
  let server = "";
  let url = "";

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === "--") {
      throw new McpBridgeError(
        "Host stdio MCP commands are not supported. Use --url so OpenShell can enforce MCP traffic and provider credentials.",
        2,
      );
    }
    if (token === "--env" || token === "-e") {
      const raw = argv[++i] ?? "";
      const eq = raw.indexOf("=");
      const name = eq >= 0 ? raw.slice(0, eq) : raw;
      validateEnvName(name);
      env.push(eq >= 0 ? { name, value: raw.slice(eq + 1) } : { name });
      continue;
    }
    if (token?.startsWith("--env=")) {
      const raw = token.slice("--env=".length);
      const eq = raw.indexOf("=");
      const name = eq >= 0 ? raw.slice(0, eq) : raw;
      validateEnvName(name);
      env.push(eq >= 0 ? { name, value: raw.slice(eq + 1) } : { name });
      continue;
    }
    if (token === "--url") {
      url = normalizeMcpServerUrl(argv[++i] ?? "");
      continue;
    }
    if (token?.startsWith("--url=")) {
      url = normalizeMcpServerUrl(token.slice("--url=".length));
      continue;
    }
    if (token?.startsWith("-")) {
      throw new McpBridgeError(`Unknown mcp add option: ${token}`, 2);
    }
    if (!server) {
      server = token ?? "";
      validateMcpServerName(server);
      continue;
    }
    throw new McpBridgeError(
      "Usage: nemoclaw <sandbox> mcp add <server> --url <http-mcp-url> [--env KEY|KEY=VALUE ...]",
      2,
    );
  }

  if (!server) {
    throw new McpBridgeError(
      "Usage: nemoclaw <sandbox> mcp add <server> --url <http-mcp-url> [--env KEY|KEY=VALUE ...]",
      2,
    );
  }
  if (!url) {
    throw new McpBridgeError("MCP server URL is required. Pass --url <http-mcp-url>.", 2);
  }

  return { server, url, env };
}

function uniqueEnvNames(env: readonly ParsedEnvReference[] | readonly string[]): string[] {
  const names = env.map((entry) => (typeof entry === "string" ? entry : entry.name));
  return [...new Set(names)];
}

export function resolveCredentialEnv(env: readonly ParsedEnvReference[]): Record<string, string> {
  const resolved: Record<string, string> = {};
  for (const entry of env) {
    validateEnvName(entry.name);
    const value = entry.value ?? process.env[entry.name];
    if (value !== undefined && value !== "") {
      resolved[entry.name] = value;
    }
  }
  return resolved;
}

export function buildMcpBridgeProviderName(sandboxName: string, server: string): string {
  validateSandboxName(sandboxName);
  validateMcpServerName(server);
  const serverSlug = server
    .toLowerCase()
    .replace(/_/g, "-")
    .replace(/[^a-z0-9-]/g, "-");
  const base = `${sandboxName}-mcp-${serverSlug}`.replace(/-+/g, "-").replace(/^-|-$/g, "");
  if (base.length <= 63) return base;
  const hash = crypto
    .createHash("sha256")
    .update(`${sandboxName}:${server}`)
    .digest("hex")
    .slice(0, MCP_PROVIDER_HASH_BYTES * 2);
  const suffix = `-${hash}`;
  return `${base.slice(0, 63 - suffix.length).replace(/-+$/g, "")}${suffix}`;
}

export function buildMcpBridgePolicyName(server: string): string {
  validateMcpServerName(server);
  return `mcp-bridge-${server.toLowerCase().replace(/_/g, "-")}`;
}

function buildMcpBridgePolicyKey(server: string): string {
  return buildMcpBridgePolicyName(server).replace(/-/g, "_");
}

function endpointPort(url: URL): number {
  if (url.port) return Number.parseInt(url.port, 10);
  return url.protocol === "https:" ? 443 : 80;
}

function endpointPath(url: URL): string {
  return url.pathname || "/";
}

function binariesForAdapter(adapter: AgentMcpAdapter): Array<{ path: string }> {
  switch (adapter) {
    case "mcporter":
      return [
        { path: "/usr/local/bin/mcporter" },
        { path: "/usr/bin/mcporter" },
        { path: "/usr/local/bin/openclaw" },
        { path: "/usr/local/bin/node" },
        { path: "/usr/bin/node" },
      ];
    case "hermes-config":
      return [{ path: "/usr/local/bin/hermes" }, { path: "/opt/hermes/.venv/bin/python*" }];
    case "deepagents-config":
      return [{ path: "/usr/local/bin/dcode" }, { path: "/opt/venv/bin/python3*" }];
  }
}

function allowedIpsForEndpoint(hostname: string): string[] | undefined {
  const normalized = hostname.toLowerCase();
  if (
    normalized === "host.openshell.internal" ||
    normalized === "host.docker.internal" ||
    normalized === "host.containers.internal"
  ) {
    return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"];
  }
  return undefined;
}

export function buildMcpBridgePolicyYaml(
  server: string,
  url: string,
  adapter: AgentMcpAdapter = "mcporter",
): string {
  const parsed = parseMcpUrl(url);
  const key = buildMcpBridgePolicyKey(server);
  const allowedIps = allowedIpsForEndpoint(parsed.hostname);
  return YAML.stringify({
    preset: {
      name: buildMcpBridgePolicyName(server),
      description: `Generated MCP policy for ${server}`,
    },
    network_policies: {
      [key]: {
        name: key,
        endpoints: [
          {
            host: parsed.hostname,
            port: endpointPort(parsed),
            path: endpointPath(parsed),
            protocol: "mcp",
            enforcement: "enforce",
            ...(allowedIps ? { allowed_ips: allowedIps } : {}),
            mcp: {
              max_body_bytes: MCP_BRIDGE_POLICY_MAX_BODY_BYTES,
            },
            rules: [
              { allow: { method: "initialize" } },
              { allow: { method: "notifications/initialized" } },
              { allow: { method: "ping" } },
              { allow: { method: "tools/list" } },
              { allow: { method: "tools/call" } },
              { allow: { method: "resources/list" } },
              { allow: { method: "resources/read" } },
              { allow: { method: "resources/templates/list" } },
              { allow: { method: "prompts/list" } },
              { allow: { method: "prompts/get" } },
              { allow: { method: "completion/complete" } },
            ],
          },
        ],
        binaries: binariesForAdapter(adapter),
      },
    },
  });
}

function authPlaceholder(entry: Pick<McpBridgeEntry, "env">): string | null {
  const envName = entry.env[0];
  return envName ? `openshell:resolve:env:${envName}` : null;
}

function authorizationValue(entry: Pick<McpBridgeEntry, "env">): string | null {
  const placeholder = authPlaceholder(entry);
  return placeholder ? `${DEFAULT_AUTH_SCHEME} ${placeholder}` : null;
}

function entryHeaders(entry: Pick<McpBridgeEntry, "env">): Record<string, string> {
  const authorization = authorizationValue(entry);
  return authorization ? { [DEFAULT_AUTH_HEADER]: authorization } : {};
}

function ensureMcporter(sandboxName: string): void {
  const check = executeSandboxCommand(sandboxName, "command -v mcporter");
  if (check?.status === 0 && check.stdout.trim()) return;
  throw new McpBridgeError(
    `mcporter is not available in sandbox '${sandboxName}'. Rebuild with a NemoClaw image that includes mcporter@${MCPORTER_VERSION}.`,
  );
}

export function buildOpenClawMcporterRegisterCommand(entry: McpBridgeEntry): string {
  const args = ["mcporter", "config", "add", entry.server, "--url", entry.url];
  const authorization = authorizationValue(entry);
  if (authorization) args.push("--header", `${DEFAULT_AUTH_HEADER}=${authorization}`);
  args.push("--scope", "home");
  return args.map(shellQuote).join(" ");
}

function pythonJsonLiteral(value: unknown): string {
  return JSON.stringify(JSON.stringify(value));
}

export function buildHermesMcpRegisterCommand(entry: McpBridgeEntry): string {
  const payload = {
    server: entry.server,
    url: entry.url,
    headers: entryHeaders(entry),
  };
  return [
    "/opt/hermes/.venv/bin/python - <<'PY'",
    "import json, os, pathlib, yaml",
    `payload = json.loads(${pythonJsonLiteral(payload)})`,
    'config_path = pathlib.Path("/sandbox/.hermes/config.yaml")',
    "data = {}",
    "if config_path.exists():",
    "    data = yaml.safe_load(config_path.read_text(encoding='utf-8')) or {}",
    "servers = data.setdefault('mcp_servers', {})",
    "server = {'url': payload['url'], 'enabled': True, 'timeout': 120, 'connect_timeout': 60, 'tools': {'resources': True, 'prompts': True}}",
    "if payload['headers']:",
    "    server['headers'] = payload['headers']",
    "servers[payload['server']] = server",
    "tmp = config_path.with_name(config_path.name + '.nemoclaw-mcp.tmp')",
    "tmp.write_text(yaml.safe_dump(data, sort_keys=False), encoding='utf-8')",
    "os.chmod(tmp, 0o660)",
    "os.replace(tmp, config_path)",
    "os.chmod(config_path, 0o660)",
    "PY",
  ].join("\n");
}

function buildHermesMcpRemoveCommand(server: string): string {
  const payload = { server };
  return [
    "/opt/hermes/.venv/bin/python - <<'PY'",
    "import json, os, pathlib, yaml",
    `payload = json.loads(${pythonJsonLiteral(payload)})`,
    'config_path = pathlib.Path("/sandbox/.hermes/config.yaml")',
    "if not config_path.exists():",
    "    raise SystemExit(0)",
    "data = yaml.safe_load(config_path.read_text(encoding='utf-8')) or {}",
    "servers = data.get('mcp_servers')",
    "if isinstance(servers, dict):",
    "    servers.pop(payload['server'], None)",
    "    if not servers:",
    "        data.pop('mcp_servers', None)",
    "tmp = config_path.with_name(config_path.name + '.nemoclaw-mcp.tmp')",
    "tmp.write_text(yaml.safe_dump(data, sort_keys=False), encoding='utf-8')",
    "os.chmod(tmp, 0o660)",
    "os.replace(tmp, config_path)",
    "os.chmod(config_path, 0o660)",
    "PY",
  ].join("\n");
}

function buildHermesMcpStatusCommand(entry: McpBridgeEntry): string {
  const payload = { server: entry.server, url: entry.url, headers: entryHeaders(entry) };
  return [
    "/opt/hermes/.venv/bin/python - <<'PY'",
    "import json, pathlib, yaml",
    `payload = json.loads(${pythonJsonLiteral(payload)})`,
    'config_path = pathlib.Path("/sandbox/.hermes/config.yaml")',
    "data = yaml.safe_load(config_path.read_text(encoding='utf-8')) if config_path.exists() else {}",
    "servers = data.get('mcp_servers') if isinstance(data, dict) else None",
    "server = servers.get(payload['server']) if isinstance(servers, dict) else None",
    "ok = isinstance(server, dict) and server.get('url') == payload['url']",
    "if payload['headers']:",
    "    ok = ok and server.get('headers') == payload['headers']",
    "print('registered' if ok else 'missing')",
    "PY",
  ].join("\n");
}

export function buildDeepAgentsMcpRegisterCommand(entry: McpBridgeEntry): string {
  const payload = {
    server: entry.server,
    url: entry.url,
    headers: entryHeaders(entry),
  };
  return [
    "python3 - <<'PY'",
    "import json, os, pathlib, sys",
    `payload = json.loads(${pythonJsonLiteral(payload)})`,
    'config_path = pathlib.Path("/sandbox/.mcp.json")',
    "data = {}",
    "if config_path.exists():",
    "    try:",
    "        data = json.loads(config_path.read_text(encoding='utf-8') or '{}')",
    "    except json.JSONDecodeError as exc:",
    "        print(f'Invalid /sandbox/.mcp.json: {exc}', file=sys.stderr)",
    "        raise SystemExit(2)",
    "if not isinstance(data, dict):",
    "    print('Invalid /sandbox/.mcp.json: expected a JSON object', file=sys.stderr)",
    "    raise SystemExit(2)",
    "servers = data.setdefault('mcpServers', {})",
    "if not isinstance(servers, dict):",
    "    print('Invalid /sandbox/.mcp.json: mcpServers must be an object', file=sys.stderr)",
    "    raise SystemExit(2)",
    "server = {'type': 'http', 'url': payload['url']}",
    "if payload['headers']:",
    "    server['headers'] = payload['headers']",
    "servers[payload['server']] = server",
    "tmp = config_path.with_name(config_path.name + '.nemoclaw-mcp.tmp')",
    "tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + '\\n', encoding='utf-8')",
    "os.chmod(tmp, 0o600)",
    "os.replace(tmp, config_path)",
    "os.chmod(config_path, 0o600)",
    "PY",
  ].join("\n");
}

function buildDeepAgentsMcpRemoveCommand(server: string): string {
  const payload = { server };
  return [
    "python3 - <<'PY'",
    "import json, os, pathlib",
    `payload = json.loads(${pythonJsonLiteral(payload)})`,
    'config_path = pathlib.Path("/sandbox/.mcp.json")',
    "if not config_path.exists():",
    "    raise SystemExit(0)",
    "try:",
    "    data = json.loads(config_path.read_text(encoding='utf-8') or '{}')",
    "except json.JSONDecodeError:",
    "    raise SystemExit(0)",
    "servers = data.get('mcpServers')",
    "if isinstance(servers, dict):",
    "    servers.pop(payload['server'], None)",
    "tmp = config_path.with_name(config_path.name + '.nemoclaw-mcp.tmp')",
    "tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + '\\n', encoding='utf-8')",
    "os.chmod(tmp, 0o600)",
    "os.replace(tmp, config_path)",
    "os.chmod(config_path, 0o600)",
    "PY",
  ].join("\n");
}

function buildDeepAgentsMcpStatusCommand(entry: McpBridgeEntry): string {
  const payload = { server: entry.server, url: entry.url, headers: entryHeaders(entry) };
  return [
    "python3 - <<'PY'",
    "import json, pathlib",
    `payload = json.loads(${pythonJsonLiteral(payload)})`,
    'config_path = pathlib.Path("/sandbox/.mcp.json")',
    "try:",
    "    data = json.loads(config_path.read_text(encoding='utf-8') or '{}')",
    "except Exception:",
    "    data = {}",
    "servers = data.get('mcpServers') if isinstance(data, dict) else None",
    "server = servers.get(payload['server']) if isinstance(servers, dict) else None",
    "ok = isinstance(server, dict) and server.get('url') == payload['url']",
    "if payload['headers']:",
    "    ok = ok and server.get('headers') == payload['headers']",
    "print('registered' if ok else 'missing')",
    "PY",
  ].join("\n");
}

export function redactBridgeSecretsForDisplay(
  text: string,
  entry?: Pick<McpBridgeEntry, "env">,
): string {
  let output = redact(text || "");
  for (const envName of entry?.env ?? []) {
    const value = process.env[envName];
    if (value) output = output.replaceAll(value, "***REDACTED***");
  }
  return output.replace(/Authorization=Bearer\s+\S+/g, "Authorization=Bearer ***REDACTED***");
}

function buildOpenClawMcporterRemoveCommand(server: string): string {
  return ["mcporter", "config", "remove", server].map(shellQuote).join(" ");
}

function registerOpenClawAdapter(sandboxName: string, entry: McpBridgeEntry): void {
  ensureMcporter(sandboxName);
  const result = executeSandboxCommand(sandboxName, buildOpenClawMcporterRegisterCommand(entry));
  const output = redactBridgeSecretsForDisplay(
    [result?.stdout, result?.stderr].filter(Boolean).join("\n").trim(),
    entry,
  );
  if (!result || result.status !== 0) {
    throw new McpBridgeError(output || `mcporter config add failed for '${entry.server}'.`);
  }
}

function runAdapterCommand(
  sandboxName: string,
  entry: Pick<McpBridgeEntry, "env">,
  command: string,
  failureMessage: string,
  options: { force?: boolean } = {},
): void {
  const result = executeSandboxCommand(sandboxName, command);
  const output = redactBridgeSecretsForDisplay(
    [result?.stdout, result?.stderr].filter(Boolean).join("\n").trim(),
    entry,
  );
  if (!result || result.status !== 0) {
    if (options.force) return;
    throw new McpBridgeError(output || failureMessage);
  }
}

function registerAgentAdapter(
  sandboxName: string,
  adapter: AgentMcpAdapter,
  entry: McpBridgeEntry,
): void {
  switch (adapter) {
    case "mcporter":
      registerOpenClawAdapter(sandboxName, entry);
      return;
    case "hermes-config":
      runAdapterCommand(
        sandboxName,
        entry,
        buildHermesMcpRegisterCommand(entry),
        `Hermes MCP config registration failed for '${entry.server}'.`,
      );
      return;
    case "deepagents-config":
      runAdapterCommand(
        sandboxName,
        entry,
        buildDeepAgentsMcpRegisterCommand(entry),
        `Deep Agents Code MCP config registration failed for '${entry.server}'.`,
      );
      return;
  }
}

function unregisterOpenClawAdapter(
  sandboxName: string,
  entry: Pick<McpBridgeEntry, "server" | "env">,
  options: { force?: boolean } = {},
): void {
  const result = executeSandboxCommand(
    sandboxName,
    buildOpenClawMcporterRemoveCommand(entry.server),
  );
  const output = redactBridgeSecretsForDisplay(
    [result?.stdout, result?.stderr].filter(Boolean).join("\n").trim(),
    entry,
  );
  if (!result || result.status !== 0) {
    if (options.force) return;
    throw new McpBridgeError(output || `mcporter config remove failed for '${entry.server}'.`);
  }
}

function unregisterAgentAdapter(
  sandboxName: string,
  adapter: AgentMcpAdapter,
  entry: Pick<McpBridgeEntry, "server" | "env">,
  options: { force?: boolean } = {},
): void {
  switch (adapter) {
    case "mcporter":
      unregisterOpenClawAdapter(sandboxName, entry, options);
      return;
    case "hermes-config":
      runAdapterCommand(
        sandboxName,
        entry,
        buildHermesMcpRemoveCommand(entry.server),
        `Hermes MCP config removal failed for '${entry.server}'.`,
        options,
      );
      return;
    case "deepagents-config":
      runAdapterCommand(
        sandboxName,
        entry,
        buildDeepAgentsMcpRemoveCommand(entry.server),
        `Deep Agents Code MCP config removal failed for '${entry.server}'.`,
        options,
      );
      return;
  }
}

export function redactCredentialValuesForDisplay(
  value: string,
  envValues: Record<string, string>,
): string {
  let redacted = redact(value);
  for (const secret of Object.values(envValues)) {
    if (!secret) continue;
    redacted = redacted.split(secret).join("***REDACTED***");
  }
  return redacted;
}

function commandOutput(
  result: OpenShellCommandResult,
  envValues: Record<string, string> = {},
): string {
  const stdout =
    typeof result.stdout === "string" ? result.stdout : (result.stdout?.toString() ?? "");
  const stderr =
    typeof result.stderr === "string" ? result.stderr : (result.stderr?.toString() ?? "");
  return redactCredentialValuesForDisplay(`${stderr}${stdout}`, envValues).replace(/\r/g, "").trim();
}

const runProviderCleanupOpenshell: SandboxProviderRunOpenshell = (args, opts) =>
  runOpenshellProviderCommand(
    args,
    opts as Parameters<typeof runOpenshellProviderCommand>[1],
  ) as OpenShellCommandResult;

function providerExists(providerName: string): boolean {
  const result = runOpenshellProviderCommand(["provider", "get", providerName], {
    ignoreError: true,
    stdio: ["ignore", "ignore", "ignore"],
  }) as OpenShellCommandResult;
  return result.status === 0;
}

function buildProviderArgs(
  action: "create" | "update",
  providerName: string,
  env: readonly ParsedEnvReference[],
  envValues: Record<string, string>,
): string[] {
  const args =
    action === "create"
      ? ["provider", "create", "--name", providerName, "--type", "generic"]
      : ["provider", "update", providerName];
  for (const entry of env) {
    const value = envValues[entry.name];
    if (value !== undefined && value !== "") {
      args.push("--credential", `${entry.name}=${value}`);
    }
  }
  return args;
}

function upsertMcpProvider(
  providerName: string,
  env: readonly ParsedEnvReference[],
): "created" | "updated" | "reused" | "none" {
  const envNames = uniqueEnvNames(env);
  if (envNames.length === 0) return "none";
  const envValues = resolveCredentialEnv(env);
  const exists = providerExists(providerName);
  if (Object.keys(envValues).length === 0) {
    if (exists) return "reused";
    throw new McpBridgeError(
      `Host environment variable '${envNames[0]}' is required to create MCP provider '${providerName}'.`,
      1,
    );
  }
  const action = exists ? "update" : "create";
  const result = runOpenshellProviderCommand(
    buildProviderArgs(action, providerName, env, envValues),
    {
      ignoreError: true,
      env: envValues,
      stdio: ["ignore", "pipe", "pipe"],
    },
  ) as OpenShellCommandResult;
  if (result.status !== 0) {
    throw new McpBridgeError(
      commandOutput(result, envValues) || `Failed to ${action} MCP provider '${providerName}'.`,
    );
  }
  return action === "create" ? "created" : "updated";
}

function attachProvider(sandboxName: string, providerName: string | undefined): void {
  if (!providerName) return;
  const result = runOpenshellProviderCommand(
    ["sandbox", "provider", "attach", sandboxName, providerName],
    { ignoreError: true, stdio: ["ignore", "pipe", "pipe"] },
  ) as OpenShellCommandResult;
  if (result.status !== 0) {
    const output = commandOutput(result);
    if (/already\s+attached|AlreadyExists/i.test(output)) return;
    throw new McpBridgeError(output || `Failed to attach MCP provider '${providerName}'.`);
  }
}

function detachProvider(
  sandboxName: string,
  providerName: string | undefined,
  options: { force?: boolean } = {},
): void {
  if (!providerName) return;
  const result = runOpenshellProviderCommand(
    ["sandbox", "provider", "detach", sandboxName, providerName],
    { ignoreError: true, stdio: ["ignore", "pipe", "pipe"], suppressOutput: true } as Record<
      string,
      unknown
    >,
  ) as OpenShellCommandResult;
  if (result.status !== 0) {
    const output = commandOutput(result);
    if (/not\s+attached|NotAttached|not\s+found|NotFound/i.test(output) || options.force) return;
    throw new McpBridgeError(output || `Failed to detach MCP provider '${providerName}'.`);
  }
}

function deleteProvider(providerName: string | undefined, options: { force?: boolean } = {}): void {
  if (!providerName) return;
  const result = deleteProviderWithRecovery(providerName, {
    runOpenshell: runProviderCleanupOpenshell,
  });
  if (!result.ok && !options.force) {
    const output = redact(`${result.stderr}${result.stdout}`).trim();
    throw new McpBridgeError(output || `Failed to delete MCP provider '${providerName}'.`);
  }
}

function providerAttached(sandboxName: string, providerName: string | undefined): boolean | null {
  if (!providerName) return null;
  const result = runOpenshellProviderCommand(["sandbox", "provider", "list", sandboxName], {
    ignoreError: true,
    stdio: ["ignore", "pipe", "pipe"],
  }) as OpenShellCommandResult;
  if (result.status !== 0) return null;
  const output = commandOutput(result);
  return output.split(/\s+/).includes(providerName) || output.includes(providerName);
}

function applyGeneratedPolicy(sandboxName: string, entry: McpBridgeEntry): void {
  const adapter = isAgentMcpAdapter(entry.adapter) ? entry.adapter : "mcporter";
  const content = buildMcpBridgePolicyYaml(entry.server, entry.url, adapter);
  const ok = policies.applyPresetContent(sandboxName, entry.policyName, content, {
    custom: { sourcePath: MCP_BRIDGE_POLICY_SOURCE },
  });
  if (ok === false) {
    throw new McpBridgeError(`Failed to apply generated MCP policy '${entry.policyName}'.`);
  }
}

function removeGeneratedPolicy(sandboxName: string, policyName: string, force = false): void {
  const ok = policies.removePreset(sandboxName, policyName);
  if (!ok && !force) {
    throw new McpBridgeError(`Failed to remove generated MCP policy '${policyName}'.`);
  }
  if (force || ok) registry.removeCustomPolicyByName(sandboxName, policyName);
}

function writeBridgeEntry(sandboxName: string, entry: McpBridgeEntry): void {
  const sandbox = getSandboxOrThrow(sandboxName);
  const bridges = { ...bridgeState(sandbox), [entry.server]: entry };
  setBridgeState(sandboxName, bridges);
}

function removeBridgeEntry(sandboxName: string, server: string): void {
  const sandbox = getSandboxOrThrow(sandboxName);
  const bridges = { ...bridgeState(sandbox) };
  delete bridges[server];
  setBridgeState(sandboxName, bridges);
}

function removeBridgeEntryIfPresent(sandboxName: string, server: string): void {
  const sandbox = registry.getSandbox(sandboxName);
  if (!sandbox || !bridgeState(sandbox)[server]) return;
  removeBridgeEntry(sandboxName, server);
}

async function ensureSandboxGatewaySelected(sandboxName: string): Promise<void> {
  await recoverNamedGatewayRuntime({ gatewayName: getSandboxTargetGatewayName(sandboxName) });
}

export async function addMcpBridge(
  sandboxName: string,
  options: McpBridgeAddOptions,
): Promise<void> {
  validateSandboxName(sandboxName);
  validateMcpServerName(options.server);
  const normalizedUrl = normalizeMcpServerUrl(options.url);
  const sandbox = getSandboxOrThrow(sandboxName);
  const agent = getSandboxAgent(sandbox);
  const adapter = getBridgeAdapter(agent);
  if (bridgeState(sandbox)[options.server]) {
    throw new McpBridgeError(
      `MCP server '${options.server}' already exists on sandbox '${sandboxName}'.`,
    );
  }

  const envNames = uniqueEnvNames(options.env);
  const providerName =
    envNames.length > 0 ? buildMcpBridgeProviderName(sandboxName, options.server) : undefined;
  const entry: McpBridgeEntry = {
    server: options.server,
    agent: agent.name,
    adapter,
    url: normalizedUrl,
    env: envNames,
    ...(providerName ? { providerName } : {}),
    policyName: buildMcpBridgePolicyName(options.server),
    addedAt: nowIso(),
  };

  let providerCreated = false;
  let providerAttachedState = false;
  let policyApplied = false;
  let adapterRegistered = false;
  try {
    await ensureSandboxGatewaySelected(sandboxName);
    const providerAction = upsertMcpProvider(providerName ?? "", options.env);
    providerCreated = providerAction === "created";
    attachProvider(sandboxName, providerName);
    providerAttachedState = !!providerName;
    applyGeneratedPolicy(sandboxName, entry);
    policyApplied = true;
    registerAgentAdapter(sandboxName, adapter, entry);
    adapterRegistered = true;
    writeBridgeEntry(sandboxName, entry);
  } catch (error) {
    if (adapterRegistered) unregisterAgentAdapter(sandboxName, adapter, entry, { force: true });
    if (policyApplied) removeGeneratedPolicy(sandboxName, entry.policyName, true);
    if (providerAttachedState) detachProvider(sandboxName, providerName, { force: true });
    if (providerCreated) deleteProvider(providerName, { force: true });
    removeBridgeEntryIfPresent(sandboxName, entry.server);
    throw error;
  }
}

export async function restartMcpBridge(sandboxName: string, server?: string): Promise<void> {
  validateSandboxName(sandboxName);
  const sandbox = getSandboxOrThrow(sandboxName);
  const agent = getSandboxAgent(sandbox);
  const adapter = getBridgeAdapter(agent);
  const bridges = bridgeState(sandbox);
  const targets = server ? [[server, bridges[server]] as const] : Object.entries(bridges);
  if (targets.length === 0) {
    console.log(`  No MCP servers for sandbox '${sandboxName}'.`);
    return;
  }
  await ensureSandboxGatewaySelected(sandboxName);
  for (const [name, entry] of targets) {
    if (!entry) {
      throw new McpBridgeError(`MCP server '${name}' not found on sandbox '${sandboxName}'.`);
    }
    const envRefs = entry.env.map((envName) => ({ name: envName }));
    upsertMcpProvider(entry.providerName ?? "", envRefs);
    attachProvider(sandboxName, entry.providerName);
    applyGeneratedPolicy(sandboxName, entry);
    registerAgentAdapter(
      sandboxName,
      (entry.adapter as AgentMcpAdapter | undefined) ?? adapter,
      entry,
    );
    writeBridgeEntry(sandboxName, {
      ...entry,
      adapter: (entry.adapter as AgentMcpAdapter | undefined) ?? adapter,
      updatedAt: nowIso(),
    });
    console.log(`  Refreshed MCP server '${name}'.`);
  }
}

export function removeMcpBridge(
  sandboxName: string,
  server: string,
  options: { force?: boolean } = {},
): void {
  validateSandboxName(sandboxName);
  validateMcpServerName(server);
  const sandbox = getSandboxOrThrow(sandboxName);
  const agent = getSandboxAgent(sandbox);
  const adapter = getBridgeAdapter(agent);
  const entry = bridgeState(sandbox)[server];
  if (!entry) {
    if (!options.force) {
      throw new McpBridgeError(`MCP server '${server}' not found on sandbox '${sandboxName}'.`);
    }
    console.log(`  No MCP server '${server}' is registered on sandbox '${sandboxName}'.`);
    return;
  }

  const failures: string[] = [];
  try {
    unregisterAgentAdapter(
      sandboxName,
      (entry.adapter as AgentMcpAdapter | undefined) ?? adapter,
      entry,
      { force: options.force === true },
    );
  } catch (error) {
    failures.push(error instanceof Error ? error.message : String(error));
  }
  try {
    removeGeneratedPolicy(sandboxName, entry.policyName, options.force === true);
  } catch (error) {
    failures.push(error instanceof Error ? error.message : String(error));
  }
  try {
    detachProvider(sandboxName, entry.providerName, { force: options.force === true });
  } catch (error) {
    failures.push(error instanceof Error ? error.message : String(error));
  }
  try {
    deleteProvider(entry.providerName, { force: options.force === true });
  } catch (error) {
    failures.push(error instanceof Error ? error.message : String(error));
  }
  if (failures.length > 0 && !options.force) {
    throw new McpBridgeError(failures.join("\n"));
  }
  removeBridgeEntry(sandboxName, server);
  console.log(`  Removed MCP server '${server}' from sandbox '${sandboxName}'.`);
}

function getPolicyPresence(sandboxName: string, policyName: string | undefined): boolean | null {
  if (!policyName) return false;
  const gatewayPresets = policies.getGatewayPresets(sandboxName);
  return gatewayPresets === null ? null : gatewayPresets.includes(policyName);
}

function getProviderPresence(providerName: string | undefined): boolean | null {
  if (!providerName) return null;
  return providerExists(providerName);
}

function getAdapterRegistration(
  sandboxName: string,
  agent: AgentDefinition,
  entry: McpBridgeEntry | undefined,
): McpBridgeStatus["adapter"] {
  if (!entry) return { registered: null };
  const adapter = getEntryAdapter(entry, agent);
  if (!adapter) return { registered: null, detail: "MCP adapter is not declared" };
  const command =
    adapter === "mcporter"
      ? ["mcporter", "config", "get", entry.server, "--json"].map(shellQuote).join(" ")
      : adapter === "hermes-config"
        ? buildHermesMcpStatusCommand(entry)
        : buildDeepAgentsMcpStatusCommand(entry);
  const result = executeSandboxCommand(sandboxName, command);
  if (!result) return { registered: null, detail: "sandbox unreachable" };
  if (result.status === 0) {
    const output = result.stdout.trim();
    if (adapter === "mcporter" || output === "registered") return { registered: true };
    return { registered: false, detail: output || "not found" };
  }
  return {
    registered: false,
    detail: redactBridgeSecretsForDisplay(result.stderr || result.stdout || "not found", entry),
  };
}

export function statusMcpBridge(sandboxName: string, server?: string): McpBridgeStatus[] {
  validateSandboxName(sandboxName);
  const sandbox = getSandboxOrThrow(sandboxName);
  const agent = getSandboxAgent(sandbox);
  const bridges = bridgeState(sandbox);
  const entries: Array<[string, McpBridgeEntry | undefined]> = server
    ? [[server, bridges[server]]]
    : Object.entries(bridges);
  if (server && !bridges[server]) {
    return [
      {
        server,
        agent: agent.name,
        support: {
          supported: agent.mcpCapability.support === "bridge",
          mode: agent.mcpCapability.support,
          ...(agent.mcpCapability.adapter ? { adapter: agent.mcpCapability.adapter } : {}),
          ...(agent.mcpCapability.reason ? { reason: agent.mcpCapability.reason } : {}),
        },
        env: { names: [], missing: [], ready: true },
        provider: { registryPresent: false, gatewayPresent: false, attached: null },
        policy: { registryPresent: false, gatewayPresent: false },
        adapter: { registered: null },
      },
    ];
  }

  return entries.map(([name, entry]) => {
    const missingEnv = entry
      ? entry.env.filter(
          (envName: string) => process.env[envName] === undefined || process.env[envName] === "",
        )
      : [];
    return {
      server: name,
      agent: entry?.agent ?? agent.name,
      support: {
        supported: agent.mcpCapability.support === "bridge",
        mode: agent.mcpCapability.support,
        ...(getEntryAdapter(entry, agent)
          ? { adapter: getEntryAdapter(entry, agent) ?? undefined }
          : {}),
        ...(agent.mcpCapability.reason ? { reason: agent.mcpCapability.reason } : {}),
      },
      ...(entry ? { url: entry.url } : {}),
      env: {
        names: entry?.env ?? [],
        missing: missingEnv,
        ready: missingEnv.length === 0 || getProviderPresence(entry?.providerName) === true,
      },
      provider: {
        name: entry?.providerName,
        registryPresent: !!entry?.providerName,
        gatewayPresent: getProviderPresence(entry?.providerName),
        attached: providerAttached(sandboxName, entry?.providerName),
      },
      policy: {
        name: entry?.policyName,
        registryPresent: !!entry?.policyName,
        gatewayPresent: getPolicyPresence(sandboxName, entry?.policyName),
      },
      adapter: getAdapterRegistration(sandboxName, agent, entry),
      ...(entry?.addedAt ? { addedAt: entry.addedAt } : {}),
      ...(entry?.updatedAt ? { updatedAt: entry.updatedAt } : {}),
    };
  });
}

function getSupportSummary(agent: AgentDefinition): McpBridgeStatus["support"] {
  return {
    supported: agent.mcpCapability.support === "bridge",
    mode: agent.mcpCapability.support,
    ...(agent.mcpCapability.adapter ? { adapter: agent.mcpCapability.adapter } : {}),
    ...(agent.mcpCapability.reason ? { reason: agent.mcpCapability.reason } : {}),
  };
}

function buildJsonSummary(
  sandboxName: string,
  agent: AgentDefinition,
  statuses: McpBridgeStatus[],
): McpBridgeJsonSummary {
  return {
    sandbox: sandboxName,
    agent: agent.name,
    support: getSupportSummary(agent),
    bridges: statuses,
  };
}

function renderList(
  sandboxName: string,
  statuses: McpBridgeStatus[],
  agent: AgentDefinition,
): void {
  console.log("");
  if (agent.mcpCapability.support !== "bridge") {
    console.log(`  MCP support: disabled for ${agent.displayName}`);
    if (agent.mcpCapability.reason) console.log(`  ${agent.mcpCapability.reason}`);
  }
  if (statuses.length === 0) {
    console.log(`  No MCP servers for sandbox '${sandboxName}'.`);
    console.log("");
    return;
  }
  console.log(`  MCP servers for sandbox '${sandboxName}':`);
  for (const status of statuses) {
    const policy = status.policy.gatewayPresent ? "policy" : "policy?";
    const provider =
      status.provider.registryPresent && status.provider.gatewayPresent ? "provider" : "provider?";
    const env = status.env.names.length > 0 ? status.env.names.join(", ") : "(none)";
    console.log(
      `    ${status.server.padEnd(18)} ${policy.padEnd(8)} ${provider.padEnd(10)} env: ${env}`,
    );
  }
  console.log("");
}

function renderStatus(
  sandboxName: string,
  statuses: McpBridgeStatus[],
  agent: AgentDefinition,
): void {
  if (statuses.length === 0) {
    console.log("");
    console.log(`  MCP servers for sandbox '${sandboxName}': none`);
    console.log(`    agent: ${agent.name}`);
    console.log(`    support: ${agent.mcpCapability.support}`);
    if (agent.mcpCapability.reason) console.log(`    reason: ${agent.mcpCapability.reason}`);
    console.log("");
    return;
  }
  for (const status of statuses) {
    console.log("");
    console.log(`  MCP server: ${status.server}`);
    console.log(`    agent: ${status.agent}`);
    console.log(`    support: ${status.support.mode}`);
    if (status.support.reason) console.log(`    reason: ${status.support.reason}`);
    if (status.url) console.log(`    endpoint: ${status.url}`);
    console.log(
      `    provider: ${status.provider.registryPresent ? status.provider.name : "(none)"}`,
    );
    console.log(
      `    provider attached: ${status.provider.attached === null ? "unknown" : status.provider.attached ? "yes" : "no"}`,
    );
    console.log(
      `    policy: ${status.policy.gatewayPresent === null ? "unknown" : status.policy.gatewayPresent ? "present" : "missing"}`,
    );
    console.log(
      `    adapter: ${status.adapter.registered === null ? "unknown" : status.adapter.registered ? "registered" : "missing"}`,
    );
    console.log(
      `    env: ${status.env.ready ? "ready" : `missing ${status.env.missing.join(", ")}`}`,
    );
  }
  console.log("");
}

function parseJsonFlag(args: string[]): { json: boolean; rest: string[] } {
  return {
    json: args.includes("--json"),
    rest: args.filter((arg) => arg !== "--json"),
  };
}

function requireNoExtraArgs(args: string[], usage: string): void {
  if (args.length > 0) throw new McpBridgeError(usage, 2);
}

function requireAtMostOneArg(args: string[], usage: string): string | undefined {
  if (args.length > 1) throw new McpBridgeError(usage, 2);
  return args[0];
}

function hasHelpFlag(args: readonly string[]): boolean {
  return args.includes("--help") || args.includes("-h");
}

function renderMcpHelp(subcommand: string): void {
  switch (subcommand) {
    case "add":
      console.log(`USAGE
  nemoclaw <name> mcp add <server> --url <http-mcp-url> [--env KEY|KEY=VALUE ...]

FLAGS
  --url URL        MCP Streamable HTTP endpoint
  --env KEY       Host credential reference registered with OpenShell
  --env KEY=VALUE Store VALUE in the OpenShell provider; only KEY is persisted by NemoClaw

SECURITY
  Credentials are registered as an OpenShell provider and appear inside the
  sandbox only as openshell:resolve:env:KEY placeholders. OpenShell resolves
  them at egress while enforcing the generated protocol: mcp policy.`);
      return;
    case "list":
      console.log(`USAGE
  nemoclaw <name> mcp list [--json]

FLAGS
  --json  Emit sandbox, support, and MCP server state as JSON`);
      return;
    case "status":
      console.log(`USAGE
  nemoclaw <name> mcp status [server] [--json]

FLAGS
  --json  Emit MCP server status as JSON`);
      return;
    case "restart":
      console.log(`USAGE
  nemoclaw <name> mcp restart [server]`);
      return;
    case "remove":
      console.log(`USAGE
  nemoclaw <name> mcp remove <server> [--force]

FLAGS
  --force  Best-effort cleanup and stale registry removal`);
      return;
    default:
      console.log(`USAGE
  nemoclaw <name> mcp <add|list|status|restart|remove> [args...]`);
  }
}

export async function dispatchMcpBridgeCommand(
  sandboxName: string,
  actionArgs: string[],
): Promise<void> {
  const [subcommand = "list", ...rest] = actionArgs;
  try {
    if (subcommand === "--help" || subcommand === "-h") {
      renderMcpHelp("mcp");
      return;
    }
    if (hasHelpFlag(rest)) {
      renderMcpHelp(subcommand);
      return;
    }
    switch (subcommand) {
      case "add": {
        const options = parseMcpAddArgs(rest);
        await addMcpBridge(sandboxName, options);
        console.log(`  MCP server '${options.server}' added to sandbox '${sandboxName}'.`);
        return;
      }
      case "list": {
        const { json, rest: listRest } = parseJsonFlag(rest);
        requireNoExtraArgs(listRest, "Usage: nemoclaw <sandbox> mcp list [--json]");
        const sandbox = getSandboxOrThrow(sandboxName);
        const agent = getSandboxAgent(sandbox);
        const statuses = statusMcpBridge(sandboxName);
        if (json)
          console.log(JSON.stringify(buildJsonSummary(sandboxName, agent, statuses), null, 2));
        else renderList(sandboxName, statuses, agent);
        return;
      }
      case "status": {
        const { json, rest: statusRest } = parseJsonFlag(rest);
        const server = requireAtMostOneArg(
          statusRest,
          "Usage: nemoclaw <sandbox> mcp status [server] [--json]",
        );
        const sandbox = getSandboxOrThrow(sandboxName);
        const agent = getSandboxAgent(sandbox);
        const statuses = statusMcpBridge(sandboxName, server);
        if (json) {
          console.log(
            JSON.stringify(
              server ? statuses[0] : buildJsonSummary(sandboxName, agent, statuses),
              null,
              2,
            ),
          );
        } else renderStatus(sandboxName, statuses, agent);
        return;
      }
      case "restart": {
        const server = requireAtMostOneArg(
          rest,
          "Usage: nemoclaw <sandbox> mcp restart [server]",
        );
        await restartMcpBridge(sandboxName, server);
        return;
      }
      case "remove": {
        const force = rest.includes("--force");
        const names = rest.filter((arg) => arg !== "--force");
        const server = names[0];
        if (!server || names.length > 1)
          throw new McpBridgeError("Usage: nemoclaw <sandbox> mcp remove <server> [--force]", 2);
        removeMcpBridge(sandboxName, server, { force });
        return;
      }
      default:
        throw new McpBridgeError(
          "Usage: nemoclaw <sandbox> mcp <add|list|status|restart|remove> [args...]",
          2,
        );
    }
  } catch (error) {
    if (error instanceof McpBridgeError) {
      console.error(`  ${error.message}`);
      process.exitCode = error.exitCode;
      return;
    }
    throw error;
  }
}
