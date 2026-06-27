// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import dns from "node:dns/promises";
import YAML from "yaml";

import { runOpenshellProviderCommand } from "../../actions/global";
import { stripAnsi } from "../../adapters/openshell/client";
import { type AgentDefinition, type AgentMcpAdapter, loadAgent } from "../../agent/defs";
import { waitUntil } from "../../core/wait";
import { recoverNamedGatewayRuntime } from "../../gateway-runtime-action";
import * as policies from "../../policy";
import { shellQuote } from "../../runner";
import {
  isBlockedMcpUrlTargetHost,
  isOpenShellMcpHostAlias,
  MCP_SERVER_URL_MAX_LENGTH,
} from "../../security/mcp-url-target";
import { redact } from "../../security/redact";
import { withMcpLifecycleLock } from "../../state/mcp-lifecycle-lock";
import type { McpBridgeEntry, SandboxEntry } from "../../state/registry";
import * as registry from "../../state/registry";
import { getSandboxTargetGatewayName } from "./gateway-target";
import { executeSandboxCommand, executeSandboxExecCommand } from "./process-recovery";

export const MCPORTER_VERSION = "0.7.3";
export { MCP_SERVER_URL_MAX_LENGTH };
// deepagents-code 0.1.12 auto-discovers this as the user-level MCP config.
// `/sandbox/.mcp.json` is project-level and is intentionally rejected by
// headless `dcode -n` unless project MCP has been separately trusted.
export const DEEPAGENTS_MCP_CONFIG_PATH = "/sandbox/.deepagents/.mcp.json";
export const MCP_BRIDGE_POLICY_SOURCE = "generated:nemoclaw-mcp-bridge";
export const MCP_BRIDGE_POLICY_MAX_BODY_BYTES = 131_072;
export const MCP_BRIDGE_ALLOWED_METHODS = [
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
] as const;

const VALID_SERVER_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const VALID_ENV_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const VALID_SANDBOX_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const DEFAULT_AUTH_HEADER = "Authorization";
const DEFAULT_AUTH_SCHEME = "Bearer";
const MCP_PROVIDER_HASH_BYTES = 8;
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
    credentialReady: boolean | null;
    detail?: string;
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
  addState?: "prepared" | "preflighted";
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

type McpProviderInspection = {
  exists: boolean | null;
  type: string | null;
  credentialKeys: string[] | null;
  error?: string;
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
  if (rawUrl.length > MCP_SERVER_URL_MAX_LENGTH) {
    throw new McpBridgeError(
      `MCP server URL must be at most ${MCP_SERVER_URL_MAX_LENGTH} characters.`,
      2,
    );
  }
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
  if (/[*{};]/.test(parsed.hostname)) {
    throw new McpBridgeError(
      "MCP server URL hosts must be literal; wildcard and glob hostnames are not supported.",
      2,
    );
  }
  if (parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]")) {
    throw new McpBridgeError(
      "IPv6-literal MCP server URLs are not supported by the current OpenShell proxy target parser. Use a DNS hostname with public A/AAAA records.",
      2,
    );
  }
  if (parsed.username || parsed.password) {
    throw new McpBridgeError(
      "MCP server URL must not embed credentials. Use --env KEY so OpenShell resolves host-only credentials.",
      2,
    );
  }
  if (parsed.search) {
    throw new McpBridgeError(
      "MCP server URLs must not include a query string because URLs are persisted and displayed. Put credentials in --env and use a stable endpoint path.",
      2,
    );
  }
  if (parsed.hash) {
    throw new McpBridgeError(
      "MCP server URLs must not include a fragment because fragments are not sent to the server.",
      2,
    );
  }
  if (parsed.port === "0") {
    throw new McpBridgeError("MCP server URL port must be between 1 and 65535.", 2);
  }
  if (
    /%[0-9a-f]{2}/i.test(rawUrl) ||
    rawUrl.includes("\\") ||
    /[\*\[\]\{\};]/.test(parsed.pathname)
  ) {
    throw new McpBridgeError(
      "MCP server URL paths must be literal and canonical; percent escapes, backslashes, semicolons, and glob metacharacters are not supported.",
      2,
    );
  }
  if (isOpenShellMcpHostAlias(parsed.hostname) && parsed.hostname.endsWith(".")) {
    // OpenShell's trusted host-alias matcher requires the canonical spelling.
    parsed.hostname = parsed.hostname.slice(0, -1);
  }
  validateMcpServerUrlTarget(parsed);
  if (parsed.protocol === "http:" && !isOpenShellMcpHostAlias(parsed.hostname)) {
    throw new McpBridgeError(
      "Public MCP server URLs must use https:// so provider credentials are encrypted in transit. Plain HTTP is allowed only for OpenShell host aliases.",
      2,
    );
  }
  if (!parsed.pathname) parsed.pathname = "/";
  const normalized = parsed.toString();
  if (normalized.length > MCP_SERVER_URL_MAX_LENGTH) {
    throw new McpBridgeError(
      `MCP server URL must be at most ${MCP_SERVER_URL_MAX_LENGTH} characters after normalization.`,
      2,
    );
  }
  return normalized;
}

function validateMcpServerUrlTarget(parsed: URL): void {
  if (isBlockedMcpUrlTargetHost(parsed.hostname)) {
    throw new McpBridgeError(
      `MCP server URL host '${parsed.hostname}' is a private, local, or special-use IP address. Use host.openshell.internal for host MCP endpoints.`,
      2,
    );
  }
}

async function validateMcpServerUrlResolvedTarget(parsed: URL): Promise<string[] | undefined> {
  if (isOpenShellMcpHostAlias(parsed.hostname)) {
    return undefined;
  }
  if (isBlockedMcpUrlTargetHost(parsed.hostname)) {
    validateMcpServerUrlTarget(parsed);
  }
  let addresses: Array<{ address: string }>;
  try {
    addresses = await dns.lookup(parsed.hostname, {
      all: true,
      verbatim: true,
    });
  } catch (error) {
    const detail = error instanceof Error && error.message ? ` ${error.message}` : "";
    throw new McpBridgeError(
      `MCP server URL host '${parsed.hostname}' could not be resolved before policy registration.${detail}`,
      2,
    );
  }
  if (addresses.length === 0) {
    throw new McpBridgeError(
      `MCP server URL host '${parsed.hostname}' resolved without any addresses before policy registration.`,
      2,
    );
  }
  for (const { address } of addresses) {
    if (isBlockedMcpUrlTargetHost(address)) {
      throw new McpBridgeError(
        `MCP server URL host '${parsed.hostname}' resolves to private, local, or special-use address '${address}'. Use host.openshell.internal for host MCP endpoints.`,
        2,
      );
    }
  }
  return [...new Set(addresses.map(({ address }) => address.toLowerCase()))];
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
  const mcpState = registry.getSandbox(sandboxName)?.mcp;
  const destroyPreparedAt = mcpState?.destroyPreparedAt;
  const destroyPendingAt = mcpState?.destroyPendingAt;
  const updated = registry.updateSandbox(sandboxName, {
    mcp:
      Object.keys(bridges).length > 0
        ? {
            bridges,
            ...(destroyPreparedAt ? { destroyPreparedAt } : {}),
            ...(destroyPendingAt ? { destroyPendingAt } : {}),
          }
        : undefined,
  });
  if (!updated) {
    throw new McpBridgeError(`Could not persist MCP lifecycle state for sandbox '${sandboxName}'.`);
  }
}

function assertMcpDestroyNotPending(sandbox: SandboxEntry): void {
  if (!sandbox.mcp?.destroyPreparedAt && !sandbox.mcp?.destroyPendingAt) return;
  throw new McpBridgeError(
    `Sandbox '${sandbox.name}' has an incomplete MCP destroy transaction. Re-run the sandbox destroy command to finish cleanup before using MCP commands.`,
  );
}

function assertNoDerivedResourceCollision(
  sandbox: SandboxEntry,
  server: string,
  providerName: string | undefined,
  policyName: string,
): void {
  const conflictingCustomPolicy = sandbox.customPolicies?.find(
    (policy) => policy.name === policyName && policy.sourcePath !== MCP_BRIDGE_POLICY_SOURCE,
  );
  if (conflictingCustomPolicy || sandbox.policies?.includes(policyName)) {
    throw new McpBridgeError(
      `Generated MCP policy name '${policyName}' conflicts with an existing non-MCP policy. Choose a different server name.`,
      2,
    );
  }
  for (const entry of Object.values(bridgeState(sandbox))) {
    if (entry.server === server) continue;
    const providerCollision =
      providerName !== undefined &&
      entry.providerName !== undefined &&
      entry.providerName === providerName;
    if (providerCollision || entry.policyName === policyName) {
      throw new McpBridgeError(
        `MCP server '${server}' conflicts with existing server '${entry.server}' after OpenShell resource-name normalization. Choose a name that differs beyond case, hyphens, and underscores.`,
        2,
      );
    }
  }
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
      if (eq >= 0) {
        throw new McpBridgeError(
          "Inline --env KEY=VALUE is not accepted because it exposes the secret in the NemoClaw process arguments and shell history. Export KEY, then pass --env KEY.",
          2,
        );
      }
      env.push({ name });
      continue;
    }
    if (token?.startsWith("--env=")) {
      const raw = token.slice("--env=".length);
      const eq = raw.indexOf("=");
      const name = eq >= 0 ? raw.slice(0, eq) : raw;
      validateEnvName(name);
      if (eq >= 0) {
        throw new McpBridgeError(
          "Inline --env KEY=VALUE is not accepted because it exposes the secret in the NemoClaw process arguments and shell history. Export KEY, then pass --env KEY.",
          2,
        );
      }
      env.push({ name });
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
      "Usage: nemoclaw <sandbox> mcp add <server> --url <http-mcp-url> --env KEY",
      2,
    );
  }

  if (!server) {
    throw new McpBridgeError(
      "Usage: nemoclaw <sandbox> mcp add <server> --url <http-mcp-url> --env KEY",
      2,
    );
  }
  if (!url) {
    throw new McpBridgeError("MCP server URL is required. Pass --url <http-mcp-url>.", 2);
  }
  if (env.length !== 1) {
    throw new McpBridgeError(
      "Authenticated MCP requires exactly one --env KEY bearer credential reference.",
      2,
    );
  }

  return { server, url, env };
}

function uniqueEnvNames(env: readonly ParsedEnvReference[] | readonly string[]): string[] {
  const names = env.map((entry) => (typeof entry === "string" ? entry : entry.name));
  return [...new Set(names)];
}

function assertAuthenticatedCredentialReference(env: readonly ParsedEnvReference[]): void {
  if (env.length !== 1) {
    throw new McpBridgeError(
      "Authenticated MCP requires exactly one --env KEY bearer credential reference.",
      2,
    );
  }
  validateEnvName(env[0].name);
}

function assertAuthenticatedBridgeEntry(entry: McpBridgeEntry): void {
  if (!Array.isArray(entry.env) || entry.env.length !== 1 || !entry.providerName) {
    throw new McpBridgeError(
      `MCP server '${entry.server}' has no complete authenticated credential binding. Remove it with --force, then add it again with --env KEY.`,
      2,
    );
  }
  validateEnvName(entry.env[0]);
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
        // Both npm entrypoints are #!/usr/bin/env node scripts. OpenShell binds
        // policy to /proc/<pid>/exe and ancestors, not spoofable argv paths.
        // The explicit endpoint/path/MCP method rules below are the compensating
        // boundary for other Node processes in the sandbox.
        { path: "/usr/local/bin/node" },
        { path: "/usr/bin/node" },
      ];
    case "hermes-config":
      return [{ path: "/usr/local/bin/hermes" }, { path: "/opt/hermes/.venv/bin/python*" }];
    case "deepagents-config":
      return [{ path: "/usr/local/bin/dcode" }, { path: "/opt/venv/bin/python3*" }];
  }
}

function allowedIpsForEndpoint(
  hostname: string,
  resolvedAddresses: readonly string[] | undefined,
): string[] | undefined {
  if (isOpenShellMcpHostAlias(hostname)) {
    return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"];
  }
  return resolvedAddresses && resolvedAddresses.length > 0 ? [...resolvedAddresses] : undefined;
}

export function buildMcpBridgePolicyYaml(
  server: string,
  url: string,
  adapter: AgentMcpAdapter = "mcporter",
  resolvedAddresses?: readonly string[],
): string {
  const parsed = parseMcpUrl(url);
  const key = buildMcpBridgePolicyKey(server);
  const allowedIps = allowedIpsForEndpoint(parsed.hostname, resolvedAddresses);
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
              strict_tool_names: true,
              allow_all_known_mcp_methods: false,
            },
            rules: MCP_BRIDGE_ALLOWED_METHODS.map((method) => ({
              allow: { method },
            })),
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

/**
 * mcporter@0.7.3 normalizes every HTTP definition returned by
 * `config get --json` with an `accept: application/json, text/event-stream`
 * header, even when that header is absent from the persisted config. Treat
 * only that synthesized header as equivalent; every persisted/other header
 * remains part of the ownership fingerprint.
 *
 * This function is also serialized into the in-sandbox inspection commands,
 * so keep it self-contained (no references to module-scope values).
 */
export function mcporterHeadersMatchExpected(
  actual: unknown,
  expected: Record<string, string>,
): boolean {
  if (!actual || typeof actual !== "object" || Array.isArray(actual)) {
    return false;
  }
  const actualHeaders = actual as Record<string, unknown>;
  for (const [name, value] of Object.entries(expected)) {
    if (actualHeaders[name] !== value) return false;
  }
  const extraNames = Object.keys(actualHeaders).filter((name) => !Object.hasOwn(expected, name));
  if (extraNames.length === 0) return true;
  if (extraNames.length !== 1) return false;
  const [extraName] = extraNames;
  return (
    extraName.toLowerCase() === "accept" &&
    actualHeaders[extraName] === "application/json, text/event-stream"
  );
}

function mcporterHeaderMatcherSource(): string {
  return `const mcporterHeadersMatchExpected = ${mcporterHeadersMatchExpected.toString()};`;
}

function ensureMcporter(sandboxName: string): void {
  const check = executeSandboxCommand(sandboxName, "command -v mcporter");
  if (check?.status === 0 && check.stdout.trim()) return;
  throw new McpBridgeError(
    `mcporter is not available in sandbox '${sandboxName}'. Rebuild with a NemoClaw image that includes mcporter@${MCPORTER_VERSION}.`,
  );
}

export function buildOpenClawMcporterRegisterCommand(
  entry: McpBridgeEntry,
  replaceExisting = false,
): string {
  const args = ["mcporter", "config", "add", entry.server, "--url", entry.url];
  const authorization = authorizationValue(entry);
  if (authorization) args.push("--header", `${DEFAULT_AUTH_HEADER}=${authorization}`);
  args.push("--scope", "home");
  const addCommand = args.map(shellQuote).join(" ");
  if (replaceExisting) return addCommand;
  const getCommand = ["mcporter", "config", "get", entry.server, "--json"]
    .map(shellQuote)
    .join(" ");
  return [
    `if ${getCommand} >/dev/null 2>&1; then`,
    `  echo ${shellQuote(`MCP server '${entry.server}' already exists in mcporter config and is not managed by NemoClaw.`)} >&2`,
    "  exit 2",
    "fi",
    addCommand,
  ].join("\n");
}

function pythonJsonLiteral(value: unknown): string {
  return JSON.stringify(JSON.stringify(value));
}

export function buildHermesMcpRegisterCommand(
  entry: McpBridgeEntry,
  replaceExisting = false,
): string {
  const payload = {
    server: entry.server,
    url: entry.url,
    headers: entryHeaders(entry),
    replace_existing: replaceExisting,
  };
  return [
    "/opt/hermes/.venv/bin/python",
    "/usr/local/lib/nemoclaw/hermes-mcp-config-transaction.py",
    "add",
    "--payload",
    shellQuote(JSON.stringify(payload)),
  ].join(" ");
}

function buildHermesMcpRemoveCommand(entry: McpBridgeEntry, force = false): string {
  const payload = {
    server: entry.server,
    url: entry.url,
    headers: entryHeaders(entry),
    force,
  };
  return [
    "/opt/hermes/.venv/bin/python",
    "/usr/local/lib/nemoclaw/hermes-mcp-config-transaction.py",
    "remove",
    "--payload",
    shellQuote(JSON.stringify(payload)),
  ].join(" ");
}

function hermesManagedServerConfig(entry: McpBridgeEntry): Record<string, unknown> {
  const headers = entryHeaders(entry);
  return {
    url: entry.url,
    enabled: true,
    timeout: 120,
    connect_timeout: 60,
    tools: { resources: true, prompts: true },
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  };
}

function buildHermesMcpStatusCommand(entry: McpBridgeEntry): string {
  const payload = {
    server: entry.server,
    expected: hermesManagedServerConfig(entry),
  };
  return [
    "/opt/hermes/.venv/bin/python - <<'PY'",
    "import json, pathlib, yaml",
    `payload = json.loads(${pythonJsonLiteral(payload)})`,
    'config_path = pathlib.Path("/sandbox/.hermes/config.yaml")',
    "data = yaml.safe_load(config_path.read_text(encoding='utf-8')) if config_path.exists() else {}",
    "servers = data.get('mcp_servers') if isinstance(data, dict) else None",
    "present = isinstance(servers, dict) and payload['server'] in servers",
    "server = servers.get(payload['server']) if present else None",
    "ok = server == payload['expected']",
    "print('registered' if ok else ('mismatch' if present else 'absent'))",
    "PY",
  ].join("\n");
}

export function buildDeepAgentsMcpRegisterCommand(
  entry: McpBridgeEntry,
  replaceExisting = false,
): string {
  const payload = {
    server: entry.server,
    expected: deepAgentsManagedServerConfig(entry),
    replaceExisting,
  };
  return [
    "python3 - <<'PY'",
    "import json, os, pathlib, sys",
    `payload = json.loads(${pythonJsonLiteral(payload)})`,
    `config_path = pathlib.Path(${JSON.stringify(DEEPAGENTS_MCP_CONFIG_PATH)})`,
    "data = {}",
    "if config_path.exists():",
    "    try:",
    "        data = json.loads(config_path.read_text(encoding='utf-8') or '{}')",
    "    except json.JSONDecodeError as exc:",
    `        print(f'Invalid ${DEEPAGENTS_MCP_CONFIG_PATH}: {exc}', file=sys.stderr)`,
    "        raise SystemExit(2)",
    "if not isinstance(data, dict):",
    `    print('Invalid ${DEEPAGENTS_MCP_CONFIG_PATH}: expected a JSON object', file=sys.stderr)`,
    "    raise SystemExit(2)",
    "servers = data.setdefault('mcpServers', {})",
    "if not isinstance(servers, dict):",
    `    print('Invalid ${DEEPAGENTS_MCP_CONFIG_PATH}: mcpServers must be an object', file=sys.stderr)`,
    "    raise SystemExit(2)",
    "if payload['server'] in servers and not payload['replaceExisting']:",
    `    print(f"MCP server '{payload['server']}' already exists in ${DEEPAGENTS_MCP_CONFIG_PATH} and is not managed by NemoClaw.", file=sys.stderr)`,
    "    raise SystemExit(2)",
    "servers[payload['server']] = payload['expected']",
    "tmp = config_path.with_name(config_path.name + '.nemoclaw-mcp.tmp')",
    "tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + '\\n', encoding='utf-8')",
    "os.chmod(tmp, 0o600)",
    "os.replace(tmp, config_path)",
    "os.chmod(config_path, 0o600)",
    "PY",
  ].join("\n");
}

function deepAgentsManagedServerConfig(entry: McpBridgeEntry): Record<string, unknown> {
  const headers = entryHeaders(entry);
  return {
    type: "http",
    url: entry.url,
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  };
}

export function buildDeepAgentsMcpRemoveCommand(entry: McpBridgeEntry, force = false): string {
  const payload = {
    server: entry.server,
    expected: deepAgentsManagedServerConfig(entry),
    force,
  };
  return [
    "python3 - <<'PY'",
    "import json, os, pathlib, sys",
    `payload = json.loads(${pythonJsonLiteral(payload)})`,
    `config_path = pathlib.Path(${JSON.stringify(DEEPAGENTS_MCP_CONFIG_PATH)})`,
    "if not config_path.exists():",
    "    raise SystemExit(0)",
    "try:",
    "    data = json.loads(config_path.read_text(encoding='utf-8') or '{}')",
    "except json.JSONDecodeError as exc:",
    `    print(f'Invalid ${DEEPAGENTS_MCP_CONFIG_PATH}: {exc}', file=sys.stderr)`,
    "    raise SystemExit(2)",
    "if not isinstance(data, dict):",
    `    print('Invalid ${DEEPAGENTS_MCP_CONFIG_PATH}: expected a JSON object', file=sys.stderr)`,
    "    raise SystemExit(2)",
    "servers = data.get('mcpServers')",
    "if servers is not None and not isinstance(servers, dict):",
    `    print('Invalid ${DEEPAGENTS_MCP_CONFIG_PATH}: mcpServers must be an object', file=sys.stderr)`,
    "    raise SystemExit(2)",
    "if isinstance(servers, dict):",
    "    present = payload['server'] in servers",
    "    current = servers.get(payload['server'])",
    "    if present and not payload['force']:",
    "        if current != payload['expected']:",
    `            print(f"Refusing to remove modified MCP server '{payload['server']}' from ${DEEPAGENTS_MCP_CONFIG_PATH}. Use --force to remove it.", file=sys.stderr)`,
    "            raise SystemExit(2)",
    "    servers.pop(payload['server'], None)",
    "    if not servers:",
    "        data.pop('mcpServers', None)",
    "        if not data:",
    "            config_path.unlink()",
    "            raise SystemExit(0)",
    "tmp = config_path.with_name(config_path.name + '.nemoclaw-mcp.tmp')",
    "tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + '\\n', encoding='utf-8')",
    "os.chmod(tmp, 0o600)",
    "os.replace(tmp, config_path)",
    "os.chmod(config_path, 0o600)",
    "PY",
  ].join("\n");
}

export function buildDeepAgentsMcpStatusCommand(entry: McpBridgeEntry): string {
  const payload = {
    server: entry.server,
    expected: deepAgentsManagedServerConfig(entry),
  };
  return [
    "python3 - <<'PY'",
    "import json, pathlib",
    `payload = json.loads(${pythonJsonLiteral(payload)})`,
    `config_path = pathlib.Path(${JSON.stringify(DEEPAGENTS_MCP_CONFIG_PATH)})`,
    "try:",
    "    data = json.loads(config_path.read_text(encoding='utf-8') or '{}')",
    "except Exception:",
    "    data = {}",
    "servers = data.get('mcpServers') if isinstance(data, dict) else None",
    "present = isinstance(servers, dict) and payload['server'] in servers",
    "server = servers.get(payload['server']) if present else None",
    "ok = server == payload['expected']",
    "print('registered' if ok else ('mismatch' if present else 'absent'))",
    "PY",
  ].join("\n");
}

export function redactBridgeSecretsForDisplay(
  text: string,
  entry?: Pick<McpBridgeEntry, "env">,
  envValues: Record<string, string> = {},
): string {
  let output = redact(text || "");
  for (const envName of entry?.env ?? []) {
    const value = envValues[envName] ?? process.env[envName];
    if (value) output = output.replaceAll(value, "***REDACTED***");
  }
  for (const value of Object.values(envValues)) {
    if (value) output = output.replaceAll(value, "***REDACTED***");
  }
  return output
    .replace(/\b(authorization\b["']?\s*[:=]\s*["']?Bearer\s+)([^"',\s}\]]+)/gi, "$1***REDACTED***")
    .replace(/Authorization=Bearer\s+\S+/g, "Authorization=Bearer ***REDACTED***");
}

export function buildOpenClawMcporterInspectCommand(
  entry: McpBridgeEntry,
  failOnMismatch: boolean,
): string {
  const payload = {
    server: entry.server,
    url: entry.url,
    headers: entryHeaders(entry),
    failOnMismatch,
  };
  return [
    "node - <<'NODE'",
    'const { spawnSync } = require("node:child_process");',
    `const expected = JSON.parse(${pythonJsonLiteral(payload)});`,
    'const result = spawnSync("mcporter", ["config", "get", expected.server, "--json"], { encoding: "utf8" });',
    "if (result.error) { console.error(result.error.message); process.exit(3); }",
    "if (result.status !== 0) {",
    '  const detail = `${result.stderr || ""}\n${result.stdout || ""}`;',
    "  if (/not\\s+found|does\\s+not\\s+exist|unknown\\s+server/i.test(detail)) { console.log('absent'); process.exit(0); }",
    "  console.error(detail.trim() || `mcporter config get exited ${result.status}`);",
    "  process.exit(3);",
    "}",
    "let actual = null;",
    "try { actual = JSON.parse(result.stdout); } catch {}",
    'const headers = actual && actual.headers && typeof actual.headers === "object" ? actual.headers : {};',
    mcporterHeaderMatcherSource(),
    'const registered = !!actual && actual.name === expected.server && actual.transport === "http" && actual.baseUrl === expected.url && mcporterHeadersMatchExpected(headers, expected.headers);',
    'console.log(registered ? "registered" : "mismatch");',
    "if (!registered && expected.failOnMismatch) process.exit(2);",
    "NODE",
  ].join("\n");
}

export function buildOpenClawMcporterRemoveCommand(entry: McpBridgeEntry, force = false): string {
  const payload = {
    server: entry.server,
    url: entry.url,
    headers: entryHeaders(entry),
    force,
  };
  return [
    "node - <<'NODE'",
    'const { spawnSync } = require("node:child_process");',
    `const expected = JSON.parse(${pythonJsonLiteral(payload)});`,
    'const get = spawnSync("mcporter", ["config", "get", expected.server, "--json"], { encoding: "utf8" });',
    "if (get.error) { console.error(get.error.message); process.exit(3); }",
    'const getDetail = `${get.stderr || ""}\n${get.stdout || ""}`;',
    "const absent = get.status !== 0 && /not\\s+found|does\\s+not\\s+exist|unknown\\s+server/i.test(getDetail);",
    "if (absent) process.exit(0);",
    "if (get.status !== 0) { console.error(getDetail.trim()); process.exit(3); }",
    "let actual = null; try { actual = JSON.parse(get.stdout); } catch {}",
    'const headers = actual && actual.headers && typeof actual.headers === "object" ? actual.headers : {};',
    mcporterHeaderMatcherSource(),
    'const registered = !!actual && actual.name === expected.server && actual.transport === "http" && actual.baseUrl === expected.url && mcporterHeadersMatchExpected(headers, expected.headers);',
    "if (!registered && !expected.force) { console.error(`Refusing to remove modified mcporter MCP server '${expected.server}'. Use --force to remove it.`); process.exit(2); }",
    'const remove = spawnSync("mcporter", ["config", "remove", expected.server], { encoding: "utf8" });',
    "if (remove.stdout) process.stdout.write(remove.stdout);",
    "if (remove.stderr) process.stderr.write(remove.stderr);",
    "if (remove.error) { console.error(remove.error.message); process.exit(3); }",
    'const removeDetail = `${remove.stderr || ""}\n${remove.stdout || ""}`;',
    "if (remove.status !== 0 && /not\\s+found|does\\s+not\\s+exist|unknown\\s+server/i.test(removeDetail)) process.exit(0);",
    "process.exit(remove.status === null ? 3 : remove.status);",
    "NODE",
  ].join("\n");
}

function registerOpenClawAdapter(
  sandboxName: string,
  entry: McpBridgeEntry,
  envValues: Record<string, string> = {},
  replaceExisting = false,
): void {
  ensureMcporter(sandboxName);
  const result = executeSandboxCommand(
    sandboxName,
    buildOpenClawMcporterRegisterCommand(entry, replaceExisting),
  );
  const output = redactBridgeSecretsForDisplay(
    [result?.stdout, result?.stderr].filter(Boolean).join("\n").trim(),
    entry,
    envValues,
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
  options: {
    force?: boolean;
    bestEffort?: boolean;
    envValues?: Record<string, string>;
  } = {},
): void {
  const result = executeSandboxCommand(sandboxName, command);
  const output = redactBridgeSecretsForDisplay(
    [result?.stdout, result?.stderr].filter(Boolean).join("\n").trim(),
    entry,
    options.envValues ?? {},
  );
  if (!result || result.status !== 0) {
    if (options.bestEffort) return;
    throw new McpBridgeError(output || failureMessage);
  }
}

type AdapterRegistrationInspection =
  | { state: "absent" | "registered" | "mismatch" }
  | { state: "error"; detail: string };

function inspectAgentAdapterRegistration(
  sandboxName: string,
  adapter: AgentMcpAdapter,
  entry: McpBridgeEntry,
): AdapterRegistrationInspection {
  const command =
    adapter === "mcporter"
      ? buildOpenClawMcporterInspectCommand(entry, false)
      : adapter === "hermes-config"
        ? buildHermesMcpStatusCommand(entry)
        : buildDeepAgentsMcpStatusCommand(entry);
  const result = executeSandboxCommand(sandboxName, command);
  if (!result) return { state: "error", detail: "sandbox unreachable" };
  const output = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
  if (result.status !== 0) {
    return {
      state: "error",
      detail:
        redactBridgeSecretsForDisplay(output, entry) ||
        `MCP adapter inspection exited ${result.status}.`,
    };
  }
  const state = output.split(/\r?\n/).at(-1)?.trim();
  if (state === "absent" || state === "registered" || state === "mismatch") {
    return { state };
  }
  return {
    state: "error",
    detail: redactBridgeSecretsForDisplay(
      output || "MCP adapter inspection returned no state.",
      entry,
    ),
  };
}

function parseLastJsonObject(output: string): Record<string, unknown> | null {
  for (const line of output.trim().split(/\r?\n/).reverse()) {
    try {
      const parsed = JSON.parse(line) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // OpenShell may frame diagnostics around the command's JSON line.
    }
  }
  return null;
}

function runHermesAdapterCommand(
  sandboxName: string,
  entry: McpBridgeEntry,
  command: string,
  failureMessage: string,
  options: {
    bestEffort?: boolean;
    envValues?: Record<string, string>;
    requireReload?: boolean;
  } = {},
): void {
  // Hermes can spend up to 180s draining before the in-sandbox service
  // manager relaunches it, followed by a 60s health window. The lifecycle
  // helper owns that reload and returns only after the replacement is ready.
  const result = executeSandboxExecCommand(sandboxName, command, 645_000);
  const output = redactBridgeSecretsForDisplay(
    [result?.stdout, result?.stderr].filter(Boolean).join("\n").trim(),
    entry,
    options.envValues ?? {},
  );
  if (!result || result.status !== 0) {
    if (options.bestEffort) return;
    throw new McpBridgeError(output || failureMessage);
  }
  const response = parseLastJsonObject(result.stdout);
  if (
    response?.ok !== true ||
    typeof response.changed !== "boolean" ||
    typeof response.reloaded !== "boolean"
  ) {
    if (options.bestEffort) return;
    throw new McpBridgeError(
      `Hermes MCP lifecycle control returned an invalid response for '${entry.server}'.`,
    );
  }
  if (options.requireReload && response.reloaded !== true) {
    if (options.bestEffort) return;
    throw new McpBridgeError(
      `Hermes gateway was not running, so MCP server '${entry.server}' was not loaded.`,
    );
  }
}

function registerAgentAdapter(
  sandboxName: string,
  adapter: AgentMcpAdapter,
  entry: McpBridgeEntry,
  envValues: Record<string, string> = {},
  options: { replaceExisting?: boolean } = {},
): void {
  switch (adapter) {
    case "mcporter":
      registerOpenClawAdapter(sandboxName, entry, envValues, options.replaceExisting === true);
      return;
    case "hermes-config":
      runHermesAdapterCommand(
        sandboxName,
        entry,
        buildHermesMcpRegisterCommand(entry, options.replaceExisting === true),
        `Hermes MCP config registration failed for '${entry.server}'.`,
        { envValues, requireReload: true },
      );
      return;
    case "deepagents-config":
      runAdapterCommand(
        sandboxName,
        entry,
        buildDeepAgentsMcpRegisterCommand(entry, options.replaceExisting === true),
        `Deep Agents Code MCP config registration failed for '${entry.server}'.`,
        { envValues },
      );
      return;
  }
}

function unregisterOpenClawAdapter(
  sandboxName: string,
  entry: McpBridgeEntry,
  options: {
    force?: boolean;
    bestEffort?: boolean;
    envValues?: Record<string, string>;
  } = {},
): void {
  const result = executeSandboxCommand(
    sandboxName,
    buildOpenClawMcporterRemoveCommand(entry, options.force === true),
  );
  const output = redactBridgeSecretsForDisplay(
    [result?.stdout, result?.stderr].filter(Boolean).join("\n").trim(),
    entry,
    options.envValues ?? {},
  );
  if (!result || result.status !== 0) {
    if (options.bestEffort) return;
    throw new McpBridgeError(output || `mcporter config remove failed for '${entry.server}'.`);
  }
}

function unregisterAgentAdapter(
  sandboxName: string,
  adapter: AgentMcpAdapter,
  entry: McpBridgeEntry,
  options: {
    force?: boolean;
    bestEffort?: boolean;
    envValues?: Record<string, string>;
  } = {},
): void {
  switch (adapter) {
    case "mcporter":
      unregisterOpenClawAdapter(sandboxName, entry, options);
      return;
    case "hermes-config":
      runHermesAdapterCommand(
        sandboxName,
        entry,
        buildHermesMcpRemoveCommand(entry, options.force === true),
        `Hermes MCP config removal failed for '${entry.server}'.`,
        options,
      );
      return;
    case "deepagents-config":
      runAdapterCommand(
        sandboxName,
        entry,
        buildDeepAgentsMcpRemoveCommand(entry, options.force === true),
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
  return redactCredentialValuesForDisplay(`${stderr}${stdout}`, envValues)
    .replace(/\r/g, "")
    .trim();
}

export function parseMcpProviderMetadata(output: string): Omit<McpProviderInspection, "exists"> {
  const clean = stripAnsi(output).replace(/\r/g, "");
  const typeMatch = clean.match(/^\s*Type:\s*(\S.*?)\s*$/m);
  const credentialMatch = clean.match(/^\s*Credential keys:\s*(.*?)\s*$/m);
  const rawKeys = credentialMatch?.[1]?.trim();
  return {
    type: typeMatch?.[1]?.trim() || null,
    credentialKeys:
      rawKeys === undefined
        ? null
        : rawKeys === "<none>" || rawKeys === ""
          ? []
          : rawKeys.split(",").map((key) => key.trim()),
  };
}

function inspectMcpProvider(providerName: string | undefined): McpProviderInspection {
  if (!providerName) {
    return { exists: false, type: null, credentialKeys: null };
  }
  const result = runOpenshellProviderCommand(["provider", "get", providerName], {
    ignoreError: true,
    stdio: ["ignore", "pipe", "pipe"],
  }) as OpenShellCommandResult;
  if (result.status !== 0) {
    const output = commandOutput(result);
    if (/not\s+found|NotFound|does\s+not\s+exist|unknown\s+provider/i.test(output)) {
      return { exists: false, type: null, credentialKeys: null };
    }
    return {
      exists: null,
      type: null,
      credentialKeys: null,
      error: output || `Could not inspect OpenShell provider '${providerName}'.`,
    };
  }
  return {
    exists: true,
    ...parseMcpProviderMetadata(commandOutput(result)),
  };
}

function providerMatchesCredential(
  inspection: McpProviderInspection,
  expectedCredential: string | undefined,
): boolean {
  return (
    inspection.exists === true &&
    inspection.type === "generic" &&
    expectedCredential !== undefined &&
    inspection.credentialKeys?.length === 1 &&
    inspection.credentialKeys[0] === expectedCredential
  );
}

function providerShapeDetail(
  inspection: McpProviderInspection,
  expectedCredential: string | undefined,
): string | undefined {
  if (inspection.exists === null) return inspection.error ?? "provider inspection failed";
  if (!inspection.exists) return undefined;
  if (providerMatchesCredential(inspection, expectedCredential)) return undefined;
  const type = inspection.type ?? "unparseable";
  const keys = inspection.credentialKeys?.join(", ") || "none or unparseable";
  return `Expected generic provider with only credential key '${expectedCredential ?? "<missing>"}', found type '${type}' with keys '${keys}'.`;
}

function assertMcpProviderRecoverable(entry: McpBridgeEntry): McpProviderInspection {
  assertAuthenticatedBridgeEntry(entry);
  const expectedCredential = entry.env[0];
  const inspection = inspectMcpProvider(entry.providerName);
  if (inspection.exists === null) {
    throw new McpBridgeError(
      inspection.error ?? `Could not inspect OpenShell provider '${entry.providerName}'.`,
    );
  }
  if (inspection.exists) {
    if (!providerMatchesCredential(inspection, expectedCredential)) {
      throw new McpBridgeError(
        `OpenShell provider '${entry.providerName}' no longer matches MCP server '${entry.server}'. ${providerShapeDetail(inspection, expectedCredential)}`,
      );
    }
    return inspection;
  }
  if (!process.env[expectedCredential]) {
    throw new McpBridgeError(
      `OpenShell provider '${entry.providerName}' is missing. Export host environment variable '${expectedCredential}' before retrying so the authenticated MCP provider can be recreated.`,
    );
  }
  return inspection;
}

async function preflightMcpEntryTargets(
  entries: readonly McpBridgeEntry[],
): Promise<Map<string, string[] | undefined>> {
  for (const entry of entries) assertAuthenticatedBridgeEntry(entry);
  const results = await Promise.all(
    entries.map(async (entry) => {
      const normalized = normalizeMcpServerUrl(entry.url);
      if (normalized !== entry.url) {
        throw new McpBridgeError(
          `MCP server '${entry.server}' has a non-canonical stored URL. Remove it with --force and add it again before lifecycle operations.`,
        );
      }
      const addresses = await validateMcpServerUrlResolvedTarget(new URL(normalized));
      return [entry.server, addresses] as const;
    }),
  );
  return new Map(results);
}

export function buildMcpBridgeProviderArgs(
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
      args.push("--credential", entry.name);
    }
  }
  return args;
}

function upsertMcpProvider(
  providerName: string,
  env: readonly ParsedEnvReference[],
  options: { allowExisting: boolean },
): "created" | "updated" | "reused" | "none" {
  const envNames = uniqueEnvNames(env);
  if (envNames.length === 0) return "none";
  const envValues = resolveCredentialEnv(env);
  const inspection = inspectMcpProvider(providerName);
  if (inspection.exists === null) {
    throw new McpBridgeError(
      inspection.error ?? `Could not inspect OpenShell provider '${providerName}'.`,
    );
  }
  if (inspection.exists && !options.allowExisting) {
    throw new McpBridgeError(
      `OpenShell provider '${providerName}' already exists but is not owned by a registered MCP bridge. Remove or rename that provider before retrying.`,
    );
  }
  if (inspection.exists && !providerMatchesCredential(inspection, envNames[0])) {
    throw new McpBridgeError(
      `OpenShell provider '${providerName}' no longer matches MCP server credential '${envNames[0]}'. ${providerShapeDetail(inspection, envNames[0])} Remove the stale provider and run mcp restart with the credential exported.`,
    );
  }
  if (Object.keys(envValues).length === 0) {
    if (inspection.exists) return "reused";
    throw new McpBridgeError(
      `Host environment variable '${envNames[0]}' is required to create MCP provider '${providerName}'.`,
      1,
    );
  }
  const action = inspection.exists ? "update" : "create";
  const result = runOpenshellProviderCommand(
    buildMcpBridgeProviderArgs(action, providerName, env, envValues),
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

const MCP_CREDENTIAL_SNAPSHOT_PATH_RE = /^\/tmp\/nemoclaw-mcp-provider-sync-[0-9a-f-]{36}$/;

function validateMcpCredentialSnapshotPath(snapshotPath: string): void {
  if (!MCP_CREDENTIAL_SNAPSHOT_PATH_RE.test(snapshotPath)) {
    throw new McpBridgeError("Invalid MCP credential revision snapshot path.");
  }
}

function mcpCredentialPlaceholderValidatorShell(envName: string): string[] {
  validateEnvName(envName);
  const canonical = `openshell:resolve:env:${envName}`;
  const revisionPrefix = "openshell:resolve:env:v";
  const revisionSuffix = `_${envName}`;
  return [
    `canonical=${shellQuote(canonical)}`,
    `prefix=${shellQuote(revisionPrefix)}`,
    `suffix=${shellQuote(revisionSuffix)}`,
    "valid_placeholder() {",
    '  candidate="$1"',
    '  [ "$candidate" = "$canonical" ] && return 0',
    '  versioned="${candidate#"$prefix"}"',
    '  [ "$versioned" != "$candidate" ] || return 1',
    '  revision="${versioned%"$suffix"}"',
    '  [ "$revision" != "$versioned" ] || return 1',
    '  [ "$versioned" = "$revision$suffix" ] || return 1',
    '  case "$revision" in ""|*[!0-9]*) return 1 ;; *) return 0 ;; esac',
    "}",
  ];
}

/**
 * Capture only a validated OpenShell placeholder in a descriptor opened with
 * noclobber. Raw environment values are never written or printed. The file is
 * used solely to compare the supervisor's provider revision across fresh execs.
 */
export function buildMcpCredentialRevisionSnapshotCommand(
  envName: string,
  snapshotPath: string,
): string {
  validateMcpCredentialSnapshotPath(snapshotPath);
  return [
    ...mcpCredentialPlaceholderValidatorShell(envName),
    `snapshot=${shellQuote(snapshotPath)}`,
    "umask 077",
    "set -C",
    'exec 3>"$snapshot" || exit 1',
    "set +C",
    `value="\${${envName}-}"`,
    '[ -z "$value" ] && exit 0',
    'valid_placeholder "$value" || exit 1',
    'printf "%s" "$value" >&3',
  ].join("\n");
}

export function buildMcpCredentialReadinessCommand(
  envName: string,
  previousRevisionSnapshotPath?: string,
): string {
  if (previousRevisionSnapshotPath) {
    validateMcpCredentialSnapshotPath(previousRevisionSnapshotPath);
  }
  return [
    ...mcpCredentialPlaceholderValidatorShell(envName),
    `value="\${${envName}-}"`,
    'valid_placeholder "$value" || exit 1',
    ...(previousRevisionSnapshotPath
      ? [
          `snapshot=${shellQuote(previousRevisionSnapshotPath)}`,
          '[ -f "$snapshot" ] && [ ! -L "$snapshot" ] || exit 1',
          'prior="$(cat -- "$snapshot")" || exit 1',
          '[ -z "$prior" ] || valid_placeholder "$prior" || exit 1',
          '[ -z "$prior" ] || [ "$value" != "$prior" ] || exit 1',
        ]
      : []),
  ].join("\n");
}

function snapshotMcpCredentialRevision(sandboxName: string, entry: McpBridgeEntry): string {
  assertAuthenticatedBridgeEntry(entry);
  const snapshotPath = `/tmp/nemoclaw-mcp-provider-sync-${crypto.randomUUID()}`;
  const result = executeSandboxExecCommand(
    sandboxName,
    buildMcpCredentialRevisionSnapshotCommand(entry.env[0], snapshotPath),
  );
  if (!result || result.status !== 0) {
    throw new McpBridgeError(
      `Could not capture the current OpenShell credential revision for sandbox '${sandboxName}'.`,
    );
  }
  return snapshotPath;
}

function removeMcpCredentialRevisionSnapshot(
  sandboxName: string,
  snapshotPath: string | undefined,
): void {
  if (!snapshotPath) return;
  validateMcpCredentialSnapshotPath(snapshotPath);
  executeSandboxExecCommand(sandboxName, `rm -f -- ${shellQuote(snapshotPath)}`);
}

function waitForAttachedMcpCredential(
  sandboxName: string,
  entry: McpBridgeEntry,
  options: { previousRevisionSnapshotPath?: string } = {},
): void {
  assertAuthenticatedBridgeEntry(entry);
  const envName = entry.env[0];
  const timeoutSeconds = Number.parseInt(
    process.env.NEMOCLAW_MCP_PROVIDER_SYNC_TIMEOUT_SECONDS ?? "30",
    10,
  );
  const ready = waitUntil(
    () => {
      // Each exec is a fresh OpenShell process. A status-zero comparison proves
      // the supervisor has consumed the provider_env_revision without ever
      // printing either a placeholder or a credential value.
      const probe = executeSandboxExecCommand(
        sandboxName,
        buildMcpCredentialReadinessCommand(envName, options.previousRevisionSnapshotPath),
      );
      return probe?.status === 0;
    },
    Number.isFinite(timeoutSeconds) && timeoutSeconds > 0 ? timeoutSeconds : 30,
    1_000,
  );
  if (!ready) {
    throw new McpBridgeError(
      `OpenShell did not synchronize the expected credential revision for placeholder '${envName}' into sandbox '${sandboxName}' after provider attachment or update.`,
    );
  }
}

export function providerDetachChangedState(status: number | null, output: string): boolean {
  return (
    status === 0 &&
    !/\bwas\s+not\s+attached\b|\balready\s+detached\b|\bNotAttached\b/i.test(stripAnsi(output))
  );
}

function detachProvider(
  sandboxName: string,
  providerName: string | undefined,
  options: { bestEffort?: boolean } = {},
): boolean {
  if (!providerName) return false;
  const result = runOpenshellProviderCommand(
    ["sandbox", "provider", "detach", sandboxName, providerName],
    {
      ignoreError: true,
      stdio: ["ignore", "pipe", "pipe"],
      suppressOutput: true,
    } as Record<string, unknown>,
  ) as OpenShellCommandResult;
  const output = commandOutput(result);
  if (result.status !== 0) {
    if (/not\s+attached|NotAttached|not\s+found|NotFound/i.test(output)) return false;
    if (options.bestEffort) return false;
    throw new McpBridgeError(output || `Failed to detach MCP provider '${providerName}'.`);
  }
  return providerDetachChangedState(result.status, output);
}

function deleteProvider(
  providerName: string | undefined,
  options: { allowMissing?: boolean; bestEffort?: boolean } = {},
): void {
  if (!providerName) return;
  const result = runOpenshellProviderCommand(["provider", "delete", providerName], {
    ignoreError: true,
    stdio: ["ignore", "pipe", "pipe"],
    suppressOutput: true,
  } as Record<string, unknown>) as OpenShellCommandResult;
  if (result.status !== 0) {
    const output = commandOutput(result);
    if (options.allowMissing && /not\s+found|NotFound/i.test(output)) return;
    if (options.bestEffort) return;
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
  return output.split(/\s+/).includes(providerName);
}

function applyGeneratedPolicy(
  sandboxName: string,
  entry: McpBridgeEntry,
  resolvedAddresses?: readonly string[],
): void {
  const adapter = isAgentMcpAdapter(entry.adapter) ? entry.adapter : "mcporter";
  const content = buildMcpBridgePolicyYaml(entry.server, entry.url, adapter, resolvedAddresses);
  const policyKey = buildMcpBridgePolicyKey(entry.server);
  const previousPolicy = registry
    .getCustomPolicies(sandboxName)
    .find(
      (policy) =>
        policy.name === entry.policyName && policy.sourcePath === MCP_BRIDGE_POLICY_SOURCE,
    );
  let ownsExistingPolicyKey = false;
  if (previousPolicy) {
    const previousState = policies.getPresetContentGatewayState(
      sandboxName,
      previousPolicy.content,
    );
    if (previousState !== "absent" && previousState !== "match") {
      throw new McpBridgeError(
        `Generated MCP policy '${entry.policyName}' has drifted or could not be inspected against its recorded content. Refusing to replace the live key.`,
      );
    }
    // A prior ownership record may have been reserved immediately before a
    // process died, so an absent key is safe to create. A present key is safe
    // to replace only after its full content matches that ownership record.
    ownsExistingPolicyKey = previousState === "match";
  } else if (!previousPolicy) {
    const unownedState = policies.getPresetContentGatewayState(sandboxName, content);
    if (unownedState !== "absent") {
      throw new McpBridgeError(
        `Generated MCP policy key '${policyKey}' is already present or could not be inspected without a NemoClaw ownership record.`,
      );
    }
  }

  // Reserve/update ownership before the live gateway mutation. This avoids a
  // successful policy set followed by a registry-write failure leaving an
  // unowned live key that neither rollback nor retry can safely touch.
  const ownershipRecorded = registry.addCustomPolicy(sandboxName, {
    name: entry.policyName,
    content,
    sourcePath: MCP_BRIDGE_POLICY_SOURCE,
  });
  if (!ownershipRecorded) {
    throw new McpBridgeError(
      `Could not reserve ownership for generated MCP policy '${entry.policyName}'.`,
    );
  }
  const ok = policies.applyPresetContent(sandboxName, entry.policyName, content, {
    custom: { sourcePath: MCP_BRIDGE_POLICY_SOURCE },
    allowedExistingNetworkPolicyKeys: ownsExistingPolicyKey ? [policyKey] : [],
    nonFatal: true,
    skipRegistryUpdate: true,
  });
  if (ok === false) {
    const after = policies.getPresetContentGatewayState(sandboxName, content);
    if (after !== "match") {
      if (previousPolicy) {
        registry.addCustomPolicy(sandboxName, previousPolicy);
      } else {
        registry.removeCustomPolicyByName(sandboxName, entry.policyName);
      }
    }
    throw new McpBridgeError(`Failed to apply generated MCP policy '${entry.policyName}'.`);
  }
}

function generatedPolicyContent(entry: McpBridgeEntry): string {
  const adapter = isAgentMcpAdapter(entry.adapter) ? entry.adapter : "mcporter";
  return buildMcpBridgePolicyYaml(entry.server, entry.url, adapter);
}

function assertGeneratedPolicyMutationSafe(sandboxName: string, entry: McpBridgeEntry): void {
  const registeredPolicy = registry
    .getCustomPolicies(sandboxName)
    .find((policy) => policy.name === entry.policyName);
  const content = registeredPolicy?.content ?? generatedPolicyContent(entry);
  const state = policies.getPresetContentGatewayState(sandboxName, content);
  const owned = registeredPolicy?.sourcePath === MCP_BRIDGE_POLICY_SOURCE;
  if (state === "absent") return;
  if (!owned || state !== "match") {
    throw new McpBridgeError(
      `Generated MCP policy '${entry.policyName}' is unowned, unreachable, or drifted. Refusing to mutate the adapter, provider, or same-key live policy until ownership is resolved.`,
    );
  }
}

function removeGeneratedPolicy(
  sandboxName: string,
  entry: McpBridgeEntry,
  options: { bestEffort?: boolean } = {},
): void {
  const policyName = entry.policyName;
  const registeredPolicy = registry
    .getCustomPolicies(sandboxName)
    .find((policy) => policy.name === policyName);
  const content = registeredPolicy?.content ?? generatedPolicyContent(entry);
  const gatewayState = policies.getPresetContentGatewayState(sandboxName, content);
  if (gatewayState === "absent") {
    if (registeredPolicy?.sourcePath === MCP_BRIDGE_POLICY_SOURCE) {
      registry.removeCustomPolicyByName(sandboxName, policyName);
    }
    return;
  }
  const ownsRegistration = registeredPolicy?.sourcePath === MCP_BRIDGE_POLICY_SOURCE;
  if (!ownsRegistration || gatewayState !== "match") {
    if (options.bestEffort) return;
    throw new McpBridgeError(
      `Generated MCP policy '${policyName}' is unowned, unreachable, or no longer matches its registered content. Refusing to delete same-key policy state.`,
    );
  }
  const ok = policies.removePreset(sandboxName, policyName, { nonFatal: true });
  if (!ok) {
    if (options.bestEffort) return;
    throw new McpBridgeError(`Failed to remove generated MCP policy '${policyName}'.`);
  }
  registry.removeCustomPolicyByName(sandboxName, policyName);
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
  const gatewayName = getSandboxTargetGatewayName(sandboxName);
  const recovery = await recoverNamedGatewayRuntime({
    gatewayName,
  });
  if (!recovery.recovered || recovery.after.state !== "healthy_named") {
    throw new McpBridgeError(
      `Could not select healthy OpenShell gateway '${gatewayName}' for sandbox '${sandboxName}' (before: ${recovery.before.state}, after: ${recovery.after.state}). Refusing to mutate MCP resources on another gateway.`,
    );
  }
  // Pin every subsequent OpenShell subprocess in this lifecycle operation to
  // the sandbox's recorded gateway. The globally selected gateway is mutable
  // shared metadata and another NemoClaw process may select a sibling between
  // this health check and the provider/policy mutation.
  process.env.OPENSHELL_GATEWAY = gatewayName;
}

function sameMcpAddIntent(existing: McpBridgeEntry, requested: McpBridgeEntry): boolean {
  return (
    existing.server === requested.server &&
    existing.agent === requested.agent &&
    existing.adapter === requested.adapter &&
    existing.url === requested.url &&
    existing.providerName === requested.providerName &&
    existing.policyName === requested.policyName &&
    existing.env.length === requested.env.length &&
    existing.env.every((name, index) => name === requested.env[index])
  );
}

function assertPreparedMcpAddResourcesAbsent(
  sandboxName: string,
  adapter: AgentMcpAdapter,
  entry: McpBridgeEntry,
  resolvedAddresses?: readonly string[],
): void {
  const adapterInspection = inspectAgentAdapterRegistration(sandboxName, adapter, entry);
  if (adapterInspection.state !== "absent") {
    const detail =
      adapterInspection.state === "error"
        ? adapterInspection.detail
        : `server name is already ${adapterInspection.state}`;
    throw new McpBridgeError(
      `MCP add preflight for '${entry.server}' found an existing ${adapter} adapter entry: ${detail}. The durable add manifest was preserved without claiming it.`,
    );
  }

  const providerInspection = inspectMcpProvider(entry.providerName);
  if (providerInspection.exists !== false) {
    const detail =
      providerInspection.exists === null
        ? (providerInspection.error ?? "provider inspection failed")
        : (providerShapeDetail(providerInspection, entry.env[0]) ?? "provider already exists");
    throw new McpBridgeError(
      `MCP add preflight for '${entry.server}' could not prove provider '${entry.providerName}' absent: ${detail}. The durable add manifest was preserved without claiming it.`,
    );
  }

  const existingPolicy = registry
    .getCustomPolicies(sandboxName)
    .find((policy) => policy.name === entry.policyName);
  if (existingPolicy) {
    throw new McpBridgeError(
      `MCP add preflight for '${entry.server}' found an existing policy ownership record '${entry.policyName}'. The durable add manifest was preserved without claiming it.`,
    );
  }
  const policyContent = buildMcpBridgePolicyYaml(
    entry.server,
    entry.url,
    adapter,
    resolvedAddresses,
  );
  const policyState = policies.getPresetContentGatewayState(sandboxName, policyContent);
  if (policyState !== "absent") {
    throw new McpBridgeError(
      `MCP add preflight for '${entry.server}' could not prove generated policy key '${buildMcpBridgePolicyKey(entry.server)}' absent (state: ${policyState ?? "unreachable"}). The durable add manifest was preserved without claiming it.`,
    );
  }
}

export async function addMcpBridge(
  sandboxName: string,
  options: McpBridgeAddOptions,
): Promise<void> {
  return withMcpLifecycleLock(sandboxName, () => addMcpBridgeUnlocked(sandboxName, options));
}

async function addMcpBridgeUnlocked(
  sandboxName: string,
  options: McpBridgeAddOptions,
): Promise<void> {
  validateSandboxName(sandboxName);
  validateMcpServerName(options.server);
  assertAuthenticatedCredentialReference(options.env);
  const normalizedUrl = normalizeMcpServerUrl(options.url);
  const resolvedAddresses = await validateMcpServerUrlResolvedTarget(new URL(normalizedUrl));
  const sandbox = getSandboxOrThrow(sandboxName);
  assertMcpDestroyNotPending(sandbox);
  const agent = getSandboxAgent(sandbox);
  const adapter = getBridgeAdapter(agent);
  const existingEntry = bridgeState(sandbox)[options.server];
  if (existingEntry && !existingEntry.addState) {
    throw new McpBridgeError(
      `MCP server '${options.server}' already exists on sandbox '${sandboxName}'.`,
    );
  }

  const envNames = uniqueEnvNames(options.env);
  const envCollision = Object.values(bridgeState(sandbox)).find(
    (entry) =>
      entry.server !== options.server && entry.env.some((envName) => envNames.includes(envName)),
  );
  if (envCollision) {
    const duplicate = envCollision.env.find((envName) => envNames.includes(envName));
    throw new McpBridgeError(
      `Credential key '${duplicate}' is already attached through MCP server '${envCollision.server}'. OpenShell static credential keys must be unique within a sandbox; use a distinct host environment name.`,
      2,
    );
  }
  const providerName =
    envNames.length > 0 ? buildMcpBridgeProviderName(sandboxName, options.server) : undefined;
  const policyName = buildMcpBridgePolicyName(options.server);
  assertNoDerivedResourceCollision(sandbox, options.server, providerName, policyName);
  const requestedEntry: McpBridgeEntry = {
    server: options.server,
    agent: agent.name,
    adapter,
    url: normalizedUrl,
    env: envNames,
    ...(providerName ? { providerName } : {}),
    policyName,
    addedAt: existingEntry?.addedAt ?? nowIso(),
    addState: existingEntry?.addState ?? "prepared",
  };

  if (existingEntry && !sameMcpAddIntent(existingEntry, requestedEntry)) {
    throw new McpBridgeError(
      `MCP server '${options.server}' has an incomplete add transaction with different URL, credential, agent, or derived resources. Re-run the original add command or remove it with --force before changing the definition.`,
      2,
    );
  }

  let entry: McpBridgeEntry = existingEntry
    ? { ...existingEntry, env: [...existingEntry.env] }
    : requestedEntry;
  const resumingPreflightedAdd = existingEntry?.addState === "preflighted";
  // This is the durable ownership manifest for every resource created below.
  // It intentionally precedes gateway selection and all OpenShell mutations,
  // so process death can never leave an unowned provider/policy/adapter entry.
  if (!existingEntry) writeBridgeEntry(sandboxName, entry);

  let providerCreated = false;
  let providerAttachedState = false;
  let policyApplied = false;
  let adapterMutationAttempted = false;
  let credentialRevisionSnapshotPath: string | undefined;
  const adapterEnvValues = resolveCredentialEnv(options.env);
  try {
    await ensureSandboxGatewaySelected(sandboxName);

    if (entry.addState === "prepared") {
      assertPreparedMcpAddResourcesAbsent(sandboxName, adapter, entry, resolvedAddresses);
      entry = { ...entry, addState: "preflighted" };
      // This second durable boundary proves the derived resource names and the
      // adapter slot were absent before any side effect. After a crash, retries
      // may therefore reuse only missing or exact resources, never drift.
      writeBridgeEntry(sandboxName, entry);
    }

    const adapterInspection = inspectAgentAdapterRegistration(sandboxName, adapter, entry);
    if (
      adapterInspection.state !== "absent" &&
      !(resumingPreflightedAdd && adapterInspection.state === "registered")
    ) {
      const detail =
        adapterInspection.state === "error"
          ? adapterInspection.detail
          : `server name is already ${adapterInspection.state}`;
      throw new McpBridgeError(
        `MCP server '${entry.server}' cannot be registered in the ${adapter} adapter: ${detail}.`,
      );
    }
    credentialRevisionSnapshotPath = snapshotMcpCredentialRevision(sandboxName, entry);
    const providerAction = upsertMcpProvider(providerName ?? "", options.env, {
      allowExisting: true,
    });
    providerCreated = providerAction === "created";
    applyGeneratedPolicy(sandboxName, entry, resolvedAddresses);
    policyApplied = true;
    attachProvider(sandboxName, providerName);
    providerAttachedState = !!providerName;
    waitForAttachedMcpCredential(sandboxName, entry, {
      ...(providerAction === "updated"
        ? {
            previousRevisionSnapshotPath: credentialRevisionSnapshotPath,
          }
        : {}),
    });
    // The adapter was proven absent above, so cleanup is safe even when a
    // command commits config and then fails during its runtime reload.
    adapterMutationAttempted = true;
    registerAgentAdapter(sandboxName, adapter, entry, adapterEnvValues, {
      // An exact adapter entry is evidence of a post-commit process death.
      // Replacing it is idempotent and, for Hermes, re-verifies runtime reload.
      replaceExisting: resumingPreflightedAdd && adapterInspection.state === "registered",
    });
    const { addState: _completedAddState, ...committedEntry } = entry;
    writeBridgeEntry(sandboxName, committedEntry);
  } catch (error) {
    if (adapterMutationAttempted) {
      unregisterAgentAdapter(sandboxName, adapter, entry, {
        force: false,
        bestEffort: true,
        envValues: adapterEnvValues,
      });
    }
    if (providerAttachedState) detachProvider(sandboxName, providerName, { bestEffort: true });
    if (policyApplied)
      removeGeneratedPolicy(sandboxName, entry, {
        bestEffort: true,
      });
    if (providerCreated) deleteProvider(providerName, { allowMissing: true, bestEffort: true });
    // Exception rollback is best-effort and process death skips it entirely.
    // Keep the durable add manifest until a retry converges or `mcp remove`
    // proves and cleans each exact resource.
    throw error;
  } finally {
    removeMcpCredentialRevisionSnapshot(sandboxName, credentialRevisionSnapshotPath);
  }
}

export async function restartMcpBridge(sandboxName: string, server?: string): Promise<void> {
  return withMcpLifecycleLock(sandboxName, () => restartMcpBridgeUnlocked(sandboxName, server));
}

async function restartMcpBridgeUnlocked(sandboxName: string, server?: string): Promise<void> {
  validateSandboxName(sandboxName);
  const sandbox = getSandboxOrThrow(sandboxName);
  assertMcpDestroyNotPending(sandbox);
  const agent = getSandboxAgent(sandbox);
  const adapter = getBridgeAdapter(agent);
  const bridges = bridgeState(sandbox);
  const targets = server ? [[server, bridges[server]] as const] : Object.entries(bridges);
  if (targets.length === 0) {
    console.log(`  No MCP servers for sandbox '${sandboxName}'.`);
    return;
  }
  for (const [name, entry] of targets) {
    if (!entry) {
      throw new McpBridgeError(`MCP server '${name}' not found on sandbox '${sandboxName}'.`);
    }
    if (entry.addState) {
      throw new McpBridgeError(
        `MCP server '${name}' has an incomplete add transaction (${entry.addState}). Re-run mcp add with the same URL and --env ${entry.env[0] ?? "KEY"}, or remove it with --force.`,
      );
    }
    assertAuthenticatedBridgeEntry(entry);
  }
  const targetEntries = targets
    .map(([, entry]) => entry)
    .filter((entry): entry is McpBridgeEntry => !!entry);
  const resolvedByServer = await preflightMcpEntryTargets(targetEntries);
  await ensureSandboxGatewaySelected(sandboxName);
  // Prove every policy key is absent or still matches its recorded ownership
  // before inspecting or updating any provider. `applyGeneratedPolicy` repeats
  // this check immediately before mutation to close the preflight-to-apply race.
  for (const entry of targetEntries) assertGeneratedPolicyMutationSafe(sandboxName, entry);
  for (const entry of targetEntries) assertMcpProviderRecoverable(entry);
  for (const [name, entry] of targets) {
    // Validated as a complete authenticated entry before gateway side effects.
    if (!entry) continue;
    const envRefs = entry.env.map((envName) => ({ name: envName }));
    const adapterEnvValues = resolveCredentialEnv(envRefs);
    const resolvedAddresses = resolvedByServer.get(entry.server);
    const credentialRevisionSnapshotPath = snapshotMcpCredentialRevision(sandboxName, entry);
    try {
      const providerAction = upsertMcpProvider(entry.providerName ?? "", envRefs, {
        allowExisting: true,
      });
      applyGeneratedPolicy(sandboxName, entry, resolvedAddresses);
      attachProvider(sandboxName, entry.providerName);
      waitForAttachedMcpCredential(sandboxName, entry, {
        ...(providerAction === "updated"
          ? { previousRevisionSnapshotPath: credentialRevisionSnapshotPath }
          : {}),
      });
      registerAgentAdapter(
        sandboxName,
        (entry.adapter as AgentMcpAdapter | undefined) ?? adapter,
        entry,
        adapterEnvValues,
        { replaceExisting: true },
      );
    } finally {
      removeMcpCredentialRevisionSnapshot(sandboxName, credentialRevisionSnapshotPath);
    }
    writeBridgeEntry(sandboxName, {
      ...entry,
      adapter: (entry.adapter as AgentMcpAdapter | undefined) ?? adapter,
      updatedAt: nowIso(),
    });
    console.log(`  Refreshed MCP server '${name}'.`);
  }
}

export interface McpDestroyPreparation {
  entries: McpBridgeEntry[];
  detachedProviderEntries: McpBridgeEntry[];
  scrubbedAdapterEntries: McpBridgeEntry[];
  /** True when phase one was completed by an earlier destroy process. */
  destroyAlreadyPrepared: boolean;
  /** True when a previous destroy already confirmed the sandbox was absent. */
  destroyAlreadyPending: boolean;
}

function cloneMcpBridgeEntry(entry: McpBridgeEntry): McpBridgeEntry {
  return { ...entry, env: [...entry.env] };
}

function mcpBridgeEntriesEqual(left: McpBridgeEntry, right: McpBridgeEntry): boolean {
  return (
    left.server === right.server &&
    left.agent === right.agent &&
    left.adapter === right.adapter &&
    left.url === right.url &&
    left.providerName === right.providerName &&
    left.policyName === right.policyName &&
    left.addedAt === right.addedAt &&
    left.updatedAt === right.updatedAt &&
    left.addState === right.addState &&
    left.env.length === right.env.length &&
    left.env.every((name, index) => name === right.env[index])
  );
}

function discardPreparedMcpAddsBeforeDestroy(
  sandboxName: string,
  sandbox: SandboxEntry,
): SandboxEntry {
  const bridges = bridgeState(sandbox);
  const remaining = Object.fromEntries(
    Object.entries(bridges).filter(([, entry]) => entry.addState !== "prepared"),
  );
  if (Object.keys(remaining).length === Object.keys(bridges).length) {
    return sandbox;
  }
  // A prepared add precedes all external side effects, so destroy must drop
  // only its local manifest and must not inspect/delete same-name global state.
  setBridgeState(sandboxName, remaining);
  return getSandboxOrThrow(sandboxName);
}

function assertMcpDestroySnapshotCurrent(
  sandboxName: string,
  entries: readonly McpBridgeEntry[],
): SandboxEntry {
  const sandbox = getSandboxOrThrow(sandboxName);
  const current = bridgeState(sandbox);
  const expectedServers = new Set(entries.map((entry) => entry.server));
  if (
    Object.keys(current).length !== expectedServers.size ||
    entries.some(
      (entry) => !current[entry.server] || !mcpBridgeEntriesEqual(current[entry.server], entry),
    )
  ) {
    throw new McpBridgeError(
      `MCP bridge definitions changed while sandbox '${sandboxName}' was being destroyed. Cleanup state was preserved; re-run destroy to reconcile the current definitions.`,
    );
  }
  return sandbox;
}

function inspectExactMcpDestroyProvider(
  entry: McpBridgeEntry,
  options: { allowMissing: boolean; force?: boolean },
): McpProviderInspection {
  assertAuthenticatedBridgeEntry(entry);
  const inspection = inspectMcpProvider(entry.providerName);
  if (inspection.exists === null) {
    throw new McpBridgeError(
      inspection.error ?? `Could not inspect OpenShell provider '${entry.providerName}'.`,
    );
  }
  if (!inspection.exists) {
    if (options.allowMissing) return inspection;
    throw new McpBridgeError(
      `OpenShell provider '${entry.providerName}' is missing. Refusing to destroy sandbox state because a failed sandbox delete could not restore authenticated MCP without the preserved provider credential.`,
    );
  }
  if (!providerMatchesCredential(inspection, entry.env[0])) {
    const forceDetail = options.force
      ? " --force does not delete a non-matching global provider because it may be owned by another workflow."
      : "";
    throw new McpBridgeError(
      `OpenShell provider '${entry.providerName}' no longer exactly matches MCP server '${entry.server}'. ${providerShapeDetail(inspection, entry.env[0])}${forceDetail}`,
    );
  }
  return inspection;
}

/**
 * Build the cleanup manifest when a gateway-pinned `sandbox list` has already
 * proved the sandbox is absent. No sandbox exec/adapter mutation is possible
 * in this branch; exact provider ownership is still required before delete
 * confirmation and final cleanup.
 */
export async function prepareMcpBridgesForAbsentSandboxDestroy(
  sandboxName: string,
  options: { force?: boolean } = {},
): Promise<McpDestroyPreparation> {
  validateSandboxName(sandboxName);
  const sandbox = discardPreparedMcpAddsBeforeDestroy(sandboxName, getSandboxOrThrow(sandboxName));
  const entries = Object.values(bridgeState(sandbox)).map(cloneMcpBridgeEntry);
  const destroyAlreadyPrepared = !!sandbox.mcp?.destroyPreparedAt;
  const destroyAlreadyPending = !!sandbox.mcp?.destroyPendingAt;
  for (const entry of entries) {
    // Missing providers are already converged once the sandbox is confirmed
    // absent. Existing providers must still match exactly, including in force
    // mode, so this path cannot delete another workflow's credential.
    inspectExactMcpDestroyProvider(entry, {
      allowMissing: true,
      force: options.force,
    });
  }
  return {
    entries,
    detachedProviderEntries: [],
    scrubbedAdapterEntries: [],
    destroyAlreadyPrepared,
    destroyAlreadyPending,
  };
}

/**
 * Phase one of sandbox destroy. Remove the adapter entry from the retained
 * sandbox volume and detach exact MCP providers while preserving the global
 * provider objects (and therefore their host-only credentials), generated
 * policy, and registry cleanup manifest. Any failure restores adapter and
 * attachment state before returning.
 */
export async function prepareMcpBridgesForDestroy(
  sandboxName: string,
): Promise<McpDestroyPreparation> {
  validateSandboxName(sandboxName);
  const sandbox = discardPreparedMcpAddsBeforeDestroy(sandboxName, getSandboxOrThrow(sandboxName));
  const entries = Object.values(bridgeState(sandbox)).map(cloneMcpBridgeEntry);
  const destroyAlreadyPrepared = !!sandbox.mcp?.destroyPreparedAt;
  const destroyAlreadyPending = !!sandbox.mcp?.destroyPendingAt;
  const incompleteAdd = entries.find((entry) => entry.addState === "preflighted");
  if (incompleteAdd) {
    throw new McpBridgeError(
      `MCP server '${incompleteAdd.server}' has an incomplete add transaction. Re-run the original mcp add command or remove it with --force before destroying the live sandbox.`,
    );
  }
  if (entries.length === 0) {
    return {
      entries: [],
      detachedProviderEntries: [],
      scrubbedAdapterEntries: [],
      destroyAlreadyPrepared,
      destroyAlreadyPending,
    };
  }

  // A pending marker is written only after OpenShell confirmed deletion. On
  // retry, a provider may therefore already be absent due to partial cleanup;
  // the retained entries are the durable, idempotent cleanup manifest.
  for (const entry of entries) {
    inspectExactMcpDestroyProvider(entry, {
      allowMissing: destroyAlreadyPending,
    });
  }
  if (destroyAlreadyPending) {
    return {
      entries,
      detachedProviderEntries: [],
      scrubbedAdapterEntries: [],
      destroyAlreadyPrepared,
      destroyAlreadyPending: true,
    };
  }
  if (destroyAlreadyPrepared) {
    // Phase one completed before a prior process stopped. The sandbox may be
    // live with its adapter scrubbed/provider detached, or it may already be
    // gone. In either case, repeating delete is the next idempotent step.
    return {
      entries,
      detachedProviderEntries: entries.map(cloneMcpBridgeEntry),
      scrubbedAdapterEntries: entries.map(cloneMcpBridgeEntry),
      destroyAlreadyPrepared: true,
      destroyAlreadyPending: false,
    };
  }

  await ensureSandboxGatewaySelected(sandboxName);
  const detached: McpBridgeEntry[] = [];
  const scrubbedAdapters: McpBridgeEntry[] = [];
  try {
    for (const entry of entries) {
      const adapter = isAgentMcpAdapter(entry.adapter)
        ? entry.adapter
        : getBridgeAdapter(getSandboxAgent(sandbox));
      unregisterAgentAdapter(sandboxName, adapter, entry, {
        envValues: {},
      });
      scrubbedAdapters.push(entry);
    }
    for (const entry of entries) {
      if (detachProvider(sandboxName, entry.providerName)) detached.push(entry);
    }
    const marked = registry.updateSandbox(sandboxName, {
      mcp: {
        bridges: Object.fromEntries(
          entries.map((entry) => [entry.server, cloneMcpBridgeEntry(entry)]),
        ),
        destroyPreparedAt: nowIso(),
      },
    });
    if (!marked) {
      throw new McpBridgeError(
        `Could not persist prepared MCP destroy state for sandbox '${sandboxName}'.`,
      );
    }
  } catch (error) {
    const rollbackFailures: string[] = [];
    for (const entry of [...detached].reverse()) {
      try {
        attachProvider(sandboxName, entry.providerName);
        // Reattach preserves the provider value, so presence is sufficient;
        // still wait before reloading an adapter that may connect immediately.
        waitForAttachedMcpCredential(sandboxName, entry);
      } catch (rollbackError) {
        rollbackFailures.push(
          rollbackError instanceof Error ? rollbackError.message : String(rollbackError),
        );
      }
    }
    for (const entry of scrubbedAdapters) {
      try {
        const adapter = isAgentMcpAdapter(entry.adapter)
          ? entry.adapter
          : getBridgeAdapter(getSandboxAgent(sandbox));
        registerAgentAdapter(
          sandboxName,
          adapter,
          entry,
          {},
          {
            replaceExisting: true,
          },
        );
      } catch (rollbackError) {
        rollbackFailures.push(
          rollbackError instanceof Error ? rollbackError.message : String(rollbackError),
        );
      }
    }
    const current = registry.getSandbox(sandboxName);
    if (current?.mcp?.destroyPreparedAt) {
      try {
        registry.updateSandbox(sandboxName, {
          mcp: {
            bridges: Object.fromEntries(
              entries.map((entry) => [entry.server, cloneMcpBridgeEntry(entry)]),
            ),
          },
        });
      } catch (rollbackError) {
        rollbackFailures.push(
          rollbackError instanceof Error ? rollbackError.message : String(rollbackError),
        );
      }
    }
    const detail = error instanceof Error ? error.message : String(error);
    throw new McpBridgeError(
      rollbackFailures.length > 0
        ? `${detail}\nMCP destroy rollback could not reattach: ${rollbackFailures.join("; ")}`
        : detail,
    );
  }
  return {
    entries,
    detachedProviderEntries: detached,
    scrubbedAdapterEntries: scrubbedAdapters,
    destroyAlreadyPrepared: false,
    destroyAlreadyPending: false,
  };
}

/** Restore all MCP runtime state after OpenShell refused to delete the sandbox. */
export async function restoreMcpBridgesAfterDestroyAbort(
  sandboxName: string,
  preparation: McpDestroyPreparation,
): Promise<void> {
  if (preparation.entries.length === 0 || preparation.destroyAlreadyPending) {
    return;
  }
  assertMcpDestroySnapshotCurrent(sandboxName, preparation.entries);
  const cleared = registry.updateSandbox(sandboxName, {
    mcp: {
      bridges: Object.fromEntries(
        preparation.entries.map((entry) => [entry.server, cloneMcpBridgeEntry(entry)]),
      ),
    },
  });
  if (!cleared) {
    throw new McpBridgeError(
      `Could not clear prepared MCP destroy state for sandbox '${sandboxName}' before runtime restoration.`,
    );
  }
  // Exact providers were required before phase one. Reusing them does not
  // require the host secret environment variable: OpenShell retains the
  // credential and restart writes only the placeholder into agent config.
  for (const entry of preparation.entries) {
    inspectExactMcpDestroyProvider(entry, { allowMissing: false });
  }
  await restartMcpBridge(sandboxName);
}

/**
 * Phase two of sandbox destroy, called only after OpenShell confirmed the
 * sandbox is gone. Delete exact matching global providers, then clear the MCP
 * bridge manifest and owned custom-policy records in one registry update.
 */
export async function finalizeMcpBridgesAfterSandboxDelete(
  sandboxName: string,
  preparation: McpDestroyPreparation,
  options: { force?: boolean } = {},
): Promise<void> {
  const entries = preparation.entries;
  if (entries.length === 0) return;

  let sandbox = assertMcpDestroySnapshotCurrent(sandboxName, entries);
  if (!sandbox.mcp?.destroyPendingAt) {
    const marked = registry.updateSandbox(sandboxName, {
      mcp: {
        bridges: Object.fromEntries(
          entries.map((entry) => [entry.server, cloneMcpBridgeEntry(entry)]),
        ),
        destroyPendingAt: nowIso(),
      },
    });
    if (!marked) {
      throw new McpBridgeError(
        `Could not persist MCP destroy cleanup state for sandbox '${sandboxName}'. No MCP providers were deleted.`,
      );
    }
    sandbox = assertMcpDestroySnapshotCurrent(sandboxName, entries);
  }

  // Inspect every provider before deleting any so ownership drift cannot
  // produce a predictable partial cleanup. Missing is safe only now that the
  // durable pending marker proves the sandbox was already deleted.
  const inspections = entries.map((entry) =>
    inspectExactMcpDestroyProvider(entry, {
      allowMissing: true,
      force: options.force,
    }),
  );
  for (const [index, entry] of entries.entries()) {
    if (!inspections[index]?.exists) continue;
    deleteProvider(entry.providerName, { allowMissing: true });
    const after = inspectMcpProvider(entry.providerName);
    if (after.exists !== false) {
      throw new McpBridgeError(
        after.error ??
          `OpenShell provider '${entry.providerName}' still exists after delete. MCP cleanup state was preserved for retry.`,
      );
    }
  }

  sandbox = assertMcpDestroySnapshotCurrent(sandboxName, entries);
  const ownedPolicyNames = new Set(entries.map((entry) => entry.policyName));
  const remainingCustomPolicies = (sandbox.customPolicies ?? []).filter(
    (policy) =>
      !(ownedPolicyNames.has(policy.name) && policy.sourcePath === MCP_BRIDGE_POLICY_SOURCE),
  );
  const cleared = registry.updateSandbox(sandboxName, {
    mcp: undefined,
    customPolicies: remainingCustomPolicies.length > 0 ? remainingCustomPolicies : undefined,
  });
  if (!cleared) {
    throw new McpBridgeError(
      `MCP providers were deleted, but cleanup state for sandbox '${sandboxName}' could not be cleared. Re-run destroy; missing providers are accepted while cleanup is pending.`,
    );
  }
}

export interface McpRebuildPreparation {
  entries: McpBridgeEntry[];
  detachedProviderEntries: McpBridgeEntry[];
  scrubbedAdapterEntries: McpBridgeEntry[];
}

function getCompleteMcpRebuildEntries(sandboxName: string): McpBridgeEntry[] {
  validateSandboxName(sandboxName);
  const sandbox = getSandboxOrThrow(sandboxName);
  const entries = Object.values(bridgeState(sandbox)).map(cloneMcpBridgeEntry);
  const incompleteAdd = entries.find((entry) => entry.addState);
  if (incompleteAdd) {
    throw new McpBridgeError(
      `MCP server '${incompleteAdd.server}' has an incomplete add transaction (${incompleteAdd.addState}). Re-run the original mcp add command or remove it with --force before rebuilding the sandbox.`,
    );
  }
  return entries;
}

/**
 * Preserve MCP intent for stale-registry recovery after OpenShell has already
 * proved the sandbox absent. There is no sandbox process or retained adapter
 * to scrub, so this path validates targets and provider recoverability without
 * attempting sandbox exec or changing provider attachment state.
 */
export async function prepareMcpBridgesForAbsentSandboxRebuild(
  sandboxName: string,
): Promise<McpRebuildPreparation> {
  const entries = getCompleteMcpRebuildEntries(sandboxName);
  if (entries.length === 0) {
    return {
      entries: [],
      detachedProviderEntries: [],
      scrubbedAdapterEntries: [],
    };
  }
  await preflightMcpEntryTargets(entries);
  await ensureSandboxGatewaySelected(sandboxName);
  for (const entry of entries) assertMcpProviderRecoverable(entry);
  return {
    entries,
    detachedProviderEntries: [],
    scrubbedAdapterEntries: [],
  };
}

export async function prepareMcpBridgesForRebuild(
  sandboxName: string,
): Promise<McpRebuildPreparation> {
  const sandbox = getSandboxOrThrow(sandboxName);
  const entries = getCompleteMcpRebuildEntries(sandboxName);
  if (entries.length === 0) {
    return {
      entries: [],
      detachedProviderEntries: [],
      scrubbedAdapterEntries: [],
    };
  }
  await preflightMcpEntryTargets(entries);
  await ensureSandboxGatewaySelected(sandboxName);
  for (const entry of entries) assertMcpProviderRecoverable(entry);
  const detached: McpBridgeEntry[] = [];
  const scrubbedAdapters: McpBridgeEntry[] = [];
  try {
    for (const entry of entries) {
      const adapter = isAgentMcpAdapter(entry.adapter)
        ? entry.adapter
        : getBridgeAdapter(getSandboxAgent(sandbox));
      // `/sandbox` may be a retained PVC. Scrub before delete so a replacement
      // Hermes/agent cannot boot with a stale placeholder while its provider
      // is intentionally detached during recreate.
      unregisterAgentAdapter(sandboxName, adapter, entry, { envValues: {} });
      scrubbedAdapters.push(entry);
    }
    for (const entry of entries) {
      // Keep the provider and its host-only credentials for the replacement
      // sandbox, but detach it before OpenShell deletes the old attachment.
      if (detachProvider(sandboxName, entry.providerName)) detached.push(entry);
    }
  } catch (error) {
    const rollbackFailures: string[] = [];
    for (const entry of detached.reverse()) {
      try {
        attachProvider(sandboxName, entry.providerName);
        // Reattach preserves the provider value, so presence is sufficient;
        // still wait before reloading an adapter that may connect immediately.
        waitForAttachedMcpCredential(sandboxName, entry);
      } catch (rollbackError) {
        rollbackFailures.push(
          rollbackError instanceof Error ? rollbackError.message : String(rollbackError),
        );
      }
    }
    for (const entry of scrubbedAdapters) {
      try {
        const adapter = isAgentMcpAdapter(entry.adapter)
          ? entry.adapter
          : getBridgeAdapter(getSandboxAgent(sandbox));
        registerAgentAdapter(
          sandboxName,
          adapter,
          entry,
          {},
          {
            replaceExisting: true,
          },
        );
      } catch (rollbackError) {
        rollbackFailures.push(
          rollbackError instanceof Error ? rollbackError.message : String(rollbackError),
        );
      }
    }
    const detail = error instanceof Error ? error.message : String(error);
    throw new McpBridgeError(
      rollbackFailures.length > 0
        ? `${detail}\nMCP rebuild rollback could not reattach: ${rollbackFailures.join("; ")}`
        : detail,
    );
  }
  return {
    entries,
    detachedProviderEntries: detached,
    scrubbedAdapterEntries: scrubbedAdapters,
  };
}

export async function reattachMcpProvidersAfterRebuildAbort(
  sandboxName: string,
  entries: readonly McpBridgeEntry[],
  scrubbedAdapterEntries: readonly McpBridgeEntry[] = [],
): Promise<void> {
  if (entries.length === 0 && scrubbedAdapterEntries.length === 0) return;
  await ensureSandboxGatewaySelected(sandboxName);

  const failures: string[] = [];
  for (const entry of entries) {
    try {
      attachProvider(sandboxName, entry.providerName);
      waitForAttachedMcpCredential(sandboxName, entry);
    } catch (error) {
      failures.push(error instanceof Error ? error.message : String(error));
    }
  }
  const sandbox = getSandboxOrThrow(sandboxName);
  for (const entry of scrubbedAdapterEntries) {
    try {
      const adapter = isAgentMcpAdapter(entry.adapter)
        ? entry.adapter
        : getBridgeAdapter(getSandboxAgent(sandbox));
      registerAgentAdapter(
        sandboxName,
        adapter,
        entry,
        {},
        {
          replaceExisting: true,
        },
      );
    } catch (error) {
      failures.push(error instanceof Error ? error.message : String(error));
    }
  }
  if (failures.length > 0) {
    throw new McpBridgeError(failures.join("; "));
  }
}

export async function restoreMcpBridgesAfterRebuild(
  sandboxName: string,
  entries: readonly McpBridgeEntry[],
): Promise<void> {
  if (entries.length === 0) return;
  for (const entry of entries) assertAuthenticatedBridgeEntry(entry);
  const bridges = Object.fromEntries(
    entries.map((entry) => [entry.server, { ...entry, env: [...entry.env] }]),
  );
  // Persist the recovery contract before touching the gateway. If refresh
  // fails, `mcp restart` remains retryable after the operator fixes the cause.
  setBridgeState(sandboxName, bridges);
  await restartMcpBridge(sandboxName);
}

export async function removeMcpBridge(
  sandboxName: string,
  server: string,
  options: { force?: boolean; allowResidual?: boolean } = {},
): Promise<void> {
  return withMcpLifecycleLock(sandboxName, () =>
    removeMcpBridgeUnlocked(sandboxName, server, options),
  );
}

async function removeMcpBridgeUnlocked(
  sandboxName: string,
  server: string,
  options: { force?: boolean; allowResidual?: boolean } = {},
): Promise<void> {
  validateSandboxName(sandboxName);
  validateMcpServerName(server);
  const sandbox = getSandboxOrThrow(sandboxName);
  assertMcpDestroyNotPending(sandbox);
  const entry = bridgeState(sandbox)[server];
  if (!entry) {
    if (!options.force) {
      throw new McpBridgeError(`MCP server '${server}' not found on sandbox '${sandboxName}'.`);
    }
    console.log(`  No MCP server '${server}' is registered on sandbox '${sandboxName}'.`);
    return;
  }
  if (entry.addState === "prepared") {
    // `prepared` is persisted before gateway selection and is advanced only
    // after adapter/provider/policy absence has been proven. It therefore owns
    // no external resources and can be cancelled without touching same-name
    // state another workflow may own.
    removeBridgeEntry(sandboxName, server);
    console.log(`  Cancelled incomplete MCP add for '${server}' on sandbox '${sandboxName}'.`);
    return;
  }
  // Cleanup follows the adapter persisted with the bridge. Requiring the
  // sandbox's current agent to still advertise MCP support would strand old
  // resources after an agent/capability migration.
  const adapter = isAgentMcpAdapter(entry.adapter)
    ? entry.adapter
    : getBridgeAdapter(getSandboxAgent(sandbox));
  await ensureSandboxGatewaySelected(sandboxName);

  assertGeneratedPolicyMutationSafe(sandboxName, entry);
  const failures: string[] = [];
  let providerOwnershipProved = !entry.providerName;
  let providerWasMissing = false;
  if (entry.providerName) {
    const inspection = inspectMcpProvider(entry.providerName);
    if (inspection.exists === false) {
      providerOwnershipProved = true;
      providerWasMissing = true;
    } else if (
      inspection.exists === true &&
      entry.env.length === 1 &&
      providerMatchesCredential(inspection, entry.env[0])
    ) {
      providerOwnershipProved = true;
    } else {
      const detail =
        inspection.exists === null
          ? (inspection.error ?? `Could not inspect OpenShell provider '${entry.providerName}'.`)
          : `OpenShell provider '${entry.providerName}' has drifted or lacks a complete registered credential binding. ${providerShapeDetail(inspection, entry.env[0]) ?? ""}`;
      if (!options.force) {
        throw new McpBridgeError(detail);
      }
      // Force is allowed to continue cleaning resources whose ownership is
      // independently provable, but it never broadens ownership of a global
      // provider merely because the local bridge registry names it.
      failures.push(detail);
    }
  }

  const adapterEnvValues = resolveCredentialEnv(entry.env.map((envName) => ({ name: envName })));
  try {
    unregisterAgentAdapter(
      sandboxName,
      (entry.adapter as AgentMcpAdapter | undefined) ?? adapter,
      entry,
      { force: options.force === true, envValues: adapterEnvValues },
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    if (!options.force) throw new McpBridgeError(detail);
    failures.push(detail);
  }
  if (providerOwnershipProved) {
    try {
      detachProvider(sandboxName, entry.providerName);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      if (!options.force) throw new McpBridgeError(detail);
      failures.push(detail);
    }
  }
  try {
    removeGeneratedPolicy(sandboxName, entry);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    if (!options.force) throw new McpBridgeError(detail);
    failures.push(detail);
  }
  if (providerOwnershipProved) {
    try {
      deleteProvider(entry.providerName, {
        allowMissing:
          options.force === true || entry.addState === "preflighted" || providerWasMissing,
      });
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      if (!options.force) throw new McpBridgeError(detail);
      failures.push(detail);
    }
  }
  if (failures.length > 0) {
    console.warn(`  MCP force cleanup warnings:\n${failures.join("\n")}`);
    if (!options.allowResidual) {
      throw new McpBridgeError(
        `MCP force cleanup left residual resources for '${server}'. The registry entry was preserved so cleanup can be retried.`,
      );
    }
    return;
  }
  removeBridgeEntry(sandboxName, server);
  console.log(`  Removed MCP server '${server}' from sandbox '${sandboxName}'.`);
}

function getRegisteredGeneratedPolicy(
  sandboxName: string,
  entry: McpBridgeEntry | undefined,
): ReturnType<typeof registry.getCustomPolicies>[number] | undefined {
  if (!entry?.policyName) return undefined;
  return registry
    .getCustomPolicies(sandboxName)
    .find(
      (policy) =>
        policy.name === entry.policyName && policy.sourcePath === MCP_BRIDGE_POLICY_SOURCE,
    );
}

function getPolicyPresence(sandboxName: string, entry: McpBridgeEntry | undefined): boolean | null {
  if (!entry?.policyName) return false;
  const registeredPolicy = getRegisteredGeneratedPolicy(sandboxName, entry);
  if (!registeredPolicy) return null;
  return policies.presetContentMatchesGateway(sandboxName, registeredPolicy.content);
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
      ? buildOpenClawMcporterInspectCommand(entry, false)
      : adapter === "hermes-config"
        ? buildHermesMcpStatusCommand(entry)
        : buildDeepAgentsMcpStatusCommand(entry);
  const result = executeSandboxCommand(sandboxName, command);
  if (!result) return { registered: null, detail: "sandbox unreachable" };
  if (result.status === 0) {
    const output = result.stdout.trim();
    if (output === "registered") return { registered: true };
    return { registered: false, detail: output || "not found" };
  }
  const envValues = resolveCredentialEnv(entry.env.map((envName) => ({ name: envName })));
  return {
    registered: false,
    detail: redactBridgeSecretsForDisplay(
      result.stderr || result.stdout || "not found",
      entry,
      envValues,
    ),
  };
}

export async function statusMcpBridge(
  sandboxName: string,
  server?: string,
): Promise<McpBridgeStatus[]> {
  validateSandboxName(sandboxName);
  const sandbox = getSandboxOrThrow(sandboxName);
  const agent = getSandboxAgent(sandbox);
  const bridges = bridgeState(sandbox);
  if (Object.keys(bridges).length > 0) {
    await ensureSandboxGatewaySelected(sandboxName);
  }
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
        env: { names: [], missing: [], ready: false },
        provider: {
          registryPresent: false,
          gatewayPresent: false,
          attached: null,
          credentialReady: null,
        },
        policy: { registryPresent: false, gatewayPresent: false },
        adapter: { registered: null },
      },
    ];
  }

  return entries.map(([name, entry]) => {
    const registeredPolicy = getRegisteredGeneratedPolicy(sandboxName, entry);
    const hasCredentialBinding =
      !!entry && Array.isArray(entry.env) && entry.env.length === 1 && !!entry.providerName;
    const missingEnv = entry
      ? entry.env.filter(
          (envName: string) => process.env[envName] === undefined || process.env[envName] === "",
        )
      : [];
    const expectedCredential = entry?.env.length === 1 ? entry.env[0] : undefined;
    const providerInspection = inspectMcpProvider(entry?.providerName);
    const providerCredentialReady = providerMatchesCredential(
      providerInspection,
      expectedCredential,
    );
    const providerDetail = providerShapeDetail(providerInspection, expectedCredential);
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
      ...(entry?.addState ? { addState: entry.addState } : {}),
      env: {
        names: entry?.env ?? [],
        missing: missingEnv,
        ready:
          hasCredentialBinding &&
          !entry?.addState &&
          (providerInspection.exists ? providerCredentialReady : missingEnv.length === 0),
      },
      provider: {
        name: entry?.providerName,
        registryPresent: !!entry?.providerName,
        gatewayPresent: entry?.providerName ? providerInspection.exists : null,
        attached: providerAttached(sandboxName, entry?.providerName),
        credentialReady: entry ? providerCredentialReady : null,
        ...(providerDetail ? { detail: providerDetail } : {}),
      },
      policy: {
        name: entry?.policyName,
        registryPresent: !!registeredPolicy,
        gatewayPresent: getPolicyPresence(sandboxName, entry),
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
      status.provider.registryPresent &&
      status.provider.gatewayPresent &&
      status.provider.attached === true &&
      status.provider.credentialReady === true
        ? "provider"
        : "provider?";
    const env = status.env.names.length > 0 ? status.env.names.join(", ") : "(none)";
    console.log(
      `    ${status.server.padEnd(18)} ${policy.padEnd(8)} ${provider.padEnd(10)} env: ${env}${status.addState ? `  add:${status.addState}` : ""}`,
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
    if (status.addState) console.log(`    add transaction: incomplete (${status.addState})`);
    console.log(
      `    provider: ${status.provider.registryPresent ? status.provider.name : "(none)"}`,
    );
    console.log(
      `    provider attached: ${status.provider.attached === null ? "unknown" : status.provider.attached ? "yes" : "no"}`,
    );
    console.log(
      `    provider credentials: ${status.provider.credentialReady === null ? "unknown" : status.provider.credentialReady ? "ready" : "drifted or missing"}`,
    );
    if (status.provider.detail) console.log(`    provider detail: ${status.provider.detail}`);
    console.log(
      `    policy: ${status.policy.gatewayPresent === null ? "unknown" : status.policy.gatewayPresent ? "present" : "missing"}`,
    );
    console.log(
      `    adapter: ${status.adapter.registered === null ? "unknown" : status.adapter.registered ? "registered" : "missing"}`,
    );
    console.log(
      `    env: ${status.env.ready ? "ready" : status.env.missing.length > 0 ? `missing ${status.env.missing.join(", ")}` : "not ready"}`,
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
  nemoclaw <name> mcp add <server> --url <http-mcp-url> --env KEY

FLAGS
  --url URL        MCP Streamable HTTP endpoint
  --env KEY        Required host credential reference registered with OpenShell

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
  --force  Best-effort owned cleanup; preserves registry state when residuals remain`);
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
        const statuses = await statusMcpBridge(sandboxName);
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
        const statuses = await statusMcpBridge(sandboxName, server);
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
        const server = requireAtMostOneArg(rest, "Usage: nemoclaw <sandbox> mcp restart [server]");
        await restartMcpBridge(sandboxName, server);
        return;
      }
      case "remove": {
        const force = rest.includes("--force");
        const names = rest.filter((arg) => arg !== "--force");
        const server = names[0];
        if (!server || names.length > 1)
          throw new McpBridgeError("Usage: nemoclaw <sandbox> mcp remove <server> [--force]", 2);
        await removeMcpBridge(sandboxName, server, { force });
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
