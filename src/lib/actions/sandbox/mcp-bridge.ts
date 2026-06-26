// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import YAML from "yaml";

import { type AgentDefinition, loadAgent } from "../../agent/defs";
import { shellQuote } from "../../runner";
import { ensureConfigDir } from "../../state/config-io";
import * as registry from "../../state/registry";
import type { McpBridgeEntry, SandboxEntry } from "../../state/registry";
import * as policies from "../../policy";
import { executeSandboxCommand } from "./process-recovery";

export const MCP_PORT_START = 3100;
export const MCP_PORT_END = 3199;
export const MCP_HOST = "host.docker.internal";
export const MCPORTER_VERSION = "0.7.3";
export const MCP_BRIDGE_POLICY_SOURCE = "generated:nemoclaw-mcp-bridge";

const VALID_SERVER_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const VALID_ENV_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const VALID_SANDBOX_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const BRIDGE_TOKEN_ENV = "NEMOCLAW_MCP_BRIDGE_TOKEN";

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
  env: ParsedEnvReference[];
  command: string;
  args: string[];
}

export interface McpBridgeAddOptions extends ParsedMcpAddArgs {}

export interface McpBridgeStatus {
  server: string;
  agent: string;
  support: {
    supported: boolean;
    mode: "bridge" | "disabled";
    reason?: string;
  };
  command?: string;
  args?: string[];
  env: {
    names: string[];
    missing: string[];
    ready: boolean;
  };
  port?: number;
  url?: string;
  proxy: {
    pid: number | null;
    running: boolean;
    pidFile?: string;
    logFile?: string;
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
  token: "[REDACTED]" | null;
  addedAt?: string;
  updatedAt?: string;
}

interface McpBridgeJsonSummary {
  sandbox: string;
  agent: string;
  support: McpBridgeStatus["support"];
  bridges: McpBridgeStatus[];
}

type StartedProxy = {
  pid: number;
  logFile: string;
  pidFile: string;
};

function nowIso(): string {
  return new Date().toISOString();
}

function mcpProxyScriptPath(): string {
  return path.resolve(__dirname, "..", "..", "..", "mcp-proxy.js");
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
  if (name === BRIDGE_TOKEN_ENV) {
    throw new McpBridgeError(`${BRIDGE_TOKEN_ENV} is reserved for the local MCP bridge token.`, 2);
  }
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
    : " MCP bridge support is disabled for this agent.";
  return `${agent.displayName} does not support MCP bridges yet.${reason} Issue #566 tracks future design.`;
}

function assertBridgeSupported(agent: AgentDefinition): void {
  if (agent.mcpCapability.support === "bridge") return;
  throw new McpBridgeError(unsupportedMessage(agent), 1);
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
  let command = "";
  let args: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === "--") {
      const rest = argv.slice(i + 1);
      command = rest[0] ?? "";
      args = rest.slice(1);
      break;
    }
    if (token === "--env" || token === "-e") {
      const raw = argv[++i] ?? "";
      const eq = raw.indexOf("=");
      const name = eq >= 0 ? raw.slice(0, eq) : raw;
      if (eq >= 0) {
        throw new McpBridgeError(
          "Inline --env KEY=VALUE is not supported for restart-safe MCP bridges. Export KEY in the host environment and pass --env KEY.",
          2,
        );
      }
      validateEnvName(name);
      env.push({ name });
      continue;
    }
    if (token?.startsWith("--env=")) {
      const raw = token.slice("--env=".length);
      const eq = raw.indexOf("=");
      const name = eq >= 0 ? raw.slice(0, eq) : raw;
      if (eq >= 0) {
        throw new McpBridgeError(
          "Inline --env KEY=VALUE is not supported for restart-safe MCP bridges. Export KEY in the host environment and pass --env KEY.",
          2,
        );
      }
      validateEnvName(name);
      env.push({ name });
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
      "Command must follow '--': mcp add <server> [--env KEY] -- <command> [args...]",
      2,
    );
  }

  if (!server) {
    throw new McpBridgeError(
      "Usage: nemoclaw <sandbox> mcp add <server> [--env KEY ...] -- <command> [args...]",
      2,
    );
  }
  if (!command) {
    throw new McpBridgeError("MCP server command is required after '--'.", 2);
  }
  if (command.includes("\0") || command.includes("\n")) {
    throw new McpBridgeError("MCP server command must not contain control characters.", 2);
  }
  for (const arg of args) {
    if (arg.includes("\0")) {
      throw new McpBridgeError("MCP server arguments must not contain NUL bytes.", 2);
    }
  }

  return { server, env, command, args };
}

function uniqueEnvNames(env: readonly ParsedEnvReference[] | readonly string[]): string[] {
  const names = env.map((entry) => (typeof entry === "string" ? entry : entry.name));
  return [...new Set(names)];
}

export function resolveLaunchEnv(env: readonly ParsedEnvReference[]): Record<string, string> {
  const resolved: Record<string, string> = {};
  for (const entry of env) {
    validateEnvName(entry.name);
    const hostValue = process.env[entry.name];
    if (entry.value !== undefined) {
      throw new McpBridgeError(
        `Inline --env ${entry.name}=VALUE is not supported for restart-safe MCP bridges. Export '${entry.name}' in the host environment and pass --env ${entry.name}.`,
        1,
      );
    }
    const value = hostValue;
    if (value === undefined || value === "") {
      throw new McpBridgeError(
        `Host environment variable '${entry.name}' is required to launch this MCP bridge.`,
        1,
      );
    }
    resolved[entry.name] = value;
  }
  return resolved;
}

function runtimeRoot(): string {
  const home = process.env.HOME || os.homedir();
  return path.join(home, ".nemoclaw", "runtime", "mcp");
}

export function bridgeRuntimeDir(sandboxName: string, server: string): string {
  validateSandboxName(sandboxName);
  validateMcpServerName(server);
  return path.join(runtimeRoot(), sandboxName, server);
}

function ensureBridgeRuntimeDir(sandboxName: string, server: string): string {
  const dir = bridgeRuntimeDir(sandboxName, server);
  ensureConfigDir(dir);
  fs.chmodSync(dir, 0o700);
  return dir;
}

function bridgePidFile(sandboxName: string, server: string): string {
  return path.join(bridgeRuntimeDir(sandboxName, server), "proxy.pid");
}

function bridgeLogFile(sandboxName: string, server: string): string {
  return path.join(bridgeRuntimeDir(sandboxName, server), "proxy.log");
}

export function readLivePid(pidFile: string): number | null {
  try {
    const raw = fs.readFileSync(pidFile, "utf8").trim().split(/\s+/)[0] ?? "";
    const pid = Number.parseInt(raw, 10);
    if (!Number.isFinite(pid) || pid <= 0) return null;
    process.kill(pid, 0);
    return pid;
  } catch {
    return null;
  }
}

export function cleanupStalePidFile(pidFile: string): boolean {
  if (!fs.existsSync(pidFile)) return false;
  if (readLivePid(pidFile)) return false;
  fs.rmSync(pidFile, { force: true });
  return true;
}

function writePidFile(pidFile: string, pid: number): void {
  fs.writeFileSync(pidFile, `${String(pid)}\n${nowIso()}\n`, { mode: 0o600 });
}

export function buildMcpBridgePolicyName(server: string): string {
  validateMcpServerName(server);
  return `mcp-bridge-${server.toLowerCase().replace(/_/g, "-")}`;
}

function buildMcpBridgePolicyKey(server: string): string {
  return buildMcpBridgePolicyName(server).replace(/-/g, "_");
}

export function buildMcpBridgePolicyYaml(server: string, port: number): string {
  const key = buildMcpBridgePolicyKey(server);
  return YAML.stringify({
    preset: {
      name: buildMcpBridgePolicyName(server),
      description: `Generated MCP bridge policy for ${server}`,
    },
    network_policies: {
      [key]: {
        name: key,
        endpoints: [
          {
            host: MCP_HOST,
            port,
            protocol: "rest",
            enforcement: "enforce",
            rules: [{ allow: { method: "POST", path: "/" } }],
          },
        ],
        binaries: [
          { path: "/usr/local/bin/mcporter" },
          { path: "/usr/bin/mcporter" },
          { path: "/usr/local/bin/openclaw" },
          { path: "/usr/bin/node" },
          { path: "/usr/local/bin/node" },
        ],
      },
    },
  });
}

async function isTcpPortAvailable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", () => resolve(false));
    server.once("listening", () => {
      server.close(() => resolve(true));
    });
    server.listen(port, "127.0.0.1");
  });
}

export async function allocateMcpPort(): Promise<number> {
  const data = registry.load();
  const used = new Set<number>();
  for (const sandbox of Object.values(data.sandboxes)) {
    for (const entry of Object.values(bridgeState(sandbox))) {
      used.add(entry.port);
      cleanupStalePidFile(bridgePidFile(sandbox.name, entry.server));
    }
  }
  for (let port = MCP_PORT_START; port <= MCP_PORT_END; port++) {
    if (used.has(port)) continue;
    if (await isTcpPortAvailable(port)) return port;
  }
  throw new McpBridgeError(`No available MCP bridge ports in ${MCP_PORT_START}-${MCP_PORT_END}.`);
}

function startProxy(
  sandboxName: string,
  server: string,
  entry: Pick<McpBridgeEntry, "command" | "args" | "port" | "token" | "env">,
  envValues: Record<string, string>,
): StartedProxy {
  const dir = ensureBridgeRuntimeDir(sandboxName, server);
  const logPath = path.join(dir, "proxy.log");
  const pidPath = path.join(dir, "proxy.pid");
  const logFd = fs.openSync(logPath, "a", 0o600);
  const proxyArgs = [
    mcpProxyScriptPath(),
    "--command",
    entry.command,
    "--port",
    String(entry.port),
    "--token-env",
    BRIDGE_TOKEN_ENV,
  ];
  for (const arg of entry.args) proxyArgs.push("--arg", arg);
  for (const name of entry.env) proxyArgs.push("--env", name);

  const proxyEnv: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    ...envValues,
    [BRIDGE_TOKEN_ENV]: entry.token,
  };
  const child = spawn(process.execPath, proxyArgs, {
    detached: true,
    stdio: ["ignore", logFd, logFd],
    env: proxyEnv,
    shell: false,
  });
  child.unref();
  fs.closeSync(logFd);
  if (!child.pid) {
    throw new McpBridgeError("Failed to start MCP proxy.");
  }
  writePidFile(pidPath, child.pid);
  return { pid: child.pid, logFile: logPath, pidFile: pidPath };
}

function stopProxy(sandboxName: string, server: string): number | null {
  const pidPath = bridgePidFile(sandboxName, server);
  const pid = readLivePid(pidPath);
  if (pid) {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      /* already gone */
    }
  }
  fs.rmSync(pidPath, { force: true });
  return pid;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function waitForProxyReady(
  sandboxName: string,
  server: string,
  port: number,
  sinceOffset: number,
  timeoutMs = 5000,
): Promise<"ready" | "failed" | "timeout"> {
  const logPath = bridgeLogFile(sandboxName, server);
  const pidPath = bridgePidFile(sandboxName, server);
  const listening = `[mcp-proxy] listening on 127.0.0.1:${String(port)}`;
  const readTail = (): string => {
    try {
      const buffer = fs.readFileSync(logPath);
      return buffer.subarray(Math.min(sinceOffset, buffer.length)).toString("utf8");
    } catch {
      return "";
    }
  };
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const tail = readTail();
    if (tail.includes("failed to listen") || tail.includes("child exited")) return "failed";
    if (tail.includes(listening)) {
      await sleep(250);
      return readLivePid(pidPath) ? "ready" : "failed";
    }
    if (!readLivePid(pidPath)) return tail.includes(listening) ? "ready" : "failed";
    await sleep(100);
  }
  return "timeout";
}

function ensureMcporter(sandboxName: string): void {
  const check = executeSandboxCommand(sandboxName, "command -v mcporter");
  if (check?.status === 0 && check.stdout.trim()) return;
  throw new McpBridgeError(
    `mcporter is not available in sandbox '${sandboxName}'. Rebuild with a NemoClaw image that includes mcporter@${MCPORTER_VERSION}.`,
  );
}

export function buildOpenClawMcporterRegisterCommand(entry: McpBridgeEntry): string {
  const url = `http://${MCP_HOST}:${String(entry.port)}`;
  const header = `Authorization=Bearer ${entry.token}`;
  return [
    "mcporter",
    "config",
    "add",
    entry.server,
    "--url",
    url,
    "--header",
    header,
    "--scope",
    "home",
  ]
    .map(shellQuote)
    .join(" ");
}

export function redactBridgeSecretsForDisplay(
  text: string,
  entry: Pick<McpBridgeEntry, "token">,
): string {
  if (!text) return text;
  return text
    .replaceAll(entry.token, "***REDACTED***")
    .replace(/Authorization=Bearer\s+\S+/g, "Authorization=Bearer ***REDACTED***");
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

function unregisterOpenClawAdapter(
  sandboxName: string,
  entry: Pick<McpBridgeEntry, "server" | "token">,
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

function getLogOffset(logPath: string): number {
  try {
    return fs.statSync(logPath).size;
  } catch {
    return 0;
  }
}

function applyGeneratedPolicy(sandboxName: string, entry: McpBridgeEntry): void {
  const content = buildMcpBridgePolicyYaml(entry.server, entry.port);
  const ok = policies.applyPresetContent(sandboxName, entry.policyName, content, {
    custom: { sourcePath: MCP_BRIDGE_POLICY_SOURCE },
  });
  if (ok === false) {
    throw new McpBridgeError(`Failed to apply generated MCP bridge policy '${entry.policyName}'.`);
  }
}

function removeGeneratedPolicy(sandboxName: string, policyName: string, force = false): void {
  const ok = policies.removePreset(sandboxName, policyName);
  if (!ok && !force) {
    throw new McpBridgeError(`Failed to remove generated MCP bridge policy '${policyName}'.`);
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

export async function addMcpBridge(
  sandboxName: string,
  options: McpBridgeAddOptions,
): Promise<void> {
  validateSandboxName(sandboxName);
  validateMcpServerName(options.server);
  const sandbox = getSandboxOrThrow(sandboxName);
  const agent = getSandboxAgent(sandbox);
  assertBridgeSupported(agent);
  if (bridgeState(sandbox)[options.server]) {
    throw new McpBridgeError(
      `MCP server '${options.server}' already exists on sandbox '${sandboxName}'.`,
    );
  }

  const envValues = resolveLaunchEnv(options.env);
  const port = await allocateMcpPort();
  const entry: McpBridgeEntry = {
    server: options.server,
    agent: agent.name,
    command: options.command,
    args: options.args,
    env: uniqueEnvNames(options.env),
    port,
    token: crypto.randomBytes(32).toString("hex"),
    policyName: buildMcpBridgePolicyName(options.server),
    addedAt: nowIso(),
    lifecycle: {},
  };

  let proxyStarted = false;
  let policyApplied = false;
  let adapterRegistered = false;
  try {
    const logPath = bridgeLogFile(sandboxName, entry.server);
    const logOffset = getLogOffset(logPath);
    const proxy = startProxy(sandboxName, entry.server, entry, envValues);
    proxyStarted = true;
    entry.lifecycle = { pid: proxy.pid, startedAt: nowIso() };
    const readiness = await waitForProxyReady(sandboxName, entry.server, entry.port, logOffset);
    if (readiness !== "ready") {
      throw new McpBridgeError(
        readiness === "timeout"
          ? `MCP proxy for '${entry.server}' did not start listening in time. See ${proxy.logFile}.`
          : `MCP proxy for '${entry.server}' exited during startup. See ${proxy.logFile}.`,
      );
    }

    applyGeneratedPolicy(sandboxName, entry);
    policyApplied = true;
    registerOpenClawAdapter(sandboxName, entry);
    adapterRegistered = true;
    writeBridgeEntry(sandboxName, entry);
  } catch (error) {
    if (adapterRegistered) unregisterOpenClawAdapter(sandboxName, entry, { force: true });
    if (policyApplied) removeGeneratedPolicy(sandboxName, entry.policyName, true);
    if (proxyStarted) stopProxy(sandboxName, entry.server);
    removeBridgeEntryIfPresent(sandboxName, entry.server);
    throw error;
  }
}

function removeBridgeEntryIfPresent(sandboxName: string, server: string): void {
  const sandbox = registry.getSandbox(sandboxName);
  if (!sandbox || !bridgeState(sandbox)[server]) return;
  removeBridgeEntry(sandboxName, server);
}

function entryEnvRefsFromHost(entry: McpBridgeEntry): ParsedEnvReference[] {
  return entry.env.map((name) => ({ name }));
}

export async function restartMcpBridge(sandboxName: string, server?: string): Promise<void> {
  validateSandboxName(sandboxName);
  const sandbox = getSandboxOrThrow(sandboxName);
  const agent = getSandboxAgent(sandbox);
  assertBridgeSupported(agent);
  const bridges = bridgeState(sandbox);
  const targets = server ? [[server, bridges[server]] as const] : Object.entries(bridges);
  if (targets.length === 0) {
    console.log(`  No MCP bridges for sandbox '${sandboxName}'.`);
    return;
  }
  for (const [name, entry] of targets) {
    if (!entry) {
      throw new McpBridgeError(`MCP server '${name}' not found on sandbox '${sandboxName}'.`);
    }
    const envValues = resolveLaunchEnv(entryEnvRefsFromHost(entry));
    stopProxy(sandboxName, name);
    const logOffset = getLogOffset(bridgeLogFile(sandboxName, name));
    let proxyStarted = false;
    try {
      const proxy = startProxy(sandboxName, name, entry, envValues);
      proxyStarted = true;
      const readiness = await waitForProxyReady(sandboxName, name, entry.port, logOffset);
      if (readiness !== "ready") {
        throw new McpBridgeError(`MCP proxy for '${name}' failed to restart.`);
      }
      applyGeneratedPolicy(sandboxName, entry);
      registerOpenClawAdapter(sandboxName, entry);
      writeBridgeEntry(sandboxName, {
        ...entry,
        updatedAt: nowIso(),
        lifecycle: { pid: proxy.pid, startedAt: nowIso(), lastError: null },
      });
    } catch (error) {
      if (proxyStarted) stopProxy(sandboxName, name);
      writeBridgeEntry(sandboxName, {
        ...entry,
        updatedAt: nowIso(),
        lifecycle: {
          ...entry.lifecycle,
          lastError: error instanceof Error ? error.message : String(error),
        },
      });
      throw error;
    }
    console.log(`  Restarted MCP bridge '${name}' on port ${String(entry.port)}.`);
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
  const entry = bridgeState(sandbox)[server];
  if (!entry) {
    if (options.force) {
      stopProxy(sandboxName, server);
      fs.rmSync(bridgeRuntimeDir(sandboxName, server), { recursive: true, force: true });
      console.log(`  Cleared stale MCP bridge runtime for '${server}'.`);
      return;
    }
    throw new McpBridgeError(`MCP server '${server}' not found on sandbox '${sandboxName}'.`);
  }

  const failures: string[] = [];
  try {
    unregisterOpenClawAdapter(sandboxName, entry, { force: options.force === true });
  } catch (error) {
    failures.push(error instanceof Error ? error.message : String(error));
  }
  try {
    removeGeneratedPolicy(sandboxName, entry.policyName, options.force === true);
  } catch (error) {
    failures.push(error instanceof Error ? error.message : String(error));
  }
  stopProxy(sandboxName, server);
  if (failures.length > 0 && !options.force) {
    throw new McpBridgeError(failures.join("\n"));
  }
  removeBridgeEntry(sandboxName, server);
  fs.rmSync(bridgeRuntimeDir(sandboxName, server), { recursive: true, force: true });
  console.log(`  Removed MCP bridge '${server}' from sandbox '${sandboxName}'.`);
}

function getPolicyPresence(sandboxName: string, policyName: string | undefined): boolean | null {
  if (!policyName) return false;
  const gatewayPresets = policies.getGatewayPresets(sandboxName);
  return gatewayPresets === null ? null : gatewayPresets.includes(policyName);
}

function getAdapterRegistration(
  sandboxName: string,
  entry: McpBridgeEntry | undefined,
): McpBridgeStatus["adapter"] {
  if (!entry) return { registered: null };
  const result = executeSandboxCommand(
    sandboxName,
    ["mcporter", "config", "get", entry.server, "--json"].map(shellQuote).join(" "),
  );
  if (!result) return { registered: null, detail: "sandbox unreachable" };
  if (result.status === 0) return { registered: true };
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
          ...(agent.mcpCapability.reason ? { reason: agent.mcpCapability.reason } : {}),
        },
        env: { names: [], missing: [], ready: true },
        proxy: { pid: null, running: false },
        policy: { registryPresent: false, gatewayPresent: false },
        adapter: { registered: null },
        token: null,
      },
    ];
  }

  return entries.map(([name, entry]) => {
    const pidPath = bridgePidFile(sandboxName, name);
    const logPath = bridgeLogFile(sandboxName, name);
    const pid = readLivePid(pidPath);
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
        ...(agent.mcpCapability.reason ? { reason: agent.mcpCapability.reason } : {}),
      },
      ...(entry ? { command: entry.command, args: entry.args } : {}),
      env: {
        names: entry?.env ?? [],
        missing: missingEnv,
        ready: missingEnv.length === 0,
      },
      ...(entry ? { port: entry.port, url: `http://${MCP_HOST}:${String(entry.port)}` } : {}),
      proxy: {
        pid,
        running: pid !== null,
        pidFile: pidPath,
        logFile: logPath,
      },
      policy: {
        name: entry?.policyName,
        registryPresent: !!entry?.policyName,
        gatewayPresent: getPolicyPresence(sandboxName, entry?.policyName),
      },
      adapter: getAdapterRegistration(sandboxName, entry),
      token: entry ? "[REDACTED]" : null,
      ...(entry?.addedAt ? { addedAt: entry.addedAt } : {}),
      ...(entry?.updatedAt ? { updatedAt: entry.updatedAt } : {}),
    };
  });
}

function getSupportSummary(agent: AgentDefinition): McpBridgeStatus["support"] {
  return {
    supported: agent.mcpCapability.support === "bridge",
    mode: agent.mcpCapability.support,
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
    console.log(`  No MCP bridges for sandbox '${sandboxName}'.`);
    console.log("");
    return;
  }
  console.log(`  MCP bridges for sandbox '${sandboxName}':`);
  for (const status of statuses) {
    const marker = status.proxy.running ? "running" : "stopped";
    const env = status.env.names.length > 0 ? status.env.names.join(", ") : "(none)";
    const port = status.port ? `:${String(status.port)}` : "";
    console.log(
      `    ${status.server.padEnd(18)} ${marker.padEnd(8)} ${port.padEnd(6)} env: ${env}`,
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
    console.log(`  MCP bridges for sandbox '${sandboxName}': none`);
    console.log(`    agent: ${agent.name}`);
    console.log(`    support: ${agent.mcpCapability.support}`);
    if (agent.mcpCapability.reason) console.log(`    reason: ${agent.mcpCapability.reason}`);
    console.log("");
    return;
  }
  for (const status of statuses) {
    console.log("");
    console.log(`  MCP bridge: ${status.server}`);
    console.log(`    agent: ${status.agent}`);
    console.log(`    support: ${status.support.mode}`);
    if (status.support.reason) console.log(`    reason: ${status.support.reason}`);
    if (status.port) console.log(`    endpoint: ${MCP_HOST}:${String(status.port)}`);
    console.log(
      `    proxy: ${status.proxy.running ? `running (pid ${String(status.proxy.pid)})` : "stopped"}`,
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

function hasHelpFlag(args: readonly string[]): boolean {
  return args.includes("--help") || args.includes("-h");
}

function renderMcpHelp(subcommand: string): void {
  switch (subcommand) {
    case "add":
      console.log(`USAGE
  nemoclaw <name> mcp add <server> [--env KEY ...] -- <command> [args...]

  FLAGS
    --env KEY  Host environment variable reference for the bridge process`);
      return;
    case "list":
      console.log(`USAGE
  nemoclaw <name> mcp list [--json]

FLAGS
  --json  Emit sandbox, support, and bridge state as JSON`);
      return;
    case "status":
      console.log(`USAGE
  nemoclaw <name> mcp status [server] [--json]

FLAGS
  --json  Emit MCP bridge status as JSON`);
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
        console.log(`  MCP bridge '${options.server}' added to sandbox '${sandboxName}'.`);
        return;
      }
      case "list": {
        const { json } = parseJsonFlag(rest);
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
        const sandbox = getSandboxOrThrow(sandboxName);
        const agent = getSandboxAgent(sandbox);
        const statuses = statusMcpBridge(sandboxName, statusRest[0]);
        if (json) {
          console.log(
            JSON.stringify(
              statusRest[0] ? statuses[0] : buildJsonSummary(sandboxName, agent, statuses),
              null,
              2,
            ),
          );
        } else renderStatus(sandboxName, statuses, agent);
        return;
      }
      case "restart": {
        await restartMcpBridge(sandboxName, rest[0]);
        return;
      }
      case "remove": {
        const force = rest.includes("--force");
        const names = rest.filter((arg) => arg !== "--force");
        const server = names[0];
        if (!server)
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
