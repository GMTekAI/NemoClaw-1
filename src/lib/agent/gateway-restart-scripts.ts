// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Gateway recovery/restart shell generation. Kept separate from runtime.ts so
// agent lookup and display metadata do not grow around security-sensitive
// process-control scripts.

import { DASHBOARD_PORT } from "../core/ports";
import { shellQuote } from "../runner";
import { type AgentDefinition, isTerminalAgent } from "./defs";
import { GATEWAY_RESTART_MARKERS as MARKERS } from "./gateway-restart-markers";
import {
  buildGatewayGuardRecoveryLines,
  buildGatewayLogSelection,
  buildGatewayLogSetup,
  buildGatewayStopLines,
  gatewayGuardRefusalCommand,
  gatewayLaunchCommand,
  gatewayRootGosuLaunchCommand,
} from "./gateway-script-shared";
import {
  buildHermesDashboardRecoveryLines,
  type HermesDashboardRecoveryConfig,
  hermesGatewayEnvPrefix,
} from "./hermes-gateway-scripts";
import {
  buildHermesEnvFileBoundaryGuard,
  buildHermesRuntimeEnvBoundaryGuard,
} from "./hermes-recovery-boundary";

export const TERMINAL_AGENT_RECOVERY_SCRIPT = Object.freeze({ kind: "terminal" } as const);

export type AgentRecoveryScript = string | typeof TERMINAL_AGENT_RECOVERY_SCRIPT | null;

export function isTerminalAgentRecoveryScript(
  script: AgentRecoveryScript,
): script is typeof TERMINAL_AGENT_RECOVERY_SCRIPT {
  return script === TERMINAL_AGENT_RECOVERY_SCRIPT;
}

export function getTerminalCommand(
  agent: AgentDefinition | null,
  mode: "interactive" | "headless" = "interactive",
): string | null {
  if (!agent || !isTerminalAgent(agent)) return null;
  if (mode === "headless") return agent.runtime?.headless_command ?? null;
  return agent.runtime?.interactive_command ?? agent.runtime?.headless_command ?? null;
}

function getRecoveryHealthProbeUrl(
  agent: AgentDefinition | null,
  fallbackPort = DASHBOARD_PORT,
): string {
  if (!agent) return `http://127.0.0.1:${fallbackPort}/health`;
  if (isTerminalAgent(agent)) return "";
  return agent.healthProbe?.url || `http://127.0.0.1:${fallbackPort}/health`;
}

function escapeEre(value: string): string {
  return value.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

function escapeCharClass(value: string): string {
  return value.replace(/[\\\]\[\^\-]/g, "\\$&");
}

function selfSafeGatewayProcessPattern(command: string): string {
  const [executable = "", ...args] = command.trim().split(/\s+/).filter(Boolean);
  const [first = "", ...rest] = Array.from(executable);
  if (!first) return "";
  const executablePattern = `[${escapeCharClass(first)}]${escapeEre(rest.join(""))}`;
  const commandPattern = [executablePattern, ...args.map(escapeEre)].join("[[:space:]]+");
  return `${commandPattern}([[:space:]]|$)`;
}

/**
 * Build the OpenClaw recovery shell script used by the default sandbox.
 */
export function buildOpenClawRecoveryScript(port: number): string {
  const staleGatewayPattern = "[o]penclaw([ -]gateway| gateway run|$)";
  return [
    ...buildGatewayLogSetup(true, "gateway"),
    buildGatewayLogSelection(),
    ...buildGatewayGuardRecoveryLines(),
    gatewayGuardRefusalCommand(),
    "[ -f ~/.bashrc ] && . ~/.bashrc;",
    `_GW_CODE=$(curl -so /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:${port}/health 2>/dev/null || echo 000); case "$_GW_CODE" in 200|401) echo ALREADY_RUNNING; exit 0 ;; esac;`,
    "rm -rf /tmp/openclaw-*/gateway.*.lock 2>/dev/null;",
    `_GATEWAY_PROC_PATTERN=${shellQuote(staleGatewayPattern)};`,
    `if [ -n "$_GATEWAY_PROC_PATTERN" ]; then pkill -TERM -f "$_GATEWAY_PROC_PATTERN" 2>/dev/null || true; for _i in 1 2 3 4 5; do pgrep -f "$_GATEWAY_PROC_PATTERN" >/dev/null 2>&1 || break; sleep 1; done; pkill -KILL -f "$_GATEWAY_PROC_PATTERN" 2>/dev/null || true; for _i in 1 2 3 4 5; do pgrep -f "$_GATEWAY_PROC_PATTERN" >/dev/null 2>&1 || break; sleep 1; done; if pgrep -f "$_GATEWAY_PROC_PATTERN" >/dev/null 2>&1; then echo ${MARKERS.GATEWAY_STALE_PROCESSES}; exit 1; fi; fi;`,
    'OPENCLAW="$(command -v openclaw)";',
    'if [ -z "$OPENCLAW" ]; then echo OPENCLAW_MISSING; exit 1; fi;',
    gatewayLaunchCommand('"$OPENCLAW" gateway run --port ' + port, "gateway"),
    "GPID=$!; sleep 2;",
    `if kill -0 "$GPID" 2>/dev/null; then echo "GATEWAY_PID=$GPID"; else echo ${MARKERS.GATEWAY_FAILED}; tail -5 "$_GATEWAY_LOG" 2>/dev/null; fi`,
  ].join(" ");
}

/**
 * Build the OpenClaw forced-restart shell script used by
 * `sandbox gateway restart`. Unlike recovery, this intentionally skips the
 * ALREADY_RUNNING fast path.
 */
export function buildOpenClawGatewayRestartScript(port: number): string {
  const staleGatewayPattern = "[o]penclaw([ -]gateway| gateway run|$)";
  return [
    `[ "$(id -u)" = "0" ] || { echo ${MARKERS.ROOT_EXEC_UNAVAILABLE}; exit 1; };`,
    ...buildGatewayLogSetup(true, "gateway"),
    buildGatewayLogSelection(),
    ...buildGatewayGuardRecoveryLines(),
    gatewayGuardRefusalCommand(),
    "[ -f ~/.bashrc ] && . ~/.bashrc;",
    "rm -rf /tmp/openclaw-*/gateway.*.lock 2>/dev/null;",
    ...buildGatewayStopLines(staleGatewayPattern),
    'OPENCLAW="$(command -v openclaw)";',
    'if [ -z "$OPENCLAW" ]; then echo OPENCLAW_MISSING; exit 1; fi;',
    gatewayRootGosuLaunchCommand('"$OPENCLAW" gateway run --port ' + port, "gateway"),
    "GPID=$!; sleep 2;",
    `if kill -0 "$GPID" 2>/dev/null; then echo "GATEWAY_PID=$GPID"; else echo ${MARKERS.GATEWAY_FAILED}; tail -5 "$_GATEWAY_LOG" 2>/dev/null; exit 1; fi;`,
  ].join(" ");
}

/**
 * Build the recovery shell script for a non-OpenClaw agent.
 * Returns the script string, null if agent is null (use existing inline
 * OpenClaw script instead), or a terminal sentinel for agents without a
 * gateway process.
 */
export function buildRecoveryScript(
  agent: AgentDefinition & { runtime: { kind: "terminal" } },
  port: number,
  options?: { hermesDashboard?: HermesDashboardRecoveryConfig | null },
): typeof TERMINAL_AGENT_RECOVERY_SCRIPT;
export function buildRecoveryScript(
  agent: AgentDefinition | null,
  port: number,
  options?: { hermesDashboard?: HermesDashboardRecoveryConfig | null },
): string | null;
export function buildRecoveryScript(
  agent: AgentDefinition | null,
  port: number,
  options: { hermesDashboard?: HermesDashboardRecoveryConfig | null } = {},
): AgentRecoveryScript {
  if (!agent) return null;
  if (isTerminalAgent(agent)) return TERMINAL_AGENT_RECOVERY_SCRIPT;

  const probeUrl = getRecoveryHealthProbeUrl(agent, port);
  const binaryPath = agent.binary_path || "/usr/local/bin/openclaw";
  const binaryName = binaryPath.split("/").pop() ?? "openclaw";
  const defaultGatewayCommand = `${binaryName} gateway run`;
  const configuredGatewayCommand = agent.gateway_command?.trim() || defaultGatewayCommand;
  const usesValidatedBinary = configuredGatewayCommand === defaultGatewayCommand;
  const customGatewayExecutable = configuredGatewayCommand.split(/\s+/)[0] ?? binaryName;
  const staleGatewayPattern = selfSafeGatewayProcessPattern(configuredGatewayCommand);
  const validationSteps = usesValidatedBinary
    ? [
        `AGENT_BIN=${shellQuote(binaryPath)}; if [ ! -x "$AGENT_BIN" ]; then AGENT_BIN="$(command -v ${shellQuote(binaryName)})"; fi;`,
        'if [ -z "$AGENT_BIN" ]; then echo AGENT_MISSING; exit 1; fi;',
      ]
    : [
        `GATEWAY_CMD_BIN=${shellQuote(customGatewayExecutable)};`,
        'case "$GATEWAY_CMD_BIN" in */*) [ -x "$GATEWAY_CMD_BIN" ] || { echo AGENT_MISSING; exit 1; } ;; *) command -v "$GATEWAY_CMD_BIN" >/dev/null 2>&1 || { echo AGENT_MISSING; exit 1; } ;; esac;',
      ];
  // Append (>>) rather than truncate (>) so the [gateway-recovery] WARNING
  // lines that the recovery script writes to gateway.log moments earlier
  // survive past the gateway launch. Otherwise the warning explaining why the
  // gateway is about to crash gets wiped by the same launch that is about to
  // crash on a missing guard. (#2478)
  const isHermes = agent.name === "hermes";
  const hermesHome = isHermes ? "export HERMES_HOME=/sandbox/.hermes; " : "";
  const hermesLaunchEnv = isHermes ? `env ${hermesGatewayEnvPrefix()} ` : "";
  const launchCommand = usesValidatedBinary
    ? gatewayLaunchCommand(
        `${hermesLaunchEnv}"$AGENT_BIN" gateway run${isHermes ? "" : ` --port ${port}`}`,
      )
    : gatewayLaunchCommand(
        `${hermesLaunchEnv}${configuredGatewayCommand}${isHermes ? "" : ` --port ${port}`}`,
      );

  // Validate or rebuild /tmp/nemoclaw-proxy-env.sh before shell init and the
  // health fast path so a healthy gateway cannot leave a wiped guard chain
  // unrepaired. Recovery also stops stale launcher/gateway processes that may
  // have respawned between the health probe and relaunch.
  return [
    hermesHome,
    ...(isHermes ? [buildHermesEnvFileBoundaryGuard()] : []),
    ...buildGatewayLogSetup(false),
    buildGatewayLogSelection(),
    ...buildGatewayGuardRecoveryLines(),
    gatewayGuardRefusalCommand(),
    "[ -f ~/.bashrc ] && . ~/.bashrc;",
    `_GW_CODE=$(curl -so /dev/null -w '%{http_code}' --max-time 3 ${shellQuote(probeUrl)} 2>/dev/null || echo 000); case "$_GW_CODE" in 200|401) echo ALREADY_RUNNING; exit 0 ;; esac;`,
    `_GATEWAY_PROC_PATTERN=${shellQuote(staleGatewayPattern)};`,
    `if [ -n "$_GATEWAY_PROC_PATTERN" ]; then pkill -TERM -f "$_GATEWAY_PROC_PATTERN" 2>/dev/null || true; for _i in 1 2 3 4 5; do pgrep -f "$_GATEWAY_PROC_PATTERN" >/dev/null 2>&1 || break; sleep 1; done; pkill -KILL -f "$_GATEWAY_PROC_PATTERN" 2>/dev/null || true; for _i in 1 2 3 4 5; do pgrep -f "$_GATEWAY_PROC_PATTERN" >/dev/null 2>&1 || break; sleep 1; done; if pgrep -f "$_GATEWAY_PROC_PATTERN" >/dev/null 2>&1; then echo ${MARKERS.GATEWAY_STALE_PROCESSES}; exit 1; fi; fi;`,
    ...validationSteps,
    ...(isHermes ? [buildHermesRuntimeEnvBoundaryGuard()] : []),
    launchCommand,
    "GPID=$!; sleep 2;",
    `if kill -0 "$GPID" 2>/dev/null; then echo "GATEWAY_PID=$GPID"; else echo ${MARKERS.GATEWAY_FAILED}; tail -5 "$_GATEWAY_LOG" 2>/dev/null; exit 1; fi`,
    ...(isHermes && options.hermesDashboard
      ? buildHermesDashboardRecoveryLines(options.hermesDashboard)
      : []),
  ].join(" ");
}

/**
 * Build a single copy-pasteable command for the user to run when automatic
 * gateway recovery fails. Unlike the raw gateway command, this keeps the
 * process alive after disconnect and preserves the agent-specific launch shape.
 */
export function buildManualRecoveryCommand(agent: AgentDefinition | null, port: number): string {
  if (agent && isTerminalAgent(agent)) return getTerminalCommand(agent) ?? agent.versionCommand;
  const binaryPath = agent?.binary_path || "/usr/local/bin/openclaw";
  const defaultGatewayCommand = `${shellQuote(binaryPath)} gateway run`;
  const gatewayCmd = agent?.gateway_command?.trim() || defaultGatewayCommand;
  const isHermes = agent?.name === "hermes";
  const envPrefix = isHermes ? `${hermesGatewayEnvPrefix()} ` : "";
  const portFlag = isHermes ? "" : ` --port ${port}`;
  const hermesHome = isHermes ? "export HERMES_HOME=/sandbox/.hermes;" : "";
  return [
    hermesHome,
    ...(isHermes ? [buildHermesEnvFileBoundaryGuard()] : []),
    ...buildGatewayLogSetup(false),
    buildGatewayLogSelection(),
    ...buildGatewayGuardRecoveryLines(),
    gatewayGuardRefusalCommand(),
    "[ -f ~/.bashrc ] && . ~/.bashrc;",
    ...(isHermes ? [buildHermesRuntimeEnvBoundaryGuard()] : []),
    `${envPrefix}nohup ${gatewayCmd}${portFlag} >> "$_GATEWAY_LOG" 2>&1 &`,
  ]
    .filter(Boolean)
    .join(" ");
}
