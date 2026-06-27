// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { shellQuote } from "../runner";
import { type AgentDefinition } from "./defs";
import { GATEWAY_RESTART_MARKERS as MARKERS } from "./gateway-restart-markers";
import {
  buildGatewayGuardRecoveryLines,
  buildGatewayLogSelection,
  buildGatewayLogSetup,
  buildGatewayStopLines,
  buildNoFollowLogSetupCommand,
  gatewayGuardRefusalCommand,
  gatewayRootGosuLaunchCommand,
} from "./gateway-script-shared";
import {
  buildHermesEnvFileBoundaryGuard,
  buildHermesRuntimeEnvBoundaryGuard,
  HERMES_SECRET_BOUNDARY_VALIDATOR_PATH,
} from "./hermes-recovery-boundary";

export interface HermesDashboardRecoveryConfig {
  publicPort: number;
  internalPort: number;
  tuiEnabled?: boolean;
}

export function hermesGatewayEnvPrefix(): string {
  return "HERMES_HOME=/sandbox/.hermes";
}

function hermesDashboardEnvPrefix(): string {
  return 'HERMES_HOME="$_HERMES_DASHBOARD_HOME" GATEWAY_HEALTH_URL="http://127.0.0.1:$_HERMES_DASHBOARD_GATEWAY_PORT"';
}

export function buildHermesDashboardRecoveryLines(config: HermesDashboardRecoveryConfig): string[] {
  const tuiFlag = config.tuiEnabled ? " --tui" : "";
  const dashboardLogSelection =
    '_DASHBOARD_LOG=/tmp/hermes-dashboard.log; if ! : >> "$_DASHBOARD_LOG" 2>/dev/null; then _DASHBOARD_LOG=/tmp/hermes-dashboard-recovery.log; : >> "$_DASHBOARD_LOG" 2>/dev/null || true; fi;';
  return [
    "_HERMES_DASHBOARD_HOME=/sandbox/.hermes/dashboard-home;",
    `_HERMES_DASHBOARD_GATEWAY_PORT=${config.internalPort};`,
    '_HERMES_PYTHON=/opt/hermes/.venv/bin/python; [ -x "$_HERMES_PYTHON" ] || _HERMES_PYTHON="$(command -v python3 || echo python3)";',
    "_HERMES_DASHBOARD_CONFIG_SEEDER=/usr/local/lib/nemoclaw/seed-hermes-dashboard-config.py;",
    `_DASH_CODE=$(curl -so /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:${config.internalPort}/ 2>/dev/null || echo 000); case "$_DASH_CODE" in 200|301|302|307|308) echo DASHBOARD_ALREADY_RUNNING; ;; *)`,
    `${buildNoFollowLogSetupCommand("/tmp/hermes-dashboard.log")} || exit 1;`,
    dashboardLogSelection,
    '[ -f "$_HERMES_DASHBOARD_CONFIG_SEEDER" ] || { echo "[dashboard-recovery] ERROR: dashboard config seeder missing"; exit 1; };',
    'if [ -L "$_HERMES_DASHBOARD_HOME" ]; then echo "[dashboard-recovery] ERROR: refusing symlinked dashboard home"; exit 1; fi;',
    'mkdir -p "$_HERMES_DASHBOARD_HOME"; if [ -L "$_HERMES_DASHBOARD_HOME" ] || [ ! -d "$_HERMES_DASHBOARD_HOME" ]; then echo "[dashboard-recovery] ERROR: unsafe dashboard home"; exit 1; fi;',
    'chmod 700 "$_HERMES_DASHBOARD_HOME"; rm -f "${_HERMES_DASHBOARD_HOME}/gateway_state.json" 2>/dev/null || true;',
    '"$_HERMES_PYTHON" "$_HERMES_DASHBOARD_CONFIG_SEEDER" /sandbox/.hermes/config.yaml "${_HERMES_DASHBOARD_HOME}/config.yaml" /sandbox/.hermes/.env "${_HERMES_DASHBOARD_HOME}/.env" || { echo "[dashboard-recovery] ERROR: config seed failed"; exit 1; };',
    "_DASHBOARD_PROC_PATTERN='[h]ermes[[:space:]]+dashboard([[:space:]]|$)';",
    'pkill -TERM -f "$_DASHBOARD_PROC_PATTERN" 2>/dev/null || true; sleep 1; pkill -KILL -f "$_DASHBOARD_PROC_PATTERN" 2>/dev/null || true;',
    `${hermesDashboardEnvPrefix()} nohup "$AGENT_BIN" dashboard --host 127.0.0.1 --port ${config.internalPort} --skip-build --no-open${tuiFlag} >> "$_DASHBOARD_LOG" 2>&1 &`,
    "DPID=$!; sleep 2;",
    'if kill -0 "$DPID" 2>/dev/null; then echo "DASHBOARD_PID=$DPID"; else echo DASHBOARD_FAILED; tail -5 "$_DASHBOARD_LOG" 2>/dev/null; exit 1; fi ;; esac;',
  ];
}

export function buildHermesDashboardProcessRecoveryScript(
  config: HermesDashboardRecoveryConfig,
): string {
  return [
    "export HERMES_HOME=/sandbox/.hermes;",
    buildHermesEnvFileBoundaryGuard(),
    ...buildGatewayGuardRecoveryLines(),
    '[ "$_GUARDS_MISSING" = "1" ] && { _E="[gateway-recovery] ERROR: NODE_OPTIONS missing safety-net preload or ciao preload after trusted recovery - refusing unguarded dashboard relaunch (#2478/#2701)"; echo "$_E" >&2; exit 1; };',
    "[ -f ~/.bashrc ] && . ~/.bashrc;",
    buildHermesRuntimeEnvBoundaryGuard(),
    "AGENT_BIN=/usr/local/bin/hermes;",
    'if [ ! -x "$AGENT_BIN" ]; then echo AGENT_MISSING; exit 1; fi;',
    ...buildHermesDashboardRecoveryLines(config),
  ].join(" ");
}

export function buildHermesConfigRestartLines(): string[] {
  return [
    "_HERMES_DIR=/sandbox/.hermes;",
    "_HERMES_HASH_FILE=/etc/nemoclaw/hermes.config-hash;",
    '_HERMES_PYTHON=/opt/hermes/.venv/bin/python; [ -x "$_HERMES_PYTHON" ] || _HERMES_PYTHON="$(command -v python3 || echo python3)";',
    "_HERMES_RUNTIME_CONFIG_GUARD=/usr/local/lib/nemoclaw/hermes-runtime-config-guard.py;",
    `[ -f "$_HERMES_RUNTIME_CONFIG_GUARD" ] || { echo ${MARKERS.HERMES_RUNTIME_CONFIG_GUARD_MISSING}; exit 1; };`,
    `[ -d "$_HERMES_DIR" ] && [ ! -L "$_HERMES_DIR" ] || { echo ${MARKERS.HERMES_UNSAFE_CONFIG_PATH}; exit 1; };`,
    '_nemoclaw_mode_has_write_bit() { _mode="$1"; [ -n "$_mode" ] || return 0; _mode="${_mode#0}"; case "$_mode" in \'\'|*[!0-7]*) return 0 ;; *[2367]*) return 0 ;; *) return 1 ;; esac; };',
    '_nemoclaw_owner_mode() { _path="$1"; _owner="$(stat -c \'%U:%G\' "$_path" 2>/dev/null || stat -f \'%Su:%Sg\' "$_path" 2>/dev/null || true)"; _mode="$(stat -c \'%a\' "$_path" 2>/dev/null || stat -f \'%Lp\' "$_path" 2>/dev/null || true)"; printf \'%s %s\\n\' "$_owner" "$_mode"; };',
    '_nemoclaw_hermes_path_locked() { _path="$1"; [ -f "$_path" ] && [ ! -L "$_path" ] || return 1; _om="$(_nemoclaw_owner_mode "$_path")"; _owner="${_om% *}"; _mode="${_om##* }"; [ "$_owner" = "root:root" ] || return 1; ! _nemoclaw_mode_has_write_bit "$_mode"; };',
    '_nemoclaw_hermes_root_locked() { _om="$(_nemoclaw_owner_mode "$_HERMES_DIR")"; _owner="${_om% *}"; _mode="${_om##* }"; case "${_owner} ${_mode}" in \'root:root 755\'|\'root:root 0755\') ;; *) return 1 ;; esac; _nemoclaw_hermes_path_locked "$_HERMES_DIR/config.yaml" && _nemoclaw_hermes_path_locked "$_HERMES_DIR/.env"; };',
    '_nemoclaw_hermes_hash_locked() { [ -f "$_HERMES_HASH_FILE" ] && [ ! -L "$_HERMES_HASH_FILE" ] || return 1; _uid="$(stat -c \'%u\' "$_HERMES_HASH_FILE" 2>/dev/null || stat -f \'%u\' "$_HERMES_HASH_FILE" 2>/dev/null || echo unknown)"; _mode="$(stat -c \'%a\' "$_HERMES_HASH_FILE" 2>/dev/null || stat -f \'%Lp\' "$_HERMES_HASH_FILE" 2>/dev/null || echo unknown)"; [ "$_uid" = "0" ] || return 1; ! _nemoclaw_mode_has_write_bit "$_mode"; };',
    "if _nemoclaw_hermes_root_locked; then",
    `  _nemoclaw_hermes_hash_locked || { echo ${MARKERS.HERMES_UNSAFE_CONFIG_PATH}; exit 1; };`,
    `  sha256sum -c "$_HERMES_HASH_FILE" --status || { echo ${MARKERS.HERMES_LOCKED_HASH_MISMATCH}; exit 1; };`,
    "else",
    `  "$_HERMES_PYTHON" "$_HERMES_RUNTIME_CONFIG_GUARD" refresh-hashes --hermes-dir "$_HERMES_DIR" --hash-file "$_HERMES_HASH_FILE" --mode strict || { echo ${MARKERS.HERMES_UNSAFE_CONFIG_PATH}; exit 1; };`,
    `  "$_HERMES_PYTHON" "$_HERMES_RUNTIME_CONFIG_GUARD" refresh-hashes --hermes-dir "$_HERMES_DIR" --hash-file "$_HERMES_HASH_FILE" --mode compat || { echo ${MARKERS.HERMES_UNSAFE_CONFIG_PATH}; exit 1; };`,
    "fi;",
  ];
}

export function buildHermesRootBoundaryGuard(
  args: "env-file /sandbox/.hermes/.env" | "runtime-env",
): string {
  const gatewayPattern = "[h]ermes[[:space:]]+gateway([[:space:]]|$)";
  const dashboardPattern = "[h]ermes[[:space:]]+dashboard([[:space:]]|$)";
  const kill = [
    `pkill -TERM -f ${shellQuote(gatewayPattern)} 2>/dev/null || true;`,
    `pkill -TERM -f ${shellQuote(dashboardPattern)} 2>/dev/null || true;`,
    "sleep 1;",
    `pkill -KILL -f ${shellQuote(gatewayPattern)} 2>/dev/null || true;`,
    `pkill -KILL -f ${shellQuote(dashboardPattern)} 2>/dev/null || true;`,
  ].join(" ");
  return `python3 ${shellQuote(HERMES_SECRET_BOUNDARY_VALIDATOR_PATH)} ${args} || { ${kill} echo ${MARKERS.SECRET_BOUNDARY_REFUSED}; exit 1; };`;
}

function buildHermesApiSocatRecoveryLines(): string[] {
  return [
    "_HERMES_PUBLIC_PORT=8642;",
    "_HERMES_INTERNAL_PORT=18642;",
    '_HERMES_PUBLIC_CODE=$(curl -so /dev/null -w "%{http_code}" --max-time 3 "http://127.0.0.1:${_HERMES_PUBLIC_PORT}/health" 2>/dev/null || echo 000);',
    'case "$_HERMES_PUBLIC_CODE" in 200|401) echo HERMES_SOCAT_HEALTHY ;; *)',
    '  if ! ss -tln 2>/dev/null | grep -q "[.:]${_HERMES_PUBLIC_PORT}[[:space:]]"; then',
    "    if command -v socat >/dev/null 2>&1; then",
    '      for _i in 1 2 3 4 5 6 7 8 9 10; do ss -tln 2>/dev/null | grep -q "127.0.0.1:${_HERMES_INTERNAL_PORT}[[:space:]]" && break; sleep 1; done;',
    '      nohup socat TCP-LISTEN:"${_HERMES_PUBLIC_PORT}",bind=0.0.0.0,fork,reuseaddr TCP:127.0.0.1:"${_HERMES_INTERNAL_PORT}" >/dev/null 2>&1 &',
    '      echo "HERMES_SOCAT_PID=$!";',
    "    else echo HERMES_SOCAT_MISSING; fi;",
    "  fi ;;",
    "esac;",
  ];
}

function hermesAgentBinaryValidationSteps(agent: AgentDefinition): string[] {
  const binaryPath = agent.binary_path || "/usr/local/bin/hermes";
  return [
    `AGENT_BIN=${shellQuote(binaryPath)};`,
    'if [ ! -x "$AGENT_BIN" ]; then echo AGENT_MISSING; exit 1; fi;',
  ];
}

function buildHermesRootRecoveryPrefix(): string[] {
  return [
    "export HERMES_HOME=/sandbox/.hermes;",
    `[ "$(id -u)" = "0" ] || { echo ${MARKERS.ROOT_EXEC_UNAVAILABLE}; exit 1; };`,
    ...buildGatewayLogSetup(false),
    `${buildNoFollowLogSetupCommand("/tmp/gateway-recovery.log")} || exit 1;`,
    buildGatewayLogSelection(),
    `[ -f ${shellQuote(HERMES_SECRET_BOUNDARY_VALIDATOR_PATH)} ] || { echo ${MARKERS.SECRET_BOUNDARY_VALIDATOR_MISSING}; exit 1; };`,
    buildHermesRootBoundaryGuard("env-file /sandbox/.hermes/.env"),
    ...buildGatewayGuardRecoveryLines(),
    gatewayGuardRefusalCommand(),
    "[ -f ~/.bashrc ] && . ~/.bashrc;",
  ];
}

/**
 * Build the Hermes root-mediated recovery script used by `recover` when the
 * gateway is stopped. Unlike `gateway restart`, this keeps the health fast path
 * so invoking recovery on a healthy gateway remains idempotent.
 */
export function buildHermesGatewayRecoveryScript(agent: AgentDefinition, port: number): string {
  const launchCommand = gatewayRootGosuLaunchCommand(
    `env ${hermesGatewayEnvPrefix()} "$AGENT_BIN" gateway run`,
    "gateway",
  );
  const staleGatewayPattern = "[h]ermes[[:space:]]+gateway[[:space:]]+run([[:space:]]|$)";
  const probeUrl = agent.healthProbe?.url || `http://127.0.0.1:${port}/health`;

  return [
    ...buildHermesRootRecoveryPrefix(),
    `_GW_CODE=$(curl -so /dev/null -w '%{http_code}' --max-time 3 ${shellQuote(probeUrl)} 2>/dev/null || echo 000); case "$_GW_CODE" in 200|401) echo ALREADY_RUNNING; exit 0 ;; esac;`,
    ...buildGatewayStopLines(staleGatewayPattern),
    ...hermesAgentBinaryValidationSteps(agent),
    buildHermesRootBoundaryGuard("runtime-env"),
    launchCommand,
    "GPID=$!; sleep 2;",
    `if kill -0 "$GPID" 2>/dev/null; then echo "GATEWAY_PID=$GPID"; else echo ${MARKERS.GATEWAY_FAILED}; tail -5 "$_GATEWAY_LOG" 2>/dev/null; exit 1; fi;`,
    ...buildHermesApiSocatRecoveryLines(),
  ].join(" ");
}

/**
 * Build the Hermes forced-restart shell script used by
 * `sandbox gateway restart`. This runs only through root sandbox exec so the
 * host, not the sandbox user, mediates gateway-user process control.
 */
export function buildHermesGatewayRestartScript(agent: AgentDefinition, port: number): string {
  const launchCommand = gatewayRootGosuLaunchCommand(
    `env ${hermesGatewayEnvPrefix()} "$AGENT_BIN" gateway run`,
    "gateway",
  );
  const staleGatewayPattern = "[h]ermes[[:space:]]+gateway[[:space:]]+run([[:space:]]|$)";

  return [
    `export HERMES_HOME=/sandbox/.hermes; _NEMOCLAW_RESTART_HEALTH_PORT=${port};`,
    `[ "$(id -u)" = "0" ] || { echo ${MARKERS.ROOT_EXEC_UNAVAILABLE}; exit 1; };`,
    ...buildGatewayLogSetup(false),
    `${buildNoFollowLogSetupCommand("/tmp/gateway-recovery.log")} || exit 1;`,
    buildGatewayLogSelection(),
    `[ -f ${shellQuote(HERMES_SECRET_BOUNDARY_VALIDATOR_PATH)} ] || { echo ${MARKERS.SECRET_BOUNDARY_VALIDATOR_MISSING}; exit 1; };`,
    buildHermesRootBoundaryGuard("env-file /sandbox/.hermes/.env"),
    ...buildGatewayGuardRecoveryLines(),
    gatewayGuardRefusalCommand(),
    "[ -f ~/.bashrc ] && . ~/.bashrc;",
    buildHermesRootBoundaryGuard("runtime-env"),
    ...buildHermesConfigRestartLines(),
    ...buildGatewayStopLines(staleGatewayPattern),
    ...hermesAgentBinaryValidationSteps(agent),
    launchCommand,
    "GPID=$!; sleep 2;",
    `if kill -0 "$GPID" 2>/dev/null; then echo "GATEWAY_PID=$GPID"; else echo ${MARKERS.GATEWAY_FAILED}; tail -5 "$_GATEWAY_LOG" 2>/dev/null; exit 1; fi;`,
    ...buildHermesApiSocatRecoveryLines(),
  ].join(" ");
}
