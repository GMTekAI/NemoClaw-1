// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { HERMES_SECRET_BOUNDARY_VALIDATOR_PATH } from "../../../dist/lib/agent/hermes-recovery-boundary";
import {
  buildHermesGatewayRecoveryScript,
  buildHermesGatewayRestartScript,
  buildManualRecoveryCommand,
  buildOpenClawGatewayRestartScript,
} from "../../../dist/lib/agent/runtime";
import {
  createRecoveryPreloadHarnessPaths,
  type RecoveryPreloadHarnessPaths,
  rewriteRecoveryPreloadPaths,
} from "../../../test/helpers/runtime-recovery-preload-test-helpers";
import type { AgentDefinition } from "./defs";

function makeAgent(overrides: Partial<AgentDefinition> = {}): AgentDefinition {
  return {
    name: "test-agent",
    displayName: "Test Agent",
    binary_path: "/usr/local/bin/test-agent",
    gateway_command: "test-agent gateway run",
    healthProbe: { url: "http://127.0.0.1:19000/", port: 19000, timeout_seconds: 5 },
    forwardPort: 19000,
    dashboard: { kind: "ui", label: "UI", path: "/", healthPath: "/health", auth: "url_token" },
    webAuth: { method: "none", env: null },
    configPaths: {
      dir: "/tmp/agent",
      configFile: "/tmp/agent/config.yaml",
      envFile: null,
      format: "yaml",
    },
    inferenceProviderOptions: [],
    stateDirs: [],
    stateFiles: [],
    userManagedFiles: [],
    versionCommand: "test-agent --version",
    expectedVersion: null,
    hasDevicePairing: false,
    phoneHomeHosts: [],
    dockerfileBasePath: null,
    dockerfilePath: null,
    startScriptPath: null,
    policyAdditionsPath: null,
    policyPermissivePath: null,
    pluginDir: null,
    legacyPaths: null,
    agentDir: "/tmp/agent",
    manifestPath: "/tmp/agent/manifest.yaml",
    ...overrides,
  };
}

const minimalAgent = makeAgent();
const hermesAgent = makeAgent({
  name: "hermes",
  displayName: "Hermes Agent",
  binary_path: "/usr/local/bin/hermes",
  gateway_command: "hermes gateway run",
  healthProbe: { url: "http://localhost:8642/health", port: 8642, timeout_seconds: 90 },
  forwardPort: 8642,
  configPaths: {
    dir: "/sandbox/.hermes",
    configFile: "/sandbox/.hermes/config.yaml",
    envFile: "/sandbox/.hermes/.env",
    format: "yaml",
  },
});

interface HermesRestartHarness extends RecoveryPreloadHarnessPaths {
  tmp: string;
  stubsDir: string;
  hermesDir: string;
  etcNemoclawDir: string;
  validatorPath: string;
  configGuardPath: string;
  gatewayLogPath: string;
  recoveryLogPath: string;
  proxyEnvPath: string;
  recoveredProxyEnvPath: string;
  hermesBin: string;
  pkillLog: string;
  guardLog: string;
  gosuLog: string;
  launchMarker: string;
}

function writeStub(dir: string, name: string, body: string) {
  const stub = path.join(dir, name);
  fs.writeFileSync(stub, `#!/usr/bin/env bash\n${body}\n`, { mode: 0o755 });
  return stub;
}

function removeTempDir(dir: string) {
  fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

function prepareHermesRestartHarness(name: string): HermesRestartHarness {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `nemoclaw-hermes-restart-${name}-`));
  const stubsDir = path.join(tmp, "bin");
  const hermesDir = path.join(tmp, "sandbox", ".hermes");
  const etcNemoclawDir = path.join(tmp, "etc", "nemoclaw");
  const validatorPath = path.join(tmp, "usr-local-lib-nemoclaw", "validate-boundary.py");
  const configGuardPath = path.join(
    tmp,
    "usr-local-lib-nemoclaw",
    "hermes-runtime-config-guard.py",
  );
  const hermesBin = path.join(stubsDir, "hermes");
  const harness = {
    tmp,
    stubsDir,
    hermesDir,
    etcNemoclawDir,
    validatorPath,
    configGuardPath,
    gatewayLogPath: path.join(tmp, "gateway.log"),
    recoveryLogPath: path.join(tmp, "gateway-recovery.log"),
    proxyEnvPath: path.join(tmp, "nemoclaw-proxy-env.sh"),
    recoveredProxyEnvPath: path.join(tmp, "nemoclaw-recovered-proxy-env.sh"),
    hermesBin,
    pkillLog: path.join(tmp, "pkill.log"),
    guardLog: path.join(tmp, "guard.log"),
    gosuLog: path.join(tmp, "gosu.log"),
    launchMarker: path.join(tmp, "hermes-launched"),
    ...createRecoveryPreloadHarnessPaths(tmp),
  };

  fs.mkdirSync(stubsDir, { recursive: true });
  fs.mkdirSync(hermesDir, { recursive: true });
  fs.mkdirSync(etcNemoclawDir, { recursive: true });
  fs.mkdirSync(path.dirname(validatorPath), { recursive: true });
  fs.writeFileSync(path.join(hermesDir, "config.yaml"), "telegram:\n  enabled: false\n");
  fs.writeFileSync(path.join(hermesDir, ".env"), "API_SERVER_PORT=18642\n");
  fs.writeFileSync(validatorPath, "#!/usr/bin/env python3\n");
  fs.writeFileSync(configGuardPath, "#!/usr/bin/env python3\n");
  fs.writeFileSync(hermesBin, "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
  return harness;
}

function installHermesRestartStubs(harness: HermesRestartHarness) {
  writeStub(
    harness.stubsDir,
    "id",
    [
      'if [ "${1:-}" = "-u" ]; then echo 0; exit 0; fi',
      'if [ "${1:-}" = "gateway" ]; then exit 0; fi',
      "exit 0",
    ].join("\n"),
  );
  writeStub(
    harness.stubsDir,
    "python3",
    [
      'if [ "${1:-}" = "-c" ]; then',
      '  : > "$3"',
      "  exit 0",
      "fi",
      `if [ "$1" = ${JSON.stringify(harness.configGuardPath)} ]; then`,
      `  printf '%s\\n' "$*" >> ${JSON.stringify(harness.guardLog)}`,
      "  exit 0",
      "fi",
      'mode="${2:-}"',
      'if [ "$mode" = "env-file" ]; then',
      '  if [ "${STUB_ENVFILE_EXIT:-0}" = "1" ]; then',
      '    printf "[SECURITY] Refusing Hermes startup because /sandbox/.hermes/.env contains raw secret-shaped values.\\n" >&2',
      '    printf "[SECURITY]   TELEGRAM_BOT_TOKEN (line 2)\\n" >&2',
      "    exit 1",
      "  fi",
      "  exit 0",
      "fi",
      'if [ "$mode" = "runtime-env" ]; then',
      '  if [ "${STUB_RUNTIMEENV_EXIT:-0}" = "1" ]; then',
      '    printf "[SECURITY] Refusing Hermes startup because the process environment contains raw secret-shaped values.\\n" >&2',
      '    printf "[SECURITY]   TELEGRAM_BOT_TOKEN\\n" >&2',
      "    exit 1",
      "  fi",
      "  exit 0",
      "fi",
      "exit 2",
    ].join("\n"),
  );
  writeStub(
    harness.stubsDir,
    "stat",
    [
      'fmt="${1:-}"; target="${3:-${2:-}}"',
      'case "$fmt" in',
      "  -c)",
      '    case "${2:-}" in',
      "      %u) echo 0 ;;",
      "      %a)",
      '        case "$target" in',
      "          *preload-tmp*|*nemoclaw-proxy-env.sh|*nemoclaw-recovered-proxy-env.sh) echo 444 ;;",
      "          *) echo 644 ;;",
      "        esac",
      "        ;;",
      "      %U:%G) echo sandbox:sandbox ;;",
      '      *) /usr/bin/stat "$@" ;;',
      "    esac",
      "    ;;",
      "  -f)",
      '    case "${2:-}" in',
      "      %u) echo 0 ;;",
      "      %Lp) echo 644 ;;",
      "      %Su:%Sg) echo sandbox:sandbox ;;",
      '      *) /usr/bin/stat "$@" ;;',
      "    esac",
      "    ;;",
      '  *) /usr/bin/stat "$@" ;;',
      "esac",
    ].join("\n"),
  );
  writeStub(
    harness.stubsDir,
    "pkill",
    `printf '%s\\n' "$*" >> ${JSON.stringify(harness.pkillLog)}\nexit 0`,
  );
  writeStub(harness.stubsDir, "pgrep", "exit 1");
  writeStub(harness.stubsDir, "chown", "exit 0");
  writeStub(harness.stubsDir, "sleep", "exit 0");
  writeStub(harness.stubsDir, "curl", 'printf "000"\nexit 0');
  writeStub(harness.stubsDir, "ss", 'printf "LISTEN 0 4096 127.0.0.1:18642 0.0.0.0:*\\n"\nexit 0');
  writeStub(
    harness.stubsDir,
    "gosu",
    `printf '%s\\n' "$*" >> ${JSON.stringify(harness.gosuLog)}\n: > ${JSON.stringify(
      harness.launchMarker,
    )}\n/bin/sleep 1`,
  );
  writeStub(harness.stubsDir, "socat", "/bin/sleep 1");
  writeStub(harness.stubsDir, "sha256sum", "exit 0");
}

function rewriteHermesRestartScript(script: string, harness: HermesRestartHarness): string {
  return rewriteRecoveryPreloadPaths(script, harness)
    .replaceAll(HERMES_SECRET_BOUNDARY_VALIDATOR_PATH, harness.validatorPath)
    .replaceAll("/usr/local/lib/nemoclaw/hermes-runtime-config-guard.py", harness.configGuardPath)
    .replaceAll("/usr/local/bin/hermes", harness.hermesBin)
    .replaceAll("/sandbox/.hermes", harness.hermesDir)
    .replaceAll("/etc/nemoclaw", harness.etcNemoclawDir)
    .replaceAll("/tmp/gateway-recovery.log", harness.recoveryLogPath)
    .replaceAll("/tmp/gateway.log", harness.gatewayLogPath)
    .replaceAll("/tmp/nemoclaw-recovered-proxy-env.sh", harness.recoveredProxyEnvPath)
    .replaceAll("/tmp/nemoclaw-proxy-env.sh", harness.proxyEnvPath)
    .replaceAll("/tmp/.nemoclaw-proxy-env.sh.tmp.", `${harness.tmp}/.nemoclaw-proxy-env.sh.tmp.`);
}

function runHermesRestartScript(harness: HermesRestartHarness, env: Record<string, string> = {}) {
  const script = rewriteHermesRestartScript(
    buildHermesGatewayRestartScript(hermesAgent, 8642),
    harness,
  );
  return spawnSync("/bin/sh", ["-c", script], {
    encoding: "utf-8",
    timeout: 15_000,
    env: {
      HOME: harness.tmp,
      PATH: `${harness.stubsDir}:/usr/bin:/bin`,
      ...env,
    },
  });
}

describe("buildHermesGatewayRestartScript (#2426)", () => {
  it("uses root/gateway relaunch, HERMES_HOME, and no port override", () => {
    const script = buildHermesGatewayRestartScript(hermesAgent, 8642);

    expect(script).toContain('[ "$(id -u)" = "0" ] || { echo ROOT_EXEC_UNAVAILABLE; exit 1; };');
    expect(script).toContain("gosu 'gateway' env HERMES_HOME=/sandbox/.hermes");
    expect(script).toContain('"$AGENT_BIN" gateway run');
    expect(script).toContain("AGENT_BIN='/usr/local/bin/hermes';");
    expect(script).toContain('if [ ! -x "$AGENT_BIN" ]; then echo AGENT_MISSING; exit 1; fi;');
    expect(script).toContain("export HERMES_HOME=/sandbox/.hermes");
    expect(script).not.toContain("command -v 'hermes'");
    expect(script).not.toContain("--port 8642");
    expect(script).not.toContain("ALREADY_RUNNING");
  });

  it("ignores custom Hermes gateway_command shell text for root-mediated restart", () => {
    const script = buildHermesGatewayRestartScript(
      makeAgent({
        ...hermesAgent,
        gateway_command: "hermes gateway run; touch /tmp/nemoclaw-review-finding",
      }),
      8642,
    );

    expect(script).toContain('"$AGENT_BIN" gateway run');
    expect(script).not.toContain("touch /tmp/nemoclaw-review-finding");
    expect(script).not.toContain("GATEWAY_CMD_BIN");
  });

  it("keeps the root-exec shell compatible with sh", () => {
    const script = buildHermesGatewayRestartScript(hermesAgent, 8642);
    const configSection = script.slice(
      script.indexOf("_HERMES_DIR=/sandbox/.hermes;"),
      script.indexOf("_GATEWAY_PROC_PATTERN="),
    );

    expect(configSection).not.toMatch(/(^|[;\s])local\s+/);
  });

  it("validates Hermes boundaries before hash adoption and relaunch", () => {
    const script = buildHermesGatewayRestartScript(hermesAgent, 8642);

    const envBoundaryIdx = script.indexOf("env-file /sandbox/.hermes/.env");
    const runtimeBoundaryIdx = script.indexOf("runtime-env");
    const refreshHashIdx = script.indexOf("refresh-hashes --hermes-dir");
    const stopIdx = script.indexOf('pkill -TERM -f "$_GATEWAY_PROC_PATTERN"');
    const launchIdx = script.indexOf("gosu 'gateway'");

    expect(envBoundaryIdx).toBeGreaterThanOrEqual(0);
    expect(runtimeBoundaryIdx).toBeGreaterThan(envBoundaryIdx);
    expect(refreshHashIdx).toBeGreaterThan(runtimeBoundaryIdx);
    expect(stopIdx).toBeGreaterThan(refreshHashIdx);
    expect(launchIdx).toBeGreaterThan(stopIdx);
  });

  it("verifies locked hashes and refreshes strict and compatibility hashes only for mutable config state", () => {
    const script = buildHermesGatewayRestartScript(hermesAgent, 8642);

    expect(script).toContain("if _nemoclaw_hermes_root_locked; then");
    expect(script).toContain(
      "_nemoclaw_hermes_hash_locked || { echo HERMES_UNSAFE_CONFIG_PATH; exit 1; };",
    );
    expect(script).toContain('sha256sum -c "$_HERMES_HASH_FILE" --status');
    expect(script).toContain("HERMES_LOCKED_HASH_MISMATCH");
    expect(script).toContain("--mode strict");
    expect(script).toContain("--mode compat");

    const lockedIdx = script.indexOf("if _nemoclaw_hermes_root_locked; then");
    const hashLockedIdx = script.indexOf("_nemoclaw_hermes_hash_locked", lockedIdx);
    const strictVerifyIdx = script.indexOf('sha256sum -c "$_HERMES_HASH_FILE" --status');
    const elseIdx = script.indexOf("else", strictVerifyIdx);
    const strictRefreshIdx = script.indexOf("--mode strict", elseIdx);
    const compatRefreshIdx = script.indexOf("--mode compat", elseIdx);
    const fiIdx = script.indexOf("fi;", compatRefreshIdx);
    const lockedBranch = script.slice(lockedIdx, elseIdx);
    const mutableBranch = script.slice(elseIdx, fiIdx);

    expect(lockedIdx).toBeGreaterThanOrEqual(0);
    expect(hashLockedIdx).toBeGreaterThan(lockedIdx);
    expect(hashLockedIdx).toBeLessThan(strictVerifyIdx);
    expect(strictVerifyIdx).toBeGreaterThan(lockedIdx);
    expect(strictRefreshIdx).toBeGreaterThan(elseIdx);
    expect(compatRefreshIdx).toBeGreaterThan(strictRefreshIdx);
    expect(lockedBranch).not.toContain("refresh-hashes");
    expect(mutableBranch).toContain("refresh-hashes --hermes-dir");
    expect(mutableBranch).not.toContain('sha256sum -c "$_HERMES_HASH_FILE" --status');
  });

  it("preserves or recreates the Hermes API socat bridge before health validation", () => {
    const script = buildHermesGatewayRestartScript(hermesAgent, 8642);

    expect(script).toContain("HERMES_SOCAT_HEALTHY");
    expect(script).toContain("TCP-LISTEN");
    expect(script).toContain("18642");
    expect(script).toContain("8642");
  });

  it("executes under /bin/sh -c and refuses poisoned env before launch", () => {
    const harness = prepareHermesRestartHarness("refusal");
    installHermesRestartStubs(harness);

    try {
      const result = runHermesRestartScript(harness, { STUB_ENVFILE_EXIT: "1" });

      expect(result.status).toBe(1);
      expect(result.stdout).toContain("SECRET_BOUNDARY_REFUSED");
      expect(result.stdout).not.toContain("GATEWAY_PID=");
      expect(fs.existsSync(harness.launchMarker)).toBe(false);
      const pkillCalls = fs.readFileSync(harness.pkillLog, "utf-8");
      expect(pkillCalls).toContain("[h]ermes");
      expect(pkillCalls).toContain("gateway");
      expect(pkillCalls).toContain("dashboard");
    } finally {
      removeTempDir(harness.tmp);
    }
  });

  it("executes under /bin/sh -c and launches after mutable hash refresh", () => {
    const harness = prepareHermesRestartHarness("launch");
    installHermesRestartStubs(harness);

    try {
      const result = runHermesRestartScript(harness);

      expect(result.status).toBe(0);
      expect(result.stdout).toContain("GATEWAY_PID=");
      expect(result.stdout).toContain("HERMES_SOCAT_PID=");
      expect(fs.existsSync(harness.launchMarker)).toBe(true);
      const guardCalls = fs.readFileSync(harness.guardLog, "utf-8");
      expect(guardCalls).toContain("refresh-hashes");
      expect(guardCalls).toContain("--mode strict");
      expect(guardCalls).toContain("--mode compat");
      const gosuCall = fs.readFileSync(harness.gosuLog, "utf-8");
      expect(gosuCall).toContain(`gateway env HERMES_HOME=${harness.hermesDir}`);
      expect(gosuCall).toContain(`${harness.hermesBin} gateway run`);
      expect(gosuCall).not.toContain("--port 8642");
    } finally {
      removeTempDir(harness.tmp);
    }
  });
});

describe("buildHermesGatewayRecoveryScript (#2426)", () => {
  it("keeps recover idempotent while relaunching stopped Hermes gateways as gateway", () => {
    const script = buildHermesGatewayRecoveryScript(hermesAgent, 8642);

    expect(script).toContain("ALREADY_RUNNING");
    expect(script).toContain("gosu 'gateway'");
    expect(script).toContain("HERMES_HOME=/sandbox/.hermes");
    expect(script).toContain('"$AGENT_BIN" gateway run');
    expect(script).not.toContain('"$AGENT_BIN" gateway run --port 8642');
    expect(script).not.toContain("_NEMOCLAW_RESTART_HEALTH_PORT");
    expect(script).not.toContain("command -v 'hermes'");
  });
});

describe("buildOpenClawGatewayRestartScript (#2426)", () => {
  it("force-restarts OpenClaw as the gateway user without a healthy fast path", () => {
    const script = buildOpenClawGatewayRestartScript(18789);

    const rootCheckIndex = script.indexOf("ROOT_EXEC_UNAVAILABLE");
    const logSetupIndex = script.indexOf("_GATEWAY_LOG=/tmp/gateway.log");
    const lockRemovalIndex = script.indexOf("rm -rf /tmp/openclaw-*/gateway.*.lock");
    const stopIndex = script.indexOf('pkill -TERM -f "$_GATEWAY_PROC_PATTERN"');

    expect(rootCheckIndex).toBeGreaterThanOrEqual(0);
    expect(logSetupIndex).toBeGreaterThanOrEqual(0);
    expect(lockRemovalIndex).toBeGreaterThanOrEqual(0);
    expect(stopIndex).toBeGreaterThanOrEqual(0);
    expect(rootCheckIndex).toBeLessThan(logSetupIndex);
    expect(rootCheckIndex).toBeLessThan(lockRemovalIndex);
    expect(rootCheckIndex).toBeLessThan(stopIndex);
    expect(script).toContain("gosu 'gateway'");
    expect(script).toContain('"$OPENCLAW" gateway run --port 18789');
    expect(script).toContain('pkill -TERM -f "$_GATEWAY_PROC_PATTERN"');
    expect(script).toContain("GATEWAY_STALE_PROCESSES");
    expect(script).toContain("O_NONBLOCK");
    expect(script).toContain("errno.ENXIO");
    expect(script).not.toContain("ALREADY_RUNNING");
  });
});

describe("buildManualRecoveryCommand (#2426)", () => {
  it("backgrounds non-Hermes gateways with nohup and the requested port", () => {
    const cmd = buildManualRecoveryCommand(minimalAgent, 19000);
    expect(cmd).toContain("nohup test-agent gateway run --port 19000");
    expect(cmd).toContain('>> "$_GATEWAY_LOG" 2>&1 &');
  });

  it("selects a writable gateway log before launching", () => {
    const cmd = buildManualRecoveryCommand(minimalAgent, 19000);
    expect(cmd).toContain("_GATEWAY_LOG=/tmp/gateway.log");
    expect(cmd).toContain("_GATEWAY_LOG=/tmp/gateway-recovery.log");
    expect(cmd).not.toContain(">/tmp/gateway.log 2>&1");
  });

  it("uses the same preload guard before the manual nohup launch", () => {
    const cmd = buildManualRecoveryCommand(minimalAgent, 19000);
    const guardIndex = cmd.indexOf("_GUARDS_MISSING");
    const launchIndex = cmd.indexOf("nohup test-agent gateway run --port 19000");
    expect(cmd).toContain("nemoclaw-sandbox-safety-net");
    expect(cmd).toContain("nemoclaw-ciao-network-guard");
    expect(cmd).toContain("refusing unguarded gateway relaunch");
    expect(guardIndex).toBeGreaterThanOrEqual(0);
    expect(launchIndex).toBeGreaterThan(guardIndex);
  });

  it("omits --port for Hermes and uses the current Hermes home", () => {
    const cmd = buildManualRecoveryCommand(hermesAgent, 8642);
    expect(cmd).toContain("HERMES_HOME=/sandbox/.hermes");
    expect(cmd).not.toContain("DISCORD_PROXY=");
    expect(cmd).not.toContain("PYTHONPATH=/opt/nemoclaw-hermes-discord-preload");
    expect(cmd).not.toContain("HTTPS_PROXY=http://127.0.0.1:3129");
    expect(cmd).not.toContain("nemoclaw-decode-proxy");
    expect(cmd).not.toContain("nemoclaw-discord-facade");
    expect(cmd).not.toContain("NEMOCLAW_DISCORD_FACADE_URL");
    expect(cmd).toContain("nohup hermes gateway run");
    expect(cmd).not.toContain("--port 8642");
    expect(cmd).not.toContain("/sandbox/.hermes-data");
  });

  it("derives the default gateway command from binary_path when gateway_command is blank", () => {
    const agent = makeAgent({ gateway_command: "   " });
    const cmd = buildManualRecoveryCommand(agent, 19000);
    expect(cmd).toContain("nohup '/usr/local/bin/test-agent' gateway run --port 19000");
  });

  it("falls back to openclaw gateway run for a null agent", () => {
    const cmd = buildManualRecoveryCommand(null, 18789);
    expect(cmd).toContain("nohup '/usr/local/bin/openclaw' gateway run --port 18789");
  });
});
