// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  buildHermesGatewayRecoveryScript,
  buildHermesGatewayRestartScript,
  buildManualRecoveryCommand,
  buildOpenClawGatewayRestartScript,
} from "../../../dist/lib/agent/runtime";
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
