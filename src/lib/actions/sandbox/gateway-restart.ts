// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as agentRuntime from "../../agent/runtime";
import { G, R } from "../../cli/terminal-style";
import { redactFull } from "../../security/redact";

export type GatewayRestartCommandResult = {
  status: number;
  stdout: string;
  stderr: string;
};

export type GatewayRestartFailureLayer =
  | "unsupported agent"
  | "root exec unavailable"
  | "secret-boundary refusal"
  | "unsafe config path"
  | "hash mismatch while locked"
  | "launch failure"
  | "health timeout";

export type GatewayRestartResult =
  | {
      ok: true;
      restarted: true;
      healthPassed: true;
      forwardRecovered: boolean;
    }
  | {
      ok: false;
      failureLayer: GatewayRestartFailureLayer;
      detail: string;
    };

type SandboxAgentLookup = (sandboxName: string) => { agent?: string | null } | null | undefined;

type SandboxExec = (
  sandboxName: string,
  command: string,
  timeout?: number,
) => GatewayRestartCommandResult | null;

export type GatewayRestartDeps = {
  getSessionAgent: typeof agentRuntime.getSessionAgent;
  getSandbox: SandboxAgentLookup;
  resolveSandboxDashboardPort: (sandboxName: string) => number;
  buildOpenClawGatewayRestartScript: typeof agentRuntime.buildOpenClawGatewayRestartScript;
  buildHermesGatewayRestartScript: typeof agentRuntime.buildHermesGatewayRestartScript;
  executeSandboxExecCommand: SandboxExec;
  waitForRecoveredSandboxGateway: (sandboxName: string, options?: { quiet?: boolean }) => boolean;
  ensureSandboxPortForward: (sandboxName: string) => boolean;
  ensureHermesDashboardPortForwardIfEnabled: (sandboxName: string) => boolean | null;
  recoverHermesDashboardProcessIfEnabled: (sandboxName: string) => boolean | null;
  recoverMessagingHostForward: (sandboxName: string, options: { quiet: boolean }) => boolean | null;
  recoverDeclaredAgentForwardPorts: (
    sandboxName: string,
    recoveryPort: number,
    options: { quiet: boolean },
  ) => boolean | null;
  printGatewayWedgeDiagnostics: (
    sandboxName: string,
    exec: (sandboxName: string, command: string) => GatewayRestartCommandResult | null,
  ) => boolean;
};

export type RestartSandboxGatewayOptions = {
  quiet?: boolean;
  deps?: Partial<GatewayRestartDeps>;
};

export function sandboxAgentName(
  sandboxName: string,
  getSandbox: SandboxAgentLookup,
): string | null {
  try {
    return getSandbox(sandboxName)?.agent ?? null;
  } catch {
    return null;
  }
}

function gatewayRestartOutput(result: GatewayRestartCommandResult): string {
  return [result.stdout, result.stderr].filter(Boolean).join("\n");
}

const ANSI_CONTROL_RE =
  /\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\)|[@-_])|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

function sanitizeGatewayRestartFailureLine(line: string): string {
  return redactFull(line.replace(ANSI_CONTROL_RE, ""));
}

export function classifyGatewayRestartFailure(result: GatewayRestartCommandResult | null): {
  layer: GatewayRestartFailureLayer;
  detail: string;
} {
  if (!result) {
    return {
      layer: "root exec unavailable",
      detail: "root sandbox exec did not return command output",
    };
  }

  const output = gatewayRestartOutput(result);
  if (
    output.includes("ROOT_EXEC_UNAVAILABLE") ||
    output.includes("GOSU_MISSING") ||
    output.includes("GATEWAY_USER_MISSING")
  ) {
    return { layer: "root exec unavailable", detail: output.trim() || "root exec unavailable" };
  }
  if (output.includes("SECRET_BOUNDARY_REFUSED")) {
    return { layer: "secret-boundary refusal", detail: output.trim() || "boundary refused" };
  }
  if (
    output.includes("HERMES_UNSAFE_CONFIG_PATH") ||
    output.includes("HERMES_RUNTIME_CONFIG_GUARD_MISSING") ||
    output.includes("SECRET_BOUNDARY_VALIDATOR_MISSING") ||
    output.includes("refusing unsafe Hermes runtime config path") ||
    output.includes("refusing runtime config update") ||
    output.includes("refusing to follow symlink") ||
    output.includes("refusing hardlinked runtime config path")
  ) {
    return { layer: "unsafe config path", detail: output.trim() || "unsafe config path" };
  }
  if (output.includes("HERMES_LOCKED_HASH_MISMATCH")) {
    return {
      layer: "hash mismatch while locked",
      detail: output.trim() || "Hermes config hash mismatch while locked",
    };
  }
  return { layer: "launch failure", detail: output.trim() || `restart exited ${result.status}` };
}

export function printGatewayRestartFailure(
  sandboxName: string,
  layer: GatewayRestartFailureLayer,
  detail: string,
): void {
  console.error(`  Failure layer: ${layer} - gateway restart failed for '${sandboxName}'.`);
  if (!detail.trim()) return;
  const lines = detail
    .split(/\r?\n/)
    .map((line) => sanitizeGatewayRestartFailureLine(line.trim()))
    .filter(Boolean)
    .slice(-12);
  for (const line of lines) {
    console.error(`  ${line}`);
  }
}

function isValidPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 65535;
}

function restartPortForAgent(
  agent: ReturnType<typeof agentRuntime.getSessionAgent>,
  fallback: number,
): number {
  const port = (agent as { healthProbe?: { port?: unknown } } | null)?.healthProbe?.port;
  return isValidPort(port) ? port : fallback;
}

export function restartSandboxGatewayWithDeps(
  sandboxName: string,
  {
    quiet = false,
    deps,
  }: {
    quiet?: boolean;
    deps: GatewayRestartDeps;
  },
): GatewayRestartResult {
  const agent = deps.getSessionAgent(sandboxName);
  const persistedAgent = sandboxAgentName(sandboxName, deps.getSandbox);
  const agentName = agent?.name ?? persistedAgent ?? "openclaw";
  const dashboardPort = deps.resolveSandboxDashboardPort(sandboxName);

  let script: string | null = null;
  if (!agent && persistedAgent && persistedAgent !== "openclaw") {
    const detail = `${persistedAgent} agent definition could not be loaded.`;
    printGatewayRestartFailure(sandboxName, "unsupported agent", detail);
    return { ok: false, failureLayer: "unsupported agent", detail };
  }
  if (agent && !agentRuntime.hasGatewayRuntime(agent)) {
    const detail = `${agentRuntime.getAgentDisplayName(agent)} has no gateway runtime.`;
    printGatewayRestartFailure(sandboxName, "unsupported agent", detail);
    return { ok: false, failureLayer: "unsupported agent", detail };
  }
  if (agentName === "hermes") {
    if (!agent || agent.name !== "hermes") {
      const detail = "Hermes agent definition could not be loaded.";
      printGatewayRestartFailure(sandboxName, "unsupported agent", detail);
      return { ok: false, failureLayer: "unsupported agent", detail };
    }
    script = deps.buildHermesGatewayRestartScript(agent, restartPortForAgent(agent, dashboardPort));
  } else if (!agent || agentName === "openclaw") {
    script = deps.buildOpenClawGatewayRestartScript(dashboardPort);
  } else {
    const detail =
      `${agentRuntime.getAgentDisplayName(agent)} does not declare a supported root-mediated ` +
      "gateway restart runtime.";
    printGatewayRestartFailure(sandboxName, "unsupported agent", detail);
    return { ok: false, failureLayer: "unsupported agent", detail };
  }

  if (!quiet) {
    console.log("");
    console.log(
      `  Restarting ${agentRuntime.getAgentDisplayName(agent)} gateway in '${sandboxName}'...`,
    );
  }
  const restartResult = deps.executeSandboxExecCommand(sandboxName, script, 30000);
  const hasRestartMarker =
    restartResult?.status === 0 &&
    restartResult.stdout.split(/\r?\n/).some((line) => line.startsWith("GATEWAY_PID="));
  if (!hasRestartMarker) {
    const failure = classifyGatewayRestartFailure(restartResult);
    printGatewayRestartFailure(sandboxName, failure.layer, failure.detail);
    return { ok: false, failureLayer: failure.layer, detail: failure.detail };
  }

  if (!deps.waitForRecoveredSandboxGateway(sandboxName, { quiet })) {
    const detail = "gateway process restarted but health did not pass before timeout";
    printGatewayRestartFailure(sandboxName, "health timeout", detail);
    deps.printGatewayWedgeDiagnostics(sandboxName, deps.executeSandboxExecCommand);
    return { ok: false, failureLayer: "health timeout", detail };
  }

  const forwardRecovered = deps.ensureSandboxPortForward(sandboxName);
  const dashboardProcessRecovered = deps.recoverHermesDashboardProcessIfEnabled(sandboxName);
  const dashboardForwardRecovered = deps.ensureHermesDashboardPortForwardIfEnabled(sandboxName);
  const messagingForwardRecovered = deps.recoverMessagingHostForward(sandboxName, { quiet });
  const declaredForwardsRecovered = deps.recoverDeclaredAgentForwardPorts(
    sandboxName,
    dashboardPort,
    { quiet },
  );

  if (!quiet) {
    if (!forwardRecovered) {
      console.error("  Dashboard port forward could not be re-established.");
    }
    console.log(
      `  ${G}✓${R} Gateway restarted; health passed; forwards checked/recovered for '${sandboxName}'.`,
    );
  }
  return {
    ok: true,
    restarted: true,
    healthPassed: true,
    forwardRecovered:
      forwardRecovered ||
      dashboardProcessRecovered === true ||
      dashboardForwardRecovered === true ||
      messagingForwardRecovered === true ||
      declaredForwardsRecovered === true,
  };
}
