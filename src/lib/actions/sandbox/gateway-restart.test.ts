// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { createRequire } from "node:module";

import { afterEach, describe, expect, it, vi } from "vitest";

import { classifyGatewayRestartFailure } from "../../../../dist/lib/actions/sandbox/gateway-restart";
import { restartSandboxGateway } from "../../../../dist/lib/actions/sandbox/process-recovery";
import { GATEWAY_RESTART_MARKERS as MARKERS } from "../../../../dist/lib/agent/gateway-restart-markers";
import {
  buildHermesGatewayRestartScript,
  buildOpenClawGatewayRestartScript,
} from "../../../../dist/lib/agent/runtime";

const requireDist = createRequire(import.meta.url);

afterEach(() => {
  vi.restoreAllMocks();
});

describe("gateway restart failure markers", () => {
  it("keeps generated Hermes restart markers aligned with the classifier", () => {
    const script = buildHermesGatewayRestartScript(
      {
        name: "hermes",
        displayName: "Hermes Agent",
        binary_path: "/usr/local/bin/hermes",
        gateway_command: "hermes gateway run",
      } as never,
      8642,
    );
    const expectedMarkers: Array<
      [string, ReturnType<typeof classifyGatewayRestartFailure>["layer"]]
    > = [
      [MARKERS.ROOT_EXEC_UNAVAILABLE, "root exec unavailable"],
      [MARKERS.GOSU_MISSING, "root exec unavailable"],
      [MARKERS.GATEWAY_USER_MISSING, "root exec unavailable"],
      [MARKERS.SECRET_BOUNDARY_REFUSED, "secret-boundary refusal"],
      [MARKERS.SECRET_BOUNDARY_VALIDATOR_MISSING, "unsafe config path"],
      [MARKERS.HERMES_RUNTIME_CONFIG_GUARD_MISSING, "unsafe config path"],
      [MARKERS.HERMES_UNSAFE_CONFIG_PATH, "unsafe config path"],
      [MARKERS.HERMES_LOCKED_HASH_MISMATCH, "hash mismatch while locked"],
      [MARKERS.GATEWAY_FAILED, "launch failure"],
    ] as const;

    for (const [marker, layer] of expectedMarkers) {
      expect(script).toContain(marker);
      expect(
        classifyGatewayRestartFailure({
          status: 1,
          stdout: marker,
          stderr: "",
        }),
      ).toMatchObject({ layer });
    }
  });

  it("keeps generated OpenClaw restart markers aligned with the classifier", () => {
    const script = buildOpenClawGatewayRestartScript(18789);
    const expectedMarkers: Array<
      [string, ReturnType<typeof classifyGatewayRestartFailure>["layer"]]
    > = [
      [MARKERS.ROOT_EXEC_UNAVAILABLE, "root exec unavailable"],
      [MARKERS.GOSU_MISSING, "root exec unavailable"],
      [MARKERS.GATEWAY_USER_MISSING, "root exec unavailable"],
      [MARKERS.GATEWAY_FAILED, "launch failure"],
    ] as const;

    for (const [marker, layer] of expectedMarkers) {
      expect(script).toContain(marker);
      expect(
        classifyGatewayRestartFailure({
          status: 1,
          stdout: marker,
          stderr: "",
        }),
      ).toMatchObject({ layer });
    }
  });
});

describe("restartSandboxGateway — host-mediated gateway restart", () => {
  function silenceConsole() {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    return () => {
      log.mockRestore();
      error.mockRestore();
    };
  }

  function baseDeps(overrides = {}) {
    return {
      getSessionAgent: () => null,
      getSandbox: () => ({ name: "alpha", agent: "openclaw" }),
      resolveSandboxDashboardPort: () => 18789,
      buildOpenClawGatewayRestartScript: vi.fn(() => "restart openclaw"),
      buildHermesGatewayRestartScript: vi.fn(() => "restart hermes"),
      executeSandboxExecCommand: vi.fn(() => ({
        status: 0,
        stdout: "GATEWAY_PID=123",
        stderr: "",
      })),
      waitForRecoveredSandboxGateway: vi.fn(() => true),
      ensureSandboxPortForward: vi.fn(() => true),
      recoverHermesDashboardProcessIfEnabled: vi.fn(() => null),
      ensureHermesDashboardPortForwardIfEnabled: vi.fn(() => null),
      recoverMessagingHostForward: vi.fn(() => null),
      recoverDeclaredAgentForwardPorts: vi.fn(() => null),
      printGatewayWedgeDiagnostics: vi.fn(() => false),
      ...overrides,
    };
  }

  it("refuses unframed OpenShell root exec output without using the Docker fallback", () => {
    const childProcess = requireDist("node:child_process");
    const dockerExec = requireDist("../../../../dist/lib/adapters/docker/exec.js");
    const openshellRuntime = requireDist("../../../../dist/lib/adapters/openshell/runtime.js");
    const agentRuntime = requireDist("../../../../dist/lib/agent/runtime.js");
    const registry = requireDist("../../../../dist/lib/state/registry.js");
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.spyOn(openshellRuntime, "getOpenshellBinary").mockReturnValue("openshell");
    vi.spyOn(childProcess, "spawnSync").mockReturnValue({
      status: 0,
      stdout: "OpenShell transport preamble without child stdout marker\n",
      stderr: "",
    } as never);
    const dockerSpawnSync = vi.spyOn(dockerExec, "dockerSpawnSync").mockReturnValue({
      status: 0,
      stdout: "__NEMOCLAW_SANDBOX_EXEC_STARTED__\nGATEWAY_PID=123\n",
      stderr: "",
    } as never);
    vi.spyOn(agentRuntime, "getSessionAgent").mockReturnValue(null);
    vi.spyOn(registry, "getSandbox").mockReturnValue({
      name: "openclaw-box",
      agent: "openclaw",
      dashboardPort: 18789,
    });

    const result = restartSandboxGateway("openclaw-box", { quiet: true });

    expect(result).toMatchObject({
      ok: false,
      failureLayer: "root exec unavailable",
    });
    expect(dockerSpawnSync).not.toHaveBeenCalled();
    expect(errorSpy).toHaveBeenCalledWith(
      "  Failure layer: root exec unavailable - gateway restart failed for 'openclaw-box'.",
    );
  });

  it("force-restarts through root exec even when a gateway might already be healthy", () => {
    const restore = silenceConsole();
    try {
      const deps = baseDeps();
      const result = restartSandboxGateway("alpha", { deps });

      expect(result).toMatchObject({ ok: true, restarted: true, healthPassed: true });
      expect(deps.buildOpenClawGatewayRestartScript).toHaveBeenCalledWith(18789);
      expect(deps.executeSandboxExecCommand).toHaveBeenCalledWith(
        "alpha",
        "restart openclaw",
        30000,
      );
      expect(deps.waitForRecoveredSandboxGateway).toHaveBeenCalledWith("alpha", {
        quiet: false,
      });
      expect(deps.ensureSandboxPortForward).toHaveBeenCalledWith("alpha");
    } finally {
      restore();
    }
  });

  it("suppresses restart success output in quiet mode", () => {
    const restore = silenceConsole();
    try {
      const deps = baseDeps();
      const result = restartSandboxGateway("alpha", { quiet: true, deps });

      expect(result).toMatchObject({ ok: true, restarted: true, healthPassed: true });
      expect(console.log).not.toHaveBeenCalled();
    } finally {
      restore();
    }
  });

  it("reports root exec unavailability", () => {
    const restore = silenceConsole();
    try {
      const deps = baseDeps({ executeSandboxExecCommand: vi.fn(() => null) });
      const result = restartSandboxGateway("alpha", { quiet: true, deps });

      expect(result).toMatchObject({
        ok: false,
        failureLayer: "root exec unavailable",
      });
    } finally {
      restore();
    }
  });

  it("reports Hermes boundary refusals without hiding diagnostics in quiet mode", () => {
    const restore = silenceConsole();
    try {
      const hermesAgent = {
        name: "hermes",
        displayName: "Hermes Agent",
        healthProbe: { port: 8642 },
      };
      const deps = baseDeps({
        getSessionAgent: () => hermesAgent,
        getSandbox: () => ({ name: "alpha", agent: "hermes" }),
        buildHermesGatewayRestartScript: vi.fn(() => "restart hermes"),
        executeSandboxExecCommand: vi.fn(() => ({
          status: 1,
          stdout: "SECRET_BOUNDARY_REFUSED",
          stderr: "[SECURITY] TELEGRAM_BOT_TOKEN (line 2)",
        })),
      });
      const result = restartSandboxGateway("alpha", { quiet: true, deps });

      expect(result).toMatchObject({
        ok: false,
        failureLayer: "secret-boundary refusal",
      });
      expect(deps.buildHermesGatewayRestartScript).toHaveBeenCalledWith(hermesAgent, 8642);
      expect(console.error).toHaveBeenCalledWith(
        "  Failure layer: secret-boundary refusal - gateway restart failed for 'alpha'.",
      );
    } finally {
      restore();
    }
  });

  it("reports launch failure markers", () => {
    const restore = silenceConsole();
    try {
      const deps = baseDeps({
        executeSandboxExecCommand: vi.fn(() => ({
          status: 1,
          stdout: "GATEWAY_FAILED",
          stderr: "tail output",
        })),
      });
      const result = restartSandboxGateway("alpha", { deps });

      expect(result).toMatchObject({ ok: false, failureLayer: "launch failure" });
    } finally {
      restore();
    }
  });

  it("redacts and strips restart failure detail before printing it", () => {
    const restore = silenceConsole();
    try {
      const deps = baseDeps({
        executeSandboxExecCommand: vi.fn(() => ({
          status: 1,
          stdout: "GATEWAY_FAILED",
          stderr: "\u001b[31mOPENAI_API_KEY=sk-review-secret\u001b[0m",
        })),
      });
      const result = restartSandboxGateway("alpha", { deps });

      expect(result).toMatchObject({ ok: false, failureLayer: "launch failure" });
      expect(result.ok).toBe(false);
      const failure = result as Extract<typeof result, { ok: false }>;
      expect(failure.detail).toContain("OPENAI_API_KEY=<REDACTED>");
      expect(failure.detail).not.toContain("\u001b");
      expect(failure.detail).not.toContain("sk-review-secret");
      const errorOutput = vi.mocked(console.error).mock.calls.join("\n");
      expect(errorOutput).toContain("Failure layer: launch failure");
      expect(errorOutput).toContain("OPENAI_API_KEY=<REDACTED>");
      expect(errorOutput).not.toContain("\u001b");
      expect(errorOutput).not.toContain("sk-review-secret");
    } finally {
      restore();
    }
  });

  it("reports a health timeout after the restart process marker", () => {
    const restore = silenceConsole();
    try {
      const deps = baseDeps({ waitForRecoveredSandboxGateway: vi.fn(() => false) });
      const result = restartSandboxGateway("alpha", { deps });

      expect(result).toMatchObject({ ok: false, failureLayer: "health timeout" });
      expect(deps.printGatewayWedgeDiagnostics).toHaveBeenCalledWith(
        "alpha",
        deps.executeSandboxExecCommand,
      );
    } finally {
      restore();
    }
  });

  it("refuses terminal agents with an unsupported-agent layer", () => {
    const restore = silenceConsole();
    try {
      const deps = baseDeps({
        getSessionAgent: () => ({
          name: "terminal-agent",
          displayName: "Terminal Agent",
          runtime: { kind: "terminal" },
        }),
        getSandbox: () => ({ name: "alpha", agent: "terminal-agent" }),
      });
      const result = restartSandboxGateway("alpha", { deps });

      expect(result).toMatchObject({ ok: false, failureLayer: "unsupported agent" });
      expect(deps.executeSandboxExecCommand).not.toHaveBeenCalled();
    } finally {
      restore();
    }
  });

  it("refuses custom agents when the explicit runtime definition is unavailable", () => {
    const restore = silenceConsole();
    try {
      const deps = baseDeps({
        getSessionAgent: () => null,
        getSandbox: () => ({ name: "alpha", agent: "custom-agent" }),
      });
      const result = restartSandboxGateway("alpha", { deps });

      expect(result).toMatchObject({ ok: false, failureLayer: "unsupported agent" });
      expect(result.ok).toBe(false);
      const failure = result as Extract<typeof result, { ok: false }>;
      expect(failure.detail).toContain("custom-agent agent definition could not be loaded");
      expect(deps.buildOpenClawGatewayRestartScript).not.toHaveBeenCalled();
      expect(deps.executeSandboxExecCommand).not.toHaveBeenCalled();
    } finally {
      restore();
    }
  });
});
