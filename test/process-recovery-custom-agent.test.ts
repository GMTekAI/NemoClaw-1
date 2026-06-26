// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";
import { checkAndRecoverSandboxProcesses } from "../dist/lib/actions/sandbox/process-recovery.js";

const requireDist = createRequire(import.meta.url);

afterEach(() => {
  vi.restoreAllMocks();
});

function getSandboxExecShellCommand(rawArgs: unknown): string {
  const args = Array.isArray(rawArgs) ? rawArgs.map(String) : [];
  return String(args.at(-1) ?? "");
}

function withFakeOpenshellBinary<T>(fn: () => T): T {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-fake-openshell-"));
  const bin = path.join(dir, "openshell");
  const previous = process.env.NEMOCLAW_OPENSHELL_BIN;
  fs.writeFileSync(bin, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  process.env.NEMOCLAW_OPENSHELL_BIN = bin;
  try {
    return fn();
  } finally {
    if (previous === undefined) {
      delete process.env.NEMOCLAW_OPENSHELL_BIN;
    } else {
      process.env.NEMOCLAW_OPENSHELL_BIN = previous;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("checkAndRecoverSandboxProcesses custom agent recovery", () => {
  it("recovers a stopped custom gateway agent over SSH fallback", () => {
    const openshellRuntime = requireDist("../dist/lib/adapters/openshell/runtime.js");
    const agentRuntime = requireDist("../dist/lib/agent/runtime.js");
    const registry = requireDist("../dist/lib/state/registry.js");
    const forwardHealth = requireDist("../dist/lib/actions/sandbox/forward-health.js");
    const childProcess = requireDist("node:child_process");
    const runningForward = `SANDBOX  BIND  PORT  PID  STATUS
custom-box  127.0.0.1  19000  12345  running`;
    const sshCommands: string[] = [];
    const previousWaitSeconds = process.env.NEMOCLAW_GATEWAY_RECOVERY_WAIT_SECONDS;
    const previousPollInterval = process.env.NEMOCLAW_GATEWAY_RECOVERY_POLL_INTERVAL_SECONDS;
    const previousSettleSeconds = process.env.NEMOCLAW_GATEWAY_RECOVERY_SETTLE_SECONDS;
    let recovered = false;

    process.env.NEMOCLAW_GATEWAY_RECOVERY_WAIT_SECONDS = "2";
    process.env.NEMOCLAW_GATEWAY_RECOVERY_POLL_INTERVAL_SECONDS = "0";
    process.env.NEMOCLAW_GATEWAY_RECOVERY_SETTLE_SECONDS = "0";

    try {
      vi.spyOn(openshellRuntime, "captureSandboxSshConfig").mockReturnValue({
        status: 0,
        output: "Host openshell-custom-box\n  HostName 127.0.0.1\n",
      } as never);
      vi.spyOn(childProcess, "spawnSync").mockImplementation(
        (command: unknown, rawArgs: unknown) => {
          const args = Array.isArray(rawArgs) ? rawArgs.map(String) : [];
          if (String(command).endsWith("openshell")) {
            const shellCommand = getSandboxExecShellCommand(args);
            const status = shellCommand.includes("HTTP_CODE=$(curl")
              ? recovered
                ? "RUNNING"
                : "STOPPED"
              : "";
            return {
              status: 0,
              stdout: `__NEMOCLAW_SANDBOX_EXEC_STARTED__\n${status}\n`,
              stderr: "",
            } as never;
          }
          if (command === "ssh") {
            const sshCommand = getSandboxExecShellCommand(args);
            sshCommands.push(sshCommand);
            if (sshCommand.includes("HTTP_CODE=$(curl")) {
              return { status: 0, stdout: recovered ? "RUNNING" : "STOPPED", stderr: "" } as never;
            }
            recovered = sshCommand.includes('"$AGENT_BIN" gateway run --port 19000');
            return {
              status: 0,
              stdout: recovered ? "GATEWAY_PID=5150" : "",
              stderr: "",
            } as never;
          }
          return { status: 1, stdout: "", stderr: "" } as never;
        },
      );
      vi.spyOn(agentRuntime, "getSessionAgent").mockReturnValue({
        name: "custom-agent",
        displayName: "Custom Agent",
        binary_path: "/usr/local/bin/custom-agent",
        gateway_command: "custom-agent gateway run",
        forwardPort: 19000,
        healthProbe: { url: "http://127.0.0.1:19000/health", port: 19000 },
      });
      vi.spyOn(registry, "getSandbox").mockReturnValue({
        name: "custom-box",
        agent: "custom-agent",
        dashboardPort: 19000,
      });
      vi.spyOn(forwardHealth, "isLocalForwardReachable").mockReturnValue(true);
      vi.spyOn(openshellRuntime, "captureOpenshell").mockReturnValue({
        status: 0,
        output: runningForward,
      });
      vi.spyOn(openshellRuntime, "runOpenshell").mockReturnValue({ status: 0 } as never);

      expect(
        withFakeOpenshellBinary(() =>
          checkAndRecoverSandboxProcesses("custom-box", { quiet: true }),
        ),
      ).toEqual({
        checked: true,
        wasRunning: false,
        recovered: true,
        forwardRecovered: true,
      });
      expect(sshCommands.some((command) => command.includes('"$AGENT_BIN" gateway run'))).toBe(
        true,
      );
      expect(recovered).toBe(true);
    } finally {
      previousWaitSeconds === undefined
        ? delete process.env.NEMOCLAW_GATEWAY_RECOVERY_WAIT_SECONDS
        : (process.env.NEMOCLAW_GATEWAY_RECOVERY_WAIT_SECONDS = previousWaitSeconds);
      previousPollInterval === undefined
        ? delete process.env.NEMOCLAW_GATEWAY_RECOVERY_POLL_INTERVAL_SECONDS
        : (process.env.NEMOCLAW_GATEWAY_RECOVERY_POLL_INTERVAL_SECONDS = previousPollInterval);
      previousSettleSeconds === undefined
        ? delete process.env.NEMOCLAW_GATEWAY_RECOVERY_SETTLE_SECONDS
        : (process.env.NEMOCLAW_GATEWAY_RECOVERY_SETTLE_SECONDS = previousSettleSeconds);
    }
  });
});
