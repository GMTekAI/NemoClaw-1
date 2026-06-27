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

function compactTeamsMessagingPlan(port = "3978") {
  return {
    schemaVersion: 1,
    sandboxName: "beta",
    agent: "openclaw",
    workflow: "onboard",
    disabledChannels: [],
    networkPolicy: {
      presets: ["teams"],
      entries: [
        {
          channelId: "teams",
          presetName: "teams",
          policyKeys: ["teams"],
          source: "manifest",
        },
      ],
    },
    channels: [
      {
        channelId: "teams",
        active: true,
        configured: true,
        disabled: false,
        inputs: [
          { inputId: "allowedUsers", value: "00000000-0000-0000-0000-000000000001" },
          { inputId: "appId", value: "test-teams-app-id" },
          { inputId: "clientSecret", credentialAvailable: true },
          { inputId: "requireMention", value: "1" },
          { inputId: "tenantId", value: "test-teams-tenant-id" },
          { inputId: "webhookPort", value: port },
        ],
      },
    ],
    credentialBindings: [],
  };
}

describe("checkAndRecoverSandboxProcesses primary forward failure", () => {
  it("reports failure when the primary forward cannot recover even if secondary forwards recover", () => {
    const openshellRuntime = requireDist("../dist/lib/adapters/openshell/runtime.js");
    const agentRuntime = requireDist("../dist/lib/agent/runtime.js");
    const registry = requireDist("../dist/lib/state/registry.js");
    const forwardHealth = requireDist("../dist/lib/actions/sandbox/forward-health.js");
    const childProcess = requireDist("node:child_process");
    let teamsForwardStarted = false;

    vi.spyOn(childProcess, "spawnSync").mockReturnValue({
      status: 0,
      stdout: "__NEMOCLAW_SANDBOX_EXEC_STARTED__\nRUNNING\n",
      stderr: "",
    } as never);
    vi.spyOn(agentRuntime, "getSessionAgent").mockReturnValue(null);
    vi.spyOn(registry, "getSandbox").mockReturnValue({
      name: "beta",
      agent: "openclaw",
      dashboardPort: 18789,
      messaging: { schemaVersion: 1, plan: compactTeamsMessagingPlan() },
    });
    vi.spyOn(forwardHealth, "isLocalForwardReachable").mockReturnValue(false);
    vi.spyOn(openshellRuntime, "captureOpenshell").mockImplementation(() => ({
      status: 0,
      output: teamsForwardStarted
        ? `SANDBOX  BIND  PORT  PID  STATUS
beta  127.0.0.1  3978  12346  running`
        : `SANDBOX  BIND  PORT  PID  STATUS
beta  127.0.0.1  18789  12345  dead`,
    }));
    const runOpenshell = vi
      .spyOn(openshellRuntime, "runOpenshell")
      .mockImplementation((rawArgs: unknown) => {
        const args = Array.isArray(rawArgs) ? rawArgs.map(String) : [];
        if (args[0] === "forward" && args[1] === "start" && args.includes("18789")) {
          return { status: 1 } as never;
        }
        if (args[0] === "forward" && args[1] === "start" && args.includes("3978")) {
          teamsForwardStarted = true;
        }
        return { status: 0 } as never;
      });

    expect(
      withFakeOpenshellBinary(() => checkAndRecoverSandboxProcesses("beta", { quiet: true })),
    ).toEqual({
      checked: true,
      wasRunning: true,
      recovered: false,
      forwardRecovered: false,
      forwardRecoveryFailed: true,
    });
    expect(teamsForwardStarted).toBe(true);
    expect(runOpenshell).toHaveBeenCalledWith(
      ["forward", "start", "--background", "3978", "beta"],
      { ignoreError: true },
    );
  });
});
