// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

describe("MCP provider ownership", () => {
  it("never detaches or deletes a non-matching provider in force mode", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-provider-owner-"));
    const script = `
process.env.HOME = ${JSON.stringify(home)};
const registry = require("./dist/lib/state/registry.js");
const agentDefs = require("./dist/lib/agent/defs.js");
const gatewayRuntime = require("./dist/lib/gateway-runtime-action.js");
const policies = require("./dist/lib/policy/index.js");
const processRecovery = require("./dist/lib/actions/sandbox/process-recovery.js");
const globalActions = require("./dist/lib/actions/global.js");
const calls = [];
agentDefs.loadAgent = () => { throw new Error("persisted adapter must be used"); };
gatewayRuntime.recoverNamedGatewayRuntime = async () => ({
  recovered: true,
  attempted: false,
  before: { state: "healthy_named" },
  after: { state: "healthy_named" },
});
policies.getPresetContentGatewayState = () => "absent";
policies.removePreset = () => true;
processRecovery.executeSandboxCommand = () => ({ status: 0, stdout: "", stderr: "" });
globalActions.runOpenshellProviderCommand = (args) => {
  calls.push(args.join(" "));
  if (args[0] === "provider" && args[1] === "get") {
    return {
      status: 0,
      stdout: "Type: generic\\nCredential keys: OTHER_TOKEN\\n",
      stderr: "",
    };
  }
  return { status: 0, stdout: "", stderr: "" };
};
registry.registerSandbox({
  name: "alpha",
  agent: "legacy-disabled",
  mcp: { bridges: { fake: {
    server: "fake",
    url: "https://mcp.example.test/mcp",
    env: ["EXPECTED_TOKEN"],
    providerName: "alpha-mcp-fake",
    policyName: "mcp-bridge-fake",
    adapter: "mcporter",
    addedAt: "2026-06-01T00:00:00.000Z",
  } } },
});
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
bridge.removeMcpBridge("alpha", "fake", { force: true }).then(
  () => process.exit(9),
  (error) => process.stdout.write(JSON.stringify({
    message: error.message,
    calls,
    bridgePresent: !!registry.getSandbox("alpha")?.mcp?.bridges?.fake,
  })),
);
`;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, HOME: home },
    });
    fs.rmSync(home, { recursive: true, force: true });

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    const payload = JSON.parse(result.stdout.slice(result.stdout.indexOf("{"))) as {
      message: string;
      calls: string[];
      bridgePresent: boolean;
    };
    expect(payload.message).toContain("registry entry was preserved");
    expect(payload.calls).toEqual(["provider get alpha-mcp-fake"]);
    expect(payload.bridgePresent).toBe(true);
  });
});
