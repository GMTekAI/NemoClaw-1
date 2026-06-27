// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

type CrashBoundary = "provider" | "policy" | "adapter" | "";

function runAddProcess(home: string, crashAfter: CrashBoundary) {
  const script = String.raw`
process.env.HOME = ${JSON.stringify(home)};
process.env.FAKE_MCP_SECRET = "host-only-secret";
const fs = require("node:fs");
const path = require("node:path");
const crashAfter = ${JSON.stringify(crashAfter)};
const marker = (name) => path.join(process.env.HOME, name + ".marker");
const mark = (name) => fs.writeFileSync(marker(name), "yes\n", { mode: 0o600 });
const marked = (name) => fs.existsSync(marker(name));

const registry = require("./dist/lib/state/registry.js");
const globalActions = require("./dist/lib/actions/global.js");
const gatewayRuntime = require("./dist/lib/gateway-runtime-action.js");
const policies = require("./dist/lib/policy/index.js");
const processRecovery = require("./dist/lib/actions/sandbox/process-recovery.js");

gatewayRuntime.recoverNamedGatewayRuntime = async () => ({
  recovered: true,
  attempted: false,
  before: { state: "healthy_named" },
  after: { state: "healthy_named" },
});

globalActions.runOpenshellProviderCommand = (args) => {
  if (args[0] === "provider" && args[1] === "get") {
    return marked("provider")
      ? { status: 0, stdout: "Type: generic\nCredential keys: FAKE_MCP_SECRET\n", stderr: "" }
      : { status: 1, stdout: "", stderr: "NotFound: provider" };
  }
  if (args[0] === "provider" && (args[1] === "create" || args[1] === "update")) {
    mark("provider");
    if (crashAfter === "provider") process.exit(86);
    return { status: 0, stdout: "created", stderr: "" };
  }
  if (args[0] === "sandbox" && args[1] === "provider" && args[2] === "attach") {
    return { status: 0, stdout: "attached", stderr: "" };
  }
  if (args[0] === "sandbox" && args[1] === "provider" && args[2] === "detach") {
    return { status: 0, stdout: "detached", stderr: "" };
  }
  if (args[0] === "provider" && args[1] === "delete") {
    fs.rmSync(marker("provider"), { force: true });
    return { status: 0, stdout: "deleted", stderr: "" };
  }
  return { status: 0, stdout: "", stderr: "" };
};

policies.getPresetContentGatewayState = () => marked("policy") ? "match" : "absent";
policies.applyPresetContent = () => {
  mark("policy");
  if (crashAfter === "policy") process.exit(86);
  return true;
};
policies.removePreset = () => {
  fs.rmSync(marker("policy"), { force: true });
  return true;
};

processRecovery.executeSandboxExecCommand = () => ({ status: 0, stdout: "", stderr: "" });
processRecovery.executeSandboxCommand = (_sandbox, command) => {
  if (command === "command -v mcporter") {
    return { status: 0, stdout: "/usr/local/bin/mcporter\n", stderr: "" };
  }
  if (command.includes("config' 'add")) {
    mark("adapter");
    if (crashAfter === "adapter") process.exit(86);
    return { status: 0, stdout: "", stderr: "" };
  }
  if (command.includes("config' 'remove")) {
    fs.rmSync(marker("adapter"), { force: true });
    return { status: 0, stdout: "", stderr: "" };
  }
  return {
    status: 0,
    stdout: marked("adapter") ? "registered\n" : "absent\n",
    stderr: "",
  };
};

if (!registry.getSandbox("crash-test")) {
  registry.registerSandbox({
    name: "crash-test",
    agent: "openclaw",
    gatewayName: "nemoclaw",
  });
}
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
bridge.addMcpBridge("crash-test", {
  server: "fake",
  url: "https://8.8.8.8/mcp",
  env: [{ name: "FAKE_MCP_SECRET" }],
}).then(
  () => process.exit(0),
  (error) => {
    console.error(error && error.stack || error);
    process.exit(2);
  },
);
`;
  return spawnSync(process.execPath, ["-e", script], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, HOME: home },
    timeout: 30_000,
  });
}

function runRemoveProcess(home: string, crashAfterProviderDelete: boolean) {
  const script = String.raw`
process.env.HOME = ${JSON.stringify(home)};
process.env.FAKE_MCP_SECRET = "host-only-secret";
const fs = require("node:fs");
const path = require("node:path");
const crashAfterProviderDelete = ${JSON.stringify(crashAfterProviderDelete)};
const marker = (name) => path.join(process.env.HOME, name + ".marker");
const marked = (name) => fs.existsSync(marker(name));

const globalActions = require("./dist/lib/actions/global.js");
const gatewayRuntime = require("./dist/lib/gateway-runtime-action.js");
const policies = require("./dist/lib/policy/index.js");
const processRecovery = require("./dist/lib/actions/sandbox/process-recovery.js");

gatewayRuntime.recoverNamedGatewayRuntime = async () => ({
  recovered: true,
  attempted: false,
  before: { state: "healthy_named" },
  after: { state: "healthy_named" },
});

globalActions.runOpenshellProviderCommand = (args) => {
  if (args[0] === "provider" && args[1] === "get") {
    return marked("provider")
      ? { status: 0, stdout: "Type: generic\nCredential keys: FAKE_MCP_SECRET\n", stderr: "" }
      : { status: 1, stdout: "", stderr: "NotFound: provider" };
  }
  if (args[0] === "sandbox" && args[1] === "provider" && args[2] === "detach") {
    return marked("provider")
      ? { status: 0, stdout: "detached", stderr: "" }
      : { status: 1, stdout: "", stderr: "NotFound: provider" };
  }
  if (args[0] === "provider" && args[1] === "delete") {
    if (!marked("provider")) {
      return { status: 1, stdout: "", stderr: "NotFound: provider" };
    }
    fs.rmSync(marker("provider"), { force: true });
    if (crashAfterProviderDelete) process.exit(87);
    return { status: 0, stdout: "deleted", stderr: "" };
  }
  return { status: 0, stdout: "", stderr: "" };
};

policies.getPresetContentGatewayState = () => marked("policy") ? "match" : "absent";
policies.removePreset = () => {
  fs.rmSync(marker("policy"), { force: true });
  return true;
};

processRecovery.executeSandboxCommand = (_sandbox, command) => {
  if (command.includes('["config", "remove"')) {
    fs.rmSync(marker("adapter"), { force: true });
  }
  return { status: 0, stdout: "", stderr: "" };
};

const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
bridge.removeMcpBridge("crash-test", "fake").then(
  () => process.exit(0),
  (error) => {
    console.error(error && error.stack || error);
    process.exit(2);
  },
);
`;
  return spawnSync(process.execPath, ["-e", script], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, HOME: home },
    timeout: 30_000,
  });
}

function runStatusProcess(home: string) {
  const script = String.raw`
process.env.HOME = ${JSON.stringify(home)};
const globalActions = require("./dist/lib/actions/global.js");
const gatewayRuntime = require("./dist/lib/gateway-runtime-action.js");
const policies = require("./dist/lib/policy/index.js");
const processRecovery = require("./dist/lib/actions/sandbox/process-recovery.js");

gatewayRuntime.recoverNamedGatewayRuntime = async () => ({
  recovered: true,
  attempted: false,
  before: { state: "healthy_named" },
  after: { state: "healthy_named" },
});
globalActions.runOpenshellProviderCommand = (args) => {
  if (args[0] === "provider" && args[1] === "get") {
    return {
      status: 0,
      stdout: "Type: generic\nCredential keys: FAKE_MCP_SECRET\n",
      stderr: "",
    };
  }
  if (args[0] === "sandbox" && args[1] === "provider" && args[2] === "list") {
    return { status: 0, stdout: "", stderr: "" };
  }
  return { status: 0, stdout: "", stderr: "" };
};
policies.presetContentMatchesGateway = () => {
  throw new Error("unowned prepared policy must not be inspected as registered");
};
processRecovery.executeSandboxCommand = () => ({
  status: 0,
  stdout: "absent\n",
  stderr: "",
});

const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
bridge.statusMcpBridge("crash-test", "fake").then(
  (status) => {
    process.stdout.write(JSON.stringify(status[0]));
    process.exit(0);
  },
  (error) => {
    console.error(error && error.stack || error);
    process.exit(2);
  },
);
`;
  return spawnSync(process.execPath, ["-e", script], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, HOME: home },
    timeout: 30_000,
  });
}

function readBridge(home: string): Record<string, unknown> {
  const parsed = JSON.parse(
    fs.readFileSync(path.join(home, ".nemoclaw", "sandboxes.json"), "utf8"),
  ) as {
    sandboxes: {
      "crash-test": { mcp: { bridges: { fake: Record<string, unknown> } } };
    };
  };
  return parsed.sandboxes["crash-test"].mcp.bridges.fake;
}

describe("MCP add crash consistency", () => {
  for (const boundary of ["provider", "policy", "adapter"] as const) {
    it(`resumes exact resources after process death at the ${boundary} boundary`, () => {
      const home = fs.mkdtempSync(path.join(os.tmpdir(), `nemoclaw-mcp-add-${boundary}-`));
      try {
        const crashed = runAddProcess(home, boundary);
        expect(crashed.status, `${crashed.stdout}\n${crashed.stderr}`).toBe(86);
        const pending = readBridge(home);
        expect(pending.addState).toBe("preflighted");
        expect(JSON.stringify(pending)).not.toContain("host-only-secret");

        const resumed = runAddProcess(home, "");
        expect(resumed.status, `${resumed.stdout}\n${resumed.stderr}`).toBe(0);
        const committed = readBridge(home);
        expect(committed.addState).toBeUndefined();
        expect(committed).toMatchObject({
          server: "fake",
          env: ["FAKE_MCP_SECRET"],
          providerName: "crash-test-mcp-fake",
          policyName: "mcp-bridge-fake",
        });
        expect(fs.existsSync(path.join(home, "provider.marker"))).toBe(true);
        expect(fs.existsSync(path.join(home, "policy.marker"))).toBe(true);
        expect(fs.existsSync(path.join(home, "adapter.marker"))).toBe(true);
      } finally {
        fs.rmSync(home, { recursive: true, force: true });
      }
    });
  }

  it("does not claim or delete a same-name resource found before preflight", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-add-foreign-provider-"));
    try {
      const providerMarker = path.join(home, "provider.marker");
      fs.writeFileSync(providerMarker, "foreign\n", { mode: 0o600 });

      const rejected = runAddProcess(home, "");
      expect(rejected.status, `${rejected.stdout}\n${rejected.stderr}`).toBe(2);
      expect(rejected.stderr).toContain("could not prove provider");
      expect(readBridge(home).addState).toBe("prepared");

      const statusResult = runStatusProcess(home);
      expect(statusResult.status, `${statusResult.stdout}\n${statusResult.stderr}`).toBe(0);
      const status = JSON.parse(statusResult.stdout) as {
        addState?: string;
        policy: { registryPresent: boolean; gatewayPresent: boolean | null };
      };
      expect(status.addState).toBe("prepared");
      expect(status.policy).toEqual({
        name: "mcp-bridge-fake",
        registryPresent: false,
        gatewayPresent: null,
      });

      const cancelScript = `
process.env.HOME = ${JSON.stringify(home)};
const registry = require("./dist/lib/state/registry.js");
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
bridge.removeMcpBridge("crash-test", "fake", { force: true }).then(
  () => process.exit(0),
  (error) => { console.error(error); process.exit(2); },
);
`;
      const cancelled = spawnSync(process.execPath, ["-e", cancelScript], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: { ...process.env, HOME: home },
        timeout: 30_000,
      });
      expect(cancelled.status, `${cancelled.stdout}\n${cancelled.stderr}`).toBe(0);
      expect(fs.existsSync(providerMarker)).toBe(true);
      const registry = JSON.parse(
        fs.readFileSync(path.join(home, ".nemoclaw", "sandboxes.json"), "utf8"),
      ) as { sandboxes: { "crash-test": { mcp?: unknown } } };
      expect(registry.sandboxes["crash-test"].mcp).toBeUndefined();
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

describe("MCP remove crash consistency", () => {
  it("converges when the process dies after provider deletion", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-remove-provider-"));
    try {
      const added = runAddProcess(home, "");
      expect(added.status, `${added.stdout}\n${added.stderr}`).toBe(0);

      const crashed = runRemoveProcess(home, true);
      expect(crashed.status, `${crashed.stdout}\n${crashed.stderr}`).toBe(87);
      expect(readBridge(home)).toMatchObject({
        server: "fake",
        providerName: "crash-test-mcp-fake",
      });
      expect(fs.existsSync(path.join(home, "provider.marker"))).toBe(false);
      expect(fs.existsSync(path.join(home, "policy.marker"))).toBe(false);
      expect(fs.existsSync(path.join(home, "adapter.marker"))).toBe(false);

      const resumed = runRemoveProcess(home, false);
      expect(resumed.status, `${resumed.stdout}\n${resumed.stderr}`).toBe(0);
      const registry = JSON.parse(
        fs.readFileSync(path.join(home, ".nemoclaw", "sandboxes.json"), "utf8"),
      ) as { sandboxes: { "crash-test": { mcp?: unknown } } };
      expect(registry.sandboxes["crash-test"].mcp).toBeUndefined();
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
