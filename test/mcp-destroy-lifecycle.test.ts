// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

function runDestroyLifecycleScenario(body: string) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-destroy-"));
  const script = `
process.env.HOME = ${JSON.stringify(home)};
const registry = require("./dist/lib/state/registry.js");
const globalActions = require("./dist/lib/actions/global.js");
const gatewayRuntime = require("./dist/lib/gateway-runtime-action.js");
const policies = require("./dist/lib/policy/index.js");
const processRecovery = require("./dist/lib/actions/sandbox/process-recovery.js");

const providers = new Map([
  ["alpha-mcp-github", "GITHUB_TOKEN"],
  ["alpha-mcp-slack", "SLACK_TOKEN"],
]);
const calls = [];
const adapterCalls = [];
let policyApplyCalls = 0;
let failProviderDelete = null;
globalActions.runOpenshellProviderCommand = (args) => {
  calls.push(args.join(" "));
  if (args[0] === "provider" && args[1] === "get") {
    const credential = providers.get(args[2]);
    return credential
      ? { status: 0, stdout: "Type: generic\\nCredential keys: " + credential + "\\n", stderr: "" }
      : { status: 1, stdout: "", stderr: "Provider not found" };
  }
  if (args[0] === "sandbox" && args[1] === "provider" && args[2] === "detach") {
    return { status: 0, stdout: "Detached provider", stderr: "" };
  }
  if (args[0] === "sandbox" && args[1] === "provider" && args[2] === "attach") {
    return { status: 0, stdout: "Attached provider", stderr: "" };
  }
  if (args[0] === "provider" && args[1] === "delete") {
    if (failProviderDelete === args[2]) {
      return { status: 9, stdout: "", stderr: "provider delete failed" };
    }
    providers.delete(args[2]);
    return { status: 0, stdout: "Deleted provider", stderr: "" };
  }
  throw new Error("Unexpected OpenShell call: " + args.join(" "));
};
gatewayRuntime.recoverNamedGatewayRuntime = async () => ({
  recovered: true,
  attempted: false,
  before: { state: "healthy_named" },
  after: { state: "healthy_named" },
});
policies.applyPresetContent = () => {
  policyApplyCalls += 1;
  return true;
};
policies.getPresetContentGatewayState = () => "match";
processRecovery.executeSandboxCommand = (_sandbox, command) => {
  adapterCalls.push(command);
  return {
    status: 0,
    stdout: command === "command -v mcporter" ? "/usr/local/bin/mcporter\\n" : "",
    stderr: "",
  };
};
processRecovery.executeSandboxExecCommand = (_sandbox, command) => ({
  status:
    command.includes("openshell:resolve:env:GITHUB_TOKEN") ||
    command.includes("openshell:resolve:env:SLACK_TOKEN")
      ? 0
      : 1,
  stdout: "",
  stderr: "",
});

const bridgeEntry = (server, credential) => ({
  server,
  agent: "openclaw",
  adapter: "mcporter",
  url: "https://8.8.8.8/" + server,
  env: [credential],
  providerName: "alpha-mcp-" + server,
  policyName: "mcp-bridge-" + server,
  addedAt: "2026-06-27T00:00:00.000Z",
});
const bridgeEntries = {
  github: bridgeEntry("github", "GITHUB_TOKEN"),
  slack: bridgeEntry("slack", "SLACK_TOKEN"),
};
const ownedPolicy = (server) => ({
  name: "mcp-bridge-" + server,
  content: "network_policies: {}\\n",
  sourcePath: "generated:nemoclaw-mcp-bridge",
});
${body}
`;
  const result = spawnSync(process.execPath, ["-e", script], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, HOME: home },
  });
  fs.rmSync(home, { recursive: true, force: true });
  return result;
}

describe("authenticated MCP sandbox destroy lifecycle", () => {
  it("prepares an absent-sandbox rebuild without adapter exec or provider detach", () => {
    const result = runDestroyLifecycleScenario(`
delete process.env.GITHUB_TOKEN;
registry.registerSandbox({
  name: "alpha",
  agent: "openclaw",
  gatewayName: "nemoclaw",
  mcp: { bridges: { github: bridgeEntries.github } },
});
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
(async () => {
  const preparation = await bridge.prepareMcpBridgesForAbsentSandboxRebuild("alpha");
  process.stdout.write(JSON.stringify({
    preparation,
    providers: [...providers.keys()],
    calls,
    adapterCalls,
  }));
})().catch((error) => { console.error(error); process.exit(1); });
`);

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    const payload = JSON.parse(result.stdout) as {
      preparation: {
        entries: unknown[];
        detachedProviderEntries: unknown[];
        scrubbedAdapterEntries: unknown[];
      };
      providers: string[];
      calls: string[];
      adapterCalls: string[];
    };
    expect(payload.preparation.entries).toHaveLength(1);
    expect(payload.preparation.detachedProviderEntries).toEqual([]);
    expect(payload.preparation.scrubbedAdapterEntries).toEqual([]);
    expect(payload.calls).toEqual(["provider get alpha-mcp-github"]);
    expect(payload.adapterCalls).toEqual([]);
    expect(payload.providers).toContain("alpha-mcp-github");
  });

  it("finalizes an externally absent sandbox without attempting sandbox adapter exec", () => {
    const result = runDestroyLifecycleScenario(`
registry.registerSandbox({
  name: "alpha",
  agent: "openclaw",
  mcp: { bridges: { github: bridgeEntries.github } },
});
registry.addCustomPolicy("alpha", ownedPolicy("github"));
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
(async () => {
  const preparation = await bridge.prepareMcpBridgesForAbsentSandboxDestroy("alpha");
  await bridge.finalizeMcpBridgesAfterSandboxDelete("alpha", preparation);
  process.stdout.write(JSON.stringify({
    preparation,
    sandbox: registry.getSandbox("alpha"),
    providers: [...providers.keys()],
    calls,
    adapterCalls,
  }));
})().catch((error) => { console.error(error); process.exit(1); });
`);

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    const payload = JSON.parse(result.stdout) as {
      preparation: { entries: unknown[] };
      sandbox: { mcp?: unknown; customPolicies?: unknown };
      providers: string[];
      calls: string[];
      adapterCalls: string[];
    };
    expect(payload.preparation.entries).toHaveLength(1);
    expect(payload.adapterCalls).toEqual([]);
    expect(payload.calls.some((call) => call.includes("sandbox provider"))).toBe(false);
    expect(payload.providers).not.toContain("alpha-mcp-github");
    expect(payload.sandbox.mcp).toBeUndefined();
    expect(payload.sandbox.customPolicies).toBeUndefined();
  });

  it("restores policy, attachment, and adapter without the host secret env", () => {
    const result = runDestroyLifecycleScenario(`
delete process.env.GITHUB_TOKEN;
registry.registerSandbox({
  name: "alpha",
  agent: "openclaw",
  mcp: { bridges: { github: bridgeEntries.github } },
});
registry.addCustomPolicy("alpha", ownedPolicy("github"));
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
(async () => {
  const preparation = await bridge.prepareMcpBridgesForDestroy("alpha");
  await bridge.restoreMcpBridgesAfterDestroyAbort("alpha", preparation);
  process.stdout.write(JSON.stringify({
    sandbox: registry.getSandbox("alpha"),
    providers: [...providers.keys()],
    calls,
    adapterCalls,
    policyApplyCalls,
    secretPresent: Object.prototype.hasOwnProperty.call(process.env, "GITHUB_TOKEN"),
  }));
})().catch((error) => { console.error(error); process.exit(1); });
`);

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    const payload = JSON.parse(result.stdout.slice(result.stdout.indexOf("{"))) as {
      sandbox: {
        mcp: {
          bridges: Record<string, unknown>;
          destroyPreparedAt?: string;
          destroyPendingAt?: string;
        };
      };
      providers: string[];
      calls: string[];
      adapterCalls: string[];
      policyApplyCalls: number;
      secretPresent: boolean;
    };
    expect(payload.secretPresent).toBe(false);
    expect(payload.providers).toContain("alpha-mcp-github");
    expect(payload.calls).toContain("sandbox provider attach alpha alpha-mcp-github");
    expect(payload.calls.some((call) => /^provider (create|update) /.test(call))).toBe(false);
    expect(payload.policyApplyCalls).toBe(1);
    expect(payload.adapterCalls).toContain("command -v mcporter");
    expect(
      payload.adapterCalls.some((call) => call.includes("openshell:resolve:env:GITHUB_TOKEN")),
    ).toBe(true);
    expect(payload.sandbox.mcp.bridges).toHaveProperty("github");
    expect(payload.sandbox.mcp.destroyPreparedAt).toBeUndefined();
    expect(payload.sandbox.mcp.destroyPendingAt).toBeUndefined();
  });

  it("preserves credentials and bridge state until sandbox deletion is confirmed", () => {
    const result = runDestroyLifecycleScenario(`
registry.registerSandbox({
  name: "alpha",
  agent: "openclaw",
  mcp: { bridges: { github: bridgeEntries.github } },
});
registry.addCustomPolicy("alpha", ownedPolicy("github"));
registry.addCustomPolicy("alpha", { name: "operator", content: "version: 1\\n" });
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
(async () => {
  const preparation = await bridge.prepareMcpBridgesForDestroy("alpha");
  const afterPrepare = registry.getSandbox("alpha");
  await bridge.finalizeMcpBridgesAfterSandboxDelete("alpha", preparation);
  const afterFinalize = registry.getSandbox("alpha");
  process.stdout.write(JSON.stringify({
    afterPrepare,
    afterFinalize,
    providers: [...providers.keys()],
    calls,
    adapterCalls,
  }));
})().catch((error) => { console.error(error); process.exit(1); });
`);

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    const payload = JSON.parse(result.stdout) as {
      afterPrepare: {
        mcp: {
          bridges: Record<string, unknown>;
          destroyPreparedAt?: string;
          destroyPendingAt?: string;
        };
        customPolicies: Array<{ name: string }>;
      };
      afterFinalize: {
        mcp?: unknown;
        customPolicies: Array<{ name: string }>;
      };
      providers: string[];
      calls: string[];
      adapterCalls: string[];
    };
    expect(payload.afterPrepare.mcp.bridges).toHaveProperty("github");
    expect(payload.afterPrepare.mcp.destroyPreparedAt).toBeTruthy();
    expect(payload.afterPrepare.mcp.destroyPendingAt).toBeUndefined();
    expect(payload.afterPrepare.customPolicies.map((policy) => policy.name)).toContain(
      "mcp-bridge-github",
    );
    expect(payload.afterFinalize.mcp).toBeUndefined();
    expect(payload.afterFinalize.customPolicies.map((policy) => policy.name)).toEqual(["operator"]);
    expect(payload.providers).not.toContain("alpha-mcp-github");
    expect(payload.calls).toContain("sandbox provider detach alpha alpha-mcp-github");
    expect(
      payload.adapterCalls.some((call) => call.includes("config") && call.includes("remove")),
    ).toBe(true);
  });

  it("keeps a pending manifest after partial provider deletion and completes on retry", () => {
    const result = runDestroyLifecycleScenario(`
registry.registerSandbox({
  name: "alpha",
  agent: "openclaw",
  mcp: { bridges: bridgeEntries },
});
registry.addCustomPolicy("alpha", ownedPolicy("github"));
registry.addCustomPolicy("alpha", ownedPolicy("slack"));
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
(async () => {
  const preparation = await bridge.prepareMcpBridgesForDestroy("alpha");
  failProviderDelete = "alpha-mcp-slack";
  let firstError = "";
  try {
    await bridge.finalizeMcpBridgesAfterSandboxDelete("alpha", preparation, { force: true });
  } catch (error) {
    firstError = error.message;
  }
  const afterFailure = registry.getSandbox("alpha");
  failProviderDelete = null;
  const retry = await bridge.prepareMcpBridgesForDestroy("alpha");
  await bridge.finalizeMcpBridgesAfterSandboxDelete("alpha", retry, { force: true });
  process.stdout.write(JSON.stringify({
    firstError,
    afterFailure,
    retry,
    afterRetry: registry.getSandbox("alpha"),
    providers: [...providers.keys()],
    calls,
  }));
})().catch((error) => { console.error(error); process.exit(1); });
`);

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    const payload = JSON.parse(result.stdout) as {
      firstError: string;
      afterFailure: {
        mcp: {
          bridges: Record<string, unknown>;
          destroyPreparedAt?: string;
          destroyPendingAt?: string;
        };
        customPolicies: Array<{ name: string }>;
      };
      retry: { destroyAlreadyPending: boolean };
      afterRetry: { mcp?: unknown; customPolicies?: unknown };
      providers: string[];
      calls: string[];
    };
    expect(payload.firstError).toContain("provider delete failed");
    expect(payload.afterFailure.mcp.destroyPendingAt).toBeTruthy();
    expect(payload.afterFailure.mcp.destroyPreparedAt).toBeUndefined();
    expect(Object.keys(payload.afterFailure.mcp.bridges)).toEqual(["github", "slack"]);
    expect(payload.afterFailure.customPolicies).toHaveLength(2);
    expect(payload.retry.destroyAlreadyPending).toBe(true);
    expect(payload.afterRetry.mcp).toBeUndefined();
    expect(payload.afterRetry.customPolicies).toBeUndefined();
    expect(payload.providers).toEqual([]);
    expect(
      payload.calls.filter((call) => call === "sandbox provider detach alpha alpha-mcp-github"),
    ).toHaveLength(1);
  });

  it("resumes from the durable prepared phase after delete-before-finalize interruption", () => {
    const result = runDestroyLifecycleScenario(`
registry.registerSandbox({
  name: "alpha",
  agent: "openclaw",
  mcp: { bridges: { github: bridgeEntries.github } },
});
registry.addCustomPolicy("alpha", ownedPolicy("github"));
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
(async () => {
  await bridge.prepareMcpBridgesForDestroy("alpha");
  const callsAfterFirstPrepare = calls.length;
  const adapterCallsAfterFirstPrepare = adapterCalls.length;
  const retry = await bridge.prepareMcpBridgesForDestroy("alpha");
  await bridge.finalizeMcpBridgesAfterSandboxDelete("alpha", retry);
  process.stdout.write(JSON.stringify({
    callsAfterFirstPrepare,
    adapterCallsAfterFirstPrepare,
    calls,
    adapterCalls,
    retry,
    sandbox: registry.getSandbox("alpha"),
    providers: [...providers.keys()],
  }));
})().catch((error) => { console.error(error); process.exit(1); });
`);

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    const payload = JSON.parse(result.stdout) as {
      callsAfterFirstPrepare: number;
      adapterCallsAfterFirstPrepare: number;
      calls: string[];
      adapterCalls: string[];
      retry: {
        destroyAlreadyPrepared: boolean;
        destroyAlreadyPending: boolean;
      };
      sandbox: { mcp?: unknown };
      providers: string[];
    };
    expect(payload.retry.destroyAlreadyPrepared).toBe(true);
    expect(payload.retry.destroyAlreadyPending).toBe(false);
    expect(payload.calls.slice(0, payload.callsAfterFirstPrepare)).toContain(
      "sandbox provider detach alpha alpha-mcp-github",
    );
    expect(
      payload.calls
        .slice(payload.callsAfterFirstPrepare)
        .filter((call) => call.includes("sandbox provider detach")),
    ).toEqual([]);
    expect(payload.adapterCalls).toHaveLength(payload.adapterCallsAfterFirstPrepare);
    expect(payload.sandbox.mcp).toBeUndefined();
    expect(payload.providers).not.toContain("alpha-mcp-github");
  });

  it("does not let force delete a drifted global provider", () => {
    const result = runDestroyLifecycleScenario(`
providers.set("alpha-mcp-github", "OTHER_TOKEN");
registry.registerSandbox({
  name: "alpha",
  agent: "openclaw",
  mcp: {
    bridges: { github: bridgeEntries.github },
    destroyPendingAt: "2026-06-27T01:00:00.000Z",
  },
});
registry.addCustomPolicy("alpha", ownedPolicy("github"));
const bridge = require("./dist/lib/actions/sandbox/mcp-bridge.js");
(async () => {
  const sandbox = registry.getSandbox("alpha");
  const preparation = {
    entries: Object.values(sandbox.mcp.bridges),
    detachedProviderEntries: [],
    scrubbedAdapterEntries: [],
    destroyAlreadyPrepared: false,
    destroyAlreadyPending: true,
  };
  let message = "";
  try {
    await bridge.finalizeMcpBridgesAfterSandboxDelete("alpha", preparation, { force: true });
  } catch (error) {
    message = error.message;
  }
  process.stdout.write(JSON.stringify({
    message,
    sandbox: registry.getSandbox("alpha"),
    providers: [...providers.keys()],
    calls,
  }));
})().catch((error) => { console.error(error); process.exit(1); });
`);

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    const payload = JSON.parse(result.stdout) as {
      message: string;
      sandbox: { mcp: { bridges: Record<string, unknown> } };
      providers: string[];
      calls: string[];
    };
    expect(payload.message).toContain("no longer exactly matches");
    expect(payload.message).toContain("--force does not delete");
    expect(payload.sandbox.mcp.bridges).toHaveProperty("github");
    expect(payload.providers).toContain("alpha-mcp-github");
    expect(payload.calls).not.toContain("provider delete alpha-mcp-github");
  });
});
