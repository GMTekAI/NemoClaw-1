// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { type SpawnSyncReturns, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "vitest";

const repoRoot = path.join(import.meta.dirname, "..");

function runScript(scriptBody: string): SpawnSyncReturns<string> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-generated-policy-"));
  const scriptPath = path.join(tmpDir, "script.js");
  fs.writeFileSync(scriptPath, scriptBody);
  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: repoRoot,
    encoding: "utf-8",
    env: {
      HOME: tmpDir,
      NEMOCLAW_NON_INTERACTIVE: "1",
      NEMOCLAW_SKIP_MATTERMOST_AUTH_VALIDATION: "1",
      MATTERMOST_BOT_TOKEN: "test-mattermost-token",
      MATTERMOST_URL: "https://mattermost.com",
    },
    timeout: 15000,
  });
  fs.rmSync(tmpDir, { recursive: true, force: true });
  return result;
}

function parseResultPayload<T extends Record<string, unknown>>(
  result: SpawnSyncReturns<string>,
): T {
  const marker = result.stdout.lastIndexOf("__RESULT__");
  assert.ok(marker >= 0, `no __RESULT__ marker in stdout:\n${result.stdout}`);
  const payload = JSON.parse(result.stdout.slice(marker + "__RESULT__".length).trim()) as T;
  assert.ok(!payload.error, `unexpected error: ${payload.error}\n${payload.stack || ""}`);
  return payload;
}

function buildPreamble(): string {
  const j = (p: string) => JSON.stringify(path.join(repoRoot, "dist", "lib", p));
  return String.raw`
const resolver = require(${j("adapters/openshell/resolve.js")});
resolver.resolveOpenshell = () => "/fake/openshell";

const openshellRuntime = require(${j("adapters/openshell/runtime.js")});
openshellRuntime.runOpenshell = () => ({ status: 0, stdout: "", stderr: "" });

const processRecovery = require(${j("actions/sandbox/process-recovery.js")});
processRecovery.executeSandboxExecCommand = () => ({ status: 0, stdout: "", stderr: "" });
processRecovery.executeSandboxCommand = () => null;

const runner = require(${j("runner.js")});
runner.run = () => ({ status: 0, stdout: "", stderr: "" });
runner.runCapture = () => "";

const gatewayRuntime = require(${j("gateway-runtime-action.js")});
gatewayRuntime.recoverNamedGatewayRuntime = async () => ({ recovered: true });

const credentials = require(${j("credentials/store.js")});
credentials.getCredential = (key) => process.env[key] || null;
credentials.saveCredential = () => true;
credentials.deleteCredential = () => true;
credentials.prompt = async (msg) => { throw new Error("unexpected prompt: " + msg); };

const onboard = require(${j("onboard.js")});
onboard.isNonInteractive = () => true;

const onboardProviders = require(${j("onboard/providers.js")});
onboardProviders.upsertMessagingProviders = () => {};

const registry = require(${j("state/registry.js")});
registry.getSandbox = () => ({ name: "test-sb", agent: "openclaw" });
registry.updateSandbox = () => true;

const policies = require(${j("policy/index.js")});
const appliedCalls = [];
const appliedContentCalls = [];
const callOrder = [];
policies.listPresets = () => ["telegram", "slack", "discord", "npm", "github"].map((name) => ({ name }));
policies.applyPreset = (sandboxName, presetName) => {
  appliedCalls.push({ sandboxName, presetName });
  callOrder.push("applyPreset:" + presetName);
  return true;
};
policies.applyPresetContent = (sandboxName, presetName, content, options) => {
  appliedContentCalls.push({ sandboxName, presetName, content, options });
  callOrder.push("applyPresetContent:" + presetName);
  return true;
};
policies.getAppliedPresets = () => [];

const onboardSession = require(${j("state/onboard-session.js")});
onboardSession.loadSession = () => ({ sandboxName: "test-sb", policyPresets: [] });
onboardSession.updateSession = (mutator) => mutator({ sandboxName: "test-sb", policyPresets: [] });

const origLog = console.log;
console.log = (...args) => {
  const line = args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ");
  if (line.includes("Change queued")) callOrder.push("promptAndRebuild");
  origLog.call(console, ...args);
};

const channelModule = require(${j("actions/sandbox/policy-channel.js")});
module.exports = { channelModule, appliedCalls, appliedContentCalls, callOrder };
`;
}

describe("channels add generated policy templates", () => {
  it("applies the generated Mattermost policy before triggering rebuild", () => {
    const script = `${buildPreamble()}
const ctx = module.exports;
(async () => {
  try {
    await ctx.channelModule.addSandboxChannel("test-sb", { channel: "mattermost" });
    process.stdout.write("\\n__RESULT__" + JSON.stringify({
      appliedCalls: ctx.appliedCalls,
      appliedContentCalls: ctx.appliedContentCalls,
      callOrder: ctx.callOrder,
    }) + "\\n");
  } catch (err) {
    process.stdout.write("\\n__RESULT__" + JSON.stringify({ error: err.message, stack: err.stack }) + "\\n");
  }
})();
`;
    const result = runScript(script);
    assert.equal(result.status, 0, `script failed: ${result.stderr}\n${result.stdout}`);
    const payload = parseResultPayload<{
      appliedCalls: unknown[];
      appliedContentCalls: Array<{
        sandboxName: string;
        presetName: string;
        content: string;
        options: unknown;
      }>;
      callOrder: string[];
    }>(result);

    assert.deepEqual(payload.appliedCalls, []);
    assert.equal(payload.appliedContentCalls.length, 1);
    assert.equal(payload.appliedContentCalls[0].sandboxName, "test-sb");
    assert.equal(payload.appliedContentCalls[0].presetName, "mattermost");
    assert.deepEqual(payload.appliedContentCalls[0].options, {
      custom: { sourcePath: "messaging:mattermost" },
    });
    assert.match(payload.appliedContentCalls[0].content, /host: mattermost\.com/);
    assert.match(payload.appliedContentCalls[0].content, /port: 443/);

    const applyIdx = payload.callOrder.indexOf("applyPresetContent:mattermost");
    const rebuildIdx = payload.callOrder.indexOf("promptAndRebuild");
    assert.ok(applyIdx >= 0, `applyPresetContent was never called: ${payload.callOrder}`);
    assert.ok(rebuildIdx >= 0, `promptAndRebuild was never called: ${payload.callOrder}`);
    assert.ok(applyIdx < rebuildIdx, `generated policy applied too late: ${payload.callOrder}`);
  });
});

describe("channel preset source-of-truth", () => {
  it("every known channel ships a preset YAML or generated policy template", () => {
    const { knownChannelNames } = require(
      path.join(repoRoot, "dist", "lib", "sandbox", "channels.js"),
    ) as { knownChannelNames: () => string[] };
    const { loadPreset, parsePresetPolicyKeys } = require(
      path.join(repoRoot, "dist", "lib", "policy", "index.js"),
    ) as {
      loadPreset: (name: string) => string | null;
      parsePresetPolicyKeys: (content: string | null | undefined) => string[];
    };
    const { listBuiltInMessagingChannelManifests } = require(
      path.join(repoRoot, "dist", "lib", "messaging", "channels", "index.js"),
    ) as {
      listBuiltInMessagingChannelManifests: () => Array<{
        id: string;
        policyTemplates?: readonly unknown[];
      }>;
    };
    const generatedPolicyChannels = new Set(
      listBuiltInMessagingChannelManifests()
        .filter((manifest) => (manifest.policyTemplates?.length ?? 0) > 0)
        .map((manifest) => manifest.id),
    );
    const failures = knownChannelNames()
      .filter((name) => !generatedPolicyChannels.has(name))
      .map((name) => ({ name, content: loadPreset(name) }))
      .map(({ name, content }) => ({ name, content, keys: parsePresetPolicyKeys(content) }))
      .filter(({ content, keys }) => content === null || keys.length === 0)
      .map(({ name }) => name);
    assert.deepEqual(failures, []);
  });
});
