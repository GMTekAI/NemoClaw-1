// @ts-nocheck
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

const PRELOAD_PATH = path.join(
  import.meta.dirname,
  "..",
  "src",
  "lib",
  "messaging",
  "channels",
  "mattermost",
  "runtime",
  "mattermost-trusted-env-proxy.ts",
);

function runDriver(driverBody: string) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mattermost-proxy-"));
  const driverPath = path.join(tmpDir, "driver.js");
  try {
    fs.writeFileSync(driverPath, driverBody);
    return spawnSync(process.execPath, [driverPath], {
      encoding: "utf-8",
      env: {
        PATH: process.env.PATH || "/usr/bin:/bin",
        PRELOAD_PATH,
        TEST_ROOT: tmpDir,
      },
      timeout: 5_000,
    });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

describe("mattermost trusted env-proxy preload", () => {
  it("patches the Mattermost API and probe guarded-fetch call sites", () => {
    const result = runDriver(String.raw`
      const fs = require("node:fs");
      const path = require("node:path");
      const openclawDist = path.join(process.env.TEST_ROOT, "node_modules", "openclaw", "dist");
      fs.mkdirSync(openclawDist, { recursive: true });
      const fixture = path.join(openclawDist, "mattermost-fixture.js");
      fs.writeFileSync(fixture, [
        "const calls = [];",
        "function fetchWithSsrFGuard(params) { calls.push(params); return params; }",
        "function ssrfPolicyFromPrivateNetworkOptIn(value) { return value; }",
        "fetchWithSsrFGuard({",
        "  url: 'https://chat.example.com/api/v4/users/me',",
        "  init: {},",
        "  auditContext: \"mattermost-api\",",
        "  policy: ssrfPolicyFromPrivateNetworkOptIn(false),",
        "});",
        "fetchWithSsrFGuard({",
        "  url: 'https://chat.example.com/api/v4/users/me',",
        "  init: {},",
        "  auditContext: \"mattermost-probe\",",
        "  policy: ssrfPolicyFromPrivateNetworkOptIn(false),",
        "});",
        "module.exports = calls;",
      ].join(String.fromCharCode(10)));

      require(process.env.PRELOAD_PATH);
      const calls = require(fixture);
      console.log(JSON.stringify(calls.map((call) => ({
        auditContext: call.auditContext,
        mode: call.mode,
      }))));
    `);

    expect(result.status, result.stderr || result.stdout).toBe(0);
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout.trim())).toEqual([
      { auditContext: "mattermost-api", mode: "trusted_env_proxy" },
      { auditContext: "mattermost-probe", mode: "trusted_env_proxy" },
    ]);
  });

  it("fails closed when a Mattermost guarded-fetch call shape is ambiguous", () => {
    const result = runDriver(String.raw`
      const fs = require("node:fs");
      const path = require("node:path");
      const openclawDist = path.join(process.env.TEST_ROOT, "node_modules", "openclaw", "dist");
      fs.mkdirSync(openclawDist, { recursive: true });
      const fixture = path.join(openclawDist, "mattermost-ambiguous.js");
      fs.writeFileSync(fixture, [
        "function fetchWithSsrFGuard(params) { return params; }",
        "fetchWithSsrFGuard({ auditContext: \"mattermost-api\" });",
        "fetchWithSsrFGuard({ auditContext: \"mattermost-api\" });",
      ].join(String.fromCharCode(10)));

      require(process.env.PRELOAD_PATH);
      require(fixture);
    `);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("expected one mattermost-api audit context");
  });

  it("leaves non-Mattermost guarded-fetch call sites untouched", () => {
    const result = runDriver(String.raw`
      const fs = require("node:fs");
      const path = require("node:path");
      const openclawDist = path.join(process.env.TEST_ROOT, "node_modules", "openclaw", "dist");
      fs.mkdirSync(openclawDist, { recursive: true });
      const fixture = path.join(openclawDist, "other-fixture.js");
      fs.writeFileSync(fixture, [
        "const calls = [];",
        "function fetchWithSsrFGuard(params) { calls.push(params); return params; }",
        "fetchWithSsrFGuard({",
        "  url: 'https://example.com',",
        "  auditContext: \"other-api\",",
        "});",
        "module.exports = calls;",
      ].join(String.fromCharCode(10)));

      require(process.env.PRELOAD_PATH);
      const calls = require(fixture);
      console.log(JSON.stringify(calls[0]));
    `);

    expect(result.status, result.stderr || result.stdout).toBe(0);
    expect(JSON.parse(result.stdout.trim())).toEqual({
      url: "https://example.com",
      auditContext: "other-api",
    });
  });
});
