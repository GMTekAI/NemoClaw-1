// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";

import { describe, expect, it } from "vitest";

import {
  buildMcpCredentialReadinessCommand,
  buildMcpCredentialRevisionSnapshotCommand,
  parseMcpProviderMetadata,
  providerDetachChangedState,
} from "./mcp-bridge";

describe("OpenShell MCP provider state", () => {
  it("parses provider type and credential keys without values", () => {
    expect(
      parseMcpProviderMetadata(`
Provider:

  Id: 11111111-2222-4333-8444-555555555555
  Name: alpha-mcp-github
  Type: generic
  Resource version: 7
  Credential keys: GITHUB_TOKEN
  Config keys: <none>
`),
    ).toEqual({
      id: "11111111-2222-4333-8444-555555555555",
      resourceVersion: 7,
      type: "generic",
      credentialKeys: ["GITHUB_TOKEN"],
    });
    expect(parseMcpProviderMetadata("Type: generic\nCredential keys: <none>\n")).toEqual({
      id: null,
      resourceVersion: null,
      type: "generic",
      credentialKeys: [],
    });
  });

  it("distinguishes a real detach from OpenShell's idempotent success", () => {
    expect(
      providerDetachChangedState(0, "✓ Detached provider alpha-mcp-github from sandbox alpha"),
    ).toBe(true);
    expect(
      providerDetachChangedState(0, "Provider alpha-mcp-github was not attached to sandbox alpha."),
    ).toBe(false);
  });

  it("accepts current revision-scoped placeholders without exposing their value", () => {
    const command = buildMcpCredentialReadinessCommand("GITHUB_TOKEN");
    for (const value of [
      "openshell:resolve:env:GITHUB_TOKEN",
      "openshell:resolve:env:v11_GITHUB_TOKEN",
      "openshell:resolve:env:v0_GITHUB_TOKEN",
    ]) {
      const result = spawnSync("/bin/sh", ["-c", command], {
        encoding: "utf8",
        env: { GITHUB_TOKEN: value },
      });
      expect(result.status, value).toBe(0);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe("");
    }

    for (const value of [
      "raw-secret",
      "openshell:resolve:env:v_GITHUB_TOKEN",
      "openshell:resolve:env:v11_OTHER_TOKEN",
      "openshell:resolve:env:v11x_GITHUB_TOKEN",
    ]) {
      const result = spawnSync("/bin/sh", ["-c", command], {
        encoding: "utf8",
        env: { GITHUB_TOKEN: value },
      });
      expect(result.status, value).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe("");
    }
  });

  it("captures only validated OpenShell credential placeholders without printing values", () => {
    const snapshotPath = `/tmp/nemoclaw-mcp-provider-sync-${randomUUID()}`;
    const command = buildMcpCredentialRevisionSnapshotCommand("GITHUB_TOKEN", snapshotPath);

    try {
      for (const value of [
        "openshell:resolve:env:GITHUB_TOKEN",
        "openshell:resolve:env:v11_GITHUB_TOKEN",
      ]) {
        fs.rmSync(snapshotPath, { force: true });
        const result = spawnSync("/bin/sh", ["-c", command], {
          encoding: "utf8",
          env: { GITHUB_TOKEN: value },
        });
        expect(result.status, value).toBe(0);
        expect(result.stdout).toBe("");
        expect(result.stderr).toBe("");
        expect(fs.readFileSync(snapshotPath, "utf8")).toBe(value);
      }

      const rawSecret = "never-write-or-print-this-secret";
      fs.rmSync(snapshotPath, { force: true });
      const rawResult = spawnSync("/bin/sh", ["-c", command], {
        encoding: "utf8",
        env: { GITHUB_TOKEN: rawSecret },
      });
      expect(rawResult.status).not.toBe(0);
      expect(rawResult.stdout).toBe("");
      expect(rawResult.stderr).toBe("");
      expect(fs.readFileSync(snapshotPath, "utf8")).toBe("");
      expect(
        `${rawResult.stdout}${rawResult.stderr}${fs.readFileSync(snapshotPath, "utf8")}`,
      ).not.toContain(rawSecret);

      fs.rmSync(snapshotPath, { force: true });
      const wrapperMarker = "__NEMOCLAW_MCP_SNAPSHOT_WRAPPER_CONTINUED__";
      const absentResult = spawnSync(
        "/bin/sh",
        ["-c", `${command}\nprintf '%s\\n' '${wrapperMarker}'`],
        {
          encoding: "utf8",
          env: {},
        },
      );
      expect(absentResult.status).toBe(0);
      expect(absentResult.stdout.trim()).toBe(wrapperMarker);
      expect(absentResult.stderr).toBe("");
      expect(fs.readFileSync(snapshotPath, "utf8")).toBe("");
    } finally {
      fs.rmSync(snapshotPath, { force: true });
    }
  });

  it("does not overwrite a pre-existing credential revision snapshot", () => {
    const snapshotPath = `/tmp/nemoclaw-mcp-provider-sync-${randomUUID()}`;
    const sentinel = "pre-existing-snapshot";
    fs.writeFileSync(snapshotPath, sentinel, { mode: 0o600 });

    try {
      const result = spawnSync(
        "/bin/sh",
        ["-c", buildMcpCredentialRevisionSnapshotCommand("GITHUB_TOKEN", snapshotPath)],
        {
          encoding: "utf8",
          env: {
            GITHUB_TOKEN: "openshell:resolve:env:v11_GITHUB_TOKEN",
          },
        },
      );
      expect(result.status).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(fs.readFileSync(snapshotPath, "utf8")).toBe(sentinel);
    } finally {
      fs.rmSync(snapshotPath, { force: true });
    }
  });

  it("requires a changed credential revision after provider updates", () => {
    const snapshotPath = `/tmp/nemoclaw-mcp-provider-sync-${randomUUID()}`;
    const runReadiness = (value: string) =>
      spawnSync(
        "/bin/sh",
        ["-c", buildMcpCredentialReadinessCommand("GITHUB_TOKEN", snapshotPath)],
        { encoding: "utf8", env: { GITHUB_TOKEN: value } },
      );

    try {
      for (const [prior, stale, refreshed] of [
        [
          "openshell:resolve:env:v11_GITHUB_TOKEN",
          "openshell:resolve:env:v11_GITHUB_TOKEN",
          "openshell:resolve:env:v12_GITHUB_TOKEN",
        ],
        [
          "openshell:resolve:env:GITHUB_TOKEN",
          "openshell:resolve:env:GITHUB_TOKEN",
          "openshell:resolve:env:v1_GITHUB_TOKEN",
        ],
      ]) {
        fs.writeFileSync(snapshotPath, prior, { mode: 0o600 });
        const staleResult = runReadiness(stale);
        expect(staleResult.status, prior).not.toBe(0);
        expect(staleResult.stdout).toBe("");
        expect(staleResult.stderr).toBe("");

        const refreshedResult = runReadiness(refreshed);
        expect(refreshedResult.status, prior).toBe(0);
        expect(refreshedResult.stdout).toBe("");
        expect(refreshedResult.stderr).toBe("");
      }
    } finally {
      fs.rmSync(snapshotPath, { force: true });
    }
  });

  it("treats an empty pre-update snapshot as presence-only and rejects malformed prior state", () => {
    const snapshotPath = `/tmp/nemoclaw-mcp-provider-sync-${randomUUID()}`;
    const command = buildMcpCredentialReadinessCommand("GITHUB_TOKEN", snapshotPath);
    const run = (value: string) =>
      spawnSync("/bin/sh", ["-c", command], {
        encoding: "utf8",
        env: { GITHUB_TOKEN: value },
      });

    try {
      fs.writeFileSync(snapshotPath, "", { mode: 0o600 });
      for (const value of [
        "openshell:resolve:env:GITHUB_TOKEN",
        "openshell:resolve:env:v1_GITHUB_TOKEN",
      ]) {
        const result = run(value);
        expect(result.status, value).toBe(0);
        expect(result.stdout).toBe("");
        expect(result.stderr).toBe("");
      }

      fs.writeFileSync(snapshotPath, "raw-or-corrupt-prior-value", {
        mode: 0o600,
      });
      const malformedResult = run("openshell:resolve:env:v2_GITHUB_TOKEN");
      expect(malformedResult.status).not.toBe(0);
      expect(malformedResult.stdout).toBe("");
      expect(malformedResult.stderr).toBe("");

      fs.rmSync(snapshotPath, { force: true });
      const missingResult = run("openshell:resolve:env:v2_GITHUB_TOKEN");
      expect(missingResult.status).not.toBe(0);
      expect(missingResult.stdout).toBe("");
      expect(missingResult.stderr).toBe("");
    } finally {
      fs.rmSync(snapshotPath, { force: true });
    }
  });
});
