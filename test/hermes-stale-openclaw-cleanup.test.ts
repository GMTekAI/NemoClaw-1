// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { dockerRunCommandBetween, runDockerShell } from "./helpers/hermes-dockerfile-run";

const ROOT = path.resolve(import.meta.dirname, "..");
const HERMES_DOCKERFILE = path.join(ROOT, "agents", "hermes", "Dockerfile");

type StaleOpenclawShape = "directory" | "symlink";

type HermesCleanupFixture = {
  readonly tmp: string;
  readonly sandboxRoot: string;
  readonly hermesDir: string;
  readonly openclawDir: string;
  readonly symlinkTarget: string;
};

const staleOpenclawSetups: Record<StaleOpenclawShape, (fixture: HermesCleanupFixture) => void> = {
  directory: ({ openclawDir }) => {
    fs.mkdirSync(openclawDir, { recursive: true });
    fs.writeFileSync(path.join(openclawDir, "openclaw.json"), "{}\n");
  },
  symlink: ({ openclawDir, symlinkTarget }) => {
    fs.mkdirSync(symlinkTarget, { recursive: true });
    fs.writeFileSync(path.join(symlinkTarget, "sentinel"), "keep\n");
    fs.symlinkSync(symlinkTarget, openclawDir, "dir");
  },
};

function mode(entry: string): string {
  return (fs.statSync(entry).mode & 0o7777).toString(8);
}

function createHermesCleanupFixture(shape: StaleOpenclawShape): HermesCleanupFixture {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-hermes-openclaw-cleanup-"));
  const sandboxRoot = path.join(tmp, "sandbox");
  const hermesDir = path.join(sandboxRoot, ".hermes");
  const fixture = {
    tmp,
    sandboxRoot,
    hermesDir,
    openclawDir: path.join(sandboxRoot, ".openclaw"),
    symlinkTarget: path.join(tmp, "stale-openclaw-target"),
  };
  fs.mkdirSync(hermesDir, { recursive: true });
  fs.writeFileSync(path.join(hermesDir, "config.yaml"), "model: test\n");
  fs.writeFileSync(path.join(hermesDir, ".env"), "TOKEN=test\n");
  staleOpenclawSetups[shape](fixture);
  return fixture;
}

function runHermesCleanupFromStaleBase(shape: StaleOpenclawShape) {
  const fixture = createHermesCleanupFixture(shape);
  const dockerfile = fs.readFileSync(HERMES_DOCKERFILE, "utf-8");
  const command = dockerRunCommandBetween(
    dockerfile,
    "# Flatten stale published base images",
    "# Pin config hash at build time",
  ).replaceAll("/root/.cache/pip", path.join(fixture.tmp, "root-cache", "pip"));
  const { result } = runDockerShell(command, fixture.sandboxRoot);
  return { ...fixture, result };
}

describe("Hermes stale OpenClaw final-image cleanup", () => {
  it("removes stale OpenClaw state from the final image layout", () => {
    const run = runHermesCleanupFromStaleBase("directory");
    try {
      expect(run.result.status).toBe(0);
      expect(run.result.stderr).toBe("");
      expect(fs.existsSync(run.openclawDir)).toBe(false);
      expect(mode(run.hermesDir)).toBe("3770");
      expect(mode(path.join(run.hermesDir, "runtime"))).toBe("2770");
      expect(fs.readlinkSync(path.join(run.hermesDir, "gateway_state.json"))).toBe(
        "runtime/gateway_state.json",
      );
    } finally {
      fs.rmSync(run.tmp, { recursive: true, force: true });
    }
  });

  it("fails closed before following symlinked stale OpenClaw state", () => {
    const run = runHermesCleanupFromStaleBase("symlink");
    try {
      expect(run.result.status).toBe(1);
      expect(run.result.stderr).toContain(".openclaw is a symlink");
      expect(fs.lstatSync(run.openclawDir).isSymbolicLink()).toBe(true);
      expect(fs.readFileSync(path.join(run.symlinkTarget, "sentinel"), "utf-8")).toBe("keep\n");
    } finally {
      fs.rmSync(run.tmp, { recursive: true, force: true });
    }
  });
});
