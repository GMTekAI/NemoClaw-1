// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

const SHIELDS_DIST = path.resolve("dist/lib/shields/index.js");

describe("shields command exit serialization", () => {
  it("releases the token-bound lock before a repeated shields-down exits the process", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-shields-real-exit-"));
    const stateDir = path.join(home, ".nemoclaw", "state");
    const lockPath = path.join(stateDir, "shields-transition-lock-alpha.json");
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(stateDir, "shields-alpha.json"),
      JSON.stringify({
        shieldsDown: true,
        shieldsDownAt: "2026-06-27T00:00:00.000Z",
        updatedAt: "2026-06-27T00:00:00.000Z",
      }),
      { mode: 0o600 },
    );

    try {
      const result = spawnSync(
        process.execPath,
        [
          "-e",
          `require(${JSON.stringify(SHIELDS_DIST)}).shieldsDown("alpha", { processToken: ${JSON.stringify("a".repeat(32))} });`,
        ],
        {
          encoding: "utf-8",
          env: { ...process.env, HOME: home, NEMOCLAW_NON_INTERACTIVE: "1" },
          timeout: 10_000,
        },
      );

      expect(result.status, result.stderr).toBe(1);
      expect(`${result.stdout}\n${result.stderr}`).toContain("already unlocked");
      expect(fs.existsSync(lockPath)).toBe(false);
      expect(fs.readdirSync(stateDir).some((name) => name.includes(".acquire-"))).toBe(false);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
