// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";
import YAML from "yaml";

import { buildSystemPrompt } from "../tools/e2e-advisor/analyze.mts";

const REPO_ROOT = path.resolve(import.meta.dirname, "..");

interface WorkflowStep {
  name?: string;
  run?: string;
}

interface WorkflowJob {
  steps?: WorkflowStep[];
}

interface Workflow {
  jobs?: {
    advise?: WorkflowJob;
  };
}

function prepareTargetCheckoutScript(): string {
  const workflow = YAML.parse(
    fs.readFileSync(path.join(REPO_ROOT, ".github/workflows/e2e-advisor.yaml"), "utf8"),
  ) as Workflow;
  const step = workflow.jobs?.advise?.steps?.find(
    (entry) => entry.name === "Prepare target PR checkout",
  );
  expect(step?.run).toEqual(expect.any(String));
  return step?.run as string;
}

function runPrepareTargetCheckout(env: {
  TARGET_REPO: string;
  TARGET_PR: string;
  TARGET_BASE: string;
}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "e2e-advisor-workflow-"));
  const binDir = path.join(tmp, "bin");
  const gitLog = path.join(tmp, "git.log");
  const githubEnv = path.join(tmp, "github-env");
  fs.mkdirSync(binDir);
  fs.writeFileSync(
    path.join(binDir, "git"),
    '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >> "$FAKE_GIT_LOG"\n',
    { mode: 0o755 },
  );
  const result = spawnSync("bash", ["-c", prepareTargetCheckoutScript()], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: {
      ...process.env,
      ...env,
      FAKE_GIT_LOG: gitLog,
      GITHUB_ENV: githubEnv,
      PATH: `${binDir}:${process.env.PATH ?? ""}`,
    },
  });
  return {
    ...result,
    cleanup: () => fs.rmSync(tmp, { recursive: true, force: true }),
    gitCalls: fs.existsSync(gitLog) ? fs.readFileSync(gitLog, "utf8").trim().split(/\r?\n/u) : [],
    githubEnv: fs.existsSync(githubEnv) ? fs.readFileSync(githubEnv, "utf8") : "",
  };
}

describe("E2E recommendation advisor prompt", () => {
  it("requires resume and repair E2E for onboarding machine compatibility changes", () => {
    const prompt = buildSystemPrompt();

    expect(prompt).toContain("Onboarding resume rule");
    expect(prompt).toContain("onboard-resume-e2e");
    expect(prompt).toContain("onboard-repair-e2e");
    expect(prompt).toContain("src/lib/onboard/machine");
  });

  it("validates manual target checkout inputs before git fetch", () => {
    const invalidCases = [
      {
        TARGET_REPO: "NVIDIA/NemoClaw --upload-pack=x",
        TARGET_PR: "5756",
        TARGET_BASE: "main",
      },
      { TARGET_REPO: "NVIDIA/NemoClaw", TARGET_PR: "12:refs/heads/x", TARGET_BASE: "main" },
      {
        TARGET_REPO: "NVIDIA/NemoClaw",
        TARGET_PR: "5756",
        TARGET_BASE: "main:refs/heads/x",
      },
      { TARGET_REPO: "NVIDIA/NemoClaw", TARGET_PR: "5756", TARGET_BASE: "../main" },
      { TARGET_REPO: "NVIDIA/NemoClaw", TARGET_PR: "5756", TARGET_BASE: "-main" },
    ];

    for (const invalidEnv of invalidCases) {
      const result = runPrepareTargetCheckout(invalidEnv);
      try {
        expect(result.status).toBe(1);
        expect(result.gitCalls).toEqual([]);
      } finally {
        result.cleanup();
      }
    }

    const valid = runPrepareTargetCheckout({
      TARGET_REPO: "NVIDIA/NemoClaw",
      TARGET_PR: "5756",
      TARGET_BASE: "main",
    });
    try {
      expect(valid.status).toBe(0);
      expect(valid.gitCalls).toEqual([
        "-C /tmp/e2e-advisor-target init",
        "-C /tmp/e2e-advisor-target remote add target https://github.com/NVIDIA/NemoClaw.git",
        "-C /tmp/e2e-advisor-target fetch --no-tags target main",
        "-C /tmp/e2e-advisor-target fetch --no-tags target pull/5756/head:refs/remotes/target/pr-5756",
        "-C /tmp/e2e-advisor-target checkout --detach refs/remotes/target/pr-5756",
      ]);
      expect(valid.githubEnv).toBe("ADVISOR_WORKDIR=/tmp/e2e-advisor-target\n");
    } finally {
      valid.cleanup();
    }
  });
});
