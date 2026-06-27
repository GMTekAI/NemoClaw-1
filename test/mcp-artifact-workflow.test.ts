// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

type Step = {
  name?: string;
  env?: Record<string, string>;
};
type Job = {
  env?: Record<string, string>;
  steps?: Step[];
  with?: Record<string, unknown>;
};
type Workflow = {
  on?: {
    workflow_dispatch?: {
      inputs?: Record<string, { default?: unknown }>;
    };
  };
  jobs: Record<string, Job>;
};

function workflow(path: string): Workflow {
  const result = spawnSync(
    process.execPath,
    [
      "-e",
      'const fs=require("node:fs"); const {parse}=require("yaml"); process.stdout.write(JSON.stringify(parse(fs.readFileSync(process.argv[1], "utf8"))))',
      path,
    ],
    { cwd: process.cwd(), encoding: "utf8", timeout: 5_000 },
  );
  expect(result.status, result.stderr || `Could not parse workflow ${path}`).toBe(0);
  return JSON.parse(result.stdout) as Workflow;
}

function installStep(job: Job): Step | undefined {
  return job.steps?.find((step) => step.name === "Install OpenShell CLI");
}

describe("MCP OpenShell artifact workflow boundary", () => {
  it("targets the current OpenShell main dev build by default", () => {
    const nightly = workflow(".github/workflows/nightly-e2e.yaml");
    const vitest = workflow(".github/workflows/e2e-vitest-scenarios.yaml");
    const nightlyInstall = installStep(nightly.jobs["mcp-bridge-e2e"]);

    expect(nightly.on?.workflow_dispatch?.inputs?.openshell_channel?.default).toBe("dev");
    expect(vitest.on?.workflow_dispatch?.inputs?.openshell_channel?.default).toBe("dev");
    expect(nightlyInstall?.env?.NEMOCLAW_OPENSHELL_CHANNEL).toContain("|| 'dev'");
    expect(nightlyInstall?.env?.NEMOCLAW_OPENSHELL_FORCE_INSTALL).toBe("1");
    expect(
      installStep(workflow(".github/workflows/e2e-vitest-scenarios.yaml").jobs["mcp-bridge-vitest"])
        ?.env?.NEMOCLAW_OPENSHELL_FORCE_INSTALL,
    ).toBe("1");
  });

  it("threads the expected OpenShell head SHA into every artifact-enabled job", () => {
    const nightly = workflow(".github/workflows/nightly-e2e.yaml");
    const vitest = workflow(".github/workflows/e2e-vitest-scenarios.yaml");
    const nightlyInstall = installStep(nightly.jobs["mcp-bridge-e2e"]);

    expect(nightlyInstall?.env?.NEMOCLAW_OPENSHELL_ARTIFACT_HEAD_SHA).toContain(
      "inputs.openshell_artifact_head_sha",
    );
    const networkPolicyEnv = JSON.parse(
      String(nightly.jobs["network-policy-e2e"].with?.env_json ?? "{}"),
    ) as Record<string, string>;
    expect(networkPolicyEnv).not.toHaveProperty("NEMOCLAW_OPENSHELL_ARTIFACT_HEAD_SHA");
    expect(vitest.jobs["mcp-bridge-vitest"].env?.NEMOCLAW_OPENSHELL_ARTIFACT_HEAD_SHA).toBe(
      "${{ inputs.openshell_artifact_head_sha }}",
    );
    expect(vitest.jobs["network-policy-vitest"].env?.NEMOCLAW_OPENSHELL_ARTIFACT_HEAD_SHA).toBe(
      "${{ inputs.openshell_artifact_head_sha }}",
    );
  });

  it("uses a cross-repository read token instead of the NemoClaw GITHUB_TOKEN", () => {
    const nightly = workflow(".github/workflows/nightly-e2e.yaml");
    const vitest = workflow(".github/workflows/e2e-vitest-scenarios.yaml");

    for (const step of [
      installStep(nightly.jobs["mcp-bridge-e2e"]),
      installStep(vitest.jobs["mcp-bridge-vitest"]),
    ]) {
      const token = step?.env?.NEMOCLAW_INSTALL_OPENSHELL_GH_TOKEN ?? "";
      expect(token).toContain("secrets.OPENSHELL_ARTIFACT_READ_TOKEN");
      expect(token).not.toContain("github.token");
    }
  });
});
