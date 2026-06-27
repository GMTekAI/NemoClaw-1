// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";
import YAML from "yaml";

function readWorkflow(): Record<string, unknown> {
  return YAML.parse(
    fs.readFileSync(
      path.join(process.cwd(), ".github/workflows/e2e-vitest-scenarios.yaml"),
      "utf-8",
    ),
  ) as Record<string, unknown>;
}

describe("MCP bridge workflow boundary", () => {
  it("isolates Docker auth and withholds workflow tokens outside artifact installs", () => {
    const workflow = readWorkflow();
    const jobs = workflow.jobs as Record<
      string,
      { env?: Record<string, unknown>; steps?: Array<Record<string, unknown>> }
    >;
    const job = jobs["mcp-bridge-vitest"];
    expect(job).toBeDefined();
    expect(job.env ?? {}).not.toHaveProperty("DOCKER_CONFIG");
    const steps = job.steps ?? [];

    const configure = steps.find(
      (step) => step.name === "Configure isolated Docker auth directory",
    );
    expect(configure?.run).toContain(
      'echo "DOCKER_CONFIG=${RUNNER_TEMP}/docker-config-mcp-bridge" >> "$GITHUB_ENV"',
    );

    const auth = steps.find((step) => step.name === "Authenticate to Docker Hub");
    expect(auth?.run).toContain('mkdir -p "${DOCKER_CONFIG}"');
    expect(auth?.run).toContain('chmod 700 "${DOCKER_CONFIG}"');

    const cleanup = steps.find((step) => step.name === "Clean up Docker auth");
    expect(cleanup?.if).toBe("always()");
    expect(cleanup?.run).toContain("docker logout docker.io || true");
    expect(cleanup?.run).toContain('rm -rf "${DOCKER_CONFIG}"');

    const installOpenShell = steps.find((step) => step.name === "Install OpenShell CLI");
    const installEnv = (installOpenShell?.env ?? {}) as Record<string, unknown>;
    expect(installOpenShell?.env ?? {}).not.toHaveProperty("GH_TOKEN");
    expect(installEnv.NEMOCLAW_INSTALL_OPENSHELL_GH_TOKEN).toContain(
      "inputs.openshell_channel == 'artifact'",
    );
    expect(installOpenShell?.run).toContain(
      'if [[ "${NEMOCLAW_OPENSHELL_CHANNEL}" == "artifact" ]]',
    );
  });
});
