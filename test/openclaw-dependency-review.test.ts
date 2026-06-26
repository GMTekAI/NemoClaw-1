// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { readYaml, type WorkflowJob, type WorkflowStep } from "./helpers/e2e-workflow-contract";

const REPO_ROOT = path.join(import.meta.dirname, "..");
const DEPENDENCY_REVIEW = path.join(
  REPO_ROOT,
  "docs",
  "security",
  "openclaw-2026.6.9-dependency-review.md",
);
const CODEX_ACP_TARBALL =
  "https://registry.npmjs.org/@zed-industries/codex-acp/-/codex-acp-0.11.1.tgz";

type Workflow = {
  jobs: Record<string, WorkflowJob>;
};

function requiredStep(job: WorkflowJob, name: string): WorkflowStep {
  const step = job.steps?.find((candidate) => candidate.name === name);
  if (!step) {
    throw new Error(`Missing workflow step: ${name}`);
  }
  return step;
}

function requiredStepIndex(job: WorkflowJob, name: string): number {
  const index = job.steps?.findIndex((candidate) => candidate.name === name) ?? -1;
  if (index === -1) {
    throw new Error(`Missing workflow step: ${name}`);
  }
  return index;
}

function expectProductionDockerBuildGuard(job: WorkflowJob, stepName: string): void {
  const run = requiredStep(job, stepName).run ?? "";
  const guardIndex = run.indexOf("scripts/check-production-build-args.sh");
  const buildIndex = run.indexOf("docker build");

  expect(guardIndex, stepName).toBeGreaterThanOrEqual(0);
  expect(buildIndex, stepName).toBeGreaterThanOrEqual(0);
  expect(guardIndex, stepName).toBeLessThan(buildIndex);
}

function expectBuildPushGuard(job: WorkflowJob, guardStepName: string): void {
  const guardIndex = requiredStepIndex(job, guardStepName);
  const buildIndex =
    job.steps?.findIndex((step) =>
      String(step.uses ?? "").startsWith("docker/build-push-action@"),
    ) ?? -1;

  expect(buildIndex, guardStepName).toBeGreaterThanOrEqual(0);
  expect(guardIndex, guardStepName).toBeLessThan(buildIndex);
  expect(requiredStep(job, guardStepName).run).toContain("scripts/check-production-build-args.sh");
}

describe("OpenClaw 2026.6.9 dependency review contract", () => {
  it("keeps advisor disposition evidence in the dependency review note", () => {
    const review = readFileSync(DEPENDENCY_REVIEW, "utf-8");

    expect(review).toContain(CODEX_ACP_TARBALL);
    expect(review).toContain(
      "Codex ACP helper is also installed from the reviewed npm tarball URL",
    );
    expect(review).toContain("OpenClaw Patch Source-of-Truth Table");
    expect(review).toContain(
      "| Patch | Invalid state | Source boundary | Why upstream/source cannot be fixed here | Regression test | Removal condition |",
    );

    for (const [patch, requiredTerms] of [
      ["Patch 2:", ["assertExplicitProxyAllowed", "OPENSHELL_SANDBOX=1", "upstream"]],
      ["Patch 2b:", ["host.openshell.internal", "useEnvProxy", "allowedHostnames"]],
      ["Patch 4:", ["managed-proxy activation", "dispatcherPolicy", "strict fetches"]],
      [
        "Patch 6:",
        ["cron model-provider preflight", "trusted_env_proxy", "cron-model-provider-preflight"],
      ],
    ] as const) {
      const row = review.split("\n").find((line) => line.includes(`| ${patch}`));
      expect(row, patch).toBeDefined();
      expect(
        row
          ?.split("|")
          .slice(1, -1)
          .every((cell) => cell.trim().length > 0),
        patch,
      ).toBe(true);
      for (const term of requiredTerms) {
        expect(row, `${patch} ${term}`).toContain(term);
      }
    }

    expect(review).toContain("OpenClaw Diagnostics OTEL Host Gateway Boundary");
    expect(review).toContain("openclaw-diagnostics-otel-local");
    expect(review).toContain("separate from the `web_fetch` host-gateway exception");
    expect(review).toContain("contains no `web_fetch`, `fetchWithSsrFGuard`");

    expect(review).toContain("Microsoft Teams Live E2E Disposition");
    expect(review).toContain("MSTEAMS_E2E=1");
    expect(review).toContain("MSTEAMS_PUBLIC_WEBHOOK_URL");
    expect(review).toContain("MSTEAMS_E2E_MESSAGE_COMMAND");
    expect(review).toContain("test/e2e-scenario/live/teams-message-round-trip.test.ts");

    expect(review).toContain("Advisor Disposition");
    expect(review).toContain("src/lib/messaging/channels/manifests.test.ts");
    expect(review).toContain("npm audit result in this note is a manual snapshot");
    expect(review).toContain("stale nonterminal rebuild-resume repair");
    expect(review).toContain("scripts/check-production-build-args.sh");
    expect(review).toContain('OPENCLAW_VERSION="${OPENCLAW_VERSION}"');
    expect(review).toContain("test/messaging-build-applier-render-safety.test.ts");
    expect(review).toContain("test/onboard-resume-provider-recovery.test.ts");
  });

  it("keeps Dockerfile installs tied to the reviewed codex-acp tarball and OpenClaw build arg", () => {
    const result = spawnSync(
      "bash",
      [
        "-lc",
        `
set -euo pipefail
codex_acp_block="$(sed -n '/# Pre-install the codex-acp package/,/# Upgrade OpenClaw if the base image is stale./p' Dockerfile)"
grep -Fq "CODEX_ACP_TARBALL='${CODEX_ACP_TARBALL}'" <<<"$codex_acp_block"
grep -Fq 'npm view "\${CODEX_ACP_SPEC}" dist.integrity' <<<"$codex_acp_block"
grep -Fq 'npm view "\${CODEX_ACP_SPEC}" dist.tarball' <<<"$codex_acp_block"
grep -Fq '"\${CODEX_ACP_TARBALL}"' <<<"$codex_acp_block"
if grep -Fq '"\${CODEX_ACP_SPEC}";' <<<"$codex_acp_block"; then
  echo 'codex-acp install still uses the package spec' >&2
  exit 1
fi
count="$(grep -Ec '^RUN OPENCLAW_VERSION="\\$\\{OPENCLAW_VERSION\\}" node --experimental-strip-types /src/lib/messaging/applier/build/messaging-build-applier\\.mts --agent openclaw --phase (runtime-setup|agent-install|post-agent-install)$' Dockerfile)"
test "$count" -eq 3
`,
      ],
      { cwd: REPO_ROOT, encoding: "utf-8" },
    );

    expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
  });

  it("keeps production Docker build workflows behind the build-arg guard", () => {
    const prSelfHosted = readYaml<Workflow>(".github/workflows/pr-self-hosted.yaml");
    const sandboxImages = readYaml<Workflow>(".github/workflows/sandbox-images-and-e2e.yaml");
    const baseImages = readYaml<Workflow>(".github/workflows/base-image.yaml");

    expectProductionDockerBuildGuard(
      prSelfHosted.jobs["build-sandbox-images"] as WorkflowJob,
      "Build production image",
    );
    expectProductionDockerBuildGuard(
      prSelfHosted.jobs["build-sandbox-images-arm64"] as WorkflowJob,
      "Build production image on arm64",
    );
    expectProductionDockerBuildGuard(
      sandboxImages.jobs["build-sandbox-images"] as WorkflowJob,
      "Build production image",
    );
    expectProductionDockerBuildGuard(
      sandboxImages.jobs["build-hermes-sandbox-image"] as WorkflowJob,
      "Build Hermes production image",
    );
    expectProductionDockerBuildGuard(
      sandboxImages.jobs["build-sandbox-images-arm64"] as WorkflowJob,
      "Build production image on arm64",
    );
    expectBuildPushGuard(
      baseImages.jobs["build-and-push"] as WorkflowJob,
      "Validate production Docker build args",
    );
    expectBuildPushGuard(
      baseImages.jobs["build-and-push-hermes"] as WorkflowJob,
      "Validate Hermes production Docker build args",
    );
  });
});
