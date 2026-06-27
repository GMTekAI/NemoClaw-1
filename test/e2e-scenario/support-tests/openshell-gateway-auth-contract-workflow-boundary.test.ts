// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  evaluateE2eVitestWorkflowDispatchSelectors,
  readFreeStandingJobsInventory,
  validateE2eVitestScenariosWorkflowBoundary,
} from "../../../tools/e2e-scenarios/workflow-boundary.mts";

describe("OpenShell gateway auth contract workflow boundary", () => {
  it("keeps the auth contract job explicit-only", () => {
    const inventory = readFreeStandingJobsInventory();

    expect(validateE2eVitestScenariosWorkflowBoundary()).toEqual([]);
    expect(inventory.allowedJobs).toContain("openshell-gateway-auth-contract-vitest");
    expect(inventory.scenarioToJob.get("openshell-gateway-auth-contract")).toBe(
      "openshell-gateway-auth-contract-vitest",
    );
    expect(evaluateE2eVitestWorkflowDispatchSelectors({}).selectedFreeStandingJobs).not.toContain(
      "openshell-gateway-auth-contract-vitest",
    );
  });

  it("runs the auth contract job when explicitly selected", () => {
    for (const selector of [
      { scenarios: "openshell-gateway-auth-contract" },
      { jobs: "openshell-gateway-auth-contract-vitest" },
    ]) {
      expect(evaluateE2eVitestWorkflowDispatchSelectors(selector)).toMatchObject({
        valid: true,
        liveScenariosRuns: false,
        selectedFreeStandingJobs: ["openshell-gateway-auth-contract-vitest"],
        registryScenarios: [],
      });
    }
  });
});
