// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  evaluateE2eWorkflowDispatchSelectors,
  readFreeStandingJobsInventory,
  validateE2eWorkflowBoundary,
} from "../../../tools/e2e/workflow-boundary.mts";

describe("Jetson nvmap GPU E2E workflow boundary", () => {
  it("keeps Jetson selectable but excluded from full-suite dispatch", () => {
    const inventory = readFreeStandingJobsInventory();
    expect(validateE2eWorkflowBoundary()).toEqual([]);
    expect(inventory.allowedJobs).toContain("jetson-nvmap-gpu");
    expect(inventory.targetToJob.get("jetson-nvmap-gpu")).toBe("jetson-nvmap-gpu");
    expect(evaluateE2eWorkflowDispatchSelectors({}).selectedFreeStandingJobs).not.toContain(
      "jetson-nvmap-gpu",
    );
  });

  it("runs Jetson only when explicitly selected", () => {
    for (const selector of [{ targets: "jetson-nvmap-gpu" }, { jobs: "jetson-nvmap-gpu" }]) {
      expect(evaluateE2eWorkflowDispatchSelectors(selector)).toMatchObject({
        valid: true,
        liveTargetsRun: false,
        selectedFreeStandingJobs: ["jetson-nvmap-gpu"],
        registryTargets: [],
      });
    }
  });

  it("reports default jobs without claiming explicit-only Jetson ran", () => {
    expect(validateE2eWorkflowBoundary()).toEqual([]);
  });
});
