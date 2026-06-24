// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { TargetDefinition } from "../registry/types.ts";

export interface LiveTargetRunPlan {
  targetId: string;
  manifestPath: string | null;
  expectedStateId: string | undefined;
  suiteIds: string[];
  phases: string[];
}

export function buildLiveTargetRunPlan(target: TargetDefinition): LiveTargetRunPlan {
  return {
    targetId: target.id,
    manifestPath: target.manifestPath ?? null,
    expectedStateId: target.expectedStateId,
    suiteIds: target.suiteIds ?? [],
    phases: [
      "environment",
      "onboarding",
      ...(target.environment?.lifecycle ? ["lifecycle"] : []),
      "state-validation",
    ],
  };
}
