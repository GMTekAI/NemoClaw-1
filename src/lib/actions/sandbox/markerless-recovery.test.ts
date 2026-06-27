// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { outputLooksLikeMarkerlessGatewayLaunch } from "./markerless-recovery";

describe("markerless recovery output", () => {
  it("treats launcher-started output as provisional recovery only", () => {
    expect(
      outputLooksLikeMarkerlessGatewayLaunch({
        status: 0,
        stdout: "launcher started without legacy recovery marker",
        stderr: "",
      }),
    ).toBe(true);
  });

  it("rejects failed or unrelated output", () => {
    expect(
      outputLooksLikeMarkerlessGatewayLaunch({
        status: 0,
        stdout: "RECOVERY_FAILED",
        stderr: "gateway failed",
      }),
    ).toBe(false);
    expect(
      outputLooksLikeMarkerlessGatewayLaunch({
        status: 0,
        stdout: "plain sandbox exec output",
        stderr: "",
      }),
    ).toBe(false);
    expect(
      outputLooksLikeMarkerlessGatewayLaunch({
        status: 1,
        stdout: "launcher started",
        stderr: "",
      }),
    ).toBe(false);
  });
});
