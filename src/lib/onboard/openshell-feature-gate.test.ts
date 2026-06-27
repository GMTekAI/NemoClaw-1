// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

import {
  hasRequiredOpenshellMessagingFeatures,
  REQUIRED_OPENSHELL_MCP_FEATURES,
} from "./openshell-feature-gate";

describe("OpenShell MCP feature gate", () => {
  it("finds provider rewrite and MCP L7 markers across OpenShell binaries", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-openshell-features-"));
    try {
      const openshell = path.join(dir, "openshell");
      const gateway = path.join(dir, "openshell-gateway");
      const sandbox = path.join(dir, "openshell-sandbox");
      fs.writeFileSync(openshell, `binary ${REQUIRED_OPENSHELL_MCP_FEATURES[0]}`);
      fs.writeFileSync(gateway, `binary ${REQUIRED_OPENSHELL_MCP_FEATURES[1]}`);
      fs.writeFileSync(sandbox, `binary ${REQUIRED_OPENSHELL_MCP_FEATURES[2]}`);

      expect(
        hasRequiredOpenshellMessagingFeatures({
          openshellBin: openshell,
          gatewayBin: null,
          sandboxBin: null,
        }),
      ).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("fails closed when any required marker is absent", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-openshell-features-"));
    try {
      const openshell = path.join(dir, "openshell");
      fs.writeFileSync(openshell, `binary ${REQUIRED_OPENSHELL_MCP_FEATURES[0]}`);

      expect(
        hasRequiredOpenshellMessagingFeatures({
          openshellBin: openshell,
          gatewayBin: null,
          sandboxBin: null,
        }),
      ).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
