// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

export const REQUIRED_OPENSHELL_MCP_FEATURES = [
  "request-body-credential-rewrite",
  "websocket-credential-rewrite",
  "allow_all_known_mcp_methods",
] as const;

export function hasRequiredOpenshellMessagingFeatures(options: {
  openshellBin: string | null;
  gatewayBin: string | null;
  sandboxBin: string | null;
}): boolean {
  if (!options.openshellBin) return false;
  const candidates = [
    options.openshellBin,
    path.join(path.dirname(options.openshellBin), "openshell-gateway"),
    path.join(path.dirname(options.openshellBin), "openshell-sandbox"),
    path.join(path.dirname(options.openshellBin), "openshell-driver-vm"),
    options.gatewayBin,
    options.sandboxBin,
  ].filter(
    (candidate): candidate is string => typeof candidate === "string" && candidate.length > 0,
  );

  const requiredMarkers = REQUIRED_OPENSHELL_MCP_FEATURES.map((marker) => Buffer.from(marker));
  const foundMarkers = new Set<string>();
  const seen = new Set<string>();
  for (const candidate of candidates) {
    if (seen.has(candidate)) continue;
    seen.add(candidate);
    let content: Buffer;
    try {
      if (!fs.statSync(candidate).isFile()) continue;
      content = fs.readFileSync(candidate);
    } catch {
      continue;
    }
    for (let index = 0; index < requiredMarkers.length; index += 1) {
      if (content.includes(requiredMarkers[index])) {
        foundMarkers.add(REQUIRED_OPENSHELL_MCP_FEATURES[index]);
      }
    }
    if (REQUIRED_OPENSHELL_MCP_FEATURES.every((marker) => foundMarkers.has(marker))) {
      return true;
    }
  }
  return false;
}
