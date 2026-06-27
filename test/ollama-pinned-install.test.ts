// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCOPE_UPGRADE_SCRIPT = path.resolve(HERE, "e2e/test-issue-4462-scope-upgrade-approval.sh");

function extractShellFunction(scriptPath: string, name: string): string {
  const body = readFileSync(scriptPath, "utf8");
  const startMarker = `${name}() {`;
  const start = body.indexOf(startMarker);
  if (start < 0) throw new Error(`function ${name} not found in ${scriptPath}`);
  const lines = body.slice(start).split("\n");
  const endIndex = lines.findIndex((line, index) => index > 0 && line === "}");
  if (endIndex < 0) throw new Error(`function ${name} missing closing brace in ${scriptPath}`);
  return lines.slice(0, endIndex + 1).join("\n");
}

function runGuard(env: {
  OLLAMA_PINNED_SHA256?: string;
  OLLAMA_PINNED_VERSION?: string;
}): { rc: number; stdout: string; stderr: string } {
  const functionBody = extractShellFunction(SCOPE_UPGRADE_SCRIPT, "ollama_pinned_install_sha256_ok");
  const harness = `
set -u
${functionBody}
ollama_pinned_install_sha256_ok
`;
  const result = spawnSync("bash", ["-c", harness], {
    encoding: "utf-8",
    timeout: 20_000,
    env: {
      ...process.env,
      OLLAMA_PINNED_SHA256: env.OLLAMA_PINNED_SHA256 ?? "",
      OLLAMA_PINNED_VERSION: env.OLLAMA_PINNED_VERSION ?? "",
    },
  });
  return {
    rc: result.status ?? -1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

describe("Phase 7 Ollama pinned install SHA256 guard", () => {
  it("accepts a version + matching SHA256 lockstep", () => {
    const result = runGuard({
      OLLAMA_PINNED_VERSION: "9.9.9",
      OLLAMA_PINNED_SHA256: "deadbeef".repeat(8),
    });
    expect(result.rc).toBe(0);
    expect(result.stderr).toBe("");
  });

  it("rejects a version override without a SHA256 in lockstep", () => {
    const result = runGuard({
      OLLAMA_PINNED_VERSION: "9.9.9",
      OLLAMA_PINNED_SHA256: "",
    });
    expect(result.rc).toBe(1);
    expect(result.stderr.trim()).toBe("OLLAMA_PIN_REQUIRES_SHA256 version=9.9.9");
    expect(result.stdout).toBe("");
  });

  it("rejects an empty SHA256 even when the version variable is unset", () => {
    const result = runGuard({
      OLLAMA_PINNED_SHA256: "",
    });
    expect(result.rc).toBe(1);
    expect(result.stderr.trim()).toMatch(/^OLLAMA_PIN_REQUIRES_SHA256 version=/);
  });
});
