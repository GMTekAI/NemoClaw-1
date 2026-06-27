// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export function dockerRunCommandBetween(
  dockerfile: string,
  startMarker: string,
  endMarker: string,
): string {
  const start = dockerfile.indexOf(startMarker);
  const end = dockerfile.indexOf(endMarker, start);
  if (start === -1 || end === -1 || end <= start) {
    throw new Error(`Expected Dockerfile block between ${startMarker} and ${endMarker}`);
  }
  const runIndex = dockerfile.indexOf("RUN ", start);
  if (runIndex === -1 || runIndex > end) {
    throw new Error(`Expected RUN instruction after ${startMarker}`);
  }
  const runLines: string[] = [];
  for (const line of dockerfile.slice(runIndex, end).split("\n")) {
    runLines.push(line);
    if (!line.trimEnd().endsWith("\\")) break;
  }
  const lastLine = runLines[runLines.length - 1]?.trimEnd() ?? "";
  if (lastLine.endsWith("\\")) {
    throw new Error(`Expected complete RUN instruction before ${endMarker}`);
  }
  return runLines
    .join("\n")
    .trim()
    .replace(/^RUN\s+/, "")
    .replace(/\\\n/g, " ");
}

export function dockerRunCommandContaining(dockerfile: string, signature: string): string {
  const signatureIndex = dockerfile.indexOf(signature);
  if (signatureIndex === -1) {
    throw new Error(`Expected Dockerfile RUN signature: ${signature}`);
  }
  const runIndex = dockerfile.lastIndexOf("RUN set -eu;", signatureIndex);
  if (runIndex === -1) {
    throw new Error(`Expected RUN instruction before ${signature}`);
  }
  const linesAfterRun = dockerfile.slice(runIndex).split("\n");
  const endIndex = linesAfterRun.findIndex((line) => !line.trimEnd().endsWith("\\"));
  if (endIndex === -1) {
    throw new Error(`Expected complete RUN instruction containing ${signature}`);
  }
  return linesAfterRun
    .slice(0, endIndex + 1)
    .join("\n")
    .trim()
    .replace(/^RUN\s+/, "")
    .replace(/\\\n/g, " ");
}

export function runDockerShell(command: string, sandboxRoot: string) {
  const logPath = path.join(sandboxRoot, "calls.log");
  fs.rmSync(logPath, { force: true });
  const rewritten = command.replaceAll("/sandbox", sandboxRoot);
  const script = [
    "#!/usr/bin/env bash",
    // Extracted RUN snippets execute as shell, not docker builds; export mirrors the ARG value
    // so unit tests stay daemon-free while the real verifier covers --build-arg behavior.
    "set -euo pipefail; export BASE_IMAGE=${BASE_IMAGE:-nemoclaw-hermes-base-local}; export NEMOCLAW_STALE_OPENCLAW_BASE_DIGEST=sha256:60333c1982ad855d55887b4488e867eb343f3930a30aa8e0268e5397fc6f2926",
    `call_log=${JSON.stringify(logPath)}`,
    'chown() { printf "chown %s\\n" "$*" >> "$call_log"; }',
    rewritten,
  ].join("\n");
  const scriptPath = path.join(sandboxRoot, "run-docker-block.sh");
  fs.writeFileSync(scriptPath, script, { mode: 0o700 });
  const result = spawnSync("bash", [scriptPath], { encoding: "utf-8", timeout: 5000 });
  return { result };
}
