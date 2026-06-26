// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = path.resolve(import.meta.dirname, "..");
const HERMES_DOCKERFILE = path.join(ROOT, "agents", "hermes", "Dockerfile");
const VERIFY_SCRIPT = path.join(ROOT, "scripts", "verify-hermes-stale-openclaw-image.sh");
const STALE_DIGEST = "sha256:60333c1982ad855d55887b4488e867eb343f3930a30aa8e0268e5397fc6f2926";
const DIFFERENT_DIGEST = `sha256:${"0".repeat(64)}`;

function dockerRunCommandContaining(dockerfile: string, signature: string): string {
  const signatureIndex = dockerfile.indexOf(signature);
  expect(signatureIndex, `Expected Dockerfile RUN signature: ${signature}`).not.toBe(-1);
  const runIndex = dockerfile.lastIndexOf("RUN set -eu;", signatureIndex);
  expect(runIndex, `Expected RUN instruction before ${signature}`).not.toBe(-1);
  const linesAfterRun = dockerfile.slice(runIndex).split("\n");
  const endIndex = linesAfterRun.findIndex((line) => !line.trimEnd().endsWith("\\"));
  expect(endIndex, `Expected complete RUN instruction containing ${signature}`).toBeGreaterThan(-1);
  return linesAfterRun
    .slice(0, endIndex + 1)
    .join("\n")
    .trim()
    .replace(/^RUN\s+/, "")
    .replace(/\\\n/g, " ");
}

describe("Hermes stale OpenClaw guardrails", () => {
  it("Hermes stale cleanup digest guard fails when the default pinned GHCR base digest changes", () => {
    const dockerfile = fs.readFileSync(HERMES_DOCKERFILE, "utf-8");
    const cleanupCommand = dockerRunCommandContaining(
      dockerfile,
      'stale_base_digest="${NEMOCLAW_STALE_OPENCLAW_BASE_DIGEST:?}"',
    );
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-hermes-stale-digest-"));
    const sandboxRoot = path.join(tmp, "sandbox");
    const script = [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      `BASE_IMAGE=${JSON.stringify(`ghcr.io/nvidia/nemoclaw/hermes-sandbox-base@${DIFFERENT_DIGEST}`)}`,
      `NEMOCLAW_STALE_OPENCLAW_BASE_DIGEST=${JSON.stringify(STALE_DIGEST)}`,
      cleanupCommand.replaceAll("/sandbox", sandboxRoot),
    ].join("\n");
    const scriptPath = path.join(tmp, "run-cleanup.sh");
    fs.mkdirSync(sandboxRoot, { recursive: true });
    fs.writeFileSync(scriptPath, script, { mode: 0o700 });

    try {
      const result = spawnSync("bash", [scriptPath], { encoding: "utf-8", timeout: 5000 });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("remove stale Hermes .openclaw cleanup or update");
      expect(result.stderr).toContain(DIFFERENT_DIGEST);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("Hermes stale OpenClaw verifier rejects unsafe base image refs before docker build", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-hermes-ref-guard-"));
    const fakeBin = path.join(tmp, "bin");
    const dockerLog = path.join(tmp, "docker-called.log");
    const unsafeRefs = [
      "",
      "ghcr.io/nvidia/nemoclaw/hermes-sandbox-base @sha256:bad",
      'ghcr.io/nvidia/nemoclaw/hermes-sandbox-base"bad',
      "ghcr.io/nvidia/nemoclaw/hermes-sandbox-base`id`",
      "ghcr.io/nvidia/nemoclaw/hermes-sandbox-base;bad",
      "ghcr.io/nvidia/nemoclaw/hermes-sandbox-base\\bad",
      "localhost:5000/evil",
      "malicious:tag",
      "ghcr.io/evil/image@sha256:deadbeef",
      "ghcr.io/nvidia/nemoclaw/hermes-sandbox-base@sha256:invalid",
    ];
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(
      path.join(fakeBin, "docker"),
      '#!/usr/bin/env bash\nprintf \'docker %s\\n\' "$*" >> "$NEMOCLAW_FAKE_DOCKER_LOG"\nexit 99\n',
      { mode: 0o700 },
    );

    try {
      for (const [index, ref] of unsafeRefs.entries()) {
        fs.rmSync(dockerLog, { force: true });
        const result = spawnSync("bash", [VERIFY_SCRIPT], {
          encoding: "utf-8",
          env: {
            ...process.env,
            PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
            HERMES_BASE_IMAGE: "",
            NEMOCLAW_FAKE_DOCKER_LOG: dockerLog,
            NEMOCLAW_HERMES_BASE_IMAGE: ref,
            NEMOCLAW_HERMES_STALE_OPENCLAW_IMAGE_LOG: path.join(tmp, `script-${index}.log`),
          },
          timeout: 5000,
        });
        expect(result.status, ref).not.toBe(0);
        expect(`${result.stdout}\n${result.stderr}`, ref).toMatch(
          /Hermes base image ref|set NEMOCLAW_HERMES_BASE_IMAGE/,
        );
        expect(fs.existsSync(dockerLog), ref).toBe(false);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
