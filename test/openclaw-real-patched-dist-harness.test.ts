// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

const REPO_ROOT = path.join(import.meta.dirname, "..");
const DOCKERFILE = path.join(REPO_ROOT, "Dockerfile");
const PATCH_OPENCLAW_CHAT_SEND = path.join(REPO_ROOT, "scripts", "patch-openclaw-chat-send.js");
const PATCH_OPENCLAW_ISSUE_4434_DIAGNOSTICS = path.join(
  REPO_ROOT,
  "scripts",
  "patch-openclaw-issue-4434-diagnostics.js",
);

function readRequiredDockerArg(name: string): string {
  const match = fs
    .readFileSync(DOCKERFILE, "utf-8")
    .match(new RegExp(`^ARG ${name}=([^\\s]+)`, "m"));
  expect(match, `${name} must be pinned in Dockerfile`).not.toBeNull();
  return match![1];
}

function dockerRunCommandBetween(startMarker: string, endMarker: string): string {
  const dockerfile = fs.readFileSync(DOCKERFILE, "utf-8");
  const start = dockerfile.indexOf(startMarker);
  const end = dockerfile.indexOf(endMarker, start);
  const runIndex = dockerfile.indexOf("RUN ", start);
  expect(start, startMarker).toBeGreaterThanOrEqual(0);
  expect(end, endMarker).toBeGreaterThan(start);
  expect(runIndex, `RUN after ${startMarker}`).toBeGreaterThanOrEqual(start);
  expect(runIndex, `RUN before ${endMarker}`).toBeLessThan(end);
  return dockerfile
    .slice(runIndex, end)
    .trim()
    .replace(/^RUN\s+/, "")
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n")
    .replace(/\\\n/g, " ")
    .replace(/\\\s*$/, "");
}

function createSedWrapper(tmp: string): string {
  const fakeBin = path.join(tmp, "bin");
  fs.mkdirSync(fakeBin);
  const sedWrapper = path.join(fakeBin, "sed");
  fs.writeFileSync(
    sedWrapper,
    [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      'if [ "${1:-}" = "-i" ]; then',
      "  extended=0",
      '  if [ "${2:-}" = "-E" ]; then',
      "    extended=1",
      "    expr=$3",
      "    shift 3",
      "  else",
      "    expr=$2",
      "    shift 2",
      "  fi",
      '  for file in "$@"; do',
      "    tmp=$(mktemp)",
      '    if [ "$extended" = "1" ]; then',
      '      /usr/bin/sed -E "$expr" "$file" > "$tmp"',
      "    else",
      '      /usr/bin/sed "$expr" "$file" > "$tmp"',
      "    fi",
      '    mv "$tmp" "$file"',
      "  done",
      "  exit 0",
      "fi",
      'exec /usr/bin/sed "$@"',
    ].join("\n"),
    { mode: 0o755 },
  );
  return fakeBin;
}

function sha512Sri(file: string): string {
  return `sha512-${crypto.createHash("sha512").update(fs.readFileSync(file)).digest("base64")}`;
}

function runtimeMismatch(actual: string, expected: string, label: string): never {
  throw new Error(`${label}: expected ${expected}, got ${actual}`);
}

function requireRuntimeEqual(actual: string, expected: string, label: string): void {
  actual === expected || runtimeMismatch(actual, expected, label);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function runDockerfilePatchBlock(dist: string, tmp: string, version: string) {
  const command = dockerRunCommandBetween(
    "# Patch OpenClaw media fetch for proxy-only sandbox",
    "# Patch OpenClaw chat.send gateway behavior",
  ).replaceAll("/usr/local/lib/node_modules/openclaw/dist", dist);
  const scriptPath = path.join(tmp, "patch-openclaw-dist.sh");
  fs.writeFileSync(
    scriptPath,
    [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      `openclaw() { case "\${1:-}" in --version) printf 'OpenClaw ${version}\\n';; *) return 127;; esac; }`,
      command,
    ].join("\n"),
    { mode: 0o700 },
  );
  const fakeBin = createSedWrapper(tmp);
  return spawnSync("bash", [scriptPath], {
    encoding: "utf-8",
    env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH || ""}` },
    timeout: 180000,
  });
}

function grepRealDist(dist: string, needle: string) {
  return spawnSync(
    "bash",
    ["-lc", `grep -RIlF --include='*.js' ${shellQuote(needle)} ${shellQuote(dist)}`],
    {
      encoding: "utf-8",
      timeout: 10000,
    },
  );
}

describe.skipIf(process.env.NEMOCLAW_REAL_OPENCLAW_DIST_HARNESS !== "1")(
  "OpenClaw real patched-dist harness",
  () => {
    it("materializes the reviewed tarball and applies NemoClaw's Dockerfile OpenClaw patches", () => {
      const version = readRequiredDockerArg("OPENCLAW_VERSION");
      const integrity = readRequiredDockerArg("OPENCLAW_2026_6_9_INTEGRITY");
      const tarballUrl = readRequiredDockerArg("OPENCLAW_2026_6_9_TARBALL");
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-openclaw-real-dist-"));
      try {
        const pack = spawnSync("npm", ["pack", tarballUrl, "--pack-destination", tmp, "--silent"], {
          encoding: "utf-8",
          timeout: 60000,
        });
        expect(pack.status, pack.stderr || pack.stdout).toBe(0);

        const tarballPath = path.join(tmp, `openclaw-${version}.tgz`);
        expect(fs.existsSync(tarballPath), tarballPath).toBe(true);
        requireRuntimeEqual(sha512Sri(tarballPath), integrity, "OpenClaw tarball SRI");

        const extractDir = path.join(tmp, "extract");
        fs.mkdirSync(extractDir);
        const extract = spawnSync("tar", ["-xzf", tarballPath, "-C", extractDir], {
          encoding: "utf-8",
          timeout: 60000,
        });
        expect(extract.status, extract.stderr || extract.stdout).toBe(0);

        const dist = path.join(extractDir, "package", "dist");
        expect(fs.statSync(dist).isDirectory()).toBe(true);

        const dockerPatch = runDockerfilePatchBlock(dist, tmp, version);
        expect(dockerPatch.status, dockerPatch.stderr || dockerPatch.stdout).toBe(0);
        expect(dockerPatch.stdout).toContain(`Patch 2 applied to OpenClaw ${version}`);
        expect(dockerPatch.stdout).toContain(`Patch 2b applied to OpenClaw ${version}`);
        expect(dockerPatch.stdout).toContain(`Patch 4 applied to OpenClaw ${version}`);
        expect(dockerPatch.stdout).toContain(`Patch 6 applied to OpenClaw ${version}`);

        for (const marker of [
          "nemoclaw: env-gated bypass",
          "nemoclaw: OpenShell host gateway for web_fetch trusted env proxy",
          "nemoclaw: route unconfigured strict fetch through sandbox egress proxy",
          'mode: "trusted_env_proxy", auditContext: "cron-model-provider-preflight"',
        ]) {
          const grep = grepRealDist(dist, marker);
          expect(grep.status, `${marker}\n${grep.stderr}`).toBe(0);
          expect(grep.stdout.trim(), marker).not.toBe("");
        }

        const chatPatch = spawnSync(process.execPath, [PATCH_OPENCLAW_CHAT_SEND, dist], {
          encoding: "utf-8",
          timeout: 20000,
        });
        expect(chatPatch.status, chatPatch.stderr || chatPatch.stdout).toBe(0);
        expect(chatPatch.stdout).toContain("patched OpenClaw chat.send compatibility");

        const audit = spawnSync(process.execPath, [PATCH_OPENCLAW_CHAT_SEND, "--audit", dist], {
          encoding: "utf-8",
          timeout: 20000,
        });
        expect(audit.status, audit.stderr || audit.stdout).toBe(0);
        expect(audit.stdout).toContain("chat.send runtime:");
        expect(audit.stdout).toContain("get-reply runtime:");
        expect(audit.stdout).toContain("followup runner runtime:");

        const issue4434Patch = spawnSync(
          process.execPath,
          [PATCH_OPENCLAW_ISSUE_4434_DIAGNOSTICS, dist],
          {
            encoding: "utf-8",
            timeout: 20000,
          },
        );
        expect(issue4434Patch.status, issue4434Patch.stderr || issue4434Patch.stdout).toBe(0);
        expect(issue4434Patch.stdout).toContain("patched OpenClaw #4434 diagnostics");

        const issue4434Audit = spawnSync(
          process.execPath,
          [PATCH_OPENCLAW_ISSUE_4434_DIAGNOSTICS, "--audit", dist],
          {
            encoding: "utf-8",
            timeout: 20000,
          },
        );
        expect(issue4434Audit.status, issue4434Audit.stderr || issue4434Audit.stdout).toBe(0);
        expect(issue4434Audit.stdout).toContain("assistant error formatter:");
        expect(issue4434Audit.stdout).toContain("already-applied");

        const issue4434Marker = grepRealDist(
          dist,
          "nemoclaw: #4434 structured unreachable-inference diagnostic",
        );
        expect(issue4434Marker.status, issue4434Marker.stderr).toBe(0);
        expect(issue4434Marker.stdout.trim()).not.toBe("");
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    }, 300000);
  },
);
