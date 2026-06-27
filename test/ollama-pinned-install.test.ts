// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCOPE_UPGRADE_SCRIPT = path.resolve(HERE, "e2e/test-issue-4462-scope-upgrade-approval.sh");

function requireNonNegative(value: number, message: string): number {
  return value >= 0
    ? value
    : (() => {
        throw new Error(message);
      })();
}

function extractShellFunction(scriptPath: string, name: string): string {
  const body = readFileSync(scriptPath, "utf8");
  const startMarker = `${name}() {`;
  const start = requireNonNegative(
    body.indexOf(startMarker),
    `function ${name} not found in ${scriptPath}`,
  );
  const lines = body.slice(start).split("\n");
  const endIndex = requireNonNegative(
    lines.findIndex((line, index) => index > 0 && line === "}"),
    `function ${name} missing closing brace in ${scriptPath}`,
  );
  return lines.slice(0, endIndex + 1).join("\n");
}

function runGuard(env: { OLLAMA_PINNED_SHA256?: string; OLLAMA_PINNED_VERSION?: string }): {
  rc: number;
  stdout: string;
  stderr: string;
} {
  const functionBody = extractShellFunction(
    SCOPE_UPGRADE_SCRIPT,
    "ollama_pinned_install_sha256_ok",
  );
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

function runLayoutValidator(tarball: string): { rc: number; stderr: string } {
  const functionBody = extractShellFunction(SCOPE_UPGRADE_SCRIPT, "validate_ollama_tarball_layout");
  const harness = `
set -u
fail() { printf 'FAIL: %s\\n' "$*" >&2; }
redacted_excerpt() { printf '%s' "$1"; }
${functionBody}
validate_ollama_tarball_layout "$1"
`;
  const result = spawnSync("bash", ["-c", harness, "bash", tarball], {
    encoding: "utf-8",
    timeout: 20_000,
  });
  return {
    rc: result.status ?? -1,
    stderr: result.stderr ?? "",
  };
}

function makeTarball(root: string, name: string, prepare: () => void, members: string[]): string {
  prepare();
  const tarball = path.join(root, name);
  const tarRoot = path.join(root, "tar-src");
  const result = spawnSync("tar", ["-czf", tarball, "-C", tarRoot, ...members], {
    encoding: "utf-8",
    timeout: 20_000,
  });
  const error = result.status !== 0 ? `tar failed: ${result.stderr}` : null;
  rmSync(tarRoot, { recursive: true, force: true });
  return error === null
    ? tarball
    : (() => {
        throw new Error(error);
      })();
}

describe("Phase 7 Ollama tarball layout validator (behavioural fixtures)", () => {
  let tmpRoot: string;

  beforeEach(() => {
    tmpRoot = mkdtempSync(path.join(tmpdir(), "ollama-layout-"));
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("accepts a layout that matches the real release: bin/ + lib/ with sibling-relative symlinks", () => {
    const tarball = makeTarball(
      tmpRoot,
      "good.tgz",
      () => {
        const src = path.join(tmpRoot, "tar-src");
        mkdirSync(path.join(src, "bin"), { recursive: true });
        mkdirSync(path.join(src, "lib", "ollama"), { recursive: true });
        writeFileSync(path.join(src, "bin", "ollama"), "ELF stub\n");
        chmodSync(path.join(src, "bin", "ollama"), 0o755);
        writeFileSync(path.join(src, "lib", "ollama", "libggml-base.so.0.0.0"), "SO stub\n");
        symlinkSync("libggml-base.so.0.0.0", path.join(src, "lib", "ollama", "libggml-base.so.0"));
      },
      ["bin", "lib"],
    );
    const result = runLayoutValidator(tarball);
    expect(result.stderr).toBe("");
    expect(result.rc).toBe(0);
  });

  it("rejects a tarball with an absolute-path entry", () => {
    const tarball = path.join(tmpRoot, "abs.tgz");
    const src = path.join(tmpRoot, "tar-src");
    mkdirSync(path.join(src, "bin"), { recursive: true });
    writeFileSync(path.join(src, "bin", "ollama"), "ELF stub\n");
    const escapeFile = path.join(tmpRoot, "etc-passwd");
    writeFileSync(escapeFile, "root:x:0:0\n");
    const tarResult = spawnSync(
      "tar",
      [
        "-czf",
        tarball,
        "-C",
        src,
        "bin/ollama",
        "-C",
        tmpRoot,
        "--transform",
        "s,^etc-passwd$,/etc/passwd,",
        "etc-passwd",
      ],
      { encoding: "utf-8", timeout: 20_000 },
    );
    expect(tarResult.status).toBe(0);
    rmSync(src, { recursive: true, force: true });
    const result = runLayoutValidator(tarball);
    expect(result.rc).toBe(1);
    expect(result.stderr).toContain("absolute paths or parent traversal");
  });

  it("rejects a tarball with a parent-traversal entry", () => {
    const tarball = path.join(tmpRoot, "trav.tgz");
    const src = path.join(tmpRoot, "tar-src");
    mkdirSync(path.join(src, "bin"), { recursive: true });
    writeFileSync(path.join(src, "bin", "ollama"), "ELF stub\n");
    const tarResult = spawnSync(
      "tar",
      ["-czf", tarball, "-C", src, "--transform", "s,^bin/ollama$,../escape,", "bin/ollama"],
      { encoding: "utf-8", timeout: 20_000 },
    );
    expect(tarResult.status).toBe(0);
    rmSync(src, { recursive: true, force: true });
    const result = runLayoutValidator(tarball);
    expect(result.rc).toBe(1);
    expect(result.stderr).toContain("absolute paths or parent traversal");
  });

  it("rejects a tarball with members outside bin/ or lib/", () => {
    const tarball = makeTarball(
      tmpRoot,
      "extra.tgz",
      () => {
        const src = path.join(tmpRoot, "tar-src");
        mkdirSync(path.join(src, "bin"), { recursive: true });
        mkdirSync(path.join(src, "extras"), { recursive: true });
        writeFileSync(path.join(src, "bin", "ollama"), "ELF stub\n");
        writeFileSync(path.join(src, "extras", "marker"), "x\n");
      },
      ["bin", "extras"],
    );
    const result = runLayoutValidator(tarball);
    expect(result.rc).toBe(1);
    expect(result.stderr).toContain("members outside bin/ or lib/");
  });

  it("rejects a tarball with a symlink whose target escapes via absolute path", () => {
    const tarball = makeTarball(
      tmpRoot,
      "abs-link.tgz",
      () => {
        const src = path.join(tmpRoot, "tar-src");
        mkdirSync(path.join(src, "lib", "ollama"), { recursive: true });
        symlinkSync("/etc/passwd", path.join(src, "lib", "ollama", "escape.so"));
      },
      ["lib"],
    );
    const result = runLayoutValidator(tarball);
    expect(result.rc).toBe(1);
    expect(result.stderr).toContain("symlink with an absolute or parent-traversal target");
  });

  it("rejects a tarball with a symlink whose target escapes via parent traversal", () => {
    const tarball = makeTarball(
      tmpRoot,
      "trav-link.tgz",
      () => {
        const src = path.join(tmpRoot, "tar-src");
        mkdirSync(path.join(src, "lib", "ollama"), { recursive: true });
        symlinkSync("../../../etc/passwd", path.join(src, "lib", "ollama", "escape.so"));
      },
      ["lib"],
    );
    const result = runLayoutValidator(tarball);
    expect(result.rc).toBe(1);
    expect(result.stderr).toContain("symlink with an absolute or parent-traversal target");
  });
});

describe("Phase 7 Ollama pinned install script wiring", () => {
  it("commits the pinned default version + sha256, refuses overrides without a sha256 in lockstep, and verifies sha256 before sudo tar", () => {
    const script = readFileSync(SCOPE_UPGRADE_SCRIPT, "utf8");

    expect(script).toMatch(/OLLAMA_PINNED_VERSION_DEFAULT="\d+\.\d+\.\d+"/);
    expect(script).toMatch(/OLLAMA_PINNED_SHA256_DEFAULT="[0-9a-f]{64}"/);
    expect(script).toContain(
      'fail "Ollama install requires NEMOCLAW_CLI_SCOPE_OLLAMA_SHA256 when NEMOCLAW_CLI_SCOPE_OLLAMA_VERSION overrides the pinned default',
    );
    expect(script).toContain('if [ "$computed_sha" != "$OLLAMA_PINNED_SHA256" ]; then');
    expect(script).toContain('sudo tar -C /usr/local -xzf "${install_tmp}/ollama.tgz"');
    expect(script).not.toContain("Skipping Ollama tarball sha256 verification");
  });

  it("rejects tarballs with absolute paths, parent traversal, members outside bin/lib, or non-relative symlinks before sudo tar", () => {
    const script = readFileSync(SCOPE_UPGRADE_SCRIPT, "utf8");

    expect(script).toContain(
      "Ollama tarball contains absolute paths or parent traversal entries; refusing privileged extract",
    );
    expect(script).toContain(
      "Ollama tarball contains members outside bin/ or lib/; refusing privileged extract",
    );
    expect(script).toContain("Ollama tarball contains non-file/non-directory/non-symlink entries");
    expect(script).toContain(
      "Ollama tarball contains a symlink with an absolute or parent-traversal target; refusing privileged extract",
    );
  });

  it("default Phase 7 lane does not claim full #5343 qwen3.5 model coverage", () => {
    const script = readFileSync(SCOPE_UPGRADE_SCRIPT, "utf8");

    const defaultModelMatch = script.match(
      /OLLAMA_TWO_PROVIDER_MODEL="\$\{NEMOCLAW_CLI_SCOPE_OLLAMA_MODEL:-([^}]+)\}"/,
    );
    const specModelMatch = script.match(/OLLAMA_SPEC_MODEL_5343="([^"]+)"/);
    expect(defaultModelMatch?.[1]).toBeDefined();
    expect(specModelMatch?.[1]).toBe("qwen3.5:9b");
    expect(defaultModelMatch?.[1]).not.toBe(specModelMatch?.[1]);

    expect(script).toContain(
      'section "Phase 7 (CPU-substitute lane): Verify two-sandbox concurrent differing-provider gateway-backed agent turns"',
    );
    expect(script).toContain("Phase 7 CPU-lane substitute: using ${OLLAMA_TWO_PROVIDER_MODEL}");
    expect(script).toContain("substituting for GPU-only spec model");
  });

  it("Phase 7 requires sandbox-B provider metadata to identify Ollama, not a qwen model", () => {
    const script = readFileSync(SCOPE_UPGRADE_SCRIPT, "utf8");
    const providerBlock = script.match(/case "\$provider_b" in[\s\S]*?esac/)?.[0];

    expect(providerBlock).toBeDefined();
    expect(providerBlock).toContain("*ollama*)");
    expect(providerBlock).not.toContain("*qwen*");
    expect(script).toContain('if [ "$model_b" != "$EXPECTED_MODEL_B" ]; then');
  });
});
