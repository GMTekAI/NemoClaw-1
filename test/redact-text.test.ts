// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TEXT_REDACTOR = path.resolve(HERE, "e2e/lib/redact-text.py");
const SCOPE_UPGRADE_SCRIPT = path.resolve(HERE, "e2e/test-issue-4462-scope-upgrade-approval.sh");
const REDACTED = "[REDACTED]";

function runTextRedactor(input: string): { rc: number; stdout: string; stderr: string } {
  const result = spawnSync("python3", [TEXT_REDACTOR], {
    input,
    encoding: "utf-8",
    timeout: 20_000,
  });
  return {
    rc: result.status ?? -1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

describe("scope-upgrade diagnostic text redactor", () => {
  it("scrubs token-shaped substrings from raw gateway and auto-pair log excerpts", () => {
    const input = [
      "Authorization: Bearer nvapi-abc.def_ghi-jkl-mnopqrstu",
      "Cookie: session=eyJabcdefg.payload.signature123",
      "github-token=ghp_aaaaaaaaaaaaaaaaaa11",
      "X-API-Key: sk-projXYZ1234567890abcd",
      "request: token=github_pat_abcdefghijklmnopqrstu",
      "huggingface key hf_aaaaaaaaaaaaaaaaaa logged",
      "aws AKIAABCDEFGHIJKLMNOP",
      "slack xoxb-1111-2222-aaaaa",
      "plain gateway connect: ok",
      "",
    ].join("\n");

    const result = runTextRedactor(input);
    expect(result.rc).toBe(0);
    expect(result.stdout).not.toContain("nvapi-abc.def_ghi");
    expect(result.stdout).not.toContain("eyJabcdefg.payload");
    expect(result.stdout).not.toContain("ghp_aaaaa");
    expect(result.stdout).not.toContain("sk-projXYZ");
    expect(result.stdout).not.toContain("github_pat_abcdefg");
    expect(result.stdout).not.toContain("hf_aaaaa");
    expect(result.stdout).not.toContain("AKIAABCDEFG");
    expect(result.stdout).not.toContain("xoxb-1111");
    expect(result.stdout).toContain("plain gateway connect: ok");
    expect(result.stdout).toContain(REDACTED);
  });

  it("preserves structural prefixes while substituting only the secret value", () => {
    const result = runTextRedactor("Authorization: Bearer raw-bearer-token\n");
    expect(result.rc).toBe(0);
    expect(result.stdout).toContain("Authorization:");
    expect(result.stdout).toContain("Bearer ");
    expect(result.stdout).not.toContain("raw-bearer-token");
    expect(result.stdout).toContain(REDACTED);
  });

  it("passes through input free of token-shaped substrings unchanged", () => {
    const input = "ls -la /tmp/auto-pair.log\nslow-mode keepalive transition observed\n";
    const result = runTextRedactor(input);
    expect(result.rc).toBe(0);
    expect(result.stdout).toBe(input);
  });

  it("preserves ordinary hyphenated diagnostic text containing sk-", () => {
    const input = "task-management-system-deployment completed without fallback\n";
    const result = runTextRedactor(input);
    expect(result.rc).toBe(0);
    expect(result.stdout).toBe(input);
  });

  it("returns success on empty input", () => {
    const result = runTextRedactor("");
    expect(result.rc).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });

  it("handles input without a trailing newline", () => {
    const result = runTextRedactor("plain text without newline");
    expect(result.rc).toBe(0);
    expect(result.stdout).toBe("plain text without newline");
  });

  it("redacts multiple shapes on the same line", () => {
    const result = runTextRedactor(
      "trace: Bearer nvapi-abc.def_ghi-jkl-mnopqrstu while X-API-Key=sk-projXYZ1234567890abcd\n",
    );
    expect(result.rc).toBe(0);
    expect(result.stdout).not.toContain("nvapi-abc.def_ghi");
    expect(result.stdout).not.toContain("sk-projXYZ");
    expect(result.stdout).toContain("Bearer ");
    expect(result.stdout).toContain("X-API-Key");
    const redactedCount = (result.stdout.match(/\[REDACTED\]/g) ?? []).length;
    expect(redactedCount).toBeGreaterThanOrEqual(2);
  });

  it("preserves newline structure across long multi-line input", () => {
    const lines = Array.from({ length: 64 }, (_, i) =>
      i % 8 === 0 ? `line ${i} nvapi-secret-value-${i}-padded-12345` : `line ${i} plain diagnostic`,
    );
    const input = `${lines.join("\n")}\n`;
    const result = runTextRedactor(input);
    expect(result.rc).toBe(0);
    expect(result.stdout.split("\n").length).toBe(lines.length + 1);
    expect(result.stdout).not.toMatch(/nvapi-secret-value-\d+-padded/);
    expect(result.stdout).toMatch(/line 1 plain diagnostic/);
  });
});

describe("scope-upgrade Phase 6 secret-bearing artifacts", () => {
  it("pipes auto-pair and gateway diagnostics through the text redactor before appending to STATE_LOG", () => {
    const script = readFileSync(SCOPE_UPGRADE_SCRIPT, "utf8");

    expect(script).toContain('python3 "${E2E_DIR}/lib/redact-text.py"');
    expect(script).toContain(
      "auto_pair_diag_redacted=$(printf '%s' \"$auto_pair_diag\" | redact_text_for_log)",
    );
    expect(script).toContain(
      "auto_pair_snapshot_redacted=$(printf '%s' \"$auto_pair_log_snapshot\" | redact_text_for_log)",
    );
    expect(script).toContain(
      'printf \'=== auto-pair diagnostic ===\\n%s\\n\' "$auto_pair_diag_redacted" >>"$STATE_LOG"',
    );
    expect(script).toContain(
      'printf \'=== /tmp/auto-pair.log snapshot (waited %ss) ===\\n%s\\n\' "$((SECONDS - slow_mode_start))" "$auto_pair_snapshot_redacted" >>"$STATE_LOG"',
    );
    expect(script).toContain("[STATE_LOG_REDACTION_FAILED stage=text rc=");
    expect(script).not.toMatch(
      /printf '=== auto-pair diagnostic ===[^']+'\s+"\$auto_pair_diag"\s+>>"\$STATE_LOG"/,
    );
  });

  it("redacts approve and agent command output through redact_text_for_log_or_marker before appending to APPROVAL_LOG / AGENT_LOG", () => {
    const script = readFileSync(SCOPE_UPGRADE_SCRIPT, "utf8");

    expect(script).toContain('redact_text_for_log_or_marker "approve-output"');
    expect(script).toContain('redact_text_for_log_or_marker "legacy-approve-output"');
    expect(script).toContain('redact_text_for_log_or_marker "trigger-agent-output"');
    expect(script).toContain('redact_text_for_log_or_marker "final-agent-output"');
    expect(script).toContain('redact_text_for_log_or_marker "multi-agent-output-a"');
    expect(script).toContain('redact_text_for_log_or_marker "multi-agent-output-b"');
    expect(script).toContain("[LOG_REDACTION_FAILED stage=");
    expect(script).not.toMatch(/printf '%s\\n' "\$output"\s+\} >>"\$APPROVAL_LOG"/);
    expect(script).not.toMatch(/printf '=== trigger agent output[^']+'\s+"\$trigger_output"\s+>>/);
  });

  it("redacts truncated raw command-output excerpts in fail / info messages via redacted_excerpt", () => {
    const script = readFileSync(SCOPE_UPGRADE_SCRIPT, "utf8");

    expect(script).toContain("redacted_excerpt() {");
    expect(script).toContain("redact_text_for_log 2>/dev/null");
    expect(script).toMatch(/redacted_excerpt "\$output" 500/);
    expect(script).toMatch(/redacted_excerpt "\$state" 500/);
    expect(script).toMatch(/redacted_excerpt "\$guard_probe" 600/);
    expect(script).toMatch(/redacted_excerpt "\$upstream_a_json" 300/);
    expect(script).not.toMatch(/fail "[^"]*\$\{[A-Za-z_]+:0:[0-9]+\}"/);
  });
});
