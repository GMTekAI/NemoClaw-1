// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REDACTOR = path.resolve(HERE, "e2e/lib/redact-device-state.py");
const SCOPE_UPGRADE_SCRIPT = path.resolve(HERE, "e2e/test-issue-4462-scope-upgrade-approval.sh");
const REDACTED = "[REDACTED]";

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

function materializeRedactor(redactorScriptOverride: string | undefined): string {
  const overrideRoot = mkdtempSync(path.join(tmpdir(), "scope-upgrade-shell-"));
  mkdirSync(path.join(overrideRoot, "lib"), { recursive: true });
  const redactorSource = redactorScriptOverride ?? readFileSync(REDACTOR, "utf8");
  writeFileSync(path.join(overrideRoot, "lib", "redact-device-state.py"), redactorSource, {
    mode: 0o755,
  });
  return overrideRoot;
}

function runScopeUpgradeDeviceStateWrapper(stubs: {
  sandboxRawOutput: string;
  sandboxRc: number;
  redactorScriptOverride?: string;
}): { rc: number; stdout: string; stderr: string } {
  const functionBody = extractShellFunction(SCOPE_UPGRADE_SCRIPT, "device_state_json");
  const e2eDir = materializeRedactor(stubs.redactorScriptOverride);
  const harness = `
set -u
sandbox_exec_sh_script() {
  printf '%s' "$E2E_TEST_SANDBOX_RAW"
  return "$E2E_TEST_SANDBOX_RC"
}
extract_json_doc() { cat; }
${functionBody}
device_state_json
`;
  try {
    const result = spawnSync("bash", ["-c", harness], {
      encoding: "utf-8",
      timeout: 20_000,
      env: {
        ...process.env,
        E2E_DIR: e2eDir,
        E2E_TEST_SANDBOX_RAW: stubs.sandboxRawOutput,
        E2E_TEST_SANDBOX_RC: String(stubs.sandboxRc),
      },
    });
    return {
      rc: result.status ?? -1,
      stdout: result.stdout ?? "",
      stderr: result.stderr ?? "",
    };
  } finally {
    rmSync(e2eDir, { recursive: true, force: true });
  }
}

function runRedactor(input: unknown): { rc: number; stdout: string; stderr: string; doc: unknown } {
  const result = spawnSync("python3", [REDACTOR], {
    input: JSON.stringify(input),
    encoding: "utf-8",
    timeout: 20_000,
  });
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  const doc: unknown =
    result.status === 0 && stdout.trim().length > 0 ? JSON.parse(stdout) : undefined;
  return { rc: result.status ?? -1, stdout, stderr, doc };
}

describe("device-state JSON redactor", () => {
  it("redacts nested token, header, auth, credential fields while preserving diagnostic identifiers", () => {
    const input = {
      pending: [
        {
          requestId: "req-abc-123",
          deviceId: "dev-cli-007",
          clientMode: "cli",
          clientId: "openclaw-cli",
          scopes: ["operator.read", "operator.write"],
          requestedScopes: ["operator.read", "operator.write"],
          tokens: {
            operator: { value: "secret-operator-token", expiresAt: 9_999_999_999 },
          },
          headers: { Authorization: "Bearer raw-bearer-token" },
          credentials: { apiKey: "credential-leak" },
        },
      ],
      paired: [
        {
          deviceId: "dev-cli-008",
          clientMode: "cli",
          approvedScopes: ["operator.read"],
          auth: { primary: { secret: "do-not-leak" } },
          notes: "device pairing approved manually",
        },
      ],
      paths: {
        pending: "/sandbox/.openclaw/devices/pending.json",
        paired: "/sandbox/.openclaw/devices/paired.json",
      },
    };

    const result = runRedactor(input);
    expect(result.rc).toBe(0);
    const doc = result.doc as typeof input;

    const pending = doc.pending[0]!;
    expect(pending.requestId).toBe("req-abc-123");
    expect(pending.deviceId).toBe("dev-cli-007");
    expect(pending.clientMode).toBe("cli");
    expect(pending.clientId).toBe("openclaw-cli");
    expect(pending.scopes).toEqual(["operator.read", "operator.write"]);
    expect(pending.requestedScopes).toEqual(["operator.read", "operator.write"]);
    expect(pending.tokens).toBe(REDACTED);
    expect(pending.headers).toBe(REDACTED);
    expect(pending.credentials).toBe(REDACTED);

    const paired = doc.paired[0]!;
    expect(paired.deviceId).toBe("dev-cli-008");
    expect(paired.approvedScopes).toEqual(["operator.read"]);
    expect(paired.auth).toBe(REDACTED);
    expect(paired.notes).toBe("device pairing approved manually");

    expect(doc.paths.pending).toBe("/sandbox/.openclaw/devices/pending.json");
    expect(doc.paths.paired).toBe("/sandbox/.openclaw/devices/paired.json");
    expect(result.stdout).not.toContain("secret-operator-token");
    expect(result.stdout).not.toContain("raw-bearer-token");
    expect(result.stdout).not.toContain("credential-leak");
    expect(result.stdout).not.toContain("do-not-leak");
  });

  it("redacts dotted nvapi values and other token-shaped strings under non-secret-shaped fields", () => {
    const input = {
      pending: [
        {
          deviceId: "dev-cli-009",
          clientMode: "cli",
          scopes: ["operator.pairing"],
          providerKey: "nvapi-abc.def_ghi-jkl-mnopqrstu",
          extra: "sk-projXYZ1234567890abcd",
          githubToken: "ghp_aaaaaaaaaaaaaaaaaa11",
          githubPat: "github_pat_abcdefghijklmnopqrstu",
          hfToken: "hf_aaaaaaaaaaaaaaaaaa",
          slackBot: "xoxb-1111-2222-aaaaa",
          jwtNote: "eyJabcdefg.payload.signature123",
          awsKey: "AKIAABCDEFGHIJKLMNOP",
          plainText: "nothing to redact here",
        },
      ],
      paired: [],
    };

    const result = runRedactor(input);
    expect(result.rc).toBe(0);
    const entry = (result.doc as typeof input).pending[0]!;

    expect(entry.deviceId).toBe("dev-cli-009");
    expect(entry.scopes).toEqual(["operator.pairing"]);
    expect(entry.providerKey).toBe(REDACTED);
    expect(entry.extra).toBe(REDACTED);
    expect(entry.githubToken).toBe(REDACTED);
    expect(entry.githubPat).toBe(REDACTED);
    expect(entry.hfToken).toBe(REDACTED);
    expect(entry.slackBot).toBe(REDACTED);
    expect(entry.jwtNote).toBe(REDACTED);
    expect(entry.awsKey).toBe(REDACTED);
    expect(entry.plainText).toBe("nothing to redact here");

    expect(result.stdout).not.toContain("nvapi-abc.def_ghi");
    expect(result.stdout).not.toContain("sk-projXYZ");
    expect(result.stdout).not.toContain("ghp_aaaaa");
    expect(result.stdout).not.toContain("github_pat_abcdefg");
    expect(result.stdout).not.toContain("hf_aaaaa");
    expect(result.stdout).not.toContain("xoxb-1111");
    expect(result.stdout).not.toContain("eyJabcdefg");
    expect(result.stdout).not.toContain("AKIAABCDEFG");
  });

  it("preserves an empty document and rejects invalid JSON", () => {
    const empty = runRedactor({});
    expect(empty.rc).toBe(0);
    expect(empty.doc).toEqual({});

    const invalid = spawnSync("python3", [REDACTOR], {
      input: "not-json",
      encoding: "utf-8",
      timeout: 20_000,
    });
    expect(invalid.status).toBe(1);
    expect(invalid.stderr).toContain("invalid JSON");
  });
});

describe("scope-upgrade device_state_json shell wrapper", () => {
  const TOKEN_LEAK = "nvapi-abc.def_ghi-jkl-mnopqrstu";
  const RAW_TOKEN_PAYLOAD = `{"pending":[{"deviceId":"dev-1","tokens":{"operator":{"value":"${TOKEN_LEAK}"}}}],"paired":[],"paths":{"pending":"/sandbox/.openclaw/devices/pending.json","paired":"/sandbox/.openclaw/devices/paired.json"}}`;

  it("emits only the sandbox-exec failure marker when sandbox_exec_sh_script returns non-zero", () => {
    const result = runScopeUpgradeDeviceStateWrapper({
      sandboxRawOutput: `${RAW_TOKEN_PAYLOAD}\n`,
      sandboxRc: 5,
    });

    expect(result.rc).toBe(5);
    expect(result.stdout.trim()).toBe("[DEVICE_STATE_REDACTION_FAILED stage=sandbox-exec rc=5]");
    expect(result.stdout).not.toContain(TOKEN_LEAK);
    expect(result.stdout).not.toContain('"tokens"');
    expect(result.stderr).not.toContain(TOKEN_LEAK);
  });

  it("emits only the redactor failure marker when the redactor exits non-zero on token-bearing input", () => {
    const failingRedactor = "#!/usr/bin/env python3\nimport sys\nsys.stdin.read()\nsys.exit(7)\n";

    const result = runScopeUpgradeDeviceStateWrapper({
      sandboxRawOutput: `${RAW_TOKEN_PAYLOAD}\n`,
      sandboxRc: 0,
      redactorScriptOverride: failingRedactor,
    });

    expect(result.rc).toBe(7);
    expect(result.stdout.trim()).toBe("[DEVICE_STATE_REDACTION_FAILED stage=redactor rc=7]");
    expect(result.stdout).not.toContain(TOKEN_LEAK);
    expect(result.stdout).not.toContain('"tokens"');
    expect(result.stderr).not.toContain(TOKEN_LEAK);
  });

  it("emits redacted JSON without leaking raw token-bearing input on the success path", () => {
    const result = runScopeUpgradeDeviceStateWrapper({
      sandboxRawOutput: `${RAW_TOKEN_PAYLOAD}\n`,
      sandboxRc: 0,
    });

    expect(result.rc).toBe(0);
    expect(result.stdout).not.toContain(TOKEN_LEAK);
    expect(result.stdout).toContain(REDACTED);
    expect(result.stdout).not.toContain("[DEVICE_STATE_REDACTION_FAILED");
    expect(result.stderr).not.toContain(TOKEN_LEAK);
  });
});

describe("scope-upgrade Phase 7 sandbox-B least-privilege onboarding", () => {
  it("unsets hosted inference credentials and routing env before Ollama onboard", () => {
    const script = readFileSync(SCOPE_UPGRADE_SCRIPT, "utf8");
    const onboardCommand = "run_with_timeout 1500 nemoclaw onboard --non-interactive --fresh";
    const onboardIndex = requireNonNegative(
      script.indexOf(onboardCommand),
      "sandbox-B onboard command not found",
    );
    const sandboxBStart = requireNonNegative(
      script.lastIndexOf("export NEMOCLAW_PROVIDER=ollama", onboardIndex),
      "sandbox-B Ollama provider export not found before onboard",
    );
    const sandboxBBlock = script.slice(sandboxBStart, onboardIndex);

    for (const name of [
      "NVIDIA_INFERENCE_API_KEY",
      "COMPATIBLE_API_KEY",
      "NEMOCLAW_ENDPOINT_URL",
      "NEMOCLAW_COMPAT_MODEL",
      "NEMOCLAW_PREFERRED_API",
      "NEMOCLAW_E2E_USE_HOSTED_INFERENCE",
    ]) {
      expect(sandboxBBlock).toContain(`unset ${name}`);
    }
  });
});

describe("scope-upgrade Phase 7 hosted inference model wiring", () => {
  const script = readFileSync(SCOPE_UPGRADE_SCRIPT, "utf8");

  it("follows the reusable NVIDIA inference NEMOCLAW_MODEL export", () => {
    expect(script).toContain(
      'EXPECTED_MODEL_A="${NEMOCLAW_CLI_SCOPE_EXPECTED_MODEL_A:-${NEMOCLAW_MODEL:-',
    );
    expect(script).not.toMatch(
      /EXPECTED_MODEL_A="\$\{NEMOCLAW_CLI_SCOPE_EXPECTED_MODEL_A:-nvidia\//,
    );

    const scriptFallbackMatch = script.match(
      /EXPECTED_MODEL_A="\$\{NEMOCLAW_CLI_SCOPE_EXPECTED_MODEL_A:-\$\{NEMOCLAW_MODEL:-([^}]+)\}\}"/,
    );
    expect(scriptFallbackMatch?.[1]).toBeDefined();
  });
});
