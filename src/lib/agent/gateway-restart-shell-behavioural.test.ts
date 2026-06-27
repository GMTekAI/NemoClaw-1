// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { HERMES_SECRET_BOUNDARY_VALIDATOR_PATH } from "../../../dist/lib/agent/hermes-recovery-boundary";
import { buildHermesGatewayRestartScript } from "../../../dist/lib/agent/runtime";
import {
  createRecoveryPreloadHarnessPaths,
  type RecoveryPreloadHarnessPaths,
  rewriteRecoveryPreloadPaths,
} from "../../../test/helpers/runtime-recovery-preload-test-helpers";
import type { AgentDefinition } from "./defs";

interface HermesRestartHarness extends RecoveryPreloadHarnessPaths {
  tmp: string;
  stubsDir: string;
  hermesDir: string;
  etcNemoclawDir: string;
  validatorPath: string;
  configGuardPath: string;
  gatewayLogPath: string;
  recoveryLogPath: string;
  proxyEnvPath: string;
  recoveredProxyEnvPath: string;
  hermesBin: string;
  pkillLog: string;
  guardLog: string;
  gosuLog: string;
  launchMarker: string;
}

const hermesAgent = {
  name: "hermes",
  displayName: "Hermes Agent",
  binary_path: "/usr/local/bin/hermes",
  gateway_command: "hermes gateway run",
  healthProbe: { url: "http://localhost:8642/health", port: 8642, timeout_seconds: 90 },
  forwardPort: 8642,
  configPaths: {
    dir: "/sandbox/.hermes",
    configFile: "/sandbox/.hermes/config.yaml",
    envFile: "/sandbox/.hermes/.env",
    format: "yaml",
  },
} as AgentDefinition;

function writeStub(dir: string, name: string, body: string) {
  const stub = path.join(dir, name);
  fs.writeFileSync(stub, `#!/usr/bin/env bash\n${body}\n`, { mode: 0o755 });
  return stub;
}

function removeTempDir(dir: string) {
  fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

function prepareHermesRestartHarness(name: string): HermesRestartHarness {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `nemoclaw-hermes-restart-${name}-`));
  const stubsDir = path.join(tmp, "bin");
  const hermesDir = path.join(tmp, "sandbox", ".hermes");
  const etcNemoclawDir = path.join(tmp, "etc", "nemoclaw");
  const validatorPath = path.join(tmp, "usr-local-lib-nemoclaw", "validate-boundary.py");
  const configGuardPath = path.join(
    tmp,
    "usr-local-lib-nemoclaw",
    "hermes-runtime-config-guard.py",
  );
  const hermesBin = path.join(stubsDir, "hermes");
  const harness = {
    tmp,
    stubsDir,
    hermesDir,
    etcNemoclawDir,
    validatorPath,
    configGuardPath,
    gatewayLogPath: path.join(tmp, "gateway.log"),
    recoveryLogPath: path.join(tmp, "gateway-recovery.log"),
    proxyEnvPath: path.join(tmp, "nemoclaw-proxy-env.sh"),
    recoveredProxyEnvPath: path.join(tmp, "nemoclaw-recovered-proxy-env.sh"),
    hermesBin,
    pkillLog: path.join(tmp, "pkill.log"),
    guardLog: path.join(tmp, "guard.log"),
    gosuLog: path.join(tmp, "gosu.log"),
    launchMarker: path.join(tmp, "hermes-launched"),
    ...createRecoveryPreloadHarnessPaths(tmp),
  };

  fs.mkdirSync(stubsDir, { recursive: true });
  fs.mkdirSync(hermesDir, { recursive: true });
  fs.mkdirSync(etcNemoclawDir, { recursive: true });
  fs.mkdirSync(path.dirname(validatorPath), { recursive: true });
  fs.writeFileSync(path.join(hermesDir, "config.yaml"), "telegram:\n  enabled: false\n");
  fs.writeFileSync(path.join(hermesDir, ".env"), "API_SERVER_PORT=18642\n");
  fs.writeFileSync(validatorPath, "#!/usr/bin/env python3\n");
  fs.writeFileSync(configGuardPath, "#!/usr/bin/env python3\n");
  fs.writeFileSync(hermesBin, "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
  return harness;
}

function installHermesRestartStubs(harness: HermesRestartHarness) {
  writeStub(
    harness.stubsDir,
    "id",
    [
      'if [ "${1:-}" = "-u" ]; then echo 0; exit 0; fi',
      'if [ "${1:-}" = "gateway" ]; then exit 0; fi',
      "exit 0",
    ].join("\n"),
  );
  writeStub(
    harness.stubsDir,
    "python3",
    [
      'if [ "${1:-}" = "-c" ]; then',
      '  : > "$3"',
      "  exit 0",
      "fi",
      `if [ "$1" = ${JSON.stringify(harness.configGuardPath)} ]; then`,
      `  printf '%s\\n' "$*" >> ${JSON.stringify(harness.guardLog)}`,
      "  exit 0",
      "fi",
      'mode="${2:-}"',
      'if [ "$mode" = "env-file" ]; then',
      '  if [ "${STUB_ENVFILE_EXIT:-0}" = "1" ]; then',
      '    printf "[SECURITY] Refusing Hermes startup because /sandbox/.hermes/.env contains raw secret-shaped values.\\n" >&2',
      '    printf "[SECURITY]   TELEGRAM_BOT_TOKEN (line 2)\\n" >&2',
      "    exit 1",
      "  fi",
      "  exit 0",
      "fi",
      'if [ "$mode" = "runtime-env" ]; then',
      '  if [ "${STUB_RUNTIMEENV_EXIT:-0}" = "1" ]; then',
      '    printf "[SECURITY] Refusing Hermes startup because the process environment contains raw secret-shaped values.\\n" >&2',
      '    printf "[SECURITY]   TELEGRAM_BOT_TOKEN\\n" >&2',
      "    exit 1",
      "  fi",
      "  exit 0",
      "fi",
      "exit 2",
    ].join("\n"),
  );
  writeStub(
    harness.stubsDir,
    "stat",
    [
      'fmt="${1:-}"; target="${3:-${2:-}}"',
      'case "$fmt" in',
      "  -c)",
      '    case "${2:-}" in',
      "      %u) echo 0 ;;",
      "      %a)",
      '        case "$target" in',
      "          *preload-tmp*|*nemoclaw-proxy-env.sh|*nemoclaw-recovered-proxy-env.sh) echo 444 ;;",
      "          *) echo 644 ;;",
      "        esac",
      "        ;;",
      "      %U:%G) echo sandbox:sandbox ;;",
      '      *) /usr/bin/stat "$@" ;;',
      "    esac",
      "    ;;",
      "  -f)",
      '    case "${2:-}" in',
      "      %u) echo 0 ;;",
      "      %Lp) echo 644 ;;",
      "      %Su:%Sg) echo sandbox:sandbox ;;",
      '      *) /usr/bin/stat "$@" ;;',
      "    esac",
      "    ;;",
      '  *) /usr/bin/stat "$@" ;;',
      "esac",
    ].join("\n"),
  );
  writeStub(
    harness.stubsDir,
    "pkill",
    `printf '%s\\n' "$*" >> ${JSON.stringify(harness.pkillLog)}\nexit 0`,
  );
  writeStub(harness.stubsDir, "pgrep", "exit 1");
  writeStub(harness.stubsDir, "chown", "exit 0");
  writeStub(harness.stubsDir, "sleep", "exit 0");
  writeStub(harness.stubsDir, "curl", 'printf "000"\nexit 0');
  writeStub(harness.stubsDir, "ss", 'printf "LISTEN 0 4096 127.0.0.1:18642 0.0.0.0:*\\n"\nexit 0');
  writeStub(
    harness.stubsDir,
    "gosu",
    `printf '%s\\n' "$*" >> ${JSON.stringify(harness.gosuLog)}\n: > ${JSON.stringify(
      harness.launchMarker,
    )}\n/bin/sleep 1`,
  );
  writeStub(harness.stubsDir, "socat", "/bin/sleep 1");
  writeStub(harness.stubsDir, "sha256sum", "exit 0");
}

function rewriteHermesRestartScript(script: string, harness: HermesRestartHarness): string {
  return rewriteRecoveryPreloadPaths(script, harness)
    .replaceAll(HERMES_SECRET_BOUNDARY_VALIDATOR_PATH, harness.validatorPath)
    .replaceAll("/usr/local/lib/nemoclaw/hermes-runtime-config-guard.py", harness.configGuardPath)
    .replaceAll("/usr/local/bin/hermes", harness.hermesBin)
    .replaceAll("/sandbox/.hermes", harness.hermesDir)
    .replaceAll("/etc/nemoclaw", harness.etcNemoclawDir)
    .replaceAll("/tmp/gateway-recovery.log", harness.recoveryLogPath)
    .replaceAll("/tmp/gateway.log", harness.gatewayLogPath)
    .replaceAll("/tmp/nemoclaw-recovered-proxy-env.sh", harness.recoveredProxyEnvPath)
    .replaceAll("/tmp/nemoclaw-proxy-env.sh", harness.proxyEnvPath)
    .replaceAll("/tmp/.nemoclaw-proxy-env.sh.tmp.", `${harness.tmp}/.nemoclaw-proxy-env.sh.tmp.`);
}

function runHermesRestartScript(harness: HermesRestartHarness, env: Record<string, string> = {}) {
  const script = rewriteHermesRestartScript(
    buildHermesGatewayRestartScript(hermesAgent, 8642),
    harness,
  );
  return spawnSync("/bin/sh", ["-c", script], {
    encoding: "utf-8",
    timeout: 15_000,
    env: {
      HOME: harness.tmp,
      PATH: `${harness.stubsDir}:/usr/bin:/bin`,
      ...env,
    },
  });
}

describe("Hermes gateway restart shell behaviour (#2426)", () => {
  it("executes under /bin/sh -c and refuses poisoned env before launch", () => {
    const harness = prepareHermesRestartHarness("refusal");
    installHermesRestartStubs(harness);

    try {
      const result = runHermesRestartScript(harness, { STUB_ENVFILE_EXIT: "1" });

      expect(result.status).toBe(1);
      expect(result.stdout).toContain("SECRET_BOUNDARY_REFUSED");
      expect(result.stdout).not.toContain("GATEWAY_PID=");
      expect(fs.existsSync(harness.launchMarker)).toBe(false);
      const pkillCalls = fs.readFileSync(harness.pkillLog, "utf-8");
      expect(pkillCalls).toContain("[h]ermes");
      expect(pkillCalls).toContain("gateway");
      expect(pkillCalls).toContain("dashboard");
    } finally {
      removeTempDir(harness.tmp);
    }
  });

  it("executes under /bin/sh -c and launches after mutable hash refresh", () => {
    const harness = prepareHermesRestartHarness("launch");
    installHermesRestartStubs(harness);

    try {
      const result = runHermesRestartScript(harness);

      expect(result.status).toBe(0);
      expect(result.stdout).toContain("GATEWAY_PID=");
      expect(result.stdout).toContain("HERMES_SOCAT_PID=");
      expect(fs.existsSync(harness.launchMarker)).toBe(true);
      const guardCalls = fs.readFileSync(harness.guardLog, "utf-8");
      expect(guardCalls).toContain("refresh-hashes");
      expect(guardCalls).toContain("--mode strict");
      expect(guardCalls).toContain("--mode compat");
      const gosuCall = fs.readFileSync(harness.gosuLog, "utf-8");
      expect(gosuCall).toContain(`gateway env HERMES_HOME=${harness.hermesDir}`);
      expect(gosuCall).toContain(`${harness.hermesBin} gateway run`);
      expect(gosuCall).not.toContain("--port 8642");
    } finally {
      removeTempDir(harness.tmp);
    }
  });
});
