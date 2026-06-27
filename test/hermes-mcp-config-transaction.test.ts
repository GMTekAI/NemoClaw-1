// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

const TRANSACTION = path.resolve(
  import.meta.dirname,
  "..",
  "agents/hermes/mcp-config-transaction.py",
);
const GUARD = path.resolve(import.meta.dirname, "..", "agents/hermes/runtime-config-guard.py");

function runPython(source: string, args: string[] = []) {
  return spawnSync("python3", ["-c", source, TRANSACTION, GUARD, ...args], {
    encoding: "utf8",
  });
}

describe("Hermes managed MCP config transaction", () => {
  it("rejects raw credentials, private HTTP targets, and non-boolean control flags", () => {
    const result = runPython(`
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("mcp_tx", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
bad = [
    {"server": "fake", "url": "https://mcp.example.test/mcp", "headers": {"Authorization": "Bearer raw-secret"}},
    {"server": "fake", "url": "http://127.0.0.1/mcp", "headers": {"Authorization": "Bearer openshell:resolve:env:FAKE_TOKEN"}},
    {"server": "fake", "url": "https://mcp.example.test/mcp", "headers": {"Authorization": "Bearer openshell:resolve:env:FAKE_TOKEN"}, "replace_existing": "yes"},
]
errors = []
for payload in bad:
    try:
        module._validate_payload("add", payload)
    except ValueError as error:
        errors.append(str(error))
print(json.dumps(errors))
if len(errors) != len(bad):
    raise SystemExit(9)
`);

    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toHaveLength(3);
  });

  it("refuses a locked config snapshot", () => {
    const result = runPython(`
import importlib.util, sys, types
spec = importlib.util.spec_from_file_location("mcp_tx", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.os.geteuid = lambda: 1000
try:
    module._assert_mutable_snapshot(types.SimpleNamespace(mode=0o440, uid=1000, gid=1000))
except RuntimeError as error:
    print(str(error))
else:
    raise SystemExit(9)
`);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("locked");
  });

  it("treats edits to any managed field as drift during removal", () => {
    const result = runPython(`
import importlib.util, sys
spec = importlib.util.spec_from_file_location("mcp_tx", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
payload = {
    "server": "fake",
    "url": "https://mcp.example.test/mcp",
    "headers": {"Authorization": "Bearer openshell:resolve:env:FAKE_TOKEN"},
}
candidate = module._managed_candidate(payload)
candidate["enabled"] = False
try:
    module._mutate({"mcp_servers": {"fake": candidate}}, "remove", payload)
except ValueError as error:
    print(str(error))
else:
    raise SystemExit(9)
`);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Refusing to remove modified Hermes MCP server");
  });

  it("treats a null same-name Hermes server as drift rather than absence", () => {
    const result = runPython(`
import importlib.util, sys
spec = importlib.util.spec_from_file_location("mcp_tx", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
payload = {
    "server": "fake",
    "url": "https://mcp.example.test/mcp",
    "headers": {"Authorization": "Bearer openshell:resolve:env:FAKE_TOKEN"},
}
try:
    module._mutate({"mcp_servers": {"fake": None}}, "remove", payload)
except ValueError as error:
    print(str(error))
else:
    raise SystemExit(9)
`);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Refusing to remove modified Hermes MCP server");
  });

  it("allows root reload control to signal only the gateway service identity", () => {
    const result = runPython(`
import importlib.util, sys, types
spec = importlib.util.spec_from_file_location("mcp_tx", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
gateway = types.ModuleType("gateway")
status = types.ModuleType("gateway.status")
status.get_running_pid = lambda cleanup_stale=False: 4242
status.get_process_start_time = lambda pid: 99
sys.modules["gateway"] = gateway
sys.modules["gateway.status"] = status
module.os.geteuid = lambda: 0
module.pwd.getpwnam = lambda name: types.SimpleNamespace(pw_uid=2000)
module.os.stat = lambda path: types.SimpleNamespace(st_uid=1000)
try:
    module._gateway_identity()
except PermissionError as error:
    print(str(error))
else:
    raise SystemExit(9)
module.os.stat = lambda path: types.SimpleNamespace(st_uid=2000)
if module._gateway_identity() != (4242, 99):
    raise SystemExit(10)
`);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("expected gateway identity");
  });

  it("repairs and verifies strict and compatibility hashes on an unchanged retry", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-hermes-mcp-tx-"));
    const hermesDir = path.join(temp, ".hermes");
    const configPath = path.join(hermesDir, "config.yaml");
    const envPath = path.join(hermesDir, ".env");
    const strictHash = path.join(temp, "hermes.config-hash");
    const compatHash = path.join(hermesDir, ".config-hash");
    fs.mkdirSync(hermesDir);
    const config = `model: test
mcp_servers:
  fake:
    url: https://mcp.example.test/mcp
    enabled: true
    timeout: 120
    connect_timeout: 60
    tools:
      resources: true
      prompts: true
    headers:
      Authorization: Bearer openshell:resolve:env:FAKE_TOKEN
`;
    fs.writeFileSync(configPath, config, { mode: 0o600 });
    fs.writeFileSync(envPath, "HERMES_TEST=1\n", { mode: 0o600 });
    fs.writeFileSync(strictHash, "stale\n", { mode: 0o600 });
    fs.writeFileSync(compatHash, "different-stale\n", { mode: 0o600 });

    try {
      const result = runPython(
        `
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("mcp_tx", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.GUARD_PATH = sys.argv[2]
module.HERMES_DIR = sys.argv[3]
module.CONFIG_PATH = os.path.join(module.HERMES_DIR, "config.yaml")
module.STRICT_HASH_PATH = sys.argv[4]
module.os.geteuid = lambda: 0
module._assert_mutable_snapshot = lambda snapshot: None
changed = module.apply_transaction("add", {
    "server": "fake",
    "url": "https://mcp.example.test/mcp",
    "headers": {"Authorization": "Bearer openshell:resolve:env:FAKE_TOKEN"},
    "replace_existing": True,
})
print(json.dumps({"changed": changed}))
`,
        [hermesDir, strictHash],
      );

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(result.stdout).toContain('"changed": false');
      const strict = fs.readFileSync(strictHash, "utf8");
      const compat = fs.readFileSync(compatHash, "utf8");
      expect(strict).toBe(compat);
      expect(strict).toContain(crypto.createHash("sha256").update(config).digest("hex"));
      expect(strict).toContain(
        crypto.createHash("sha256").update(fs.readFileSync(envPath)).digest("hex"),
      );
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it("uses direct same-uid mutation and reload in a rootless OpenShell sandbox", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-hermes-mcp-rootless-"));
    const hermesDir = path.join(temp, ".hermes");
    const configPath = path.join(hermesDir, "config.yaml");
    const envPath = path.join(hermesDir, ".env");
    const compatHash = path.join(hermesDir, ".config-hash");
    const strictHash = path.join(temp, "root-owned-image-hash");
    const config = "model: test\n";
    const env = "HERMES_TEST=1\n";
    fs.mkdirSync(hermesDir);
    fs.writeFileSync(configPath, config, { mode: 0o600 });
    fs.writeFileSync(envPath, env, { mode: 0o600 });
    fs.writeFileSync(
      compatHash,
      `${crypto.createHash("sha256").update(config).digest("hex")}  ${configPath}\n${crypto.createHash("sha256").update(env).digest("hex")}  ${envPath}\n`,
      { mode: 0o600 },
    );
    fs.writeFileSync(strictHash, "ephemeral-root-anchor\n", { mode: 0o444 });

    try {
      const result = runPython(
        `
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("mcp_tx", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.GUARD_PATH = sys.argv[2]
module.HERMES_DIR = sys.argv[3]
module.CONFIG_PATH = os.path.join(module.HERMES_DIR, "config.yaml")
module.STRICT_HASH_PATH = sys.argv[4]
module.CONTROL_DIR = os.path.join(sys.argv[5], "missing-control")
module.CONTROL_SOCKET_PATH = os.path.join(module.CONTROL_DIR, "control.sock")
module.os.geteuid = lambda: 1000
module._assert_mutable_snapshot = lambda snapshot: None
module.reload_gateway = lambda: True
print(json.dumps(module.execute("add", {
    "server": "fake",
    "url": "https://mcp.example.test/mcp",
    "headers": {"Authorization": "Bearer openshell:resolve:env:FAKE_TOKEN"},
    "replace_existing": False,
})))
`,
        [hermesDir, strictHash, temp],
      );

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(JSON.parse(result.stdout)).toMatchObject({
        ok: true,
        changed: true,
        reloaded: true,
      });
      expect(fs.readFileSync(configPath, "utf8")).toContain("mcp_servers:");
      expect(fs.readFileSync(compatHash, "utf8")).not.toContain("stale");
      expect(fs.readFileSync(strictHash, "utf8")).toBe("ephemeral-root-anchor\n");
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it("restores config and hashes when runtime reload fails", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-hermes-mcp-rollback-"));
    const hermesDir = path.join(temp, ".hermes");
    const configPath = path.join(hermesDir, "config.yaml");
    const envPath = path.join(hermesDir, ".env");
    const compatHash = path.join(hermesDir, ".config-hash");
    const config = "model: test\n";
    const env = "HERMES_TEST=1\n";
    const originalHash = `${crypto.createHash("sha256").update(config).digest("hex")}  ${configPath}\n${crypto.createHash("sha256").update(env).digest("hex")}  ${envPath}\n`;
    fs.mkdirSync(hermesDir);
    fs.writeFileSync(configPath, config, { mode: 0o600 });
    fs.writeFileSync(envPath, env, { mode: 0o600 });
    fs.writeFileSync(compatHash, originalHash, { mode: 0o600 });

    try {
      const result = runPython(
        `
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("mcp_tx", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.GUARD_PATH = sys.argv[2]
module.HERMES_DIR = sys.argv[3]
module.CONFIG_PATH = os.path.join(module.HERMES_DIR, "config.yaml")
module.STRICT_HASH_PATH = os.path.join(sys.argv[4], "unused-strict")
module.os.geteuid = lambda: 1000
module._assert_mutable_snapshot = lambda snapshot: None
calls = []
def reload():
    calls.append(1)
    if len(calls) == 1:
        raise TimeoutError("forward reload timeout")
    return True
module.reload_gateway = reload
try:
    module.apply_transaction_and_reload("add", {
        "server": "fake",
        "url": "https://mcp.example.test/mcp",
        "headers": {"Authorization": "Bearer openshell:resolve:env:FAKE_TOKEN"},
        "replace_existing": False,
    })
except RuntimeError as error:
    print(json.dumps({"error": str(error), "reload_calls": len(calls)}))
else:
    raise SystemExit(9)
`,
        [hermesDir, temp],
      );

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(JSON.parse(result.stdout)).toMatchObject({ reload_calls: 2 });
      expect(fs.readFileSync(configPath, "utf8")).toBe(config);
      expect(fs.readFileSync(compatHash, "utf8")).toBe(originalHash);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });
});
