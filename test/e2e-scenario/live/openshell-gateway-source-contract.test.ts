// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { testTimeoutOptions } from "../../helpers/timeouts";
import { type ArtifactSink } from "../fixtures/artifacts.ts";
import { expect, test } from "../fixtures/e2e-test.ts";
import { prepareDockerDriverGatewayConfigEnv } from "../../../src/lib/onboard/docker-driver-gateway-config";

const OPENSHELL_TAG = "v0.0.67";
const OPENSHELL_EXPECTED_SHA = "ce788b50f9b1f977a4327e4484c5b663013dd9a5";
const REPO_ROOT = path.resolve(import.meta.dirname, "../../..");
const SOURCE_CONTRACT_TIMEOUT_MS = 45 * 60_000;
const COMMAND_TIMEOUT_MS = 12 * 60_000;
const COMMAND_BUFFER_BYTES = 80 * 1024 * 1024;

const sourceContractTest =
  process.env.NEMOCLAW_RUN_E2E_SCENARIOS === "1" ? test : test.skip;

type CommandResult = {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  error?: Error;
};

type ContractCommand = {
  id: string;
  command: string;
  args: string[];
  cwd: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
};

function commandResult(result: ReturnType<typeof spawnSync>): CommandResult {
  return {
    status: result.status,
    signal: result.signal,
    stdout:
      typeof result.stdout === "string" ? result.stdout : (result.stdout?.toString("utf8") ?? ""),
    stderr:
      typeof result.stderr === "string" ? result.stderr : (result.stderr?.toString("utf8") ?? ""),
    error: result.error,
  };
}

function resultText(result: CommandResult): string {
  return [
    `status=${result.status}`,
    `signal=${result.signal ?? ""}`,
    result.error ? `error=${result.error.message}` : "",
    result.stdout ? `stdout:\n${result.stdout}` : "",
    result.stderr ? `stderr:\n${result.stderr}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

async function runContractCommand(
  artifacts: ArtifactSink,
  command: ContractCommand,
): Promise<CommandResult> {
  const result = commandResult(
    spawnSync(command.command, command.args, {
      cwd: command.cwd,
      encoding: "utf8",
      env: {
        ...process.env,
        ...command.env,
      },
      timeout: command.timeoutMs ?? COMMAND_TIMEOUT_MS,
      killSignal: "SIGKILL",
      maxBuffer: COMMAND_BUFFER_BYTES,
    }),
  );
  await artifacts.writeText(
    `logs/${command.id}.txt`,
    [
      `$ ${[command.command, ...command.args].join(" ")}`,
      `cwd=${command.cwd}`,
      resultText(result),
      "",
    ].join("\n"),
  );
  return result;
}

async function expectCommandOk(
  artifacts: ArtifactSink,
  command: ContractCommand,
): Promise<CommandResult> {
  const result = await runContractCommand(artifacts, command);
  expect(result.signal, resultText(result)).toBeNull();
  expect(result.status, resultText(result)).toBe(0);
  return result;
}

async function cloneOpenShellSource(artifacts: ArtifactSink, workRoot: string): Promise<string> {
  const configuredSource = process.env.NEMOCLAW_OPENSHELL_SOURCE_DIR?.trim();
  const sourceRoot = path.join(workRoot, "OpenShell");
  if (configuredSource) {
    await expectCommandOk(artifacts, {
      id: "clone-configured-openshell-source",
      command: "git",
      args: ["clone", "--local", "--no-hardlinks", configuredSource, sourceRoot],
      cwd: REPO_ROOT,
    });
  } else {
    await expectCommandOk(artifacts, {
      id: "clone-openshell-source",
      command: "git",
      args: [
        "clone",
        "--filter=blob:none",
        "--depth",
        "1",
        "--branch",
        OPENSHELL_TAG,
        "https://github.com/NVIDIA/OpenShell.git",
        sourceRoot,
      ],
      cwd: REPO_ROOT,
      timeoutMs: 5 * 60_000,
    });
  }

  await expectCommandOk(artifacts, {
    id: "checkout-openshell-contract-sha",
    command: "git",
    args: ["checkout", "--detach", OPENSHELL_EXPECTED_SHA],
    cwd: sourceRoot,
  });
  const revParse = await expectCommandOk(artifacts, {
    id: "verify-openshell-contract-sha",
    command: "git",
    args: ["rev-parse", "HEAD"],
    cwd: sourceRoot,
  });
  expect(revParse.stdout.trim()).toBe(OPENSHELL_EXPECTED_SHA);
  return sourceRoot;
}

function writeNemoClawGatewayConfig(stateDir: string): { configPath: string; toml: string } {
  const env = prepareDockerDriverGatewayConfigEnv(
    {
      OPENSHELL_GRPC_ENDPOINT: "http://127.0.0.1:17670",
      OPENSHELL_DOCKER_NETWORK_NAME: "openshell-docker",
      OPENSHELL_DOCKER_SUPERVISOR_IMAGE: "ghcr.io/nvidia/openshell/supervisor:0.0.67",
    },
    stateDir,
    "/usr/bin/openshell-sandbox",
  );
  const configPath = env.OPENSHELL_GATEWAY_CONFIG;
  if (!configPath) throw new Error("expected OPENSHELL_GATEWAY_CONFIG");
  return { configPath, toml: fs.readFileSync(configPath, "utf8") };
}

function writeOpenShellGeneratedConfigContract(sourceRoot: string): string {
  const testDir = path.join(sourceRoot, "crates", "openshell-server", "tests");
  fs.mkdirSync(testDir, { recursive: true });
  const testPath = path.join(testDir, "nemoclaw_gateway_config_contract.rs");
  fs.writeFileSync(
    testPath,
    String.raw`// Generated by NemoClaw's openshell-gateway-source-contract live test.

use std::path::Path;

use openshell_core::config::ComputeDriverKind;

#[test]
fn nemoclaw_generated_gateway_config_loads_auth_jwt_and_docker_driver_contract() {
    let config_path = std::env::var("NEMOCLAW_OPENSHELL_GATEWAY_CONFIG")
        .expect("NEMOCLAW_OPENSHELL_GATEWAY_CONFIG");
    let file = openshell_server::config_file::load(Path::new(&config_path))
        .expect("NemoClaw gateway TOML must load through OpenShell config parser");
    assert_eq!(file.openshell.version, Some(1));

    let gateway = &file.openshell.gateway;
    assert_eq!(
        gateway.compute_drivers.as_ref().expect("compute drivers"),
        &vec![ComputeDriverKind::Docker]
    );

    let auth = gateway.auth.as_ref().expect("gateway auth");
    assert!(
        auth.allow_unauthenticated_users,
        "NemoClaw intentionally keeps local user CLI/API compatibility enabled"
    );

    let jwt = gateway.gateway_jwt.as_ref().expect("gateway_jwt");
    assert_eq!(jwt.ttl_secs, 3600);
    assert!(jwt.signing_key_path.exists());
    assert!(jwt.public_key_path.exists());
    assert!(jwt.kid_path.exists());
    assert!(
        !std::fs::read_to_string(&jwt.kid_path)
            .expect("kid")
            .trim()
            .is_empty()
    );

    let docker_table = file
        .openshell
        .drivers
        .get("docker")
        .expect("docker driver table");
    let merged =
        openshell_server::config_file::driver_table(ComputeDriverKind::Docker, gateway, Some(docker_table));
    assert_eq!(
        merged
            .get("grpc_endpoint")
            .and_then(toml::Value::as_str),
        Some("http://127.0.0.1:17670")
    );
    assert_eq!(
        merged
            .get("network_name")
            .and_then(toml::Value::as_str),
        Some("openshell-docker")
    );
    assert_eq!(
        merged
            .get("supervisor_bin")
            .and_then(toml::Value::as_str),
        Some("/usr/bin/openshell-sandbox")
    );
}
`,
    "utf8",
  );
  return testPath;
}

const OPENSHELL_CONTRACT_COMMANDS: Omit<ContractCommand, "cwd" | "env">[] = [
  {
    id: "cargo-openshell-generated-config-contract",
    command: "cargo",
    args: [
      "test",
      "--locked",
      "-p",
      "openshell-server",
      "--test",
      "nemoclaw_gateway_config_contract",
      "--",
      "--nocapture",
    ],
  },
  {
    id: "cargo-openshell-server-sandbox-jwt",
    command: "cargo",
    args: ["test", "--locked", "-p", "openshell-server", "sandbox_jwt", "--", "--nocapture"],
  },
  {
    id: "cargo-openshell-server-unauthenticated-dev-user",
    command: "cargo",
    args: [
      "test",
      "--locked",
      "-p",
      "openshell-server",
      "unauthenticated_dev_user",
      "--",
      "--nocapture",
    ],
  },
  {
    id: "cargo-openshell-server-sandbox-principal-allowlist",
    command: "cargo",
    args: [
      "test",
      "--locked",
      "-p",
      "openshell-server",
      "sandbox_principal_can_call_allowlisted_method",
      "--",
      "--nocapture",
    ],
  },
  {
    id: "cargo-openshell-server-user-denied-sandbox-methods",
    command: "cargo",
    args: [
      "test",
      "--locked",
      "-p",
      "openshell-server",
      "user_principal_is_denied_on_sandbox_only_methods",
      "--",
      "--nocapture",
    ],
  },
  {
    id: "cargo-openshell-server-gateway-listener-addresses",
    command: "cargo",
    args: [
      "test",
      "--locked",
      "-p",
      "openshell-server",
      "gateway_listener_addresses",
      "--",
      "--nocapture",
    ],
  },
  {
    id: "cargo-openshell-driver-docker-endpoint-rewrite",
    command: "cargo",
    args: [
      "test",
      "--locked",
      "-p",
      "openshell-driver-docker",
      "container_visible_endpoint_rewrites_loopback_hosts",
      "--",
      "--nocapture",
    ],
  },
  {
    id: "cargo-openshell-driver-docker-bridge-route",
    command: "cargo",
    args: [
      "test",
      "--locked",
      "-p",
      "openshell-driver-docker",
      "docker_gateway_route_uses_bridge_gateway_for_linux_docker",
      "--",
      "--nocapture",
    ],
  },
];

sourceContractTest(
  "openshell-gateway-source-contract: validates generated gateway config against OpenShell 0.0.67 source",
  testTimeoutOptions(SOURCE_CONTRACT_TIMEOUT_MS),
  async ({ artifacts }) => {
    const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-openshell-contract-"));
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-contract-state-"));
    const cargoTargetDir = path.join(workRoot, "cargo-target");
    try {
      const sourceRoot = await cloneOpenShellSource(artifacts, workRoot);
      const { configPath, toml } = writeNemoClawGatewayConfig(stateDir);
      const injectedTestPath = writeOpenShellGeneratedConfigContract(sourceRoot);
      await artifacts.writeText("generated-openshell-gateway.toml", toml);
      await artifacts.writeJson("contract-inputs.json", {
        openshellTag: OPENSHELL_TAG,
        openshellSha: OPENSHELL_EXPECTED_SHA,
        generatedConfigPath: configPath,
        injectedOpenShellTest: path.relative(sourceRoot, injectedTestPath),
      });

      const cargoVersion = await expectCommandOk(artifacts, {
        id: "cargo-version",
        command: "cargo",
        args: ["--version"],
        cwd: sourceRoot,
      });
      const commandResults = [];
      for (const command of OPENSHELL_CONTRACT_COMMANDS) {
        const result = await expectCommandOk(artifacts, {
          ...command,
          cwd: sourceRoot,
          env: {
            CARGO_TARGET_DIR: cargoTargetDir,
            NEMOCLAW_OPENSHELL_GATEWAY_CONFIG: configPath,
          },
        });
        commandResults.push({
          id: command.id,
          status: result.status,
        });
      }

      await artifacts.writeJson("contract-summary.json", {
        openshellTag: OPENSHELL_TAG,
        openshellSha: OPENSHELL_EXPECTED_SHA,
        cargoVersion: cargoVersion.stdout.trim(),
        generatedConfigPath: configPath,
        commands: commandResults,
      });
    } finally {
      fs.rmSync(workRoot, { recursive: true, force: true });
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  },
);
