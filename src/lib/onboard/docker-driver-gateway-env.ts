// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  GATEWAY_BIND_ADDRESS,
  getGatewayConnectHost,
  getGatewayHttpsEndpoint,
  WILDCARD_GATEWAY_BIND_ADDRESS,
} from "../core/gateway-address";
import { GATEWAY_PORT } from "../core/ports";
import { prepareDockerDriverGatewayConfigEnv } from "./docker-driver-gateway-config";
import { buildDockerDriverGatewayLocalTlsEnv } from "./docker-driver-gateway-local-tls";
import {
  hasOpenShellGatewayUserService,
  type PackageManagedDockerDriverGatewayOptions,
  startPackageManagedDockerDriverGateway,
} from "./docker-driver-gateway-service";

export { getGatewayHttpsEndpoint, startPackageManagedDockerDriverGateway };

export const DOCKER_DRIVER_GATEWAY_RUNTIME_ENV_KEYS = [
  "OPENSHELL_DRIVERS",
  "OPENSHELL_BIND_ADDRESS",
  "OPENSHELL_SERVER_PORT",
  "OPENSHELL_DISABLE_TLS",
  "OPENSHELL_DISABLE_GATEWAY_AUTH",
  "OPENSHELL_LOCAL_TLS_DIR",
  "OPENSHELL_DB_URL",
  "OPENSHELL_GRPC_ENDPOINT",
  "OPENSHELL_SSH_GATEWAY_HOST",
  "OPENSHELL_SSH_GATEWAY_PORT",
  "OPENSHELL_DOCKER_NETWORK_NAME",
  "OPENSHELL_DOCKER_SUPERVISOR_IMAGE",
  "OPENSHELL_DOCKER_SUPERVISOR_BIN",
  "OPENSHELL_GATEWAY_CONFIG",
  "OPENSHELL_VM_DRIVER_STATE_DIR",
  "OPENSHELL_DRIVER_DIR",
] as const;

export interface BuildDockerDriverGatewayEnvOptions {
  platform?: NodeJS.Platform;
  stateDir: string;
  dockerNetworkName?: string;
  getDockerSupervisorImage: () => string;
  resolveSandboxBin: () => string | null;
}

export type PackageManagedDockerDriverGatewayWithEnvOverrideOptions = Omit<
  PackageManagedDockerDriverGatewayOptions,
  "prepareOpenShellGatewayUserServiceEnv"
> & {
  gatewayEnv: Record<string, string>;
};

export function getGatewayPortCheckOptions(): { host: string } {
  return { host: GATEWAY_BIND_ADDRESS };
}

export function getGatewayStartNetworkEnv(): Record<string, string> {
  return {
    OPENSHELL_BIND_ADDRESS: GATEWAY_BIND_ADDRESS,
    OPENSHELL_SERVER_PORT: String(GATEWAY_PORT),
    OPENSHELL_SSH_GATEWAY_HOST: getGatewayConnectHost(),
    OPENSHELL_SSH_GATEWAY_PORT: String(GATEWAY_PORT),
  };
}

export function assertDockerDriverGatewayBindAddressSafe(gatewayEnv: Record<string, string>): void {
  if (gatewayEnv.OPENSHELL_BIND_ADDRESS !== WILDCARD_GATEWAY_BIND_ADDRESS) return;
  throw new Error(
    "NEMOCLAW_GATEWAY_BIND_ADDRESS=0.0.0.0 is not supported for the OpenShell 0.0.67 Docker-driver gateway while gateway JWT auth is active. Remove the override, or use NEMOCLAW_DASHBOARD_BIND for dashboard exposure.",
  );
}

function parseTomlBooleanValues(toml: string): Map<string, boolean> {
  const values = new Map<string, boolean>();
  let section = "";
  for (const rawLine of toml.split("\n")) {
    const line = rawLine.replace(/#.*/, "").trim();
    const sectionMatch = line.match(/^\[([A-Za-z0-9_.-]+)\]$/);
    if (sectionMatch?.[1]) {
      section = sectionMatch[1];
      continue;
    }
    const booleanMatch = line.match(/^([A-Za-z0-9_]+)\s*=\s*(true|false)$/);
    if (booleanMatch?.[1] && booleanMatch[2]) {
      values.set(`${section}.${booleanMatch[1]}`, booleanMatch[2] === "true");
    }
  }
  return values;
}

function assertTomlBoolean(values: Map<string, boolean>, key: string, expected: boolean): void {
  const actual = values.get(key);
  if (actual === expected) return;
  throw new Error(
    `OpenShell Docker-driver gateway config must set ${key}=${expected}; found ${
      actual === undefined ? "missing" : actual
    }`,
  );
}

export function assertDockerDriverGatewayAuthConfigSafe(gatewayEnv: Record<string, string>): void {
  assertDockerDriverGatewayBindAddressSafe(gatewayEnv);
  const configPath = gatewayEnv.OPENSHELL_GATEWAY_CONFIG?.trim();
  if (!configPath) {
    throw new Error("OpenShell Docker-driver gateway requires OPENSHELL_GATEWAY_CONFIG");
  }
  const toml = fs.readFileSync(configPath, "utf-8");
  const values = parseTomlBooleanValues(toml);
  assertTomlBoolean(values, "openshell.gateway.disable_tls", false);
  assertTomlBoolean(values, "openshell.gateway.tls.require_client_auth", true);
  assertTomlBoolean(values, "openshell.gateway.mtls_auth.enabled", true);
  assertTomlBoolean(values, "openshell.gateway.auth.allow_unauthenticated_users", false);
}

export function getDockerDriverGatewayEndpoint(): string {
  return getGatewayHttpsEndpoint();
}

export function warnIfGatewayWildcardBindAddress(): void {
  if (GATEWAY_BIND_ADDRESS !== WILDCARD_GATEWAY_BIND_ADDRESS) return;
  console.log(
    "  ! OpenShell gateway bind address set to 0.0.0.0; the gateway may be reachable from other hosts on this network.",
  );
}

export function buildDockerDriverGatewayEnv({
  platform = process.platform,
  stateDir,
  dockerNetworkName = "openshell-docker",
  getDockerSupervisorImage,
  resolveSandboxBin,
}: BuildDockerDriverGatewayEnvOptions): Record<string, string> {
  const env: Record<string, string> = {
    OPENSHELL_DRIVERS: "docker",
    ...getGatewayStartNetworkEnv(),
    ...buildDockerDriverGatewayLocalTlsEnv(stateDir),
    OPENSHELL_DB_URL: `sqlite:${path.join(stateDir, "openshell.db")}`,
    OPENSHELL_GRPC_ENDPOINT: getDockerDriverGatewayEndpoint(),
    OPENSHELL_DOCKER_NETWORK_NAME: dockerNetworkName,
    OPENSHELL_DOCKER_SUPERVISOR_IMAGE: getDockerSupervisorImage(),
  };
  if (platform === "linux") {
    const sandboxBin = resolveSandboxBin();
    if (sandboxBin) {
      env.OPENSHELL_DOCKER_SUPERVISOR_BIN = sandboxBin;
    }
  }
  prepareDockerDriverGatewayConfigEnv(env, stateDir, env.OPENSHELL_DOCKER_SUPERVISOR_BIN);
  return env;
}

export function buildDockerGatewayDebEnvFile(
  existing: string,
  override: Record<string, string>,
): string {
  const managedKeyPattern = new RegExp(`^(${DOCKER_DRIVER_GATEWAY_RUNTIME_ENV_KEYS.join("|")})=`);
  const preserved = existing
    .split("\n")
    .filter((line) => line.trim() && !managedKeyPattern.test(line));
  const managed = DOCKER_DRIVER_GATEWAY_RUNTIME_ENV_KEYS.flatMap((key) =>
    typeof override[key] === "string" ? [formatEnvironmentFileAssignment(key, override[key])] : [],
  );
  return `${[...preserved, ...managed].join("\n")}\n`;
}

function formatEnvironmentFileAssignment(key: string, value: string): string {
  if (/[\0\r\n]/.test(value)) {
    throw new Error(`Invalid OpenShell gateway env value for ${key}: contains a line break`);
  }
  return `${key}=${value}`;
}

function readTextFileIfPresent(filePath: string): string {
  try {
    return fs.readFileSync(filePath, "utf-8");
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return "";
    }
    throw error;
  }
}

function writeDockerGatewayDebEnvOverrideFile(getOverride: () => Record<string, string>): void {
  const override = getOverride();
  const envDir = path.join(os.homedir(), ".config", "openshell");
  const envFile = path.join(envDir, "gateway.env");
  fs.mkdirSync(envDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(envDir, 0o700);
  const existing = readTextFileIfPresent(envFile);
  fs.writeFileSync(envFile, buildDockerGatewayDebEnvFile(existing, override), {
    encoding: "utf-8",
    mode: 0o600,
  });
  fs.chmodSync(envFile, 0o600);
}

export function writeDockerGatewayDebEnvOverride(
  getOverride: () => Record<string, string>,
  opts: Parameters<typeof hasOpenShellGatewayUserService>[0] = {},
): boolean {
  if (!hasOpenShellGatewayUserService(opts)) return false;
  writeDockerGatewayDebEnvOverrideFile(getOverride);
  return true;
}

export function writeDockerGatewayDebEnvOverrideOrThrow(
  getOverride: () => Record<string, string>,
  opts: Parameters<typeof hasOpenShellGatewayUserService>[0] = {},
): void {
  if (!writeDockerGatewayDebEnvOverride(getOverride, opts)) {
    throw new Error("OpenShell gateway user service env file is not available");
  }
}

export function startPackageManagedDockerDriverGatewayWithEnvOverride({
  gatewayEnv,
  ...options
}: PackageManagedDockerDriverGatewayWithEnvOverrideOptions): Promise<boolean> {
  assertDockerDriverGatewayAuthConfigSafe(gatewayEnv);
  return startPackageManagedDockerDriverGateway({
    ...options,
    prepareOpenShellGatewayUserServiceEnv: () =>
      writeDockerGatewayDebEnvOverrideFile(() => gatewayEnv),
  });
}
