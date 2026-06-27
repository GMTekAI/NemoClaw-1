// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { dockerForceRm } from "../adapters/docker";

const DEFAULT_COMPAT_IMAGE = "ubuntu:24.04";
const DEFAULT_COMPAT_CONTAINER_NAME = "nemoclaw-openshell-gateway";
const GATEWAY_MOUNT_PATH = "/opt/nemoclaw/openshell-gateway";
const COMPAT_GATEWAY_CONFIG_NAME = "openshell-gateway.toml";
const GATEWAY_JWT_DIR_NAME = "jwt";
const GATEWAY_JWT_SIGNING_KEY_NAME = "signing.pem";
const GATEWAY_JWT_PUBLIC_KEY_NAME = "public.pem";
const GATEWAY_JWT_KID_NAME = "kid";
const DEFAULT_COMPAT_BIND_ADDRESS = "0.0.0.0";
const LOOPBACK_BIND_ADDRESS = "127.0.0.1";
const DEFAULT_GATEWAY_ID = "nemoclaw";

export type DockerDriverGatewayLaunch = {
  command: string;
  args: string[];
  env: NodeJS.ProcessEnv;
  mode: "host" | "container";
  processGatewayBin: string | null;
  reason?: string;
  containerName?: string;
};

export type DockerDriverGatewayRuntimeIdentity = {
  launch: DockerDriverGatewayLaunch | null;
  desiredEnv: Record<string, string>;
  driftGatewayBin: string | null;
  identityGatewayBin: string | null;
};

export function openDockerDriverGatewayLog(
  logPath: string,
  options: { exitOnFailure?: boolean } = {},
): number {
  const appendNoFollow =
    fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW;
  try {
    return fs.openSync(logPath, appendNoFollow, 0o600);
  } catch (error) {
    console.error(
      `  Failed to open OpenShell Docker-driver gateway log '${logPath}': ${String(error)}`,
    );
    if (options.exitOnFailure) process.exit(1);
    throw error;
  }
}

export function spawnDockerDriverGateway(
  launch: DockerDriverGatewayLaunch,
  logFd: number,
): ChildProcess {
  try {
    return spawn(launch.command, launch.args, {
      detached: true,
      stdio: ["ignore", logFd, logFd],
      env: launch.env,
    });
  } finally {
    fs.closeSync(logFd);
  }
}

type BuildGatewayLaunchOptions = {
  gatewayBin: string;
  gatewayEnv: Record<string, string>;
  stateDir: string;
  sandboxBin?: string | null;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  hostGlibcVersion?: string | null;
  requiredGlibcVersions?: string[];
  gatewayName?: string;
  // Default compatibility container name when NEMOCLAW_OPENSHELL_GATEWAY_COMPAT_CONTAINER_NAME
  // is unset. Callers pass a per-gateway-port name so a second sandbox's compat
  // container (and its pre-launch `docker rm`) cannot tear down the first
  // sandbox's gateway container (#4422).
  compatContainerName?: string;
};

export type DockerDriverGatewayJwtConfig = {
  signingKeyPath: string;
  publicKeyPath: string;
  kidPath: string;
  gatewayId: string;
  ttlSecs: number;
};

export function compareDottedVersions(a: string, b: string): number {
  const left = a.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const right = b.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const len = Math.max(left.length, right.length);
  for (let i = 0; i < len; i += 1) {
    const delta = (left[i] ?? 0) - (right[i] ?? 0);
    if (delta !== 0) return delta;
  }
  return 0;
}

export function maxDottedVersion(versions: string[]): string | null {
  return versions.reduce<string | null>(
    (max, version) => (!max || compareDottedVersions(version, max) > 0 ? version : max),
    null,
  );
}

export function parseGlibcVersionsFromBinaryText(text: string): string[] {
  return [
    ...new Set(
      [...text.matchAll(/GLIBC_([0-9]+(?:\.[0-9]+)+)/g)].map((match) => match[1]).filter(Boolean),
    ),
  ];
}

export function requiredGlibcVersionsForBinary(binaryPath: string): string[] {
  try {
    return parseGlibcVersionsFromBinaryText(fs.readFileSync(binaryPath, "latin1"));
  } catch {
    return [];
  }
}

export function getHostGlibcVersion(): string | null {
  const report = (
    process as unknown as {
      report?: { getReport?: () => { header?: { glibcVersionRuntime?: string } } };
    }
  ).report?.getReport?.();
  const fromNode = report?.header?.glibcVersionRuntime;
  if (fromNode) return fromNode;
  try {
    const output = execFileSync("getconf", ["GNU_LIBC_VERSION"], {
      encoding: "utf-8",
      timeout: 5_000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    return output.match(/glibc\s+([0-9]+(?:\.[0-9]+)+)/i)?.[1] ?? null;
  } catch {
    return null;
  }
}

export function getDockerSocketPath(env: NodeJS.ProcessEnv = process.env): string {
  const dockerHost = String(env.DOCKER_HOST || "").trim();
  if (dockerHost.startsWith("unix://")) return dockerHost.slice("unix://".length);
  return "/var/run/docker.sock";
}

export function shouldUseContainerizedGateway(
  options: Pick<
    BuildGatewayLaunchOptions,
    "gatewayBin" | "platform" | "env" | "hostGlibcVersion" | "requiredGlibcVersions"
  >,
): { useContainer: boolean; reason?: string } {
  const env = options.env ?? process.env;
  const override = String(env.NEMOCLAW_OPENSHELL_GATEWAY_CONTAINER_PATCH || "").trim();
  if (override === "0") return { useContainer: false };
  if ((options.platform ?? process.platform) !== "linux") return { useContainer: false };
  if (override === "1") {
    return { useContainer: true, reason: "forced by NEMOCLAW_OPENSHELL_GATEWAY_CONTAINER_PATCH=1" };
  }

  const host = options.hostGlibcVersion ?? getHostGlibcVersion();
  if (!host) return { useContainer: false };
  const required = maxDottedVersion(
    options.requiredGlibcVersions ?? requiredGlibcVersionsForBinary(options.gatewayBin),
  );
  if (!required) return { useContainer: false };
  if (compareDottedVersions(required, host) <= 0) return { useContainer: false };
  return {
    useContainer: true,
    reason: `host glibc ${host} is older than openshell-gateway requirement ${required}`,
  };
}

function addVolume(args: string[], hostPath: string, containerPath = hostPath, mode = "rw"): void {
  args.push("--volume", `${hostPath}:${containerPath}:${mode}`);
}

function addEnv(args: string[], key: string, value: string | undefined): void {
  if (typeof value === "string") args.push("--env", key);
}

function tomlString(value: string): string {
  return JSON.stringify(value);
}

function hasCompleteGatewayJwtMaterial(jwtConfig: DockerDriverGatewayJwtConfig): boolean {
  return [jwtConfig.signingKeyPath, jwtConfig.publicKeyPath, jwtConfig.kidPath].every(
    (filePath) => {
      try {
        return fs.statSync(filePath).isFile() && fs.statSync(filePath).size > 0;
      } catch {
        return false;
      }
    },
  );
}

function chmodIfPresent(filePath: string, mode: number): void {
  try {
    fs.chmodSync(filePath, mode);
  } catch {
    /* best effort; the next read/write will surface actionable errors */
  }
}

export function getDockerDriverGatewayJwtConfig(
  stateDir: string,
  gatewayName = DEFAULT_GATEWAY_ID,
): DockerDriverGatewayJwtConfig {
  const jwtDir = path.join(stateDir, GATEWAY_JWT_DIR_NAME);
  return {
    signingKeyPath: path.join(jwtDir, GATEWAY_JWT_SIGNING_KEY_NAME),
    publicKeyPath: path.join(jwtDir, GATEWAY_JWT_PUBLIC_KEY_NAME),
    kidPath: path.join(jwtDir, GATEWAY_JWT_KID_NAME),
    gatewayId: gatewayName || DEFAULT_GATEWAY_ID,
    ttlSecs: 0,
  };
}

export function ensureDockerDriverGatewayJwtMaterial(
  stateDir: string,
  gatewayName = DEFAULT_GATEWAY_ID,
): DockerDriverGatewayJwtConfig {
  const jwtConfig = getDockerDriverGatewayJwtConfig(stateDir, gatewayName);
  const jwtDir = path.dirname(jwtConfig.signingKeyPath);
  fs.mkdirSync(jwtDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(jwtDir, 0o700);

  if (hasCompleteGatewayJwtMaterial(jwtConfig)) {
    chmodIfPresent(jwtConfig.signingKeyPath, 0o600);
    chmodIfPresent(jwtConfig.publicKeyPath, 0o600);
    chmodIfPresent(jwtConfig.kidPath, 0o600);
    return jwtConfig;
  }

  for (const filePath of [jwtConfig.signingKeyPath, jwtConfig.publicKeyPath, jwtConfig.kidPath]) {
    try {
      fs.rmSync(filePath, { force: true });
    } catch {
      /* best effort before regenerating the complete bundle */
    }
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(jwtConfig.signingKeyPath, privateKey.export({ format: "pem", type: "pkcs8" }), {
    encoding: "utf-8",
    mode: 0o600,
  });
  fs.writeFileSync(jwtConfig.publicKeyPath, publicKey.export({ format: "pem", type: "spki" }), {
    encoding: "utf-8",
    mode: 0o600,
  });
  fs.writeFileSync(jwtConfig.kidPath, `${crypto.randomBytes(16).toString("hex")}\n`, {
    encoding: "utf-8",
    mode: 0o600,
  });
  fs.chmodSync(jwtConfig.signingKeyPath, 0o600);
  fs.chmodSync(jwtConfig.publicKeyPath, 0o600);
  fs.chmodSync(jwtConfig.kidPath, 0o600);
  return jwtConfig;
}

export function buildDockerDriverGatewayConfigToml(
  gatewayEnv: Record<string, string>,
  sandboxBin: string | null | undefined,
  gatewayJwt: DockerDriverGatewayJwtConfig,
): string {
  const dockerEntries: [string, string | null | undefined][] = [
    ["grpc_endpoint", gatewayEnv.OPENSHELL_GRPC_ENDPOINT],
    ["network_name", gatewayEnv.OPENSHELL_DOCKER_NETWORK_NAME],
    ["supervisor_image", gatewayEnv.OPENSHELL_DOCKER_SUPERVISOR_IMAGE],
    ["supervisor_bin", sandboxBin],
  ];
  const dockerConfig = dockerEntries
    .filter(
      (entry): entry is [string, string] => typeof entry[1] === "string" && entry[1].trim() !== "",
    )
    .map(([key, value]) => `${key} = ${tomlString(value)}`)
    .join("\n");

  return [
    "[openshell]",
    "version = 1",
    "",
    "[openshell.gateway]",
    'compute_drivers = ["docker"]',
    "",
    "[openshell.gateway.auth]",
    "allow_unauthenticated_users = true",
    "",
    "[openshell.gateway.gateway_jwt]",
    `signing_key_path = ${tomlString(gatewayJwt.signingKeyPath)}`,
    `public_key_path = ${tomlString(gatewayJwt.publicKeyPath)}`,
    `kid_path = ${tomlString(gatewayJwt.kidPath)}`,
    `gateway_id = ${tomlString(gatewayJwt.gatewayId)}`,
    `ttl_secs = ${gatewayJwt.ttlSecs}`,
    "",
    "[openshell.drivers.docker]",
    dockerConfig,
    "",
  ].join("\n");
}

function writeDockerDriverGatewayConfig(
  stateDir: string,
  gatewayEnv: Record<string, string>,
  sandboxBin: string | null | undefined,
  gatewayName = DEFAULT_GATEWAY_ID,
): string {
  const configPath = path.join(stateDir, COMPAT_GATEWAY_CONFIG_NAME);
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(stateDir, 0o700);
  const gatewayJwt = ensureDockerDriverGatewayJwtMaterial(stateDir, gatewayName);
  fs.writeFileSync(
    configPath,
    buildDockerDriverGatewayConfigToml(gatewayEnv, sandboxBin, gatewayJwt),
    {
      encoding: "utf-8",
      mode: 0o600,
    },
  );
  fs.chmodSync(configPath, 0o600);
  return configPath;
}

function safeDockerName(value: string | undefined, fallback: string): string {
  const candidate = String(value || "").trim();
  if (!candidate) return fallback;
  if (/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(candidate)) return candidate;
  throw new Error("Invalid Docker container name override.");
}

function safeDockerImage(value: string | undefined, fallback: string): string {
  const candidate = String(value || "").trim();
  if (!candidate) return fallback;
  if (/^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$/.test(candidate)) return candidate;
  throw new Error("Invalid Docker image override.");
}

function safeDockerHost(value: string | undefined): string | undefined {
  const candidate = String(value || "").trim();
  if (!candidate) return undefined;
  if (candidate.startsWith("unix://")) {
    const socketPath = candidate.slice("unix://".length);
    if (path.isAbsolute(socketPath) && !socketPath.includes("\0")) return candidate;
  }
  if (/^tcp:\/\/[A-Za-z0-9_.-]+:[0-9]{1,5}$/.test(candidate)) return candidate;
  return undefined;
}

function compatGatewayBindAddress(env: NodeJS.ProcessEnv): string {
  const raw = String(env.NEMOCLAW_OPENSHELL_GATEWAY_COMPAT_BIND_ADDRESS || "").trim();
  if (!raw) return DEFAULT_COMPAT_BIND_ADDRESS;
  if (raw === DEFAULT_COMPAT_BIND_ADDRESS || raw === LOOPBACK_BIND_ADDRESS) return raw;
  throw new Error(
    "Invalid NEMOCLAW_OPENSHELL_GATEWAY_COMPAT_BIND_ADDRESS; expected 0.0.0.0 or 127.0.0.1.",
  );
}

export function buildDockerDriverGatewayLaunch(
  options: BuildGatewayLaunchOptions,
): DockerDriverGatewayLaunch {
  const gatewayEnv = { ...options.gatewayEnv };
  if (options.sandboxBin && !gatewayEnv.OPENSHELL_DOCKER_SUPERVISOR_BIN) {
    gatewayEnv.OPENSHELL_DOCKER_SUPERVISOR_BIN = options.sandboxBin;
  }
  const baseEnv = options.env ?? process.env;
  const compat = shouldUseContainerizedGateway(options);
  if (compat.useContainer) {
    gatewayEnv.OPENSHELL_BIND_ADDRESS = compatGatewayBindAddress(baseEnv);
  }
  const sandboxBin = options.sandboxBin || gatewayEnv.OPENSHELL_DOCKER_SUPERVISOR_BIN;
  if (compat.useContainer && !sandboxBin) {
    throw new Error(
      "OpenShell gateway container compatibility mode requires openshell-sandbox. " +
        "Re-run the NemoClaw installer or set NEMOCLAW_OPENSHELL_SANDBOX_BIN.",
    );
  }
  const env = { ...baseEnv, ...gatewayEnv };
  env.OPENSHELL_GATEWAY_CONFIG = writeDockerDriverGatewayConfig(
    options.stateDir,
    gatewayEnv,
    sandboxBin,
    options.gatewayName,
  );
  if (!compat.useContainer) {
    return {
      command: options.gatewayBin,
      args: [],
      env,
      mode: "host",
      processGatewayBin: options.gatewayBin,
    };
  }

  const image = safeDockerImage(env.NEMOCLAW_OPENSHELL_GATEWAY_COMPAT_IMAGE, DEFAULT_COMPAT_IMAGE);
  // The per-port compatContainerName wins so a process-wide
  // NEMOCLAW_OPENSHELL_GATEWAY_COMPAT_CONTAINER_NAME cannot collapse two sandboxes
  // back onto one compat container (and its pre-launch `docker rm`) (#4422). The
  // env override still applies when no per-port name is supplied.
  const containerName = safeDockerName(
    options.compatContainerName,
    safeDockerName(
      env.NEMOCLAW_OPENSHELL_GATEWAY_COMPAT_CONTAINER_NAME,
      DEFAULT_COMPAT_CONTAINER_NAME,
    ),
  );
  const dockerHost = safeDockerHost(env.DOCKER_HOST);
  if (dockerHost) {
    env.DOCKER_HOST = dockerHost;
  } else {
    delete env.DOCKER_HOST;
  }
  const dockerSocket = getDockerSocketPath(env);
  const args = ["run", "--rm", "--name", containerName, "--network", "host"];
  addVolume(args, path.resolve(options.gatewayBin), GATEWAY_MOUNT_PATH, "ro");
  addVolume(args, path.resolve(options.stateDir), path.resolve(options.stateDir), "rw");
  addVolume(
    args,
    path.resolve(path.dirname(sandboxBin)),
    path.resolve(path.dirname(sandboxBin)),
    "ro",
  );
  if (fs.existsSync(dockerSocket)) addVolume(args, dockerSocket, dockerSocket, "rw");
  for (const key of Object.keys(gatewayEnv).sort()) {
    addEnv(args, key, gatewayEnv[key]);
  }
  addEnv(args, "OPENSHELL_GATEWAY_CONFIG", env.OPENSHELL_GATEWAY_CONFIG);
  addEnv(args, "DOCKER_HOST", dockerHost);
  addEnv(args, "RUST_LOG", env.RUST_LOG);
  args.push(image, GATEWAY_MOUNT_PATH);

  return {
    command: "docker",
    args,
    env,
    mode: "container",
    processGatewayBin: null,
    reason: compat.reason,
    containerName,
  };
}

export function prepareDockerDriverGatewayLaunch(launch: DockerDriverGatewayLaunch): void {
  if (launch.mode !== "container" || !launch.containerName) return;
  dockerForceRm(launch.containerName, {
    ignoreError: true,
    suppressOutput: true,
    timeout: 30_000,
  });
}

export function buildDockerDriverGatewayRuntimeIdentity(
  options: BuildGatewayLaunchOptions,
): DockerDriverGatewayRuntimeIdentity {
  const launch = buildDockerDriverGatewayLaunch(options);
  const desiredKeys = new Set([
    ...Object.keys(options.gatewayEnv),
    "OPENSHELL_DOCKER_SUPERVISOR_BIN",
    "OPENSHELL_GATEWAY_CONFIG",
  ]);
  const desiredEnv = Object.fromEntries(
    Object.entries(launch.env).filter(
      ([key, val]) => desiredKeys.has(key) && typeof val === "string",
    ) as [string, string][],
  );
  return {
    launch,
    desiredEnv,
    driftGatewayBin: launch.processGatewayBin,
    identityGatewayBin: launch.processGatewayBin || options.gatewayBin,
  };
}

/**
 * Resolve the gateway binary used for the `/proc/<pid>/exe` drift comparison.
 *
 * In containerized Docker-compat mode the gateway runs as a host-side
 * `docker run ... /opt/nemoclaw/openshell-gateway` parent, so the parent
 * process's executable is `/usr/bin/docker`, not the host openshell-gateway
 * binary. `buildDockerDriverGatewayRuntimeIdentity()` encodes that with
 * `driftGatewayBin: null` to mean "skip the executable check". Callers must
 * preserve that deliberate `null` — coalescing it back to the host binary with
 * `??` makes the drift check compare `/usr/bin/docker` against the host
 * gateway path and falsely mark a healthy compat gateway as stale (#4520).
 */
export function resolveDriftGatewayBin(
  runtimeIdentity: DockerDriverGatewayRuntimeIdentity | null,
  gatewayBin: string | null,
): string | null {
  return runtimeIdentity ? runtimeIdentity.driftGatewayBin : gatewayBin;
}

export function prepareAndLogDockerDriverGatewayLaunch(
  launch: DockerDriverGatewayLaunch,
  log: (message: string) => void = console.log,
): void {
  if (launch.mode !== "container") return;
  log(`  OpenShell gateway compatibility patch active (${launch.reason}).`);
  log("  Running openshell-gateway inside a Docker compatibility container.");
  if (launch.env.OPENSHELL_BIND_ADDRESS === "0.0.0.0") {
    log("  Compatibility gateway bind: 0.0.0.0 (required for Docker sandbox callbacks).");
  }
  prepareDockerDriverGatewayLaunch(launch);
}
