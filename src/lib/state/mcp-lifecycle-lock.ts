// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { AsyncLocalStorage } from "node:async_hooks";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { isErrnoException } from "../core/errno";
import { resolveNemoclawStateDir } from "./paths";

const LOCK_SCHEMA_VERSION = 1;
const DEFAULT_POLL_INTERVAL_MS = 100;
const DEFAULT_TIMEOUT_MS = 30 * 60_000;
const DEFAULT_CORRUPT_LOCK_GRACE_MS = 30_000;
const OWNER_IDENTITY_CACHE_MS = 1_000;

export const MCP_LIFECYCLE_LOCK_DIRNAME = "mcp-lifecycle-locks";

interface McpLifecycleLockOwner {
  version: typeof LOCK_SCHEMA_VERSION;
  sandboxName: string;
  pid: number;
  processIdentity: string | null;
  token: string;
  acquiredAt: string;
}

interface LockObservation {
  owner: McpLifecycleLockOwner | null;
  mtimeMs: number;
}

interface AcquiredMcpLifecycleLock {
  lockPath: string;
  token: string;
}

export interface McpLifecycleLockOptions {
  /** Override used by focused tests. Production callers use ~/.nemoclaw/state. */
  stateDir?: string;
  pollIntervalMs?: number;
  timeoutMs?: number;
  corruptLockGraceMs?: number;
}

interface HeldLockLease {
  active: boolean;
}

type HeldLockContext = ReadonlyMap<string, HeldLockLease>;

const heldLocks = new AsyncLocalStorage<HeldLockContext>();
const processIdentityCache = new Map<number, { checkedAt: number; identity: string | null }>();

function isLockOwner(value: unknown): value is McpLifecycleLockOwner {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return (
    candidate.version === LOCK_SCHEMA_VERSION &&
    typeof candidate.sandboxName === "string" &&
    Number.isSafeInteger(candidate.pid) &&
    (candidate.pid as number) > 0 &&
    (candidate.processIdentity === null || typeof candidate.processIdentity === "string") &&
    typeof candidate.token === "string" &&
    candidate.token.length > 0 &&
    typeof candidate.acquiredAt === "string"
  );
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return isErrnoException(error) && error.code === "EPERM";
  }
}

/**
 * Returns an OS process-start identity rather than only a PID. A stale lock
 * whose PID has been recycled must not be mistaken for its now-unrelated live
 * process. Linux exposes the kernel boot id plus /proc start ticks; macOS and
 * other supported POSIX hosts fall back to ps(1)'s process start timestamp.
 */
export function readMcpLockProcessIdentity(pid: number): string | null {
  const cached = processIdentityCache.get(pid);
  const now = Date.now();
  if (cached && now - cached.checkedAt < OWNER_IDENTITY_CACHE_MS) {
    return cached.identity;
  }

  let identity: string | null = null;
  if (process.platform === "linux") {
    try {
      const statText = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
      const closeParen = statText.lastIndexOf(")");
      if (closeParen >= 0) {
        const fieldsAfterComm = statText
          .slice(closeParen + 2)
          .trim()
          .split(/\s+/);
        // The first value after comm is field 3; index 19 is field 22,
        // process start time in clock ticks since boot.
        const startTicks = fieldsAfterComm[19];
        if (startTicks && /^\d+$/.test(startTicks)) {
          let bootIdentity = "unknown-boot";
          try {
            bootIdentity = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
          } catch {
            const bootTime = fs
              .readFileSync("/proc/stat", "utf8")
              .split("\n")
              .find((line) => line.startsWith("btime "));
            if (bootTime) bootIdentity = bootTime.trim();
          }
          identity = `linux:${bootIdentity}:${startTicks}`;
        }
      }
    } catch {
      identity = null;
    }
  } else {
    const result = spawnSync("ps", ["-o", "lstart=", "-p", String(pid)], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 1_000,
    });
    const startedAt = result.status === 0 ? result.stdout.trim() : "";
    if (startedAt) identity = `${process.platform}:${startedAt}`;
  }

  processIdentityCache.set(pid, { checkedAt: now, identity });
  return identity;
}

function lockFileStem(sandboxName: string): string {
  // Hashing makes the filesystem key traversal-safe even if a caller reaches
  // the lock before the command's normal sandbox-name validation.
  return crypto.createHash("sha256").update(sandboxName).digest("hex");
}

export function getMcpLifecycleLockPath(
  sandboxName: string,
  stateDir = resolveNemoclawStateDir(),
): string {
  return path.join(stateDir, MCP_LIFECYCLE_LOCK_DIRNAME, `${lockFileStem(sandboxName)}.lock`);
}

function ownerFileContent(owner: McpLifecycleLockOwner): string {
  return `${JSON.stringify(owner)}\n`;
}

function createLockOwner(sandboxName: string, token: string): McpLifecycleLockOwner {
  return {
    version: LOCK_SCHEMA_VERSION,
    sandboxName,
    pid: process.pid,
    processIdentity: readMcpLockProcessIdentity(process.pid),
    token,
    acquiredAt: new Date().toISOString(),
  };
}

async function readLockObservation(lockPath: string): Promise<LockObservation | null> {
  let handle: fs.promises.FileHandle;
  try {
    handle = await fs.promises.open(
      lockPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
  } catch (error) {
    if (isErrnoException(error) && error.code === "ENOENT") return null;
    try {
      const stat = await fs.promises.lstat(lockPath);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        return { owner: null, mtimeMs: stat.mtimeMs };
      }
    } catch (statError) {
      if (isErrnoException(statError) && statError.code === "ENOENT") return null;
      throw statError;
    }
    throw error;
  }

  try {
    const stat = await handle.stat();
    if (!stat.isFile()) return { owner: null, mtimeMs: stat.mtimeMs };
    try {
      const parsed: unknown = JSON.parse(await handle.readFile("utf8"));
      return {
        owner: isLockOwner(parsed) ? parsed : null,
        mtimeMs: stat.mtimeMs,
      };
    } catch {
      return { owner: null, mtimeMs: stat.mtimeMs };
    }
  } finally {
    await handle.close();
  }
}

export type McpLifecycleLockDisposition = "active" | "stale" | "wait";

/** Exported for deterministic stale-owner/PID-recycle tests. */
export function classifyMcpLifecycleLock(
  observation: LockObservation,
  sandboxName: string,
  nowMs: number,
  corruptLockGraceMs: number,
): McpLifecycleLockDisposition {
  const { owner } = observation;
  if (!owner || owner.sandboxName !== sandboxName) {
    return nowMs - observation.mtimeMs >= corruptLockGraceMs ? "stale" : "wait";
  }
  if (!processIsAlive(owner.pid)) return "stale";

  const observedIdentity = readMcpLockProcessIdentity(owner.pid);
  if (
    owner.processIdentity !== null &&
    observedIdentity !== null &&
    owner.processIdentity !== observedIdentity
  ) {
    return "stale";
  }
  // If this OS cannot recover process-start identity, a live PID is treated as
  // active. Failing closed may require waiting for that process to exit, but it
  // never breaks mutual exclusion for a legitimate long rebuild/destroy.
  return "active";
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) && (value ?? 0) > 0 ? Math.floor(value as number) : fallback;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await fs.promises.lstat(targetPath);
    return true;
  } catch (error) {
    if (isErrnoException(error) && error.code === "ENOENT") return false;
    throw error;
  }
}

async function safelyReleaseLock(lockPath: string, token: string): Promise<void> {
  const observation = await readLockObservation(lockPath);
  // This path is used only by the live owner. Stale-reaper recovery uses the
  // quarantine-and-verify protocol below so competing reclaimers cannot unlink
  // a replacement generation between this token read and unlink.
  if (!observation || observation.owner?.token !== token) return;
  try {
    await fs.promises.unlink(lockPath);
  } catch (error) {
    if (!isErrnoException(error) || error.code !== "ENOENT") throw error;
  }
}

async function reclaimStaleReaper(
  reaperPath: string,
  expectedToken: string | null,
): Promise<boolean> {
  const quarantinePath = `${reaperPath}.reclaim-${process.pid}-${crypto.randomUUID()}`;
  try {
    // Rename is the atomic claim. Another waiter may have already removed the
    // stale generation and published a replacement after our earlier read, so
    // the moved file must be verified before it is ever deleted.
    await fs.promises.rename(reaperPath, quarantinePath);
  } catch (error) {
    if (isErrnoException(error) && error.code === "ENOENT") return false;
    throw error;
  }

  const claimed = await readLockObservation(quarantinePath);
  const claimedExpectedGeneration =
    expectedToken === null
      ? claimed !== null && claimed.owner === null
      : claimed?.owner?.token === expectedToken;
  if (claimedExpectedGeneration) {
    await fs.promises.rm(quarantinePath, { force: true, recursive: true });
    return true;
  }

  // We raced a replacement owner. Restore the exact moved inode with a hard
  // link (which cannot overwrite a newer generation), then drop only our
  // quarantine name. If another generation already occupies the canonical
  // path, preserve the displaced owner record for diagnosis rather than ever
  // deleting an owner we did not claim.
  try {
    await fs.promises.link(quarantinePath, reaperPath);
    await fs.promises.rm(quarantinePath, { force: true });
  } catch (error) {
    if (!isErrnoException(error) || error.code !== "EEXIST") throw error;
  }
  return false;
}

async function tryReapStaleLock(
  lockPath: string,
  sandboxName: string,
  corruptLockGraceMs: number,
): Promise<boolean> {
  const reaperPath = `${lockPath}.reaper`;
  const reaperToken = crypto.randomUUID();
  const reaperOwner = createLockOwner(sandboxName, reaperToken);
  if (!(await writeCandidateAndLink(reaperPath, reaperOwner))) return false;

  try {
    const latest = await readLockObservation(lockPath);
    if (!latest) return true;
    if (classifyMcpLifecycleLock(latest, sandboxName, Date.now(), corruptLockGraceMs) !== "stale") {
      return false;
    }

    const quarantinePath = `${lockPath}.stale-${process.pid}-${crypto.randomUUID()}`;
    try {
      await fs.promises.rename(lockPath, quarantinePath);
    } catch (error) {
      if (isErrnoException(error) && error.code === "ENOENT") return true;
      throw error;
    }
    await fs.promises.rm(quarantinePath, { force: true, recursive: true });
    return true;
  } finally {
    await safelyReleaseLock(reaperPath, reaperToken);
  }
}

async function writeCandidateAndLink(
  lockPath: string,
  owner: McpLifecycleLockOwner,
): Promise<boolean> {
  const candidatePath = `${lockPath}.candidate-${process.pid}-${owner.token}`;
  try {
    const handle = await fs.promises.open(candidatePath, "wx", 0o600);
    try {
      await handle.writeFile(ownerFileContent(owner), "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      // The hard link is the atomic publication point: waiters can never see a
      // partially written owner record.
      await fs.promises.link(candidatePath, lockPath);
      return true;
    } catch (error) {
      if (isErrnoException(error) && error.code === "EEXIST") return false;
      throw error;
    }
  } finally {
    await fs.promises.rm(candidatePath, { force: true });
  }
}

async function acquireMcpLifecycleLock(
  sandboxName: string,
  options: McpLifecycleLockOptions,
): Promise<AcquiredMcpLifecycleLock> {
  const pollIntervalMs = positiveInteger(options.pollIntervalMs, DEFAULT_POLL_INTERVAL_MS);
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS);
  const corruptLockGraceMs = positiveInteger(
    options.corruptLockGraceMs,
    DEFAULT_CORRUPT_LOCK_GRACE_MS,
  );
  const lockPath = getMcpLifecycleLockPath(sandboxName, options.stateDir);
  await fs.promises.mkdir(path.dirname(lockPath), {
    recursive: true,
    mode: 0o700,
  });

  const startedAt = Date.now();
  let lastOwnerPid: number | null = null;
  for (;;) {
    if (Date.now() - startedAt >= timeoutMs) {
      const ownerSuffix = lastOwnerPid ? ` (owner pid ${lastOwnerPid})` : "";
      throw new Error(
        `Timed out waiting for MCP lifecycle lock for sandbox '${sandboxName}'${ownerSuffix}. Another add, restart, remove, rebuild, or destroy operation is still running.`,
      );
    }

    const reaperPath = `${lockPath}.reaper`;
    const reaperObservation = await readLockObservation(reaperPath);
    if (reaperObservation) {
      const reaperDisposition = classifyMcpLifecycleLock(
        reaperObservation,
        sandboxName,
        Date.now(),
        corruptLockGraceMs,
      );
      if (reaperDisposition === "stale") {
        // The reaper has the same atomic, PID-identified owner format as the
        // main lock. A SIGKILL at any point in stale-lock cleanup is therefore
        // recoverable without age-expiring a legitimate long operation.
        await reclaimStaleReaper(reaperPath, reaperObservation.owner?.token ?? null);
        continue;
      }
      await sleep(pollIntervalMs);
      continue;
    }

    if (!(await pathExists(reaperPath))) {
      const token = crypto.randomUUID();
      const owner = createLockOwner(sandboxName, token);
      if (await writeCandidateAndLink(lockPath, owner)) {
        // A stale-lock reaper may have appeared between our pre-check and the
        // atomic link. Do not enter the critical section until that generation
        // gate has gone away.
        if (!(await pathExists(reaperPath))) return { lockPath, token };
        await safelyReleaseLock(lockPath, token);
      }
    }

    const observation = await readLockObservation(lockPath);
    if (observation) {
      lastOwnerPid = observation.owner?.pid ?? null;
      if (
        classifyMcpLifecycleLock(observation, sandboxName, Date.now(), corruptLockGraceMs) ===
        "stale"
      ) {
        if (await tryReapStaleLock(lockPath, sandboxName, corruptLockGraceMs)) {
          continue;
        }
      }
    }
    await sleep(pollIntervalMs);
  }
}

/**
 * Serializes the complete MCP lifecycle for one sandbox across processes.
 * AsyncLocalStorage makes nested calls in the same lifecycle operation
 * reentrant (rebuild recovery -> MCP restart), while separate top-level
 * promises in one Node process still contend on the filesystem lock.
 *
 * This is a CLI state lock only. It is not an MCP bridge, proxy, listener, or
 * credential process and never participates in sandbox network traffic.
 */
export async function withMcpLifecycleLock<T>(
  sandboxName: string,
  operation: () => Promise<T> | T,
  options: McpLifecycleLockOptions = {},
): Promise<T> {
  const stateDir = options.stateDir ?? resolveNemoclawStateDir();
  const lockKey = getMcpLifecycleLockPath(sandboxName, stateDir);
  const inherited = heldLocks.getStore();
  if (inherited?.get(lockKey)?.active) return await operation();

  const acquired = await acquireMcpLifecycleLock(sandboxName, {
    ...options,
    stateDir,
  });
  const lease: HeldLockLease = { active: true };
  const context = new Map(inherited ?? []);
  context.set(lockKey, lease);
  return heldLocks.run(context, async () => {
    try {
      return await operation();
    } finally {
      // Async resources created by the callback retain their ALS store. Mark
      // the lease inactive before releasing so a detached/later promise cannot
      // mistake an ended parent operation for a still-held reentrant lock.
      lease.active = false;
      await safelyReleaseLock(acquired.lockPath, acquired.token);
    }
  });
}
