// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { type ChildProcess, spawn } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type LifecycleLockModule = typeof import("../dist/lib/state/mcp-lifecycle-lock");

const requireDist = createRequire(import.meta.url);
const lockModulePath = requireDist.resolve("../dist/lib/state/mcp-lifecycle-lock.js");
const lifecycleLock = requireDist(lockModulePath) as LifecycleLockModule;

let stateDir: string;
const children = new Set<ChildProcess>();

function options(overrides: Record<string, number> = {}) {
  return {
    stateDir,
    pollIntervalMs: 5,
    timeoutMs: 1_000,
    corruptLockGraceMs: 10,
    ...overrides,
  };
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function waitForLine(child: ChildProcess, expected: string): Promise<void> {
  return new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => reject(new Error(`Timed out waiting for ${expected}`)), 2_000);
    child.once("error", reject);
    child.stdout?.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
      if (output.split(/\r?\n/).includes(expected)) {
        clearTimeout(timeout);
        resolve();
      }
    });
  });
}

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-mcp-lock-"));
});

afterEach(() => {
  for (const child of children) child.kill("SIGKILL");
  children.clear();
  fs.rmSync(stateDir, { recursive: true, force: true });
});

describe("MCP lifecycle lock", () => {
  it("serializes separate top-level promises in one process", async () => {
    const firstEntered = deferred();
    const releaseFirst = deferred();
    const order: string[] = [];

    const first = lifecycleLock.withMcpLifecycleLock(
      "alpha",
      async () => {
        order.push("first-enter");
        firstEntered.resolve();
        await releaseFirst.promise;
        order.push("first-exit");
      },
      options(),
    );
    await firstEntered.promise;

    const second = lifecycleLock.withMcpLifecycleLock(
      "alpha",
      () => {
        order.push("second-enter");
      },
      options(),
    );
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(order).toEqual(["first-enter"]);

    releaseFirst.resolve();
    await Promise.all([first, second]);
    expect(order).toEqual(["first-enter", "first-exit", "second-enter"]);
  });

  it("is reentrant only inside the same async lifecycle context", async () => {
    const events: string[] = [];
    await lifecycleLock.withMcpLifecycleLock(
      "alpha",
      async () => {
        events.push("outer");
        await lifecycleLock.withMcpLifecycleLock(
          "alpha",
          () => events.push("nested"),
          options({ timeoutMs: 50 }),
        );
      },
      options(),
    );
    expect(events).toEqual(["outer", "nested"]);
    expect(fs.existsSync(lifecycleLock.getMcpLifecycleLockPath("alpha", stateDir))).toBe(false);
  });

  it("does not let a detached promise reuse an ended operation's lease", async () => {
    const startDetached = deferred();
    const lockPath = lifecycleLock.getMcpLifecycleLockPath("alpha", stateDir);
    let detached: Promise<void> | undefined;

    await lifecycleLock.withMcpLifecycleLock(
      "alpha",
      () => {
        detached = (async () => {
          await startDetached.promise;
          await lifecycleLock.withMcpLifecycleLock(
            "alpha",
            () => expect(fs.existsSync(lockPath)).toBe(true),
            options(),
          );
        })();
      },
      options(),
    );

    startDetached.resolve();
    await detached;
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it("serializes a second Node process on the same sandbox", async () => {
    const releasePath = path.join(stateDir, "release-child");
    const script = String.raw`
const fs = require("node:fs");
const lock = require(process.argv[1]);
const stateDir = process.argv[2];
const releasePath = process.argv[3];
(async () => {
  await lock.withMcpLifecycleLock("alpha", async () => {
    process.stdout.write("READY\n");
    while (!fs.existsSync(releasePath)) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }, { stateDir, pollIntervalMs: 5, timeoutMs: 2000 });
})().then(() => process.exit(0), (error) => {
  console.error(error);
  process.exit(1);
});
`;
    const child = spawn(process.execPath, ["-e", script, lockModulePath, stateDir, releasePath], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    children.add(child);
    const childExit = new Promise<void>((resolve, reject) => {
      child.once("exit", (code) => (code === 0 ? resolve() : reject(new Error(`child ${code}`))));
    });
    await waitForLine(child, "READY");

    let parentEntered = false;
    const parent = lifecycleLock.withMcpLifecycleLock(
      "alpha",
      () => {
        parentEntered = true;
      },
      options({ timeoutMs: 2_000 }),
    );
    await new Promise((resolve) => setTimeout(resolve, 40));
    expect(parentEntered).toBe(false);

    fs.writeFileSync(releasePath, "release\n");
    await parent;
    expect(parentEntered).toBe(true);
    await childExit;
    children.delete(child);
  });

  it("recovers an atomic lock left by a dead owner", async () => {
    const lockPath = lifecycleLock.getMcpLifecycleLockPath("alpha", stateDir);
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    fs.writeFileSync(
      lockPath,
      `${JSON.stringify({
        version: 1,
        sandboxName: "alpha",
        pid: 2_147_483_647,
        processIdentity: "dead-process",
        token: "stale-token",
        acquiredAt: "2026-01-01T00:00:00.000Z",
      })}\n`,
    );

    let entered = false;
    await lifecycleLock.withMcpLifecycleLock(
      "alpha",
      () => {
        entered = true;
      },
      options(),
    );
    expect(entered).toBe(true);
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it("recovers a reaper whose owner was killed during stale-lock cleanup", async () => {
    const lockPath = lifecycleLock.getMcpLifecycleLockPath("alpha", stateDir);
    const reaperPath = `${lockPath}.reaper`;
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    fs.writeFileSync(
      reaperPath,
      `${JSON.stringify({
        version: 1,
        sandboxName: "alpha",
        pid: 2_147_483_647,
        processIdentity: "killed-reaper",
        token: "stale-reaper-token",
        acquiredAt: "2026-01-01T00:00:00.000Z",
      })}\n`,
    );

    let entered = false;
    await lifecycleLock.withMcpLifecycleLock(
      "alpha",
      () => {
        entered = true;
      },
      options(),
    );
    expect(entered).toBe(true);
    expect(fs.existsSync(lockPath)).toBe(false);
    expect(fs.existsSync(reaperPath)).toBe(false);
  });

  it("does not unlink a replacement reaper published during stale recovery", async () => {
    const lockPath = lifecycleLock.getMcpLifecycleLockPath("alpha", stateDir);
    const reaperPath = `${lockPath}.reaper`;
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    fs.writeFileSync(
      reaperPath,
      `${JSON.stringify({
        version: 1,
        sandboxName: "alpha",
        pid: 2_147_483_647,
        processIdentity: "dead-reaper",
        token: "observed-stale-token",
        acquiredAt: "2026-01-01T00:00:00.000Z",
      })}\n`,
    );
    const replacement = {
      version: 1,
      sandboxName: "alpha",
      pid: process.pid,
      processIdentity: lifecycleLock.readMcpLockProcessIdentity(process.pid),
      token: "replacement-reaper-token",
      acquiredAt: new Date().toISOString(),
    };
    const rename = fs.promises.rename.bind(fs.promises);
    let injectedReplacement = false;
    const renameSpy = vi.spyOn(fs.promises, "rename").mockImplementation(async (from, to) => {
      if (!injectedReplacement && String(from) === reaperPath) {
        injectedReplacement = true;
        fs.unlinkSync(reaperPath);
        fs.writeFileSync(reaperPath, `${JSON.stringify(replacement)}\n`);
      }
      return rename(from, to);
    });

    try {
      await expect(
        lifecycleLock.withMcpLifecycleLock("alpha", () => undefined, options({ timeoutMs: 50 })),
      ).rejects.toThrow("Timed out waiting for MCP lifecycle lock");
    } finally {
      renameSpy.mockRestore();
    }
    expect(JSON.parse(fs.readFileSync(reaperPath, "utf8")).token).toBe("replacement-reaper-token");
  });

  it("recovers a recycled PID by comparing process-start identity", async () => {
    const identity = lifecycleLock.readMcpLockProcessIdentity(process.pid);
    if (identity === null) return;
    const lockPath = lifecycleLock.getMcpLifecycleLockPath("alpha", stateDir);
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    fs.writeFileSync(
      lockPath,
      `${JSON.stringify({
        version: 1,
        sandboxName: "alpha",
        pid: process.pid,
        processIdentity: `${identity}-different-start`,
        token: "recycled-token",
        acquiredAt: "2026-01-01T00:00:00.000Z",
      })}\n`,
    );

    await expect(
      lifecycleLock.withMcpLifecycleLock("alpha", () => undefined, options()),
    ).resolves.toBeUndefined();
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it("does not break a long-lived lock owned by the same process identity", async () => {
    const lockPath = lifecycleLock.getMcpLifecycleLockPath("alpha", stateDir);
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    fs.writeFileSync(
      lockPath,
      `${JSON.stringify({
        version: 1,
        sandboxName: "alpha",
        pid: process.pid,
        processIdentity: lifecycleLock.readMcpLockProcessIdentity(process.pid),
        token: "active-token",
        acquiredAt: "2020-01-01T00:00:00.000Z",
      })}\n`,
    );
    const old = new Date("2020-01-01T00:00:00.000Z");
    fs.utimesSync(lockPath, old, old);

    await expect(
      lifecycleLock.withMcpLifecycleLock("alpha", () => undefined, options({ timeoutMs: 40 })),
    ).rejects.toThrow("Timed out waiting for MCP lifecycle lock");
    expect(JSON.parse(fs.readFileSync(lockPath, "utf8")).token).toBe("active-token");
  });

  it("never releases a lock whose owner token changed", async () => {
    const lockPath = lifecycleLock.getMcpLifecycleLockPath("alpha", stateDir);
    await lifecycleLock.withMcpLifecycleLock(
      "alpha",
      () => {
        const owner = JSON.parse(fs.readFileSync(lockPath, "utf8"));
        fs.writeFileSync(lockPath, `${JSON.stringify({ ...owner, token: "replacement-token" })}\n`);
      },
      options(),
    );

    expect(JSON.parse(fs.readFileSync(lockPath, "utf8")).token).toBe("replacement-token");
  });
});
