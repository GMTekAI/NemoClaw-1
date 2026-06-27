// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

// Build must run before these tests (imports from dist/)
const require = createRequire(import.meta.url);
const requireCache: Record<string, unknown> = require.cache as any;
const helperPath = require.resolve("../../../dist/lib/sandbox/privileged-exec");
const dockerRunPath = require.resolve("../../../dist/lib/adapters/docker/run");
const registryPath = require.resolve("../../../dist/lib/state/registry");
const { containerNameMatchesSandbox, selectDirectSandboxContainer } = require(helperPath);

function withPrivilegedExecMocks<T>(
  deps: {
    dockerCapture: (args: readonly string[]) => string;
    getSandbox: (name: string) => { name?: string; openshellDriver?: string | null } | null;
  },
  run: (helper: typeof import("../../../dist/lib/sandbox/privileged-exec")) => T,
): T {
  const priorHelper = require.cache[helperPath];
  const priorDockerRun = require.cache[dockerRunPath];
  const priorRegistry = require.cache[registryPath];

  delete require.cache[helperPath];
  requireCache[dockerRunPath] = {
    id: dockerRunPath,
    filename: dockerRunPath,
    loaded: true,
    exports: { dockerCapture: deps.dockerCapture },
  } as any;
  requireCache[registryPath] = {
    id: registryPath,
    filename: registryPath,
    loaded: true,
    exports: { getSandbox: deps.getSandbox },
  } as any;

  try {
    return run(require(helperPath));
  } finally {
    if (priorHelper) requireCache[helperPath] = priorHelper;
    else delete requireCache[helperPath];

    if (priorDockerRun) requireCache[dockerRunPath] = priorDockerRun;
    else delete requireCache[dockerRunPath];

    if (priorRegistry) requireCache[registryPath] = priorRegistry;
    else delete requireCache[registryPath];
  }
}

describe("privileged sandbox exec routing", () => {
  it("matches only the requested OpenShell sandbox container name pattern", () => {
    expect(containerNameMatchesSandbox("openshell-demo", "demo")).toBe(true);
    expect(containerNameMatchesSandbox("openshell-demo-abc123", "demo")).toBe(true);
    expect(containerNameMatchesSandbox("openshell-demolition", "demo")).toBe(false);
    expect(containerNameMatchesSandbox("openshell-gateway-nemoclaw", "demo")).toBe(false);
  });

  it("selects the immutable id of one labeled direct sandbox container", () => {
    expect(selectDirectSandboxContainer("demo", "abc123\topenshell-demo-2026\n")).toBe("abc123");
  });

  it("rejects ambiguous labeled running containers", () => {
    expect(() =>
      selectDirectSandboxContainer(
        "demo",
        "abc123\topenshell-demo-one\ndef456\topenshell-demo-two\n",
      ),
    ).toThrow(/Multiple running OpenShell containers.*refusing ambiguous/);
  });

  it("rejects malformed Docker metadata", () => {
    expect(() => selectDirectSandboxContainer("demo", "openshell-demo\n")).toThrow(
      /malformed OpenShell sandbox container metadata/,
    );
  });

  it("rejects an authoritative label/name mismatch", () => {
    expect(() =>
      selectDirectSandboxContainer(
        "alpha",
        "gateway-id\topenshell-gateway-nemoclaw\nchild-id\topenshell-alpha-child\n",
      ),
    ).toThrow(/labels and names disagree.*refusing lifecycle execution/);
  });

  it("builds privileged argv from authoritative labels", () => {
    withPrivilegedExecMocks(
      {
        getSandbox: () => ({ name: "alpha", openshellDriver: "docker" }),
        dockerCapture: (args) => {
          expect(args).toEqual([
            "ps",
            "--no-trunc",
            "--filter",
            "label=openshell.ai/managed-by=openshell",
            "--filter",
            "label=openshell.ai/sandbox-name=alpha",
            "--format",
            "{{.ID}}\t{{.Names}}",
          ]);
          return "immutable-alpha-id\topenshell-alpha-abc123\n";
        },
      },
      ({ privilegedSandboxExecArgv }) => {
        expect(privilegedSandboxExecArgv("alpha", ["id"], true)).toEqual([
          "exec",
          "-i",
          "--user",
          "root",
          "immutable-alpha-id",
          "id",
        ]);
      },
    );
  });

  it("fails before Docker discovery when the sandbox registry entry is unavailable", () => {
    let dockerPsCalls = 0;
    withPrivilegedExecMocks(
      {
        getSandbox: () => {
          throw new Error("registry corrupt");
        },
        dockerCapture: () => {
          dockerPsCalls += 1;
          return "alpha-id\topenshell-alpha-abc123\n";
        },
      },
      ({ privilegedSandboxExecArgv }) => {
        expect(() => privilegedSandboxExecArgv("alpha", ["id"])).toThrow("registry corrupt");
      },
    );
    expect(dockerPsCalls).toBe(0);
  });

  it("surfaces Docker discovery failures instead of reporting a missing container", () => {
    withPrivilegedExecMocks(
      {
        getSandbox: () => ({ name: "alpha", openshellDriver: "docker" }),
        dockerCapture: () => {
          throw new Error("docker daemon unavailable");
        },
      },
      ({ privilegedSandboxExecArgv }) => {
        expect(() => privilegedSandboxExecArgv("alpha", ["id"])).toThrow(
          "docker daemon unavailable",
        );
      },
    );
  });

  it("fails clearly when no matching labeled direct sandbox container is running", () => {
    withPrivilegedExecMocks(
      {
        getSandbox: () => ({ name: "alpha", openshellDriver: "docker" }),
        dockerCapture: () => "",
      },
      ({ privilegedSandboxExecArgv }) => {
        expect(() => privilegedSandboxExecArgv("alpha", ["id"])).toThrow(
          /No running direct OpenShell sandbox container found for 'alpha'/,
        );
      },
    );
  });
});
