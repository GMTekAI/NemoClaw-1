// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { dockerCapture } from "../adapters/docker/run";
import * as registry from "../state/registry";

const OPENSHELL_MANAGED_BY_LABEL = "openshell.ai/managed-by";
const OPENSHELL_MANAGED_BY_VALUE = "openshell";
const OPENSHELL_SANDBOX_NAME_LABEL = "openshell.ai/sandbox-name";

type SandboxEntry = {
  name?: string;
  openshellDriver?: string | null;
};

type LabeledSandboxContainer = {
  id: string;
  name: string;
};

function normalizeDriver(driver: unknown): string | null {
  return typeof driver === "string" && driver.trim() ? driver.trim().toLowerCase() : null;
}

function readSandboxEntry(sandboxName: string): SandboxEntry | null {
  return registry.getSandbox?.(sandboxName) ?? null;
}

function containerNameMatchesSandbox(containerName: string, sandboxName: string): boolean {
  const exact = `openshell-${sandboxName}`;
  return containerName === exact || containerName.startsWith(`${exact}-`);
}

function parseLabeledSandboxContainers(output: string): LabeledSandboxContainer[] {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [id, name, ...unexpected] = line.split("\t");
      if (!id || !name || unexpected.length > 0 || /\s/.test(id)) {
        throw new Error("Docker returned malformed OpenShell sandbox container metadata.");
      }
      return { id, name };
    });
}

function selectDirectSandboxContainer(
  sandboxName: string,
  labeledContainerRows: string,
): string | null {
  const candidates = parseLabeledSandboxContainers(labeledContainerRows);
  if (candidates.some((candidate) => !containerNameMatchesSandbox(candidate.name, sandboxName))) {
    throw new Error(
      `OpenShell container labels and names disagree for sandbox '${sandboxName}'; ` +
        "refusing lifecycle execution.",
    );
  }
  if (candidates.length > 1) {
    throw new Error(
      `Multiple running OpenShell containers are labeled for sandbox '${sandboxName}'; ` +
        "refusing ambiguous lifecycle execution.",
    );
  }
  return candidates[0]?.id ?? null;
}

function expectedDirectContainerPattern(sandboxName: string): string {
  return `openshell-${sandboxName} or openshell-${sandboxName}-*`;
}

function findDirectSandboxContainer(sandboxName: string): string | null {
  const output = dockerCapture([
    "ps",
    "--no-trunc",
    "--filter",
    `label=${OPENSHELL_MANAGED_BY_LABEL}=${OPENSHELL_MANAGED_BY_VALUE}`,
    "--filter",
    `label=${OPENSHELL_SANDBOX_NAME_LABEL}=${sandboxName}`,
    "--format",
    "{{.ID}}\t{{.Names}}",
  ]);
  return selectDirectSandboxContainer(sandboxName, output);
}

function missingDirectContainerError(sandboxName: string, driver: string | null): Error {
  const driverLabel = driver ?? "unspecified";
  return new Error(
    `No running direct OpenShell sandbox container found for '${sandboxName}' ` +
      `(driver: ${driverLabel}). Expected one OpenShell-managed container labeled ` +
      `'${OPENSHELL_SANDBOX_NAME_LABEL}=${sandboxName}' and named ` +
      `${expectedDirectContainerPattern(sandboxName)}. Is the sandbox running?`,
  );
}

function missingRegistryEntryError(sandboxName: string): Error {
  return new Error(
    `No NemoClaw registry entry found for '${sandboxName}'; ` +
      "refusing lifecycle exec without a registered sandbox owner.",
  );
}

function resolveDirectSandboxContainer(sandboxName: string, driver: string | null): string {
  const selected = findDirectSandboxContainer(sandboxName);
  if (selected) return selected;
  throw missingDirectContainerError(sandboxName, driver);
}

function registeredDirectSandboxContainer(sandboxName: string): string {
  const entry = readSandboxEntry(sandboxName);
  if (!entry) throw missingRegistryEntryError(sandboxName);
  return resolveDirectSandboxContainer(sandboxName, normalizeDriver(entry.openshellDriver));
}

function privilegedSandboxExecArgv(sandboxName: string, cmd: string[], stdin = false): string[] {
  const container = registeredDirectSandboxContainer(sandboxName);
  return ["exec", ...(stdin ? ["-i"] : []), "--user", "root", container, ...cmd];
}

export {
  containerNameMatchesSandbox,
  privilegedSandboxExecArgv,
  resolveDirectSandboxContainer,
  selectDirectSandboxContainer,
};
