// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { AgentDefinition } from "../../agent/defs";
import type { McpBridgeEntry } from "../../state/registry";
import {
  buildDeepAgentsMcpStatusCommand,
  buildHermesMcpStatusCommand,
  buildOpenClawMcporterInspectCommand,
} from "./mcp-bridge-adapters";
import type { McpBridgeStatus } from "./mcp-bridge-contracts";
import { redactBridgeSecretsForDisplay } from "./mcp-bridge-output";
import { getPolicyPresence, getRegisteredGeneratedPolicy } from "./mcp-bridge-policy";
import {
  inspectMcpProvider,
  providerAttached,
  providerMatchesCredential,
  providerShapeDetail,
} from "./mcp-bridge-provider";
import {
  bridgeState,
  ensureSandboxGatewaySelected,
  getEntryAdapter,
  getSandboxAgent,
  getSandboxOrThrow,
} from "./mcp-bridge-state";
import { resolveCredentialEnv, validateSandboxName } from "./mcp-bridge-validation";
import { executeSandboxCommand } from "./process-recovery";

export interface McpBridgeJsonSummary {
  sandbox: string;
  agent: string;
  support: McpBridgeStatus["support"];
  bridges: McpBridgeStatus[];
}

function getAdapterRegistration(
  sandboxName: string,
  agent: AgentDefinition,
  entry: McpBridgeEntry | undefined,
): McpBridgeStatus["adapter"] {
  if (!entry) return { registered: null };
  const adapter = getEntryAdapter(entry, agent);
  if (!adapter) return { registered: null, detail: "MCP adapter is not declared" };
  const command =
    adapter === "mcporter"
      ? buildOpenClawMcporterInspectCommand(entry, false)
      : adapter === "hermes-config"
        ? buildHermesMcpStatusCommand(entry)
        : buildDeepAgentsMcpStatusCommand(entry);
  const result = executeSandboxCommand(sandboxName, command);
  if (!result) return { registered: null, detail: "sandbox unreachable" };
  if (result.status === 0) {
    const output = result.stdout.trim();
    if (output === "registered") return { registered: true };
    return { registered: false, detail: output || "not found" };
  }
  const envValues = resolveCredentialEnv(entry.env.map((envName) => ({ name: envName })));
  return {
    registered: false,
    detail: redactBridgeSecretsForDisplay(
      result.stderr || result.stdout || "not found",
      entry,
      envValues,
    ),
  };
}

export async function statusMcpBridge(
  sandboxName: string,
  server?: string,
): Promise<McpBridgeStatus[]> {
  validateSandboxName(sandboxName);
  const sandbox = getSandboxOrThrow(sandboxName);
  const agent = getSandboxAgent(sandbox);
  const bridges = bridgeState(sandbox);
  if (Object.keys(bridges).length > 0) {
    await ensureSandboxGatewaySelected(sandboxName);
  }
  const entries: Array<[string, McpBridgeEntry | undefined]> = server
    ? [[server, bridges[server]]]
    : Object.entries(bridges);
  if (server && !bridges[server]) {
    return [
      {
        server,
        agent: agent.name,
        support: {
          supported: agent.mcpCapability.support === "bridge",
          mode: agent.mcpCapability.support,
          ...(agent.mcpCapability.adapter ? { adapter: agent.mcpCapability.adapter } : {}),
          ...(agent.mcpCapability.reason ? { reason: agent.mcpCapability.reason } : {}),
        },
        env: { names: [], missing: [], ready: false },
        provider: {
          registryPresent: false,
          gatewayPresent: false,
          attached: null,
          credentialReady: null,
        },
        policy: { registryPresent: false, gatewayPresent: false },
        adapter: { registered: null },
      },
    ];
  }

  return entries.map(([name, entry]) => {
    const registeredPolicy = getRegisteredGeneratedPolicy(sandboxName, entry);
    const hasCredentialBinding =
      !!entry &&
      Array.isArray(entry.env) &&
      entry.env.length === 1 &&
      !!entry.providerName &&
      !!entry.providerId;
    const missingEnv = entry
      ? entry.env.filter(
          (envName: string) => process.env[envName] === undefined || process.env[envName] === "",
        )
      : [];
    const expectedCredential = entry?.env.length === 1 ? entry.env[0] : undefined;
    const providerInspection = inspectMcpProvider(entry?.providerName);
    const providerCredentialReady = providerMatchesCredential(
      providerInspection,
      expectedCredential,
      entry?.providerId,
    );
    const providerDetail = providerShapeDetail(
      providerInspection,
      expectedCredential,
      entry?.providerId,
    );
    return {
      server: name,
      agent: entry?.agent ?? agent.name,
      support: {
        supported: agent.mcpCapability.support === "bridge",
        mode: agent.mcpCapability.support,
        ...(getEntryAdapter(entry, agent)
          ? { adapter: getEntryAdapter(entry, agent) ?? undefined }
          : {}),
        ...(agent.mcpCapability.reason ? { reason: agent.mcpCapability.reason } : {}),
      },
      ...(entry ? { url: entry.url } : {}),
      ...(entry?.addState ? { addState: entry.addState } : {}),
      env: {
        names: entry?.env ?? [],
        missing: missingEnv,
        ready:
          hasCredentialBinding &&
          !entry?.addState &&
          (providerInspection.exists ? providerCredentialReady : missingEnv.length === 0),
      },
      provider: {
        name: entry?.providerName,
        registryPresent: !!entry?.providerName,
        gatewayPresent: entry?.providerName ? providerInspection.exists : null,
        attached: providerAttached(sandboxName, entry?.providerName),
        credentialReady: entry ? providerCredentialReady : null,
        ...(providerDetail ? { detail: providerDetail } : {}),
      },
      policy: {
        name: entry?.policyName,
        registryPresent: !!registeredPolicy,
        gatewayPresent: getPolicyPresence(sandboxName, entry),
      },
      adapter: getAdapterRegistration(sandboxName, agent, entry),
      ...(entry?.addedAt ? { addedAt: entry.addedAt } : {}),
      ...(entry?.updatedAt ? { updatedAt: entry.updatedAt } : {}),
    };
  });
}

function getSupportSummary(agent: AgentDefinition): McpBridgeStatus["support"] {
  return {
    supported: agent.mcpCapability.support === "bridge",
    mode: agent.mcpCapability.support,
    ...(agent.mcpCapability.adapter ? { adapter: agent.mcpCapability.adapter } : {}),
    ...(agent.mcpCapability.reason ? { reason: agent.mcpCapability.reason } : {}),
  };
}

export function buildJsonSummary(
  sandboxName: string,
  agent: AgentDefinition,
  statuses: McpBridgeStatus[],
): McpBridgeJsonSummary {
  return {
    sandbox: sandboxName,
    agent: agent.name,
    support: getSupportSummary(agent),
    bridges: statuses,
  };
}
