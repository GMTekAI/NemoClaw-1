// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { redact } from "../../security/redact";
import type { McpBridgeEntry } from "../../state/registry";

export type OpenShellCommandResult = {
  status: number | null;
  stdout?: string | Buffer | null;
  stderr?: string | Buffer | null;
};

export function redactBridgeSecretsForDisplay(
  text: string,
  entry?: Pick<McpBridgeEntry, "env">,
  envValues: Record<string, string> = {},
): string {
  let output = redact(text || "");
  for (const envName of entry?.env ?? []) {
    const value = envValues[envName] ?? process.env[envName];
    if (value) output = output.replaceAll(value, "***REDACTED***");
  }
  for (const value of Object.values(envValues)) {
    if (value) output = output.replaceAll(value, "***REDACTED***");
  }
  return output
    .replace(/\b(authorization\b["']?\s*[:=]\s*["']?Bearer\s+)([^"',\s}\]]+)/gi, "$1***REDACTED***")
    .replace(/Authorization=Bearer\s+\S+/g, "Authorization=Bearer ***REDACTED***");
}

export function redactCredentialValuesForDisplay(
  value: string,
  envValues: Record<string, string>,
): string {
  let redacted = redact(value);
  for (const secret of Object.values(envValues)) {
    if (!secret) continue;
    redacted = redacted.split(secret).join("***REDACTED***");
  }
  return redacted;
}

export function commandOutput(
  result: OpenShellCommandResult,
  envValues: Record<string, string> = {},
): string {
  const stdout =
    typeof result.stdout === "string" ? result.stdout : (result.stdout?.toString() ?? "");
  const stderr =
    typeof result.stderr === "string" ? result.stderr : (result.stderr?.toString() ?? "");
  return redactCredentialValuesForDisplay(`${stderr}${stdout}`, envValues)
    .replace(/\r/g, "")
    .trim();
}
