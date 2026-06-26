// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/** Credential-gated skeleton for Microsoft Teams tenant round-trip proof. */

import { expect, test } from "../fixtures/e2e-test.ts";
import { shouldRunLiveE2EScenarios } from "../fixtures/live-project-gate.ts";

const REQUIRED_ENV_KEYS = [
  "NVIDIA_INFERENCE_API_KEY",
  "MSTEAMS_APP_ID",
  "MSTEAMS_APP_PASSWORD",
  "MSTEAMS_TENANT_ID",
  "MSTEAMS_ALLOWED_USERS",
  "MSTEAMS_PUBLIC_WEBHOOK_URL",
  "MSTEAMS_E2E_MESSAGE_COMMAND",
] as const;

const runTeamsE2E =
  shouldRunLiveE2EScenarios() && process.env.MSTEAMS_E2E === "1" ? test : test.skip;

function missingTeamsEnv(): string[] {
  return REQUIRED_ENV_KEYS.filter((key) => !process.env[key]?.trim());
}

runTeamsE2E(
  "Microsoft Teams onboarding webhook and message round-trip proof",
  { timeout: 60 * 60_000 },
  async ({ artifacts, host, secrets, skip }) => {
    const missing = missingTeamsEnv();
    if (missing.length > 0) {
      skip(`Teams live E2E requires ${missing.join(", ")}`);
      return;
    }

    const webhookUrl = process.env.MSTEAMS_PUBLIC_WEBHOOK_URL as string;
    if (!/^https:\/\//i.test(webhookUrl)) {
      throw new Error("MSTEAMS_PUBLIC_WEBHOOK_URL must be a public HTTPS URL");
    }

    const redactions = REQUIRED_ENV_KEYS.map((key) => process.env[key] ?? "").filter(Boolean);
    const command = process.env.MSTEAMS_E2E_MESSAGE_COMMAND as string;
    await artifacts.writeJson("scenario.json", {
      id: "teams-message-round-trip",
      boundary:
        "real Microsoft tenant, Bot Framework credentials, public HTTPS webhook, Teams message send, sandbox /api/messages receive path",
      requiredEnv: REQUIRED_ENV_KEYS,
      webhookHost: new URL(webhookUrl).host,
    });

    const result = await host.command("bash", ["-lc", command], {
      artifactName: "teams-message-round-trip-driver",
      env: process.env,
      redactionValues: redactions,
      timeoutMs: 20 * 60_000,
    });

    expect(result.exitCode, secrets.redact(`${result.stdout}\n${result.stderr}`, redactions)).toBe(
      0,
    );
  },
);
