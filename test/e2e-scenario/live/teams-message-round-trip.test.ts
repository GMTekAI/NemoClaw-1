// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/** Credential-gated skeleton for Microsoft Teams tenant round-trip proof. */

import { fileURLToPath } from "node:url";

import { expect, test } from "../fixtures/e2e-test.ts";
import { shouldRunLiveE2EScenarios } from "../fixtures/live-project-gate.ts";

const REQUIRED_ENV_KEYS = [
  "NVIDIA_INFERENCE_API_KEY",
  "MSTEAMS_APP_ID",
  "MSTEAMS_APP_PASSWORD",
  "MSTEAMS_TENANT_ID",
  "MSTEAMS_ALLOWED_USERS",
  "MSTEAMS_PUBLIC_WEBHOOK_URL",
  "MSTEAMS_E2E_ACTIVITY_JSON",
] as const;

const TEAMS_ROUND_TRIP_DRIVER = fileURLToPath(
  new URL("./teams-message-round-trip-driver.mjs", import.meta.url),
);

function missingTeamsEnv(): string[] {
  return REQUIRED_ENV_KEYS.filter((key) => !process.env[key]?.trim());
}

function buildTeamsDriverEnv(): NodeJS.ProcessEnv {
  return Object.fromEntries(
    REQUIRED_ENV_KEYS.map((key) => [key, process.env[key] as string]),
  ) as NodeJS.ProcessEnv;
}

const missingTeamsEnvKeys = missingTeamsEnv();
const runTeamsE2E = test.skipIf(
  !shouldRunLiveE2EScenarios() || process.env.MSTEAMS_E2E !== "1" || missingTeamsEnvKeys.length > 0,
);

runTeamsE2E(
  "Microsoft Teams onboarding webhook and message round-trip proof",
  { timeout: 60 * 60_000 },
  async ({ artifacts, host, secrets }) => {
    const webhookUrl = process.env.MSTEAMS_PUBLIC_WEBHOOK_URL as string;
    expect(webhookUrl, "MSTEAMS_PUBLIC_WEBHOOK_URL must be a public HTTPS URL").toMatch(
      /^https:\/\//i,
    );

    const driverEnv = buildTeamsDriverEnv();
    const redactions = REQUIRED_ENV_KEYS.map((key) => driverEnv[key] ?? "").filter(Boolean);
    await artifacts.writeJson("scenario.json", {
      id: "teams-message-round-trip",
      boundary:
        "real Microsoft tenant, Bot Framework credentials, tenant-captured Bot Framework activity, public HTTPS webhook, sandbox /api/messages receive path",
      requiredEnv: REQUIRED_ENV_KEYS,
      webhookHost: new URL(webhookUrl).host,
      driver: "teams-message-round-trip-driver.mjs",
    });

    const result = await host.command(process.execPath, [TEAMS_ROUND_TRIP_DRIVER], {
      artifactName: "teams-message-round-trip-driver",
      env: driverEnv,
      redactionValues: redactions,
      timeoutMs: 20 * 60_000,
    });

    expect(result.exitCode, secrets.redact(`${result.stdout}\n${result.stderr}`, redactions)).toBe(
      0,
    );
  },
);
