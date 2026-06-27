// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const REQUIRED_ENV_KEYS = [
  "NVIDIA_INFERENCE_API_KEY",
  "MSTEAMS_APP_ID",
  "MSTEAMS_APP_PASSWORD",
  "MSTEAMS_TENANT_ID",
  "MSTEAMS_ALLOWED_USERS",
  "MSTEAMS_PUBLIC_WEBHOOK_URL",
  "MSTEAMS_E2E_ACTIVITY_JSON",
];

function requiredEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}

function parseJson(name, value) {
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`${name} must be valid JSON: ${error instanceof Error ? error.message : error}`);
  }
}

function readPath(value, path) {
  return path.reduce((current, key) => {
    if (!current || typeof current !== "object") return undefined;
    return current[key];
  }, value);
}

function stringAt(value, path) {
  const candidate = readPath(value, path);
  return typeof candidate === "string" && candidate.trim() ? candidate.trim() : null;
}

function collectStrings(value, paths) {
  return paths.map((path) => stringAt(value, path)).filter(Boolean);
}

function ensureIncludes(label, candidates, expected) {
  if (candidates.some((candidate) => candidate === expected || candidate.includes(expected))) {
    return;
  }
  throw new Error(`${label} did not include expected value`);
}

function ensureAnyAllowedUser(activity, allowedUsers) {
  const candidates = collectStrings(activity, [
    ["from", "aadObjectId"],
    ["from", "id"],
    ["channelData", "from", "aadObjectId"],
    ["channelData", "from", "id"],
  ]);
  if (candidates.some((candidate) => allowedUsers.includes(candidate))) return;
  throw new Error("activity sender did not match MSTEAMS_ALLOWED_USERS");
}

async function postActivity(webhookUrl, activity) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60_000);
  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "nemoclaw-teams-e2e-driver",
      },
      body: JSON.stringify(activity),
      signal: controller.signal,
    });
    const body = await response.text();
    if (!response.ok) {
      throw new Error(`webhook returned HTTP ${response.status}: ${body.slice(0, 500)}`);
    }
    return { status: response.status, bodyLength: body.length };
  } finally {
    clearTimeout(timeout);
  }
}

async function main() {
  const env = Object.fromEntries(REQUIRED_ENV_KEYS.map((key) => [key, requiredEnv(key)]));
  const webhookUrl = new URL(env.MSTEAMS_PUBLIC_WEBHOOK_URL);
  if (webhookUrl.protocol !== "https:") {
    throw new Error("MSTEAMS_PUBLIC_WEBHOOK_URL must use https");
  }

  const activity = parseJson("MSTEAMS_E2E_ACTIVITY_JSON", env.MSTEAMS_E2E_ACTIVITY_JSON);
  if (!activity || typeof activity !== "object" || Array.isArray(activity)) {
    throw new Error("MSTEAMS_E2E_ACTIVITY_JSON must be a Bot Framework activity object");
  }
  if (stringAt(activity, ["type"]) !== "message") {
    throw new Error("MSTEAMS_E2E_ACTIVITY_JSON must describe a message activity");
  }

  ensureIncludes(
    "activity tenant",
    collectStrings(activity, [
      ["tenant", "id"],
      ["channelData", "tenant", "id"],
    ]),
    env.MSTEAMS_TENANT_ID,
  );
  ensureIncludes(
    "activity recipient",
    collectStrings(activity, [
      ["recipient", "id"],
      ["recipient", "aadObjectId"],
      ["channelData", "recipient", "id"],
    ]),
    env.MSTEAMS_APP_ID,
  );
  ensureAnyAllowedUser(
    activity,
    env.MSTEAMS_ALLOWED_USERS.split(",")
      .map((value) => value.trim())
      .filter(Boolean),
  );

  const result = await postActivity(webhookUrl, activity);
  console.log(
    JSON.stringify({
      ok: true,
      webhookHost: webhookUrl.host,
      status: result.status,
      responseBodyLength: result.bodyLength,
    }),
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
