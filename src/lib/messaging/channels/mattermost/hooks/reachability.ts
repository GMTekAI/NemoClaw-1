// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { MessagingHookHandler, MessagingHookRegistration } from "../../../hooks/types";

export const MATTERMOST_REACHABILITY_HOOK_HANDLER_ID = "mattermost.reachability";
export const MATTERMOST_AUTH_VALIDATION_SKIP_ENV = "NEMOCLAW_SKIP_MATTERMOST_AUTH_VALIDATION";

const DEFAULT_MATTERMOST_REACHABILITY_TIMEOUT_MS = 10_000;

interface MattermostFetchResponse {
  readonly ok: boolean;
  readonly status: number;
  readonly statusText?: string;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

interface MattermostFetchOptions {
  readonly headers?: Record<string, string>;
  readonly signal?: AbortSignal;
}

type MattermostFetch = (
  url: string,
  options?: MattermostFetchOptions,
) => Promise<MattermostFetchResponse>;

export interface MattermostReachabilityHookOptions {
  readonly env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
  readonly fetch?: MattermostFetch;
  readonly timeoutMs?: number;
  readonly log?: (message: string) => void;
}

export function createMattermostReachabilityHook(
  options: MattermostReachabilityHookOptions = {},
): MessagingHookHandler {
  return async (context) => {
    const env = options.env ?? process.env;
    if (isTruthyEnvFlag(env[MATTERMOST_AUTH_VALIDATION_SKIP_ENV])) {
      return {};
    }

    const token = normalizeInput(context.inputs?.botToken);
    const rawBaseUrl = normalizeInput(context.inputs?.baseUrl);
    if (!token) {
      throw new Error("Mattermost reachability check requires botToken.");
    }
    if (!rawBaseUrl) {
      throw new Error("Mattermost reachability check requires baseUrl.");
    }
    const baseUrl = normalizeMattermostBaseUrl(rawBaseUrl);

    const log = options.log ?? console.log;
    const response = await fetchMattermostMe({ baseUrl, token }, options).catch((error) => {
      const message = formatFetchError(error);
      logMattermostDisabled(`Mattermost API was unreachable: ${message}`, log);
      throw new Error("Mattermost API was unreachable.");
    });

    if (!response.ok) {
      if (isRejectedTokenResponse(response)) {
        log("  ⚠ Mattermost token was rejected — verify the token and bot account status.");
        logMattermostDisabled("the token was rejected by Mattermost", log);
        throw new Error("Mattermost token was rejected.");
      }

      const detail = await readResponseText(response);
      logMattermostDisabled(
        `Mattermost API returned HTTP ${response.status}${
          response.statusText ? ` ${response.statusText}` : ""
        }${detail ? `: ${detail}` : ""}`,
        log,
      );
      throw new Error("Mattermost API did not accept the configured URL and token.");
    }

    const payload = await readResponseJson(response);
    if (!isObject(payload) || typeof payload.id !== "string" || payload.id.trim() === "") {
      logMattermostDisabled("Mattermost API returned an unexpected /users/me response", log);
      throw new Error("Mattermost API returned an unexpected /users/me response.");
    }

    return {};
  };
}

export function createMattermostHookRegistrations(
  options: MattermostReachabilityHookOptions = {},
): readonly MessagingHookRegistration[] {
  return [
    {
      id: MATTERMOST_REACHABILITY_HOOK_HANDLER_ID,
      handler: createMattermostReachabilityHook(options),
    },
  ] as const;
}

async function fetchMattermostMe(
  params: { readonly baseUrl: string; readonly token: string },
  options: MattermostReachabilityHookOptions,
): Promise<MattermostFetchResponse> {
  const fetchImpl = options.fetch ?? defaultFetch;
  const timeoutMs = normalizeTimeoutMs(options.timeoutMs);
  return fetchWithTimeout(fetchImpl, `${params.baseUrl}/api/v4/users/me`, params.token, timeoutMs);
}

async function defaultFetch(
  url: string,
  options?: MattermostFetchOptions,
): Promise<MattermostFetchResponse> {
  if (typeof fetch !== "function") {
    throw new Error("Mattermost reachability check requires global fetch.");
  }
  return fetch(url, options as RequestInit) as Promise<MattermostFetchResponse>;
}

function normalizeTimeoutMs(timeoutMs: number | undefined): number {
  return typeof timeoutMs === "number" && Number.isFinite(timeoutMs) && timeoutMs > 0
    ? timeoutMs
    : DEFAULT_MATTERMOST_REACHABILITY_TIMEOUT_MS;
}

async function fetchWithTimeout(
  fetchImpl: MattermostFetch,
  url: string,
  token: string,
  timeoutMs: number,
): Promise<MattermostFetchResponse> {
  const controller = typeof AbortController === "function" ? new AbortController() : null;
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => {
      controller?.abort();
      reject(new Error("Mattermost reachability check timed out."));
    }, timeoutMs);
    timeout.unref?.();
  });

  try {
    return await Promise.race([
      fetchImpl(url, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
        ...(controller ? { signal: controller.signal } : {}),
      }),
      timeoutPromise,
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function normalizeMattermostBaseUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(
      "Mattermost reachability check requires an absolute http:// or https:// baseUrl.",
    );
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Mattermost reachability check baseUrl must use http:// or https://.");
  }
  if (url.username || url.password) {
    throw new Error("Mattermost reachability check baseUrl must not include credentials.");
  }
  if (url.search || url.hash) {
    throw new Error(
      "Mattermost reachability check baseUrl must not include query strings or fragments.",
    );
  }
  const basePath = url.pathname.replace(/\/+$/g, "").replace(/\/api\/v4$/i, "");
  return `${url.origin}${basePath}`;
}

function normalizeInput(value: unknown): string {
  return typeof value === "string" ? value.replace(/\r/g, "").trim() : "";
}

function isTruthyEnvFlag(value: string | undefined): boolean {
  return value === "1" || value === "true" || value === "yes" || value === "on";
}

function isRejectedTokenResponse(response: MattermostFetchResponse): boolean {
  return response.status === 401 || response.status === 403;
}

async function readResponseJson(response: MattermostFetchResponse): Promise<unknown> {
  try {
    return await response.json();
  } catch (_error) {
    return {};
  }
}

async function readResponseText(response: MattermostFetchResponse): Promise<string> {
  try {
    return (await response.text()).replace(/\s+/g, " ").trim().slice(0, 240);
  } catch (_error) {
    return "";
  }
}

function formatFetchError(error: unknown): string {
  return error instanceof Error && error.message ? error.message : String(error);
}

function logMattermostDisabled(reason: string, log: (message: string) => void): void {
  log(`  Mattermost integration will be disabled for this enrollment run because ${reason}.`);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
