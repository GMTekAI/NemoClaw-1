// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { MessagingHookRegistry, runMessagingHook } from "../../../hooks";
import type { ChannelHookSpec } from "../../../manifest";
import {
  createMattermostReachabilityHook,
  MATTERMOST_AUTH_VALIDATION_SKIP_ENV,
  MATTERMOST_REACHABILITY_HOOK_HANDLER_ID,
} from "./reachability";

const MATTERMOST_REACHABILITY_HOOK = {
  id: "mattermost-reachability",
  phase: "reachability-check",
  handler: MATTERMOST_REACHABILITY_HOOK_HANDLER_ID,
  inputs: ["botToken", "baseUrl"],
  onFailure: "skip-channel",
} as const satisfies ChannelHookSpec;

describe("Mattermost reachability hook implementation", () => {
  it("calls Mattermost /users/me with a bearer token without exposing secrets in outputs", async () => {
    const calls: Array<{ url: string; authorization: string | undefined }> = [];
    const registry = new MessagingHookRegistry([
      {
        id: MATTERMOST_REACHABILITY_HOOK_HANDLER_ID,
        handler: createMattermostReachabilityHook({
          fetch: async (url, options) => {
            calls.push({ url, authorization: options?.headers?.Authorization });
            return {
              ok: true,
              status: 200,
              async json() {
                return { id: "bot-user-id" };
              },
              async text() {
                return "";
              },
            };
          },
        }),
      },
    ]);

    await expect(
      runMessagingHook(MATTERMOST_REACHABILITY_HOOK, registry, {
        channelId: "mattermost",
        inputs: {
          botToken: "mattermost-token",
          baseUrl: "https://chat.example.com/api/v4/",
        },
      }),
    ).resolves.toEqual({
      hookId: "mattermost-reachability",
      handlerId: MATTERMOST_REACHABILITY_HOOK_HANDLER_ID,
      phase: "reachability-check",
      outputs: {},
    });
    expect(calls).toEqual([
      {
        url: "https://chat.example.com/api/v4/users/me",
        authorization: "Bearer mattermost-token",
      },
    ]);
  });

  it("fails so the compiler can skip the channel when Mattermost rejects the token", async () => {
    const logs: string[] = [];
    const registry = new MessagingHookRegistry([
      {
        id: MATTERMOST_REACHABILITY_HOOK_HANDLER_ID,
        handler: createMattermostReachabilityHook({
          log: (message) => logs.push(message),
          fetch: async () => ({
            ok: false,
            status: 401,
            statusText: "Unauthorized",
            async json() {
              return {};
            },
            async text() {
              return "unauthorized";
            },
          }),
        }),
      },
    ]);

    await expect(
      runMessagingHook(MATTERMOST_REACHABILITY_HOOK, registry, {
        channelId: "mattermost",
        inputs: {
          botToken: "bad-token",
          baseUrl: "https://mattermost.com",
        },
      }),
    ).rejects.toThrow("Mattermost token was rejected.");
    expect(logs).toEqual([
      "  ⚠ Mattermost token was rejected — verify the token and bot account status.",
      "  Mattermost integration will be disabled for this enrollment run because the token was rejected by Mattermost.",
    ]);
  });

  it("fails so the compiler can skip the channel when the API is unreachable", async () => {
    const logs: string[] = [];
    const registry = new MessagingHookRegistry([
      {
        id: MATTERMOST_REACHABILITY_HOOK_HANDLER_ID,
        handler: createMattermostReachabilityHook({
          log: (message) => logs.push(message),
          fetch: async () => {
            throw new Error("network unavailable");
          },
        }),
      },
    ]);

    await expect(
      runMessagingHook(MATTERMOST_REACHABILITY_HOOK, registry, {
        channelId: "mattermost",
        inputs: {
          botToken: "mattermost-token",
          baseUrl: "https://mattermost.com",
        },
      }),
    ).rejects.toThrow("Mattermost API was unreachable.");
    expect(logs).toEqual([
      "  Mattermost integration will be disabled for this enrollment run because Mattermost API was unreachable: network unavailable.",
    ]);
  });

  it.each([
    ["relative URL", "chat.example.com", "requires an absolute http:// or https:// baseUrl"],
    ["non-http scheme", "ftp://chat.example.com", "baseUrl must use http:// or https://"],
    [
      "embedded credentials",
      "https://bot:token@chat.example.com",
      "baseUrl must not include credentials",
    ],
    [
      "query string",
      "https://chat.example.com?team=dev",
      "baseUrl must not include query strings or fragments",
    ],
    [
      "fragment",
      "https://chat.example.com#main",
      "baseUrl must not include query strings or fragments",
    ],
  ])("rejects unsafe Mattermost base URLs before fetching: %s", async (_name, baseUrl, error) => {
    const urls: string[] = [];
    const registry = new MessagingHookRegistry([
      {
        id: MATTERMOST_REACHABILITY_HOOK_HANDLER_ID,
        handler: createMattermostReachabilityHook({
          fetch: async (url) => {
            urls.push(url);
            throw new Error("fetch should not run");
          },
        }),
      },
    ]);

    await expect(
      runMessagingHook(MATTERMOST_REACHABILITY_HOOK, registry, {
        channelId: "mattermost",
        inputs: {
          botToken: "mattermost-token",
          baseUrl,
        },
      }),
    ).rejects.toThrow(error);
    expect(urls).toEqual([]);
  });

  it("honors the explicit skip env without calling Mattermost", async () => {
    const urls: string[] = [];
    const registry = new MessagingHookRegistry([
      {
        id: MATTERMOST_REACHABILITY_HOOK_HANDLER_ID,
        handler: createMattermostReachabilityHook({
          env: {
            [MATTERMOST_AUTH_VALIDATION_SKIP_ENV]: "1",
          },
          fetch: async (url) => {
            urls.push(url);
            throw new Error("fetch should not run");
          },
        }),
      },
    ]);

    await expect(
      runMessagingHook(MATTERMOST_REACHABILITY_HOOK, registry, {
        channelId: "mattermost",
        inputs: {
          botToken: "mattermost-token",
          baseUrl: "https://mattermost.com",
        },
      }),
    ).resolves.toMatchObject({
      hookId: "mattermost-reachability",
      outputs: {},
    });
    expect(urls).toEqual([]);
  });
});
