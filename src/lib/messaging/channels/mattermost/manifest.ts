// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { ChannelManifest } from "../../manifest";

export const mattermostManifest = {
  schemaVersion: 1,
  id: "mattermost",
  displayName: "Mattermost",
  description: "Mattermost bot messaging",
  supportedAgents: ["openclaw"],
  auth: {
    mode: "token-paste",
  },
  inputs: [
    {
      id: "botToken",
      kind: "secret",
      required: true,
      envKey: "MATTERMOST_BOT_TOKEN",
      prompt: {
        label: "Mattermost Bot Token",
        help: "Mattermost > Integrations > Bot Accounts > Add Bot Account, then copy the bot token.",
      },
    },
    {
      id: "baseUrl",
      kind: "config",
      required: true,
      envKey: "MATTERMOST_URL",
      statePath: "mattermostConfig.baseUrl",
      formatPattern: "^https?://[^\\s/]+(?:/.*)?$",
      formatHint:
        "Use an HTTP or HTTPS Mattermost base URL in the form https://host.example.com or http://host:port.",
      prompt: {
        label: "Mattermost Base URL",
        help: "Enter the Mattermost server URL in the form https://host.example.com or http://host:port. Do not include /api/v4.",
        placeholder: "https://chat.example.com",
      },
    },
    {
      id: "allowedUsers",
      kind: "config",
      required: false,
      envKey: "MATTERMOST_ALLOWED_USERS",
      statePath: "allowedIds.mattermost",
      prompt: {
        label: "Mattermost User IDs (comma-separated allowlist)",
        help: "Optional but recommended: copy Mattermost User IDs from each allowed user's profile. User IDs are long alphanumeric IDs, not @usernames.",
        emptyValueMessage:
          "DM access will require agent-side pairing or upstream authorization defaults",
      },
    },
    {
      id: "allowedChannels",
      kind: "config",
      required: false,
      envKey: "MATTERMOST_ALLOWED_CHANNELS",
      statePath: "mattermostConfig.allowedChannels",
      prompt: {
        label: "Mattermost Channel IDs (comma-separated allowlist)",
        help: "Optional: restrict channel messages to specific Mattermost channel IDs. DMs are not affected.",
        emptyValueMessage: "channel @mentions stay unrestricted by channel ID",
      },
    },
    {
      id: "requireMention",
      kind: "config",
      required: false,
      envKey: "MATTERMOST_REQUIRE_MENTION",
      statePath: "mattermostConfig.requireMention",
      validValues: ["0", "1"],
      defaultValue: "1",
      prompt: {
        label: "Mattermost mention mode",
        help: "Controls channel behavior only - reply only when @mentioned vs. to all channel messages. Direct messages still require authorization.",
      },
    },
  ],
  credentials: [
    {
      id: "mattermostBotToken",
      sourceInput: "botToken",
      providerName: "{sandboxName}-mattermost-bridge",
      providerEnvKey: "MATTERMOST_BOT_TOKEN",
      placeholder: "openshell:resolve:env:MATTERMOST_BOT_TOKEN",
    },
  ],
  policyPresets: [],
  policyTemplates: [
    {
      name: "mattermost",
      templateFile: "mattermost.yaml",
      sourceInput: "baseUrl",
      sourceType: "http-url",
      binariesByAgent: {
        openclaw: ["/usr/local/bin/node", "/usr/bin/node"],
      },
    },
  ],
  render: [
    {
      id: "mattermost-openclaw-channel",
      kind: "json-fragment",
      agent: "openclaw",
      target: "openclaw.json",
      fragment: {
        path: "channels.mattermost",
        value: {
          enabled: true,
          botToken: "{{credential.mattermostBotToken.placeholder}}",
          baseUrl: "{{mattermostConfig.baseUrl}}",
          dmPolicy: "{{allowedIds.mattermost.dmPolicy}}",
          allowFrom: "{{allowedIds.mattermost.values}}",
          groupPolicy: "{{mattermostConfig.openclawGroupPolicy}}",
          groupAllowFrom: "{{allowedIds.mattermost.values}}",
          chatmode: "{{mattermostConfig.openclawChatmode}}",
          groups: "{{mattermostConfig.openclawGroups}}",
        },
      },
    },
    {
      id: "mattermost-openclaw-plugin",
      kind: "json-fragment",
      agent: "openclaw",
      target: "openclaw.json",
      fragment: {
        path: "plugins.entries.mattermost",
        value: {
          enabled: true,
        },
      },
    },
  ],
  runtime: {
    openclaw: {
      channelName: "mattermost",
      visibility: {
        configKeys: ["mattermost"],
        logPatterns: ["mattermost"],
      },
      nodePreloads: [
        {
          module: "mattermost-trusted-env-proxy",
          injectInto: ["boot", "connect"],
          optional: false,
          installMessage:
            "[channels] Installing Mattermost trusted env-proxy guard (SSRF-preserving DNS delegation)",
          installedMessage:
            "[channels] Mattermost trusted env-proxy guard installed (NODE_OPTIONS updated)",
        },
      ],
    },
  },
  agentPackages: [],
  state: {
    persist: {
      mattermostConfig: ["baseUrl", "allowedChannels", "requireMention"],
      allowedIds: ["allowedUsers"],
    },
    rebuildHydration: [
      {
        statePath: "mattermostConfig.baseUrl",
        env: "MATTERMOST_URL",
      },
      {
        statePath: "allowedIds.mattermost",
        env: "MATTERMOST_ALLOWED_USERS",
      },
      {
        statePath: "mattermostConfig.allowedChannels",
        env: "MATTERMOST_ALLOWED_CHANNELS",
      },
      {
        statePath: "mattermostConfig.requireMention",
        env: "MATTERMOST_REQUIRE_MENTION",
      },
    ],
  },
  hooks: [
    {
      id: "mattermost-token-paste",
      phase: "enroll",
      handler: "common.tokenPaste",
      outputs: [
        {
          id: "botToken",
          kind: "secret",
          required: true,
        },
      ],
      onFailure: "skip-channel",
    },
    {
      id: "mattermost-config-prompt",
      phase: "enroll",
      handler: "common.configPrompt",
      outputs: [
        {
          id: "baseUrl",
          kind: "config",
        },
        {
          id: "allowedUsers",
          kind: "config",
        },
        {
          id: "allowedChannels",
          kind: "config",
        },
        {
          id: "requireMention",
          kind: "config",
        },
      ],
    },
    {
      id: "mattermost-reachability",
      phase: "reachability-check",
      handler: "mattermost.reachability",
      inputs: ["botToken", "baseUrl"],
      onFailure: "skip-channel",
    },
  ],
} as const satisfies ChannelManifest;
