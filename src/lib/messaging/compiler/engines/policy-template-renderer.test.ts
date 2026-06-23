// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import YAML from "yaml";

import type { SandboxMessagingInputReference } from "../../manifest";
import { renderPolicyTemplate, renderTemplateUrlContext } from "./policy-template-renderer";

function input(value: string): SandboxMessagingInputReference {
  return {
    channelId: "mattermost",
    inputId: "baseUrl",
    kind: "config",
    required: true,
    sourceEnv: "MATTERMOST_URL",
    statePath: "mattermostConfig.baseUrl",
    value,
  };
}

describe("policy template renderer", () => {
  it("normalizes HTTP and HTTPS URL sources for self-hosted policy templates", () => {
    expect(renderTemplateUrlContext("https://chat.example.com/api/v4/", "https-url")).toEqual({
      host: "chat.example.com",
      port: 443,
      basePath: "",
    });
    expect(renderTemplateUrlContext("http://chat.example.com/team/api/v4", "http-url")).toEqual({
      host: "chat.example.com",
      port: 80,
      basePath: "/team",
    });
    expect(renderTemplateUrlContext("http://192.0.2.10:8065/api/v4", "http-url")).toEqual({
      host: "192.0.2.10",
      port: 8065,
      basePath: "",
    });
  });

  it("rejects unsafe or unsupported URL sources", () => {
    expect(() => renderTemplateUrlContext("http://chat.example.com", "https-url")).toThrow(/https/);
    expect(() => renderTemplateUrlContext("ftp://chat.example.com", "http-url")).toThrow(
      /http:\/\/ or https:\/\//,
    );
    expect(() =>
      renderTemplateUrlContext("https://user:pass@chat.example.com", "http-url"),
    ).toThrow(/credentials/);
    expect(() => renderTemplateUrlContext("https://*.example.com", "http-url")).toThrow(
      /exact DNS name/,
    );
    expect(() => renderTemplateUrlContext("https://chat.example.com?x=1", "http-url")).toThrow(
      /query strings/,
    );
  });

  it("renders Mattermost template content for OpenClaw", () => {
    const rendered = renderPolicyTemplate(
      "mattermost",
      {
        name: "mattermost",
        templateFile: "mattermost.yaml",
        sourceInput: "baseUrl",
        sourceType: "http-url",
      },
      "openclaw",
      [input("http://chat.example.com:8065/team/api/v4")],
    );

    expect(rendered?.presetName).toBe("mattermost");
    expect(rendered?.policyKeys).toEqual(["mattermost"]);
    const parsed = YAML.parse(rendered?.content ?? "");
    const policy = parsed.network_policies.mattermost;
    expect(policy.endpoints).toEqual([
      expect.objectContaining({
        host: "chat.example.com",
        port: 8065,
        protocol: "rest",
        enforcement: "enforce",
        request_body_credential_rewrite: true,
        websocket_credential_rewrite: true,
        rules: [
          { allow: { method: "GET", path: "/team/api/v4/websocket" } },
          { allow: { method: "WEBSOCKET_TEXT", path: "/team/api/v4/websocket" } },
          { allow: { method: "GET", path: "/team/api/v4/**" } },
          { allow: { method: "POST", path: "/team/api/v4/**" } },
          { allow: { method: "PUT", path: "/team/api/v4/**" } },
          { allow: { method: "PATCH", path: "/team/api/v4/**" } },
          { allow: { method: "DELETE", path: "/team/api/v4/**" } },
        ],
      }),
    ]);
    expect(policy.endpoints[0]).not.toHaveProperty("allowed_ips");
    expect(policy.endpoints[0]).not.toHaveProperty("access");
    expect(policy.endpoints[0]).not.toHaveProperty("tls");
    expect(policy.binaries).toEqual([{ path: "/usr/local/bin/node" }, { path: "/usr/bin/node" }]);
    expect(parsed.preset.template).toBeUndefined();
  });
});
