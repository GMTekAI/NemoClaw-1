// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import http from "node:http";
import { describe, expect, it } from "vitest";

import {
  createMcpProxyServer,
  isAuthorizedHeader,
  MCP_PROXY_BIND_HOST,
  MCP_PROXY_MAX_BODY_BYTES,
  parseProxyArgs,
  redactSecretsFromText,
} from "./mcp-proxy";

describe("mcp-proxy", () => {
  it("parses command, args, env names, port, and token env", () => {
    expect(
      parseProxyArgs([
        "--command",
        "node",
        "--arg",
        "server.js",
        "--env",
        "GITHUB_TOKEN",
        "--port",
        "3102",
        "--token-env",
        "TOKEN",
      ]),
    ).toEqual({
      command: "node",
      args: ["server.js"],
      env: ["GITHUB_TOKEN"],
      port: 3102,
      tokenEnv: "TOKEN",
    });
  });

  it("binds loopback only and caps request bodies", () => {
    expect(MCP_PROXY_BIND_HOST).toBe("127.0.0.1");
    expect(MCP_PROXY_MAX_BODY_BYTES).toBe(1024 * 1024);
  });

  it("requires an exact bearer auth header", () => {
    expect(isAuthorizedHeader("Bearer bridge-token", "bridge-token")).toBe(true);
    expect(isAuthorizedHeader("Bearer wrong", "bridge-token")).toBe(false);
    expect(isAuthorizedHeader(undefined, "bridge-token")).toBe(false);
    expect(isAuthorizedHeader("Bearer bridge-token", null)).toBe(false);
  });

  it("redacts known env secret values and bridge token from logs", () => {
    expect(
      redactSecretsFromText("token=abc123 bridge=local-token visible", ["abc123", "local-token"]),
    ).toBe("token=***REDACTED*** bridge=***REDACTED*** visible");
  });

  it("forwards authorized JSON-RPC POSTs to a stdio MCP child", async () => {
    const prior = process.env.MCP_PROXY_TEST_SECRET;
    process.env.MCP_PROXY_TEST_SECRET = "host-secret";
    const childScript = `
let buffer = "";
process.stdin.on("data", (chunk) => {
  buffer += chunk.toString("utf8");
  const lines = buffer.split("\\n");
  buffer = lines.pop() || "";
  for (const line of lines) {
    if (!line.trim()) continue;
    const request = JSON.parse(line);
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: request.id,
      result: {
        tools: [{ name: "fake-tool" }],
        sawHostSecret: process.env.MCP_PROXY_TEST_SECRET === "host-secret",
      },
    }) + "\\n");
  }
});
`;
    const server = createMcpProxyServer(
      {
        command: process.execPath,
        args: ["-e", childScript],
        env: ["MCP_PROXY_TEST_SECRET"],
        port: 0,
        tokenEnv: null,
      },
      "bridge-token",
    );
    await new Promise<void>((resolve) => server.listen(0, MCP_PROXY_BIND_HOST, resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    try {
      const response = await new Promise<{ status: number | undefined; body: string }>(
        (resolve, reject) => {
          const req = http.request(
            {
              host: MCP_PROXY_BIND_HOST,
              port,
              method: "POST",
              path: "/",
              headers: {
                Authorization: "Bearer bridge-token",
                "Content-Type": "application/json",
              },
            },
            (res) => {
              let body = "";
              res.on("data", (chunk) => {
                body += chunk.toString("utf8");
              });
              res.on("end", () => resolve({ status: res.statusCode, body }));
            },
          );
          req.on("error", reject);
          req.end(JSON.stringify({ jsonrpc: "2.0", id: "client-1", method: "tools/list" }));
        },
      );
      const payload = JSON.parse(response.body);

      expect(response.status).toBe(200);
      expect(payload).toEqual({
        jsonrpc: "2.0",
        id: "client-1",
        result: {
          tools: [{ name: "fake-tool" }],
          sawHostSecret: true,
        },
      });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (prior === undefined) delete process.env.MCP_PROXY_TEST_SECRET;
      else process.env.MCP_PROXY_TEST_SECRET = prior;
    }
  });

  it("does not emit CORS headers on HTTP responses", async () => {
    const server = createMcpProxyServer(
      {
        command: process.execPath,
        args: ["-e", "setInterval(() => {}, 1000)"],
        env: [],
        port: 0,
        tokenEnv: null,
      },
      "bridge-token",
    );
    await new Promise<void>((resolve) => server.listen(0, MCP_PROXY_BIND_HOST, resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    try {
      const response = await new Promise<http.IncomingMessage>((resolve, reject) => {
        const req = http.request(
          {
            host: MCP_PROXY_BIND_HOST,
            port,
            method: "GET",
            path: "/",
            headers: { Authorization: "Bearer bridge-token" },
          },
          resolve,
        );
        req.on("error", reject);
        req.end();
      });
      response.resume();
      expect(response.statusCode).toBe(405);
      expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
