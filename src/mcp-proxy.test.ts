// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

import {
  createMcpProxyServer,
  isAuthorizedHeader,
  MCP_PROXY_BIND_HOST,
  MCP_PROXY_MAX_BODY_BYTES,
  parseProxyArgs,
  readBearerToken,
  redactSecretsFromText,
  resolveExecutable,
} from "./mcp-proxy";

describe("mcp-proxy", () => {
  it("parses command, args, env names, port, and token file", () => {
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
        "--token-file",
        "/tmp/token",
      ]),
    ).toEqual({
      command: "node",
      args: ["server.js"],
      env: ["GITHUB_TOKEN"],
      port: 3102,
      tokenEnv: null,
      tokenFile: "/tmp/token",
    });
  });

  it("reads bearer tokens from a one-shot mode-600 token file", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-proxy-token-"));
    const tokenFile = path.join(dir, "proxy.token");
    fs.writeFileSync(tokenFile, "bridge-token\n", { mode: 0o600 });

    expect(readBearerToken({ tokenEnv: null, tokenFile })).toBe("bridge-token");
    expect(fs.existsSync(tokenFile)).toBe(false);
  });

  it("validates the child command before launch", () => {
    expect(resolveExecutable(process.execPath)).toBe(path.resolve(process.execPath));
    expect(() => resolveExecutable("definitely-not-a-real-mcp-command", "")).toThrow(
      /not found on PATH/,
    );
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
  for (const line of lines.filter((value) => value.trim())) {
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
        tokenFile: null,
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
      prior === undefined
        ? delete process.env.MCP_PROXY_TEST_SECRET
        : (process.env.MCP_PROXY_TEST_SECRET = prior);
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
        tokenFile: null,
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

  it("does not expose child error details in JSON-RPC failures", async () => {
    const server = createMcpProxyServer(
      {
        command: process.execPath,
        args: ["-e", "process.exit(1)"],
        env: [],
        port: 0,
        tokenEnv: null,
        tokenFile: null,
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
          req.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }));
        },
      );
      const payload = JSON.parse(response.body);

      expect(response.status).toBe(500);
      expect(payload.error.message).toBe("Internal MCP proxy error");
      expect(response.body).not.toContain("child exited");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
