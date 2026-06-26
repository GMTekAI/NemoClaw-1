// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import http from "node:http";
import type { AddressInfo } from "node:net";

export interface StartedHttpServer {
  port: number;
  close(): Promise<void>;
}

export interface FakeMcpHttpServer extends StartedHttpServer {
  requests: Array<{ auth: string; body: string }>;
}

function jsonResponse(res: http.ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

async function readRequestBody(req: http.IncomingMessage): Promise<string> {
  return await new Promise((resolve) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => {
      body += chunk;
    });
    req.on("end", () => resolve(body));
  });
}

function requireTcpPort(server: http.Server, label: string): number {
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error(`${label} did not bind to a TCP port`);
  }
  return (address as AddressInfo).port;
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function listenOnRandomPort(server: http.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "0.0.0.0", () => {
      server.off("error", reject);
      resolve();
    });
  });
}

export async function startCompatibleMock(options: {
  apiKey: string;
  model: string;
}): Promise<StartedHttpServer> {
  const server = http.createServer(async (req, res) => {
    const requestPath = new URL(req.url ?? "/", "http://compatible.mock").pathname;
    const auth = req.headers.authorization === `Bearer ${options.apiKey}`;
    if (!auth) {
      jsonResponse(res, 401, { error: { message: "missing bearer credential" } });
      return;
    }

    if (req.method === "GET" && ["/models", "/v1/models"].includes(requestPath)) {
      jsonResponse(res, 200, {
        object: "list",
        data: [{ id: options.model, object: "model" }],
      });
      return;
    }

    if (
      req.method === "POST" &&
      ["/chat/completions", "/v1/chat/completions"].includes(requestPath)
    ) {
      await readRequestBody(req);
      jsonResponse(res, 200, {
        id: "chatcmpl-mcp-bridge",
        object: "chat.completion",
        choices: [
          { index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" },
        ],
      });
      return;
    }

    if (req.method === "POST" && ["/responses", "/v1/responses"].includes(requestPath)) {
      await readRequestBody(req);
      jsonResponse(res, 200, {
        id: "resp-mcp-bridge",
        object: "response",
        output: [
          {
            type: "message",
            role: "assistant",
            content: [{ type: "output_text", text: "ok" }],
          },
        ],
      });
      return;
    }

    jsonResponse(res, 404, { error: { message: "not found" } });
  });

  await listenOnRandomPort(server);
  return {
    port: requireTcpPort(server, "compatible endpoint mock"),
    close: () => closeServer(server),
  };
}

export async function startFakeMcpHttpServer(options: {
  secret: string;
}): Promise<FakeMcpHttpServer> {
  const requests: Array<{ auth: string; body: string }> = [];
  const server = http.createServer(async (req, res) => {
    const requestPath = new URL(req.url ?? "/", "http://fake-mcp.local").pathname;
    if (req.method !== "POST" || requestPath !== "/mcp") {
      jsonResponse(res, 404, { error: { message: "not found" } });
      return;
    }

    const body = await readRequestBody(req);
    const auth = Array.isArray(req.headers.authorization)
      ? req.headers.authorization.join(",")
      : (req.headers.authorization ?? "");
    requests.push({ auth, body });
    if (auth !== `Bearer ${options.secret}`) {
      jsonResponse(res, 401, { error: { message: "missing rewritten bearer credential" } });
      return;
    }

    let payload: { id?: unknown; method?: unknown };
    try {
      payload = JSON.parse(body) as { id?: unknown; method?: unknown };
    } catch {
      jsonResponse(res, 400, { error: { message: "invalid json" } });
      return;
    }

    const result =
      payload.method === "initialize"
        ? {
            protocolVersion: "2025-03-26",
            capabilities: { tools: {} },
            serverInfo: { name: "fake", version: "1.0.0" },
          }
        : payload.method === "tools/list"
          ? {
              tools: [
                {
                  name: "fake_echo",
                  description: "fake echo",
                  inputSchema: { type: "object", properties: {} },
                },
              ],
            }
          : { ok: true };
    jsonResponse(res, 200, { jsonrpc: "2.0", id: payload.id ?? 1, result });
  });

  await listenOnRandomPort(server);
  return {
    port: requireTcpPort(server, "fake MCP endpoint"),
    requests,
    close: () => closeServer(server),
  };
}
