// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from "vitest";

import {
  type StartedHttpServer,
  startCompatibleMock,
  startFakeMcpHttpServer,
} from "./e2e-scenario/live/mcp-bridge-servers";

const servers: StartedHttpServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

describe("authenticated MCP live fixtures", () => {
  it("implements stateless Streamable HTTP and validates the tool challenge", async () => {
    const secret = "fixture-secret";
    const challenge = "fixture-challenge";
    const resultToken = `MCP_AUTH_REWRITE_OK::${challenge}`;
    const server = await startFakeMcpHttpServer({
      secret,
      challenge,
      resultToken,
    });
    servers.push(server);
    const url = `http://127.0.0.1:${server.port}/mcp`;
    const headers = {
      authorization: `Bearer ${secret}`,
      "content-type": "application/json",
    };

    expect((await fetch(url, { method: "HEAD" })).status).toBe(405);
    const initialize = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18" },
      }),
    });
    expect(await initialize.json()).toMatchObject({
      result: { protocolVersion: "2025-06-18" },
    });
    const initialized = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }),
    });
    expect(initialized.status).toBe(202);

    const list = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
      }),
    });
    expect(await list.json()).toMatchObject({
      result: {
        tools: [
          {
            name: "fake_echo",
            inputSchema: { required: ["challenge"] },
          },
        ],
      },
    });

    const call = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "fake_echo", arguments: { challenge } },
      }),
    });
    expect(await call.json()).toMatchObject({
      result: {
        content: [{ type: "text", text: resultToken }],
        isError: false,
      },
    });
    expect(
      server.requests.every(
        (request) => request.auth !== "Bearer openshell:resolve:env:FAKE_TOKEN",
      ),
    ).toBe(true);
  });

  it("emits an MCP tool call and withholds success until the tool result returns", async () => {
    const resultToken = "MCP_AUTH_REWRITE_OK::fixture";
    const server = await startCompatibleMock({
      apiKey: "compatible-key",
      model: "mock/model",
      toolChallenge: "fixture",
      toolResultToken: resultToken,
      toolNames: ["mcp_fake_fake_echo"],
    });
    servers.push(server);
    const url = `http://127.0.0.1:${server.port}/v1/chat/completions`;
    const headers = {
      authorization: "Bearer compatible-key",
      "content-type": "application/json",
    };
    const first = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        model: "mock/model",
        messages: [{ role: "user", content: "use the tool" }],
        tools: [
          {
            type: "function",
            function: { name: "mcp_fake_fake_echo", parameters: {} },
          },
        ],
      }),
    });
    const firstBody = (await first.json()) as {
      choices: Array<{
        message: { tool_calls: Array<{ function: { name: string; arguments: string } }> };
      }>;
    };
    expect(firstBody.choices[0].message.tool_calls[0]).toMatchObject({
      function: {
        name: "mcp_fake_fake_echo",
        arguments: JSON.stringify({ challenge: "fixture" }),
      },
    });
    expect(JSON.stringify(firstBody)).not.toContain(resultToken);

    const final = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        model: "mock/model",
        messages: [{ role: "tool", content: resultToken }],
        tools: [
          {
            type: "function",
            function: { name: "mcp_fake_fake_echo", parameters: {} },
          },
        ],
      }),
    });
    expect(await final.json()).toMatchObject({
      choices: [{ message: { content: resultToken } }],
    });

    const streamed = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        model: "mock/model",
        stream: true,
        messages: [{ role: "user", content: "use the tool" }],
        tools: [
          {
            type: "function",
            function: { name: "mcp_fake_fake_echo", parameters: {} },
          },
        ],
      }),
    });
    const firstDataLine = (await streamed.text())
      .split("\n")
      .find((line) => line.startsWith("data: {") && line.includes("tool_calls"));
    expect(firstDataLine).toBeDefined();
    const firstChunk = JSON.parse(firstDataLine!.slice("data: ".length));
    expect(firstChunk).toMatchObject({
      model: "mock/model",
      choices: [
        {
          delta: {
            tool_calls: [
              {
                index: 0,
                function: { name: "mcp_fake_fake_echo" },
              },
            ],
          },
        },
      ],
    });
  });
});
