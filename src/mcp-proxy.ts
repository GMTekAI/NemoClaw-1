// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

export const MCP_PROXY_BIND_HOST = "127.0.0.1";
export const MCP_PROXY_REQUEST_TIMEOUT_MS = 120_000;
export const MCP_PROXY_MAX_INFLIGHT = 100;
export const MCP_PROXY_MAX_BODY_BYTES = 1024 * 1024;

export interface ProxyConfig {
  command: string | null;
  args: string[];
  env: string[];
  port: number;
  tokenEnv: string | null;
  tokenFile: string | null;
}

export interface JsonRpcMessage {
  jsonrpc?: string;
  id?: number | string | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: unknown;
}

export interface McpProxyServerOptions {
  exitOnChildFailure?: boolean;
}

export function parseProxyArgs(argv: string[]): ProxyConfig {
  const parsed: ProxyConfig = {
    command: null,
    args: [],
    env: [],
    port: 3100,
    tokenEnv: null,
    tokenFile: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    switch (flag) {
      case "--command":
      case "--exe":
        parsed.command = argv[++i] ?? null;
        break;
      case "--arg":
        parsed.args.push(argv[++i] ?? "");
        break;
      case "--env":
        parsed.env.push(argv[++i] ?? "");
        break;
      case "--port":
        parsed.port = Number.parseInt(argv[++i] ?? "", 10);
        break;
      case "--token-env":
        parsed.tokenEnv = argv[++i] ?? null;
        break;
      case "--token-file":
        parsed.tokenFile = argv[++i] ?? null;
        break;
      default:
        throw new Error(`Unknown proxy argument: ${flag}`);
    }
  }
  return parsed;
}

function isExecutable(filePath: string): boolean {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function resolveExecutable(command: string, envPath = process.env.PATH || ""): string {
  if (!command) throw new Error("MCP proxy command is required");
  if (command.includes("/") || command.includes("\\")) {
    const resolved = path.resolve(command);
    if (isExecutable(resolved)) return resolved;
    throw new Error(`MCP proxy command is not executable: ${command}`);
  }
  for (const dir of envPath.split(path.delimiter).filter(Boolean)) {
    const candidate = path.join(dir, command);
    if (isExecutable(candidate)) return candidate;
  }
  throw new Error(`MCP proxy command not found on PATH: ${command}`);
}

export function readBearerToken(
  config: Pick<ProxyConfig, "tokenEnv" | "tokenFile">,
): string | null {
  if (config.tokenFile) {
    const token = fs.readFileSync(config.tokenFile, "utf8").trim();
    fs.rmSync(config.tokenFile, { force: true });
    return token || null;
  }
  return config.tokenEnv ? process.env[config.tokenEnv] || null : null;
}

export function redactSecretsFromText(text: string, secrets: readonly string[]): string {
  let redacted = text;
  for (const secret of secrets) {
    if (!secret) continue;
    redacted = redacted.split(secret).join("***REDACTED***");
  }
  return redacted;
}

function digest(value: string): Buffer {
  return crypto.createHash("sha256").update(value).digest();
}

export function isAuthorizedHeader(
  authorizationHeader: string | string[] | undefined,
  bearerToken: string | null,
): boolean {
  if (!bearerToken) return false;
  if (typeof authorizationHeader !== "string") return false;
  return crypto.timingSafeEqual(digest(authorizationHeader), digest(`Bearer ${bearerToken}`));
}

class StdioJsonRpcClient {
  private child: ChildProcessWithoutNullStreams | null = null;
  private nextId = 1;
  private stdoutBuffer = "";
  private stderrBuffer = "";
  private stopping = false;
  private readonly responseCallbacks = new Map<
    number,
    {
      resolve: (msg: JsonRpcMessage) => void;
      reject: (error: Error) => void;
      timer: NodeJS.Timeout;
    }
  >();

  constructor(
    private readonly config: ProxyConfig,
    private readonly secrets: readonly string[],
    private readonly options: McpProxyServerOptions = {},
  ) {}

  start(): void {
    const command = this.config.command;
    if (!command) throw new Error("MCP proxy command is required");
    const resolvedCommand = resolveExecutable(command);
    this.stopping = false;

    const childEnv: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      SHELL: process.env.SHELL,
      TERM: process.env.TERM || "xterm-256color",
      NODE_ENV: process.env.NODE_ENV || "production",
    };
    for (const name of this.config.env) {
      childEnv[name] = process.env[name];
    }

    this.child = spawn(resolvedCommand, this.config.args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: childEnv,
      shell: false,
    });

    this.child.stdout.on("data", (data: Buffer) => this.onStdout(data));
    this.child.stderr.on("data", (data: Buffer) => this.onStderr(data));
    this.child.on("close", (code: number | null) => {
      this.flushStderr();
      if (this.stopping) {
        this.child = null;
        return;
      }
      const message = `MCP child exited with code ${String(code)}`;
      console.error(`[mcp-proxy] child exited with code ${String(code)}`);
      this.rejectPending(new Error(message));
      if (this.options.exitOnChildFailure) process.exit(code || 1);
    });
    this.child.on("error", (error: Error) => {
      if (this.stopping) return;
      console.error(`[mcp-proxy] child spawn error: ${error.message}`);
      this.rejectPending(error);
      if (this.options.exitOnChildFailure) process.exit(1);
    });
  }

  call(
    method: string | undefined,
    params: unknown,
    originalId: JsonRpcMessage["id"],
  ): Promise<JsonRpcMessage> {
    if (!method) {
      return Promise.resolve({
        jsonrpc: "2.0",
        id: originalId ?? null,
        error: { code: -32600, message: "Missing JSON-RPC method" },
      });
    }
    if (this.responseCallbacks.size >= MCP_PROXY_MAX_INFLIGHT) {
      return Promise.reject(new Error("Too many in-flight MCP requests"));
    }
    if (!this.child || !this.child.stdin.writable) {
      return Promise.reject(new Error("MCP child is not running"));
    }

    return new Promise((resolve, reject) => {
      const childId = this.nextId++;
      const timer = setTimeout(() => {
        this.responseCallbacks.delete(childId);
        reject(new Error("MCP request timed out"));
      }, MCP_PROXY_REQUEST_TIMEOUT_MS);
      this.responseCallbacks.set(childId, {
        resolve: (msg) => {
          clearTimeout(timer);
          resolve({ ...msg, id: originalId ?? msg.id ?? null });
        },
        reject,
        timer,
      });
      this.child?.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: childId, method, params })}\n`,
      );
    });
  }

  stop(): void {
    this.stopping = true;
    this.rejectPending(new Error("MCP child stopped"));
    if (this.child) this.child.kill();
  }

  private onStdout(data: Buffer): void {
    this.stdoutBuffer += data.toString("utf8");
    const lines = this.stdoutBuffer.split("\n");
    this.stdoutBuffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line) as JsonRpcMessage;
        this.handleChildMessage(msg);
      } catch {
        /* Ignore non-JSON child stdout. */
      }
    }
  }

  private onStderr(data: Buffer): void {
    this.stderrBuffer += data.toString("utf8");
    const lines = this.stderrBuffer.split("\n");
    this.stderrBuffer = lines.pop() ?? "";
    for (const line of lines) {
      console.error(`[mcp-proxy:child] ${redactSecretsFromText(line, this.secrets)}`);
    }
  }

  private flushStderr(): void {
    if (!this.stderrBuffer) return;
    console.error(`[mcp-proxy:child] ${redactSecretsFromText(this.stderrBuffer, this.secrets)}`);
    this.stderrBuffer = "";
  }

  private handleChildMessage(msg: JsonRpcMessage): void {
    if (typeof msg.id === "number" && this.responseCallbacks.has(msg.id)) {
      const callback = this.responseCallbacks.get(msg.id);
      this.responseCallbacks.delete(msg.id);
      callback?.resolve(msg);
      return;
    }
    if (msg.method) {
      console.log(`[mcp-proxy:notify] ${msg.method}`);
    }
  }

  private rejectPending(error: Error): void {
    for (const [id, callback] of this.responseCallbacks) {
      clearTimeout(callback.timer);
      callback.reject(error);
      this.responseCallbacks.delete(id);
    }
  }
}

function jsonResponse(res: http.ServerResponse, statusCode: number, body: unknown): void {
  res.writeHead(statusCode, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

export function createMcpProxyServer(
  config: ProxyConfig,
  bearerToken: string,
  options: McpProxyServerOptions = {},
): http.Server {
  const secrets = [
    ...config.env.map((name) => process.env[name]).filter((value): value is string => !!value),
    bearerToken,
  ];
  const client = new StdioJsonRpcClient(config, secrets, options);

  const server = http.createServer(async (req, res) => {
    if (req.method !== "POST") {
      jsonResponse(res, 405, { error: "Method not allowed" });
      return;
    }

    if (!isAuthorizedHeader(req.headers.authorization, bearerToken)) {
      jsonResponse(res, 401, {
        jsonrpc: "2.0",
        error: { code: -32000, message: "Unauthorized" },
      });
      return;
    }

    let body = "";
    let bytes = 0;
    for await (const chunk of req) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.byteLength;
      if (bytes > MCP_PROXY_MAX_BODY_BYTES) {
        jsonResponse(res, 413, {
          jsonrpc: "2.0",
          error: { code: -32600, message: "Request too large" },
        });
        return;
      }
      body += buffer.toString("utf8");
    }

    let request: JsonRpcMessage;
    try {
      request = JSON.parse(body) as JsonRpcMessage;
    } catch {
      jsonResponse(res, 400, {
        jsonrpc: "2.0",
        error: { code: -32700, message: "Parse error" },
      });
      return;
    }

    try {
      const response = await client.call(request.method, request.params, request.id);
      jsonResponse(res, 200, response);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      console.error(`[mcp-proxy:error] ${redactSecretsFromText(detail, secrets)}`);
      jsonResponse(res, 500, {
        jsonrpc: "2.0",
        id: request.id ?? null,
        error: {
          code: -32603,
          message: "Internal MCP proxy error",
        },
      });
    }
  });

  server.on("listening", () => client.start());
  server.on("close", () => client.stop());
  return server;
}

function main(): void {
  let config: ProxyConfig;
  try {
    config = parseProxyArgs(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }

  if (!config.command) {
    console.error("Usage: mcp-proxy.js --command <binary> [--arg <arg> ...] --port <port>");
    process.exit(1);
  }
  if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
    console.error(`Invalid MCP proxy port: ${String(config.port)}`);
    process.exit(1);
  }
  for (const name of config.env) {
    if (!process.env[name]) {
      console.error(`Environment variable ${name} is not set.`);
      process.exit(1);
    }
  }
  try {
    resolveExecutable(config.command);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
  let bearerToken: string | null;
  try {
    bearerToken = readBearerToken(config);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
  if (!bearerToken) {
    console.error("Bearer token is required.");
    process.exit(1);
  }
  if (config.tokenEnv) delete process.env[config.tokenEnv];

  const server = createMcpProxyServer(config, bearerToken, { exitOnChildFailure: true });
  server.on("error", (error: Error) => {
    console.error(
      `[mcp-proxy] failed to listen on ${MCP_PROXY_BIND_HOST}:${String(config.port)}: ${error.message}`,
    );
    process.exit(1);
  });
  server.listen(config.port, MCP_PROXY_BIND_HOST, () => {
    console.log(`[mcp-proxy] listening on ${MCP_PROXY_BIND_HOST}:${String(config.port)}`);
    console.log(`[mcp-proxy] command: ${config.command}`);
    console.log(`[mcp-proxy] args: ${config.args.join(" ") || "(none)"}`);
    console.log(`[mcp-proxy] env: ${config.env.join(", ") || "(none)"}`);
    console.log("[mcp-proxy] auth: bearer");
  });

  process.on("SIGTERM", () => {
    server.close(() => process.exit(0));
  });
  process.on("SIGINT", () => {
    server.close(() => process.exit(0));
  });
}

if (require.main === module) {
  main();
}
