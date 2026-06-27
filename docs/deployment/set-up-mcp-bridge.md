# Set Up MCP Servers

NemoClaw MCP support lets a sandboxed agent use MCP Streamable HTTP servers
without copying external service credentials into the sandbox.

The integration has three parts:

- an OpenShell provider that stores credentials outside the sandbox;
- a generated OpenShell network policy for the MCP endpoint using `protocol: mcp`
  with explicit JSON-RPC MCP method rules;
- an agent adapter that writes the MCP endpoint into OpenClaw, Hermes, or
  LangChain Deep Agents Code config.

This depends on the OpenShell MCP/JSON-RPC L7 policy support from
NVIDIA/OpenShell#1865. NemoClaw requires an OpenShell build that exposes the
`protocol: mcp` policy capability before managed MCP servers are enabled.

This v1 intentionally accepts Streamable HTTP MCP endpoints only. NemoClaw does
not launch an MCP server, stdio adapter, bridge, credential proxy, or relay on
the host. The sandbox agent connects directly to the configured endpoint, and
OpenShell enforces policy and replaces credentials in its existing sandbox
egress path.

This implementation replaces the earlier issue #566 stdio-proxy sketch with
the following scope:

- connect directly to an already-running Streamable HTTP MCP endpoint, with no
  stdio translation or host-side MCP process;
- keep raw external credentials in OpenShell provider state, not in the sandbox
  registry;
- require credentials to be exported on the host and accept only `--env KEY`,
  so raw values do not enter NemoClaw process arguments or shell history;
- on `mcp restart`, recover from the existing OpenShell provider when present,
  or ask the operator to re-export the same env name before recreating a missing
  provider.

## Add An MCP Server

OpenClaw:

```bash
export GITHUB_TOKEN=ghp_...
nemoclaw my-openclaw mcp add github --url https://api.githubcopilot.com/mcp/ --env GITHUB_TOKEN
```

Hermes:

```bash
export GITHUB_TOKEN=ghp_...
nemoclaw my-hermes mcp add github --url https://api.githubcopilot.com/mcp/ --env GITHUB_TOKEN
```

LangChain Deep Agents Code:

```bash
export GITHUB_TOKEN=ghp_...
nemoclaw my-dcode mcp add github --url https://api.githubcopilot.com/mcp/ --env GITHUB_TOKEN
```

`--env KEY` reads the value from the host process environment and stores it in
OpenShell's provider store. NemoClaw persists only the variable name, writes
`openshell:resolve:env:KEY` into the sandbox-side MCP config, and relies on
OpenShell to resolve the placeholder at egress.

Do not reuse OpenShell's Google Cloud compatibility names as MCP bearer keys.
NemoClaw rejects `GCP_PROJECT_ID`, `GOOGLE_CLOUD_PROJECT`, `CLOUD_ML_REGION`,
`GCP_LOCATION`, `GCP_SERVICE_ACCOUNT_EMAIL`, `GOOSE_PROVIDER`,
`ANTHROPIC_VERTEX_PROJECT_ID`, and `VERTEX_LOCATION` because OpenShell exposes
those non-secret configuration names as child-process values. It also rejects
`GCE_METADATA_HOST`, which OpenShell rewrites for its metadata emulator. Choose
a dedicated name such as `MY_SERVICE_MCP_TOKEN`.

V1 requires exactly one `--env` bearer credential per server. Remote endpoints
must use HTTPS; plain HTTP is accepted only for OpenShell host aliases. URLs
with query strings are rejected because the URL is persisted and displayed.
Use a distinct environment variable name for each managed MCP server in the same sandbox;
OpenShell static credential keys are sandbox-wide and cannot be attached twice.
Endpoint paths must be literal and canonical: percent escapes, backslashes,
semicolons, OpenShell glob metacharacters, and explicit port zero are rejected.

## Authenticated MCP Security Boundary

Authenticated MCP is the intended configuration. The agent stores only the
`openshell:resolve:env:KEY` placeholder. OpenShell keeps the raw credential in
its provider store and combines credential replacement with the generated MCP
policy at egress.

For each request, OpenShell first evaluates the effective network policy for
the host, port, runtime identity, literal endpoint path, and MCP method. The
generated MCP policy grants only the configured target and explicit MCP
profile. Only a request that passes policy reaches OpenShell's credential
replacement stage, where OpenShell replaces the authorization placeholder
immediately before writing the request upstream. An endpoint, path, binary, or
method not granted by an attached policy is denied without being rewritten or
sent to the server.

OpenShell's current static placeholder lookup is sandbox-wide; the credential
key itself is not endpoint-bound. The generated MCP policy narrows this managed
route, but current OpenShell policy cannot declare which attached placeholder
key may be resolved at that endpoint. Code running as an allowed adapter binary
can therefore present another sandbox-attached static placeholder to the
configured MCP endpoint, and any other effective policy that permits that
binary can likewise send the MCP placeholder elsewhere. Treat the configured
MCP service as trusted with every static credential attached to that sandbox,
or isolate it in a dedicated sandbox. Use dedicated, least-privilege tokens and
unique environment keys, avoid broad egress grants for adapter binaries, and
audit the sandbox's complete effective policy. NemoClaw rejects credential-key
reuse between its managed MCP servers to reduce accidental overlap, but that
does not add endpoint-level credential scoping to OpenShell.

Use an MCP service you trust with the credential it receives. MCP response
bodies and SSE streams return through OpenShell's existing sandbox egress path;
as with any authenticated API, a server that possesses a credential can
deliberately return that value in its response. This does not expose the raw
credential to the sandbox before the request is authorized and sent to that
server.

## Agent Adapters

OpenClaw uses `mcporter config add` in the sandbox.

Hermes writes an HTTP entry under `/sandbox/.hermes/config.yaml`:

```yaml
mcp_servers:
  github:
    url: https://api.githubcopilot.com/mcp/
    headers:
      Authorization: Bearer openshell:resolve:env:GITHUB_TOKEN
```

Hermes config changes and gateway reloads stay inside the sandbox. NemoClaw
invokes the validated transaction helper as a one-shot `openshell sandbox exec`
command. OpenShell current main places that command in the same workload uid
and network namespace as Hermes, so the helper can update the same-uid
compatibility hash, signal the exact gateway PID, and verify its loopback health.
The helper rejects non-root execution when the root-separated lifecycle marker
or a separately owned gateway is present, and validates the PID against the
trusted Hermes gateway launcher before signaling it. There is no persistent
control socket or service. The command carries no MCP traffic or raw service
credential; its payload contains only the endpoint definition and OpenShell
placeholder.

LangChain Deep Agents Code writes an HTTP entry under its user-level discovery
path, `/sandbox/.deepagents/.mcp.json`. Deep Agents Code 0.1.12 treats the
sandbox-root `.mcp.json` as project configuration and gates it on project trust,
so NemoClaw does not use that path for managed bridges:

```json
{
  "mcpServers": {
    "github": {
      "type": "http",
      "url": "https://api.githubcopilot.com/mcp/",
      "headers": {
        "Authorization": "Bearer openshell:resolve:env:GITHUB_TOKEN"
      }
    }
  }
}
```

External service keys such as `GITHUB_TOKEN` remain in OpenShell provider
state, not in sandbox files or NemoClaw's sandbox registry.

## Operate MCP Servers

```bash
nemoclaw my-sandbox mcp list
nemoclaw my-sandbox mcp status github --json
nemoclaw my-sandbox mcp restart github
nemoclaw my-sandbox mcp remove github
```

`status --json` never includes environment values. It reports provider
presence, provider attachment, whether the live generated policy content still
matches the registered policy, environment readiness, and adapter registration
state.

`remove --force` performs best-effort cleanup only where ownership can still be
proved. It never deletes an unowned or drifted same-key live policy. If any
cleanup step leaves a residual, the command exits nonzero and preserves the
managed MCP registry entry so cleanup can be retried. It never detaches the
provider from other sandboxes; a residual provider may require manual cleanup.

Removing a server blocks new requests and reconnects, but it does not terminate
an MCP response or SSE stream that was already open. For immediate revocation,
revoke the upstream credential and stop or rebuild the sandbox.

## Troubleshooting

If `restart` reports a missing provider and the original credential is not
registered in OpenShell, export the same variable name used during `add` and
retry.

Stdio-only MCP servers are not supported. NemoClaw does not start, wrap, or
translate them; configure a native Streamable HTTP MCP endpoint.

The generated policy permits this explicit MCP client-to-server profile: `initialize`,
`notifications/initialized`, `ping`, `tools/list`, `tools/call`,
`resources/list`, `resources/read`, `resources/templates/list`,
`resources/subscribe`, `resources/unsubscribe`, `prompts/list`, `prompts/get`,
`tasks/list`, `tasks/get`, `tasks/update`, `tasks/result`, `tasks/cancel`,
`completion/complete`, `logging/setLevel`, `server/discover`, `messages/listen`,
`notifications/cancelled`, `notifications/progress`,
`notifications/roots/list_changed`, and `notifications/elicitation/complete`. Those methods
remain bounded to the configured endpoint path and selected agent adapter
binaries. `tools/call` currently permits every tool exposed by that server;
`strict_tool_names` validates tool name syntax and is not a tool authorization
allowlist. OpenShell also handles the protocol-required empty receive-stream
`GET` and client response frames for server-originated MCP requests; those are
transport behavior rather than additional client-initiated method grants.
