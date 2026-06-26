# Set Up MCP Bridges

NemoClaw MCP bridges let a sandboxed agent use a host-side MCP server without
copying external service credentials into the sandbox.

The bridge has three parts:

- a host stdio-to-HTTP MCP proxy bound to `127.0.0.1`;
- a generated OpenShell network policy for `host.docker.internal:<port>` using
  `protocol: mcp`;
- an agent adapter that registers the HTTP endpoint inside the sandbox.

This depends on the OpenShell MCP/JSON-RPC L7 policy support from
NVIDIA/OpenShell#1865. NemoClaw requires an OpenShell release that exposes the
`allow_all_known_mcp_methods` policy capability before MCP bridges are enabled.

## Add A Bridge

OpenClaw:

```bash
export GITHUB_TOKEN=ghp_...
nemoclaw my-openclaw mcp add github --env GITHUB_TOKEN -- npx -y @modelcontextprotocol/server-github
```

Hermes:

```bash
export GITHUB_TOKEN=ghp_...
nemoclaw my-hermes mcp add github --env GITHUB_TOKEN -- npx -y @modelcontextprotocol/server-github
```

LangChain Deep Agents Code:

```bash
export GITHUB_TOKEN=ghp_...
nemoclaw my-dcode mcp add github --env GITHUB_TOKEN -- npx -y @modelcontextprotocol/server-github
```

The command after `--` runs on the host as your current user. Use MCP servers
you trust. `--env KEY` reads the value from the host process environment when
the proxy starts, persists only the variable name, and never writes the raw
external API key to the sandbox registry or sandbox config.

For one-time bootstrap you can pass `--env KEY=VALUE`. NemoClaw uses `VALUE`
only for that initial proxy launch and still persists only `KEY`; later
`restart` requires `KEY` to be exported in the host environment.

## Agent Adapters

OpenClaw uses `mcporter config add` in the sandbox.

Hermes writes an HTTP entry under `/sandbox/.hermes/config.yaml`:

```yaml
mcp_servers:
  github:
    url: http://host.docker.internal:3100
    headers:
      Authorization: Bearer <bridge-token>
```

LangChain Deep Agents Code writes an HTTP entry under `/sandbox/.mcp.json`:

```json
{
  "mcpServers": {
    "github": {
      "type": "http",
      "url": "http://host.docker.internal:3100",
      "headers": {
        "Authorization": "Bearer <bridge-token>"
      }
    }
  }
}
```

The bridge token is a local bearer token for the host proxy. External service
keys such as `GITHUB_TOKEN` remain host-side in the MCP server process
environment.

## Operate Bridges

```bash
nemoclaw my-sandbox mcp list
nemoclaw my-sandbox mcp status github --json
nemoclaw my-sandbox mcp restart github
nemoclaw my-sandbox mcp remove github
```

`status --json` redacts bridge tokens and never includes environment values. It
reports proxy liveness, host environment readiness, generated policy presence,
and adapter registration state.

`remove --force` performs best-effort cleanup for stale proxies, generated
policy records, adapter config, and registry entries.

## Troubleshooting

If `restart` fails with a missing host environment variable, export the same
variable name used during `add` and retry.

If the proxy times out during startup, check the bridge log shown by
`mcp status`. Cold `npx` launches can take longer than a warm command, so
NemoClaw waits longer than normal process probes before declaring startup
failed.

If the sandbox cannot reach `host.docker.internal`, the current v1 bridge stays
fail-closed. It does not widen the proxy bind address beyond host loopback.
