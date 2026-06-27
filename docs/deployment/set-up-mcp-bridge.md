# Set Up MCP Servers

NemoClaw MCP support lets a sandboxed agent use MCP Streamable HTTP servers
without copying external service credentials into the sandbox.

The integration has three parts:

- an OpenShell provider that stores host-side credentials;
- a generated OpenShell network policy for the MCP endpoint using `protocol: mcp`
  with explicit JSON-RPC MCP method rules;
- an agent adapter that writes the MCP endpoint into OpenClaw, Hermes, or
  LangChain Deep Agents Code config.

This depends on the OpenShell MCP/JSON-RPC L7 policy support from
NVIDIA/OpenShell#1865. NemoClaw requires an OpenShell release that exposes the
`protocol: mcp` policy capability before managed MCP servers are enabled.

This v1 intentionally accepts Streamable HTTP MCP endpoints only. NemoClaw does
not launch host stdio MCP servers or a host-side MCP credential proxy; host-only
credentials follow the same OpenShell provider model used for other provider
secrets.

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

For one-time bootstrap you can pass `--env KEY=VALUE`. NemoClaw stages
`VALUE` only in the environment of the `openshell provider create/update`
subprocess and still persists only `KEY`.

Unauthenticated MCP servers can omit `--env`.

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

LangChain Deep Agents Code writes an HTTP entry under `/sandbox/.mcp.json`:

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
presence, provider attachment, generated policy presence, environment readiness,
and adapter registration state.

`remove --force` performs best-effort cleanup for stale provider, generated
policy, adapter config, and registry entries.

## Troubleshooting

If `restart` reports a missing provider and the original credential is not
registered in OpenShell, export the same variable name used during `add` and
retry.

If the sandbox cannot reach an MCP server hosted on the workstation, use the
OpenShell host alias path that works for your runtime, such as
`host.openshell.internal`, and let the generated `protocol: mcp` policy enforce
that endpoint. Do not run a separate NemoClaw host proxy for MCP credentials.

The generated policy permits normal MCP client methods such as
`initialize`, `tools/list`, `tools/call`, `resources/*`, `prompts/*`, `ping`,
`completion/complete`, and `logging/setLevel`, bounded to the configured MCP
endpoint path and the selected agent adapter binaries.
