// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { dispatchMcpBridgeCommand } from "../../lib/actions/sandbox/mcp-bridge";
import { NemoClawCommand } from "../../lib/cli/nemoclaw-oclif-command";

export default class SandboxMcpCommand extends NemoClawCommand {
  static id = "sandbox:mcp";
  static strict = false;
  static summary = "Manage MCP bridges for a sandbox";
  static description =
    "Manage host-side stdio MCP server bridges for a sandbox. The proxy runs on the host with host environment credentials; the sandbox reaches it through a generated network policy and a bearer-authenticated local bridge.";
  static usage = ["<name> <add|list|status|restart|remove> [args...]"];
  static examples = [
    "<%= config.bin %> sandbox mcp alpha list",
    "<%= config.bin %> sandbox mcp alpha add github --env GITHUB_TOKEN -- npx -y @modelcontextprotocol/server-github",
    "<%= config.bin %> sandbox mcp alpha status github --json",
    "<%= config.bin %> sandbox mcp alpha remove github",
  ];

  public async run(): Promise<void> {
    this.parsed = true;
    const [sandboxName, ...actionArgs] = this.argv;
    if (
      !sandboxName ||
      sandboxName.trim() === "" ||
      sandboxName === "--help" ||
      sandboxName === "-h"
    ) {
      this.failWithLines(
        ["Usage: nemoclaw <sandbox> mcp <add|list|status|restart|remove> [args...]"],
        2,
      );
      return;
    }
    await dispatchMcpBridgeCommand(sandboxName, actionArgs);
  }
}
