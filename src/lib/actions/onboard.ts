// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { listAgents } from "../agent/defs";
import { runDeprecatedOnboardAliasCommand, runOnboardCommand } from "../onboard/legacy-command";
import { NOTICE_ACCEPT_ENV, NOTICE_ACCEPT_FLAG } from "../onboard/usage-notice";

async function runOnboard(options?: unknown): Promise<void> {
  // Keep the monolithic legacy onboarding graph lazy so command metadata/help
  // imports do not execute it. Resolve it only when the user invokes onboard.
  const { onboard } = (await import("../onboard")) as unknown as {
    onboard: (onboardOptions?: unknown) => Promise<void>;
  };
  await onboard(options);
}

function buildOnboardCommandDeps(args: string[]) {
  return {
    args,
    noticeAcceptFlag: NOTICE_ACCEPT_FLAG,
    noticeAcceptEnv: NOTICE_ACCEPT_ENV,
    env: process.env,
    runOnboard,
    listAgents,
    log: console.log,
    error: console.error,
    exit: (code: number) => process.exit(code),
  };
}

export async function runOnboardAction(args: string[]): Promise<void> {
  await runOnboardCommand(buildOnboardCommandDeps(args));
}

export async function runSetupAction(args: string[] = []): Promise<void> {
  await runDeprecatedOnboardAliasCommand({
    ...buildOnboardCommandDeps(args),
    kind: "setup",
  });
}

export async function runSetupSparkAction(args: string[] = []): Promise<void> {
  await runDeprecatedOnboardAliasCommand({
    ...buildOnboardCommandDeps(args),
    kind: "setup-spark",
  });
}
