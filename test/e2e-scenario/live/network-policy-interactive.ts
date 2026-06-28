// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

export const POLICY_ADD_EXPECT_SCRIPT = String.raw`
set timeout 60
spawn env NEMOCLAW_NON_INTERACTIVE= node $env(NEMOCLAW_E2E_CLI) $env(NEMOCLAW_E2E_SANDBOX) policy-add
expect {
  -glob "*Choose preset*" {
    send -- "$env(NEMOCLAW_E2E_PRESET_NUM)\r"
  }
  timeout {
    puts stderr "timed out waiting for the policy preset prompt"
    exit 2
  }
  eof {
    puts stderr "policy-add exited before the policy preset prompt"
    exit 3
  }
}
expect {
  -glob "*Y/n*" {
    send -- "Y\r"
  }
  timeout {
    puts stderr "timed out waiting for the policy confirmation prompt"
    exit 4
  }
  eof {
    puts stderr "policy-add exited before the policy confirmation prompt"
    exit 5
  }
}
expect {
  eof {}
  timeout {
    puts stderr "policy-add did not exit after confirmation"
    exit 6
  }
}
set wait_result [wait]
exit [lindex $wait_result 3]
`;

export function findPolicyPresetNumber(output: string, preset: string): string | null {
  const escapedPreset = preset.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`^\\s*(\\d+)\\)\\s+(?:[●○]\\s+)?${escapedPreset}(?:\\s|$)`, "m").exec(
    output,
  );
  return match?.[1] ?? null;
}
