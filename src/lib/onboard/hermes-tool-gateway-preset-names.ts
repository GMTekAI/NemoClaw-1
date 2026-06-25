// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

export const HERMES_TOOL_GATEWAY_PRESET_NAME_LIST = [
  "nous-web",
  "nous-image",
  "nous-audio",
  "nous-browser",
  "nous-code",
] as const;

export const HERMES_TOOL_GATEWAY_PRESET_NAMES = new Set<string>(
  HERMES_TOOL_GATEWAY_PRESET_NAME_LIST,
);
