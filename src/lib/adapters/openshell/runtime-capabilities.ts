// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Compiled into the OpenShell sandbox supervisor that requires verified TLS,
 * binds HTTP Host to the approved origin, and rejects MCP query drift before
 * credential replacement.
 */
export const OPENSHELL_MCP_TRANSPORT_CAPABILITY_MARKER =
  "authenticated-mcp-policy-bound-credential-rewrite-v1";
