// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { BlockList, isIP } from "node:net";

const OPENSHELL_HOST_ALIASES = new Set([
  "host.openshell.internal",
  "host.docker.internal",
  "host.containers.internal",
]);

const RESERVED_HOST_NAMES = new Set(["localhost", "local", "internal", "metadata"]);

const blockedMcpTargets = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  blockedMcpTargets.addSubnet(address, prefix, "ipv4");
}
for (const [address, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 32],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
] as const) {
  blockedMcpTargets.addSubnet(address, prefix, "ipv6");
}

export function normalizeMcpHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

export function isOpenShellMcpHostAlias(hostname: string): boolean {
  return OPENSHELL_HOST_ALIASES.has(normalizeMcpHostname(hostname));
}

function isReservedMcpName(hostname: string): boolean {
  if (RESERVED_HOST_NAMES.has(hostname)) return true;
  for (const reserved of RESERVED_HOST_NAMES) {
    if (hostname.endsWith(`.${reserved}`)) return true;
  }
  return false;
}

export function isBlockedMcpUrlTargetHost(hostname: string): boolean {
  const normalized = normalizeMcpHostname(hostname);
  if (isOpenShellMcpHostAlias(normalized)) return false;
  if (isReservedMcpName(normalized)) return true;
  const family = isIP(normalized);
  if (family === 0) return false;
  return blockedMcpTargets.check(normalized, family === 6 ? "ipv6" : "ipv4");
}
