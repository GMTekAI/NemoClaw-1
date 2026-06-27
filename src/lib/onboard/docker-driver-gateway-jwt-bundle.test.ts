// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  expectEd25519BundleSignsAndVerifies,
  jwtBundlePaths,
  writeGatewayConfig,
} from "../../../test/support/openshell-gateway-config-helpers";

describe("docker-driver-gateway JWT bundle", () => {
  it("preserves a complete gateway JWT bundle across config rewrites", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-config-"));
    try {
      writeGatewayConfig(stateDir);
      const paths = jwtBundlePaths(stateDir);
      const firstSigningKey = fs.readFileSync(paths.signingKeyPath, "utf-8");
      expectEd25519BundleSignsAndVerifies(paths);

      writeGatewayConfig(stateDir);

      expect(fs.readFileSync(paths.signingKeyPath, "utf-8")).toBe(firstSigningKey);
      expectEd25519BundleSignsAndVerifies(paths);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it.each([
    {
      name: "malformed signing key",
      corrupt: (paths: ReturnType<typeof jwtBundlePaths>) => {
        fs.writeFileSync(paths.signingKeyPath, "not a private key\n", { mode: 0o600 });
      },
    },
    {
      name: "empty kid",
      corrupt: (paths: ReturnType<typeof jwtBundlePaths>) => {
        fs.writeFileSync(paths.kidPath, "\n", { mode: 0o600 });
      },
    },
    {
      name: "mismatched public key",
      corrupt: (paths: ReturnType<typeof jwtBundlePaths>) => {
        const otherStateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-config-"));
        try {
          writeGatewayConfig(otherStateDir);
          fs.copyFileSync(jwtBundlePaths(otherStateDir).publicKeyPath, paths.publicKeyPath);
        } finally {
          fs.rmSync(otherStateDir, { recursive: true, force: true });
        }
      },
    },
  ])("regenerates a complete gateway JWT bundle when $name", ({ corrupt }) => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-config-"));
    try {
      writeGatewayConfig(stateDir);
      const paths = jwtBundlePaths(stateDir);
      const firstSigningKey = fs.readFileSync(paths.signingKeyPath, "utf-8");

      corrupt(paths);
      writeGatewayConfig(stateDir);

      expect(fs.readFileSync(paths.signingKeyPath, "utf-8")).not.toBe(firstSigningKey);
      expectEd25519BundleSignsAndVerifies(paths);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("regenerates an incomplete gateway JWT bundle before writing config", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-config-"));
    try {
      const jwtDir = path.join(stateDir, "jwt");
      fs.mkdirSync(jwtDir, { recursive: true, mode: 0o700 });
      const signingKeyPath = path.join(jwtDir, "signing.pem");
      const publicKeyPath = path.join(jwtDir, "public.pem");
      const kidPath = path.join(jwtDir, "kid");
      fs.writeFileSync(signingKeyPath, "stale partial key\n", { mode: 0o600 });

      writeGatewayConfig(stateDir);

      const toml = fs.readFileSync(path.join(stateDir, "openshell-gateway.toml"), "utf-8");
      expect(fs.readFileSync(signingKeyPath, "utf-8")).not.toBe("stale partial key\n");
      expect(fs.existsSync(publicKeyPath)).toBe(true);
      expect(fs.existsSync(kidPath)).toBe(true);
      expect(fs.statSync(jwtDir).mode & 0o777).toBe(0o700);
      expect(fs.statSync(signingKeyPath).mode & 0o777).toBe(0o600);
      expect(fs.statSync(publicKeyPath).mode & 0o777).toBe(0o600);
      expect(fs.statSync(kidPath).mode & 0o777).toBe(0o600);
      expect(toml).toContain(`signing_key_path = "${signingKeyPath}"`);
      expect(toml).toContain(`public_key_path = "${publicKeyPath}"`);
      expect(toml).toContain(`kid_path = "${kidPath}"`);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("recovers after a crashed temp JWT bundle write without publishing partial files", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-config-"));
    try {
      const staleTmpDir = fs.mkdtempSync(path.join(stateDir, ".jwt-tmp-"));
      fs.writeFileSync(path.join(staleTmpDir, "signing.pem"), "stale temp key\n", {
        mode: 0o600,
      });

      writeGatewayConfig(stateDir);

      const paths = jwtBundlePaths(stateDir);
      const toml = fs.readFileSync(path.join(stateDir, "openshell-gateway.toml"), "utf-8");
      expect(fs.readdirSync(stateDir).filter((entry) => entry.startsWith(".jwt-tmp-"))).toEqual([]);
      expect(toml).toContain(`signing_key_path = "${paths.signingKeyPath}"`);
      expect(toml).not.toContain(staleTmpDir);
      expectEd25519BundleSignsAndVerifies(paths);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });
});
