// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Single-entry contract for the fixture redactor.
 *
 * Both per-test explicit secret values and canonical secret-shape
 * matches must flow through `redactString` so the fixture layer has one
 * redaction entry point. This file asserts the contract so any future
 * helper that wants to add an explicit-value path stays inside the
 * canonical entry rather than introducing a parallel one.
 *
 * Canonical secret-shape coverage (regex parity with the product
 * source-of-truth) lives in e2e-redaction-parity.test.ts; this file
 * focuses on the entry-point behaviour and SecretStore delegation.
 */

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { ArtifactSink } from "../fixtures/artifacts.ts";
import { redactString } from "../fixtures/redaction.ts";
import { SecretStore } from "../fixtures/secrets.ts";
import { ShellProbe, trustedShellCommand } from "../fixtures/shell-probe.ts";

describe("fixture redaction entry point", () => {
  it("redacts explicit values with [REDACTED] and canonical shapes with <REDACTED>", () => {
    const explicit = "test-secret-aBcD";
    const canonical = `nvapi-${"x".repeat(24)}`;
    const text = `explicit=${explicit} canonical=${canonical}`;

    const out = redactString(text, [explicit]);

    expect(out).toContain("[REDACTED]");
    expect(out).toContain("<REDACTED>");
    expect(out).not.toContain(explicit);
    expect(out).not.toContain(canonical);
  });

  it("applies explicit values longest first so a shorter substring cannot expose a longer one", () => {
    const longer = "alpha-beta-gamma";
    const shorter = "alpha";
    const text = `value=${longer}`;

    const out = redactString(text, [shorter, longer]);

    expect(out).toBe("value=[REDACTED]");
    expect(out).not.toContain("-beta-gamma");
    expect(out).not.toContain(shorter);
  });

  it("ignores empty explicit values without throwing", () => {
    const out = redactString("plain text", ["", "  "]);
    expect(out).toBe("plain text");
  });

  it("returns the input unchanged when no explicit values are supplied and no shape matches", () => {
    expect(redactString("nothing sensitive here")).toBe("nothing sensitive here");
    expect(redactString("nothing sensitive here", [])).toBe("nothing sensitive here");
  });

  it("returns empty input verbatim", () => {
    expect(redactString("")).toBe("");
    expect(redactString("", ["anything"])).toBe("");
  });

  it("SecretStore.redact routes through the same entry and unions env-derived and caller-supplied values", () => {
    const envSecret = "env-secret-value";
    const extraSecret = "extra-secret-value";
    const canonical = `ghp_${"y".repeat(36)}`;
    const store = new SecretStore(
      {
        MY_API_KEY: envSecret,
        UNRELATED_VAR: "kept-visible",
      },
      (note?: string): never => {
        throw new Error(note ?? "skipped");
      },
    );

    const text = `env=${envSecret} extra=${extraSecret} canonical=${canonical} keep=kept-visible`;
    const out = store.redact(text, [extraSecret]);

    expect(out).toContain("env=[REDACTED]");
    expect(out).toContain("extra=[REDACTED]");
    expect(out).toContain("canonical=<REDACTED>");
    expect(out).toContain("keep=kept-visible");
    expect(out).not.toContain(envSecret);
    expect(out).not.toContain(extraSecret);
    expect(out).not.toContain(canonical);
  });

  it("redacts fake hosted inference keys from uploaded shell-probe artifacts", async () => {
    const fakeHostedKey = "fake-hosted-inference-key-for-artifact-scan";
    const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "nemoclaw-e2e-artifact-redaction-"));
    const artifacts = new ArtifactSink(path.join(rootDir, "e2e-artifacts/live/redaction-smoke"));
    await artifacts.ensureRoot();
    const secrets = new SecretStore(
      { NVIDIA_INFERENCE_API_KEY: fakeHostedKey },
      (note?: string): never => {
        throw new Error(note ?? "skipped");
      },
    );
    const probe = new ShellProbe({
      artifacts,
      redact: (text, extra) => secrets.redact(text, extra),
      signal: new AbortController().signal,
    });

    const result = await probe.run(
      trustedShellCommand({
        command: "bash",
        args: [
          "-lc",
          "printf 'stdout:%s\\n' \"$NVIDIA_INFERENCE_API_KEY\"; printf 'stderr:%s\\n' \"$NVIDIA_INFERENCE_API_KEY\" >&2",
        ],
        reason: "exercise hosted inference secret redaction in uploaded shell-probe artifacts",
      }),
      {
        artifactName: "hosted-inference-secret-smoke",
        env: { NVIDIA_INFERENCE_API_KEY: fakeHostedKey },
        redactionValues: [fakeHostedKey],
      },
    );
    const uploadedTexts = await Promise.all(
      Object.values(result.artifacts).map((artifactPath) => fs.readFile(artifactPath, "utf8")),
    );

    expect(result.stdout).toContain("[REDACTED]");
    expect(result.stderr).toContain("[REDACTED]");
    expect(uploadedTexts.join("\n")).not.toContain(fakeHostedKey);
    expect(uploadedTexts.join("\n")).toContain("[REDACTED]");

    await fs.rm(rootDir, { recursive: true, force: true });
  });
});
