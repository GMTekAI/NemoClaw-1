// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentDefinition } from "./defs";

type AgentOnboardModule = typeof import("./onboard");
type DockerRunModule = typeof import("../adapters/docker/run");
type DockerImageModule = typeof import("../adapters/docker/image");
type DockerInspectModule = typeof import("../adapters/docker/inspect");
type SandboxBaseImageModule = typeof import("../sandbox-base-image");

/**
 * Build a minimal Hermes agent manifest for base-image provisioning tests.
 */
function makeAgent(overrides: Partial<AgentDefinition> = {}): AgentDefinition {
  return {
    name: "hermes",
    displayName: "Hermes Agent",
    healthProbe: { url: "http://127.0.0.1:8642/health", port: 8642, timeout_seconds: 90 },
    forwardPort: 8642,
    dashboard: {
      kind: "api",
      label: "OpenAI-compatible API",
      path: "/v1",
      healthPath: "/health",
      auth: "none",
    },
    webAuth: { method: "bearer_token", env: "API_SERVER_KEY" },
    configPaths: {
      dir: "/sandbox/.hermes",
      configFile: "config.yaml",
      envFile: ".env",
      format: "yaml",
    },
    inferenceProviderOptions: [],
    mcpCapability: {
      support: "disabled",
      reason: "test fixture",
    },
    stateDirs: [],
    stateFiles: [],
    userManagedFiles: [],
    versionCommand: "hermes --version",
    expectedVersion: "2026.4.30",
    hasDevicePairing: false,
    phoneHomeHosts: [],
    dockerfileBasePath: "/test/root/agents/hermes/Dockerfile.base",
    dockerfilePath: "/test/root/agents/hermes/Dockerfile",
    startScriptPath: null,
    policyAdditionsPath: null,
    policyPermissivePath: null,
    pluginDir: null,
    legacyPaths: null,
    agentDir: "/repo/root/agents/hermes",
    manifestPath: "/repo/root/agents/hermes/manifest.yaml",
    ...overrides,
  };
}

/**
 * Load `agent-onboard` with Docker helpers replaced by Vitest mocks.
 */
function withMockedDocker<T>(
  run: (deps: {
    ensureAgentBaseImage: AgentOnboardModule["ensureAgentBaseImage"];
    dockerBuildMock: ReturnType<typeof vi.fn>;
    dockerCaptureMock: ReturnType<typeof vi.fn>;
    dockerImageInspectMock: ReturnType<typeof vi.fn>;
    resolveSandboxBaseImageMock: ReturnType<typeof vi.fn>;
    root: string;
  }) => T,
): T {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const dockerRunModule = require("../adapters/docker/run") as DockerRunModule;
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const dockerImageModule = require("../adapters/docker/image") as DockerImageModule;
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const dockerInspectModule = require("../adapters/docker/inspect") as DockerInspectModule;
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const sandboxBaseImageModule = require("../sandbox-base-image") as SandboxBaseImageModule;
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const runnerModule = require("../runner") as { ROOT: string };
  const originalDockerCapture = dockerRunModule.dockerCapture;
  const originalDockerBuild = dockerImageModule.dockerBuild;
  const originalDockerImageInspect = dockerInspectModule.dockerImageInspect;
  const originalResolveSandboxBaseImage = sandboxBaseImageModule.resolveSandboxBaseImage;
  const agentOnboardModulePath = require.resolve("./onboard");
  delete require.cache[agentOnboardModulePath];

  const dockerCaptureMock = vi.fn().mockReturnValue("nemoclaw-hermes-mcp-runtime-ok");
  const dockerBuildMock = vi.fn().mockReturnValue({ status: 0 });
  const dockerImageInspectMock = vi.fn();
  const resolveSandboxBaseImageMock = vi.fn().mockReturnValue({
    ref: "ghcr.io/nvidia/nemoclaw/hermes-sandbox-base:compatible",
    digest: null,
    source: "source-sha",
    glibcVersion: process.platform === "linux" ? "2.41" : null,
  });
  dockerRunModule.dockerCapture = dockerCaptureMock as DockerRunModule["dockerCapture"];
  dockerImageModule.dockerBuild = dockerBuildMock as DockerImageModule["dockerBuild"];
  dockerInspectModule.dockerImageInspect =
    dockerImageInspectMock as DockerInspectModule["dockerImageInspect"];
  sandboxBaseImageModule.resolveSandboxBaseImage =
    resolveSandboxBaseImageMock as SandboxBaseImageModule["resolveSandboxBaseImage"];

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const agentOnboardModule = require("./onboard") as AgentOnboardModule;
    return run({
      ensureAgentBaseImage: agentOnboardModule.ensureAgentBaseImage,
      dockerBuildMock,
      dockerCaptureMock,
      dockerImageInspectMock,
      resolveSandboxBaseImageMock,
      root: runnerModule.ROOT,
    });
  } finally {
    dockerRunModule.dockerCapture = originalDockerCapture;
    dockerImageModule.dockerBuild = originalDockerBuild;
    dockerInspectModule.dockerImageInspect = originalDockerImageInspect;
    sandboxBaseImageModule.resolveSandboxBaseImage = originalResolveSandboxBaseImage;
    delete require.cache[agentOnboardModulePath];
  }
}

describe("agent base image provisioning", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("reuses a compatible resolved agent base image during normal onboarding", () => {
    withMockedDocker(
      ({
        ensureAgentBaseImage,
        dockerBuildMock,
        dockerImageInspectMock,
        resolveSandboxBaseImageMock,
        root,
      }) => {
        const result = ensureAgentBaseImage(makeAgent());

        expect(result).toEqual({
          imageTag: "ghcr.io/nvidia/nemoclaw/hermes-sandbox-base:compatible",
          built: false,
        });
        expect(resolveSandboxBaseImageMock).toHaveBeenCalledWith(
          expect.objectContaining({
            imageName: "ghcr.io/nvidia/nemoclaw/hermes-sandbox-base",
            dockerfilePath: "/test/root/agents/hermes/Dockerfile.base",
            envVar: "NEMOCLAW_HERMES_SANDBOX_BASE_IMAGE_REF",
            label: "Hermes Agent sandbox base image",
            requireOpenshellSandboxAbi: process.platform === "linux",
            rootDir: root,
            validateImage: expect.any(Function),
            validationDescription: "the required MCP Streamable HTTP runtime",
          }),
        );
        expect(dockerImageInspectMock).not.toHaveBeenCalled();
        expect(dockerBuildMock).not.toHaveBeenCalled();
      },
    );
  });

  it("probes resolved Hermes bases for the native MCP Streamable HTTP runtime", () => {
    withMockedDocker(({ ensureAgentBaseImage, dockerCaptureMock, resolveSandboxBaseImageMock }) => {
      ensureAgentBaseImage(makeAgent());
      const options = resolveSandboxBaseImageMock.mock.calls[0]?.[0] as {
        validateImage?: (imageRef: string) => boolean;
      };

      expect(options.validateImage?.("hermes-base:test")).toBe(true);
      expect(dockerCaptureMock).toHaveBeenCalledWith(
        [
          "run",
          "--rm",
          "--entrypoint",
          "/opt/hermes/.venv/bin/python",
          "hermes-base:test",
          "-c",
          expect.stringContaining("_MCP_HTTP_AVAILABLE"),
        ],
        { ignoreError: true, timeout: 20_000 },
      );

      dockerCaptureMock.mockReturnValue("");
      expect(options.validateImage?.("hermes-base:stale")).toBe(false);
    });
  });

  it("rebuilds an agent base image when rebuild flow forces local Dockerfile.base refresh", () => {
    withMockedDocker(
      ({
        ensureAgentBaseImage,
        dockerBuildMock,
        dockerImageInspectMock,
        resolveSandboxBaseImageMock,
        root,
      }) => {
        dockerImageInspectMock.mockReturnValue({ status: 0 });

        const result = ensureAgentBaseImage(makeAgent(), { forceBaseImageRebuild: true });

        expect(result).toEqual({
          imageTag: "ghcr.io/nvidia/nemoclaw/hermes-sandbox-base:latest",
          built: true,
        });
        expect(resolveSandboxBaseImageMock).not.toHaveBeenCalled();
        expect(dockerImageInspectMock).not.toHaveBeenCalled();
        expect(dockerBuildMock).toHaveBeenCalledWith(
          "/test/root/agents/hermes/Dockerfile.base",
          "ghcr.io/nvidia/nemoclaw/hermes-sandbox-base:latest",
          root,
          { ignoreError: true, stdio: ["ignore", "inherit", "inherit"] },
        );
      },
    );
  });

  it("throws when a forced agent base image rebuild fails", () => {
    withMockedDocker(({ ensureAgentBaseImage, dockerBuildMock, resolveSandboxBaseImageMock }) => {
      dockerBuildMock.mockReturnValue({ status: 23 });

      expect(() => ensureAgentBaseImage(makeAgent(), { forceBaseImageRebuild: true })).toThrow(
        "Failed to build Hermes Agent base image (exit 23)",
      );
      expect(resolveSandboxBaseImageMock).not.toHaveBeenCalled();
    });
  });

  it("builds an agent base image when no resolved image or cached image exists on non-Linux hosts", () => {
    withMockedDocker(
      ({
        ensureAgentBaseImage,
        dockerBuildMock,
        dockerImageInspectMock,
        resolveSandboxBaseImageMock,
      }) => {
        resolveSandboxBaseImageMock.mockReturnValue(null);
        dockerImageInspectMock.mockReturnValue({ status: 1 });

        if (process.platform === "linux") {
          expect(() => ensureAgentBaseImage(makeAgent())).toThrow(
            "No compatible Hermes Agent sandbox base image found",
          );
          expect(dockerBuildMock).not.toHaveBeenCalled();
          return;
        }

        const result = ensureAgentBaseImage(makeAgent());

        expect(result.built).toBe(true);
        expect(dockerBuildMock).toHaveBeenCalledOnce();
      },
    );
  });
});
