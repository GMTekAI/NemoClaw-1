// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { createRequire } from "node:module";

import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from "vitest";

type RunSandboxDoctor =
  typeof import("../../../../dist/lib/actions/sandbox/doctor")["runSandboxDoctor"];

const requireDist = createRequire(import.meta.url);
const doctorModulePath = "../../../../dist/lib/actions/sandbox/doctor.js";

function createDoctorHarness(): {
  captureHostCommandSpy: MockInstance;
  getSandboxSpy: MockInstance;
  logSpy: MockInstance;
  repairMutableConfigPermsSpy: MockInstance;
  runSandboxDoctor: RunSandboxDoctor;
} {
  delete require.cache[requireDist.resolve(doctorModulePath)];

  const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  vi.spyOn(console, "error").mockImplementation(() => undefined);

  const resolve = requireDist("../../../../dist/lib/adapters/openshell/resolve.js");
  const runtime = requireDist("../../../../dist/lib/adapters/openshell/runtime.js");
  const agentDefs = requireDist("../../../../dist/lib/agent/defs.js");
  const agentRuntime = requireDist("../../../../dist/lib/agent/runtime.js");
  const gatewayRuntime = requireDist("../../../../dist/lib/gateway-runtime-action.js");
  const health = requireDist("../../../../dist/lib/inference/health.js");
  const dockerDriverPlatform = requireDist(
    "../../../../dist/lib/onboard/docker-driver-platform.js",
  );
  const gatewayBinding = requireDist("../../../../dist/lib/onboard/gateway-binding.js");
  const sandboxVerificationExec = requireDist(
    "../../../../dist/lib/onboard/sandbox-verification-exec.js",
  );
  const sandboxVersion = requireDist("../../../../dist/lib/sandbox/version.js");
  const shields = requireDist("../../../../dist/lib/shields/index.js");
  const registry = requireDist("../../../../dist/lib/state/registry.js");
  const statusCommandDeps = requireDist("../../../../dist/lib/status-command-deps.js");
  const tunnelServices = requireDist("../../../../dist/lib/tunnel/services.js");
  const doctorHostCommand = requireDist(
    "../../../../dist/lib/actions/sandbox/doctor-host-command.js",
  );
  const doctorToolScope = requireDist("../../../../dist/lib/actions/sandbox/doctor-tool-scope.js");
  const processRecovery = requireDist("../../../../dist/lib/actions/sandbox/process-recovery.js");

  const getSandboxSpy = vi.spyOn(registry, "getSandbox").mockReturnValue({
    name: "alpha",
    agent: "openclaw",
    model: "registry-model",
    provider: "ollama-local",
    openshellDriver: "docker",
    gatewayName: "nemoclaw-19080",
    gatewayPort: 19080,
    messaging: undefined,
  });
  vi.spyOn(registry, "getConfiguredMessagingChannelsFromEntry").mockReturnValue([]);
  vi.spyOn(registry, "getDisabledMessagingChannelsFromEntry").mockReturnValue([]);
  vi.spyOn(resolve, "resolveOpenshell").mockReturnValue("/usr/bin/openshell");
  vi.spyOn(gatewayBinding, "resolveSandboxGatewayName").mockReturnValue("nemoclaw-19080");
  vi.spyOn(gatewayBinding, "resolveGatewayName").mockReturnValue("nemoclaw-19080");
  vi.spyOn(dockerDriverPlatform, "isLinuxDockerDriverGatewayEnabled").mockReturnValue(true);
  vi.spyOn(gatewayRuntime, "recoverNamedGatewayRuntime").mockResolvedValue({
    before: { state: "healthy_named", status: "Status: Connected", gatewayInfo: "" },
    after: { state: "healthy_named", status: "Status: Connected", gatewayInfo: "" },
    recovered: false,
  });
  vi.spyOn(runtime, "captureOpenshell").mockImplementation((args: unknown) => {
    const argv = Array.isArray(args) ? args : [];
    if (argv[0] === "sandbox" && argv[1] === "list") {
      return { status: 0, output: "alpha Ready" };
    }
    if (argv[0] === "inference" && argv[1] === "get") {
      return { status: 0, output: "Provider: ollama-local\nModel: live-model\n" };
    }
    return { status: 0, output: "" };
  });
  const captureHostCommandSpy = vi
    .spyOn(doctorHostCommand, "captureHostCommand")
    .mockImplementation((command: unknown) => {
      if (command === "docker") return { status: 0, stdout: "25.0.0\n", stderr: "" };
      if (command === "curl") {
        return { status: 0, stdout: JSON.stringify({ models: [{ name: "m" }] }), stderr: "" };
      }
      return { status: 0, stdout: "", stderr: "" };
    });
  vi.spyOn(health, "probeProviderHealth").mockReturnValue({
    ok: true,
    probed: true,
    providerLabel: "Ollama",
    endpoint: "http://127.0.0.1:11434/v1/chat/completions",
    detail: "healthy",
  });
  vi.spyOn(processRecovery, "probeSandboxInferenceGatewayHealth").mockResolvedValue({
    ok: false,
    endpoint: "http://127.0.0.1:19000/v1/chat/completions",
    detail: "gateway refused connection",
  });
  vi.spyOn(agentDefs, "loadAgent").mockReturnValue({
    name: "openclaw",
    configPaths: { dir: "/sandbox/.openclaw", configFile: "openclaw.json", format: "json" },
  });
  vi.spyOn(agentRuntime, "getSessionAgent").mockReturnValue({ name: "openclaw" });
  vi.spyOn(agentRuntime, "getAgentDisplayName").mockReturnValue("OpenClaw");
  vi.spyOn(sandboxVersion, "checkAgentVersion").mockReturnValue({
    sandboxVersion: "0.1.0",
    expectedVersion: "0.2.0",
    isStale: true,
  });
  vi.spyOn(shields, "getShieldsPosture").mockReturnValue({
    mode: "temporarily_unlocked",
    detail: "temporarily unlocked for maintenance",
  });
  vi.spyOn(shields, "inspectMutableConfigPerms").mockReturnValue({
    applies: true,
    ok: true,
    dirMode: "2770",
    dirOwner: "sandbox:sandbox",
    fileMode: "660",
    fileOwner: "sandbox:sandbox",
    configDir: "/sandbox/.openclaw",
    configFile: "openclaw.json",
    issues: [],
  });
  const repairMutableConfigPermsSpy = vi
    .spyOn(shields, "repairMutableConfigPerms")
    .mockReturnValue({
      applied: true,
      verified: true,
      errors: [],
    });
  vi.spyOn(statusCommandDeps, "buildStatusCommandDeps").mockReturnValue({});
  vi.spyOn(tunnelServices, "readCloudflaredState").mockReturnValue({ kind: "running", pid: 1234 });
  vi.spyOn(sandboxVerificationExec, "executeSandboxCommandForVerification").mockReturnValue({
    status: 0,
    stdout: "ok",
    stderr: "",
  });
  vi.spyOn(doctorToolScope, "buildToolScopeChecks").mockReturnValue([
    {
      group: "Sandbox",
      label: "Tool scope approvals",
      status: "ok",
      detail: "no pending approvals",
    },
  ]);

  logSpy.mockClear();

  return {
    captureHostCommandSpy,
    getSandboxSpy,
    logSpy,
    repairMutableConfigPermsSpy,
    runSandboxDoctor: requireDist(doctorModulePath).runSandboxDoctor,
  };
}

type TelegramInputOverride = {
  inputId: string;
  value?: unknown;
};

function telegramDoctorPlan(options: {
  agent: "openclaw" | "hermes";
  inputs?: ReadonlyArray<TelegramInputOverride>;
}) {
  return {
    schemaVersion: 1 as const,
    sandboxName: "alpha",
    agent: options.agent,
    workflow: "onboard" as const,
    channels: [
      {
        channelId: "telegram",
        displayName: "telegram",
        authMode: "token-paste" as const,
        active: true,
        selected: true,
        configured: true,
        disabled: false,
        inputs: (options.inputs ?? []).map((override) => ({
          channelId: "telegram",
          inputId: override.inputId,
          kind: "config" as const,
          required: false,
          ...(override.value === undefined ? {} : { value: override.value }),
        })),
        hooks: [],
      },
    ],
    disabledChannels: [],
    credentialBindings: [],
    networkPolicy: { presets: [], entries: [] },
    agentRender: [],
    buildSteps: [],
    stateUpdates: [],
    healthChecks: [],
  };
}

function mockTelegramDoctorRegistry(options: {
  agent: "openclaw" | "hermes";
  inputs?: ReadonlyArray<TelegramInputOverride>;
}): void {
  const registry = requireDist("../../../../dist/lib/state/registry.js");
  vi.spyOn(registry, "getConfiguredMessagingChannelsFromEntry").mockReturnValue(["telegram"]);
  vi.spyOn(registry, "getDisabledMessagingChannelsFromEntry").mockReturnValue([]);
  vi.spyOn(registry, "getMessagingPlanFromEntry").mockReturnValue(telegramDoctorPlan(options));
}

describe("runSandboxDoctor flow", () => {
  let exitSpy: MockInstance;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number | string | null) => {
      throw new Error(`process.exit(${code ?? 0})`);
    }) as never);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete require.cache[requireDist.resolve(doctorModulePath)];
  });

  it("builds a JSON report with host, gateway, sandbox, inference, messaging, and local-service checks", async () => {
    const harness = createDoctorHarness();

    const report = await harness.runSandboxDoctor("alpha", ["--json"], { quietJson: true });

    expect(report).toMatchObject({
      schemaVersion: 1,
      sandbox: "alpha",
      status: "fail",
    });
    expect(report?.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ group: "Host", label: "Docker daemon", status: "ok" }),
        expect.objectContaining({ group: "Gateway", label: "OpenShell status", status: "ok" }),
        expect.objectContaining({ group: "Sandbox", label: "Live sandbox", status: "ok" }),
        expect.objectContaining({ group: "Inference", label: "Provider health", status: "ok" }),
        expect.objectContaining({
          group: "Inference",
          label: "Provider health (gateway)",
          status: "fail",
        }),
        expect.objectContaining({ group: "Messaging", label: "Channels", status: "info" }),
        expect.objectContaining({ group: "Local services", label: "Ollama", status: "ok" }),
        expect.objectContaining({
          group: "Local services",
          label: "cloudflared",
          status: "ok",
        }),
      ]),
    );
    expect(exitSpy).not.toHaveBeenCalled();
    expect(harness.logSpy).not.toHaveBeenCalled();
  });

  it("surfaces Telegram visible config inputs in the Messaging doctor section", async () => {
    const harness = createDoctorHarness();
    mockTelegramDoctorRegistry({
      agent: "openclaw",
      inputs: [{ inputId: "requireMention", value: "0" }],
    });

    const report = await harness.runSandboxDoctor("alpha", ["--json"], { quietJson: true });

    expect(report?.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          group: "Messaging",
          label: "Telegram group mention mode",
          status: "ok",
          detail: "all group messages (TELEGRAM_REQUIRE_MENTION=0)",
        }),
        expect.objectContaining({
          group: "Messaging",
          label: "Telegram group policy",
          status: "info",
          detail: "open (default)",
        }),
      ]),
    );
    const messagingChecks = (report?.checks ?? []).filter((check) => check.group === "Messaging");
    const sensitiveLabels = ["Bot Token", "User ID", "secret"];
    const leakedLabel = messagingChecks.find((check) =>
      sensitiveLabels.some((sensitive) =>
        check.label.toLowerCase().includes(sensitive.toLowerCase()),
      ),
    );
    expect(leakedLabel).toBeUndefined();
  });

  it("hides the OpenClaw-only Telegram group policy when the sandbox runs Hermes", async () => {
    const harness = createDoctorHarness();
    harness.getSandboxSpy.mockReturnValue({
      name: "alpha",
      agent: "hermes",
      model: "registry-model",
      provider: "ollama-local",
      openshellDriver: "docker",
      gatewayName: "nemoclaw-19080",
      gatewayPort: 19080,
      messaging: undefined,
    });
    mockTelegramDoctorRegistry({ agent: "hermes" });

    const report = await harness.runSandboxDoctor("alpha", ["--json"], { quietJson: true });
    const messagingChecks = (report?.checks ?? []).filter((check) => check.group === "Messaging");

    expect(messagingChecks.some((check) => check.label === "Telegram group policy")).toBe(false);
    expect(
      messagingChecks.find((check) => check.label === "Telegram group mention mode"),
    ).toMatchObject({ status: "info", detail: "mention-only (default)" });
  });

  it("falls back to OpenClaw visible config when a legacy SandboxEntry omits the agent field", async () => {
    const harness = createDoctorHarness();
    harness.getSandboxSpy.mockReturnValue({
      name: "alpha",
      model: "registry-model",
      provider: "ollama-local",
      openshellDriver: "docker",
      gatewayName: "nemoclaw-19080",
      gatewayPort: 19080,
      messaging: undefined,
    });
    mockTelegramDoctorRegistry({ agent: "openclaw" });

    const report = await harness.runSandboxDoctor("alpha", ["--json"], { quietJson: true });
    const messagingChecks = (report?.checks ?? []).filter((check) => check.group === "Messaging");

    expect(messagingChecks.find((check) => check.label === "Telegram group policy")).toMatchObject({
      status: "info",
      detail: "open (default)",
    });
    expect(
      messagingChecks.find((check) => check.label === "Telegram group mention mode"),
    ).toMatchObject({ status: "info", detail: "mention-only (default)" });
  });

  it("flags an invalid persisted Telegram group policy without echoing the raw value", async () => {
    const harness = createDoctorHarness();
    mockTelegramDoctorRegistry({
      agent: "openclaw",
      inputs: [{ inputId: "groupPolicy", value: "definitely-not-a-policy" }],
    });

    const report = await harness.runSandboxDoctor("alpha", ["--json"], { quietJson: true });
    const policyCheck = (report?.checks ?? []).find(
      (check) => check.group === "Messaging" && check.label === "Telegram group policy",
    );

    expect(policyCheck).toBeDefined();
    expect(policyCheck?.status).toBe("warn");
    expect(policyCheck?.detail).toMatch(
      /invalid persisted value \(expected: open \| allowlist \| disabled\)/,
    );
    expect(policyCheck?.detail).not.toContain("definitely-not-a-policy");
  });

  it("flags a present-but-empty Telegram mention-mode value as invalid rather than defaulting", async () => {
    const harness = createDoctorHarness();
    mockTelegramDoctorRegistry({
      agent: "openclaw",
      inputs: [{ inputId: "requireMention", value: "" }],
    });

    const report = await harness.runSandboxDoctor("alpha", ["--json"], { quietJson: true });
    const mentionCheck = (report?.checks ?? []).find(
      (check) => check.group === "Messaging" && check.label === "Telegram group mention mode",
    );

    expect(mentionCheck).toBeDefined();
    expect(mentionCheck?.status).toBe("warn");
    expect(mentionCheck?.detail).toMatch(/invalid persisted value/);
    expect(mentionCheck?.detail).not.toMatch(/default/);
  });

  it("surfaces Telegram visible config from a plan compiled out of process env through doctor", async () => {
    const harness = createDoctorHarness();
    const channelsModule = requireDist("../../../../dist/lib/messaging/channels/index.js");
    const hooksModule = requireDist("../../../../dist/lib/messaging/hooks/index.js");
    const plannerModule = requireDist(
      "../../../../dist/lib/messaging/compiler/workflow-planner.js",
    );
    const TELEGRAM_TOKEN = "123456:test-telegram-token";
    const planner = new plannerModule.MessagingWorkflowPlanner(
      channelsModule.createBuiltInChannelManifestRegistry(),
      hooksModule.createBuiltInMessagingHookRegistry({
        common: {
          env: {
            TELEGRAM_BOT_TOKEN: TELEGRAM_TOKEN,
            TELEGRAM_GROUP_POLICY: "allowlist",
          },
          getCredential: (key: string) => (key === "TELEGRAM_BOT_TOKEN" ? TELEGRAM_TOKEN : null),
          saveCredential: () => {},
          prompt: async () => "unused",
          log: () => {},
        },
        telegram: {
          fetch: async () => ({
            ok: true,
            status: 200,
            async json() {
              return { ok: true };
            },
            async text() {
              return "";
            },
          }),
        },
      }),
      channelsModule.createBuiltInRenderTemplateResolver(),
    );
    const envOverrides = {
      TELEGRAM_BOT_TOKEN: TELEGRAM_TOKEN,
      TELEGRAM_GROUP_POLICY: "allowlist",
    };
    const previous = Object.fromEntries(
      Object.keys(envOverrides).map((key) => [key, process.env[key]]),
    );
    Object.assign(process.env, envOverrides);
    let compiledPlan;
    try {
      compiledPlan = await planner.buildPlan({
        sandboxName: "alpha",
        agent: "openclaw",
        workflow: "onboard",
        isInteractive: true,
        configuredChannels: ["telegram"],
      });
    } finally {
      for (const [key, value] of Object.entries(previous)) {
        value === undefined ? Reflect.deleteProperty(process.env, key) : (process.env[key] = value);
      }
    }
    const registry = requireDist("../../../../dist/lib/state/registry.js");
    vi.spyOn(registry, "getConfiguredMessagingChannelsFromEntry").mockReturnValue(["telegram"]);
    vi.spyOn(registry, "getDisabledMessagingChannelsFromEntry").mockReturnValue([]);
    vi.spyOn(registry, "getMessagingPlanFromEntry").mockReturnValue(compiledPlan);

    const report = await harness.runSandboxDoctor("alpha", ["--json"], { quietJson: true });
    const messagingChecks = (report?.checks ?? []).filter((check) => check.group === "Messaging");

    expect(messagingChecks.find((check) => check.label === "Telegram group policy")).toMatchObject({
      status: "ok",
      detail: "allowlist",
    });
    expect(
      messagingChecks.find((check) => check.label === "Telegram group mention mode"),
    ).toMatchObject({
      status: "ok",
      detail: "mention-only (TELEGRAM_REQUIRE_MENTION=1)",
    });
  });

  it("rejects mutating --fix when JSON output was requested", async () => {
    const harness = createDoctorHarness();

    await expect(harness.runSandboxDoctor("alpha", ["--json", "--fix"])).rejects.toThrow(
      "process.exit(1)",
    );

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(harness.getSandboxSpy).not.toHaveBeenCalled();
    expect(harness.captureHostCommandSpy).not.toHaveBeenCalled();
    expect(harness.repairMutableConfigPermsSpy).not.toHaveBeenCalled();
  });
});
