// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { createBuiltInChannelManifestRegistry } from "./channels";
import type {
  ChannelInputSpec,
  ChannelManifest,
  ChannelPolicyPresetReference,
  MessagingAgentId,
  MessagingSerializableValue,
} from "./manifest";

export interface MessagingChannelDiagnosticSpec {
  readonly channelId: string;
  readonly policyPresets: readonly string[];
  readonly preferredDefault: boolean;
  readonly deepProbe?: "in-sandbox-qr";
  readonly doctorWhenNoHealthSignals?: {
    readonly detail: string;
    readonly hint: string;
  };
  readonly visibleConfigInputs: readonly VisibleChannelConfigInput[];
}

export interface VisibleChannelConfigInput {
  readonly inputId: string;
  readonly label: string;
  readonly envKey?: string;
  readonly defaultValue?: string;
  readonly validValues?: readonly string[];
  readonly valueDisplay?: Readonly<Record<string, string>>;
}

export function collectBuiltInMessagingChannelDiagnostics(
  options: { readonly agent?: MessagingAgentId } = {},
): MessagingChannelDiagnosticSpec[] {
  return collectMessagingChannelDiagnostics(
    createBuiltInChannelManifestRegistry().listAvailable(
      options.agent ? { agent: options.agent } : undefined,
    ),
  );
}

export function collectMessagingChannelDiagnostics(
  manifests: readonly ChannelManifest[],
): MessagingChannelDiagnosticSpec[] {
  return manifests.map((manifest) => {
    const deepProbe = manifest.auth.mode === "in-sandbox-qr" ? "in-sandbox-qr" : undefined;
    return {
      channelId: manifest.id,
      policyPresets: policyPresetNames(manifest.policyPresets),
      preferredDefault: deepProbe !== undefined,
      ...(deepProbe ? { deepProbe, doctorWhenNoHealthSignals: qrDeepProbeDoctorHint() } : {}),
      visibleConfigInputs: collectVisibleConfigInputs(manifest.inputs),
    };
  });
}

function collectVisibleConfigInputs(
  inputs: readonly ChannelInputSpec[],
): readonly VisibleChannelConfigInput[] {
  return inputs.flatMap((input) => {
    if (input.kind !== "config") return [];
    if (input.safeToPrintInDiagnostics !== true) return [];
    const label = input.prompt?.label;
    if (!label) return [];
    return [
      {
        inputId: input.id,
        label,
        ...(input.envKey ? { envKey: input.envKey } : {}),
        ...(input.defaultValue !== undefined ? { defaultValue: input.defaultValue } : {}),
        ...(input.validValues ? { validValues: [...input.validValues] } : {}),
        ...(input.valueDisplay ? { valueDisplay: { ...input.valueDisplay } } : {}),
      } satisfies VisibleChannelConfigInput,
    ];
  });
}

/**
 * Resolve the diagnostic detail text for one visible config input, given the
 * raw value persisted in the channel plan (or `undefined` when only the
 * manifest default is available). Returns `null` when neither a persisted
 * value nor a default exists so callers can skip the entry rather than emit
 * an empty signal.
 */
export type VisibleConfigDisplay = {
  readonly detail: string;
  readonly source: "persisted" | "default";
};

export function resolveVisibleConfigDisplay(
  input: VisibleChannelConfigInput,
  rawValue: MessagingSerializableValue | undefined,
): VisibleConfigDisplay | null {
  if (rawValue !== undefined && rawValue !== null && rawValue !== "") {
    const valueText = stringifyValue(rawValue);
    const mapped = input.valueDisplay?.[valueText];
    if (mapped && input.envKey) {
      return { detail: `${mapped} (${input.envKey}=${valueText})`, source: "persisted" };
    }
    if (mapped) {
      return { detail: `${mapped} (${valueText})`, source: "persisted" };
    }
    return { detail: valueText, source: "persisted" };
  }
  if (input.defaultValue !== undefined) {
    const mapped = input.valueDisplay?.[input.defaultValue];
    if (mapped) {
      return { detail: `${mapped} (default)`, source: "default" };
    }
    return { detail: `${input.defaultValue} (default)`, source: "default" };
  }
  return null;
}

function stringifyValue(value: MessagingSerializableValue): string {
  if (typeof value === "string") return value;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.map(stringifyValue).join(", ");
  return JSON.stringify(value);
}

function qrDeepProbeDoctorHint(): MessagingChannelDiagnosticSpec["doctorWhenNoHealthSignals"] {
  return {
    detail:
      "{channels} enabled; {channel} inbound delivery is not inferred from conflict signatures{pausedSuffix}",
    hint: "run `{cli} {sandbox} channels status --channel {channel}` to probe inbound delivery",
  };
}

function policyPresetNames(presets: readonly ChannelPolicyPresetReference[] | undefined): string[] {
  return (presets ?? []).map((preset) => (typeof preset === "string" ? preset : preset.name));
}
