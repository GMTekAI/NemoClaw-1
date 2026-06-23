// @ts-nocheck
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Mattermost's upstream OpenClaw extension calls fetchWithSsrFGuard in strict
// mode. In OpenShell/NemoClaw sandboxes, strict mode can fail before proxy
// egress because local DNS resolution is intentionally unavailable for some
// operator-routed hosts. Patch only the Mattermost guarded fetch call sites to
// keep hostname SSRF checks while delegating DNS resolution to the trusted env
// proxy.

(function () {
  "use strict";

  var PATCH_MARKER = "__nemoclawMattermostTrustedEnvProxyPatchInstalled";
  var MODE_PROPERTY = 'mode: "trusted_env_proxy",';
  var AUDIT_CONTEXTS = ["mattermost-api", "mattermost-probe"];

  if (process[PATCH_MARKER]) return;
  try {
    Object.defineProperty(process, PATCH_MARKER, { value: true });
  } catch (_e) {
    process[PATCH_MARKER] = true;
  }

  function isOpenClawDistFile(filename) {
    var normalized = String(filename || "").replace(/\\/g, "/");
    return normalized.indexOf("/openclaw/dist/") !== -1 && normalized.endsWith(".js");
  }

  function countMatches(source, pattern) {
    var count = 0;
    var match;
    pattern.lastIndex = 0;
    while ((match = pattern.exec(source)) !== null) count += 1;
    return count;
  }

  function patchAuditContext(source, filename, context) {
    var auditPattern = new RegExp("auditContext\\s*:\\s*[\"']" + context + "[\"']", "g");
    var matches = countMatches(source, auditPattern);
    if (matches === 0) return source;
    if (matches > 1) {
      throw new Error(
        "OpenClaw Mattermost trusted env-proxy patch shape not recognized in " +
          filename +
          "; expected one " +
          context +
          " audit context",
      );
    }

    auditPattern.lastIndex = 0;
    var match = auditPattern.exec(source);
    if (!match) return source;

    var auditIndex = match.index;
    var callStart = source.lastIndexOf("fetchWithSsrFGuard({", auditIndex);
    if (callStart === -1) {
      throw new Error(
        "OpenClaw Mattermost trusted env-proxy patch shape not recognized in " +
          filename +
          "; expected fetchWithSsrFGuard object before " +
          context,
      );
    }

    var prefix = source.slice(callStart, auditIndex);
    var existingMode = prefix.match(/mode\s*:\s*["']([^"']+)["']/);
    if (existingMode) {
      if (existingMode[1] === "trusted_env_proxy") return source;
      throw new Error(
        "OpenClaw Mattermost trusted env-proxy patch found unexpected guarded-fetch mode in " +
          filename +
          " for " +
          context,
      );
    }

    if (prefix.indexOf("policy:") !== -1) {
      throw new Error(
        "OpenClaw Mattermost trusted env-proxy patch shape not recognized in " +
          filename +
          "; expected policy after auditContext for " +
          context,
      );
    }

    var lineStart = source.lastIndexOf("\n", auditIndex) + 1;
    var indentMatch = source.slice(lineStart, auditIndex).match(/^\s*/);
    var indent = indentMatch ? indentMatch[0] : "";
    return source.slice(0, auditIndex) + indent + MODE_PROPERTY + "\n" + source.slice(auditIndex);
  }

  function patchMattermostGuardedFetchSource(source, filename) {
    var next = source;
    for (var i = 0; i < AUDIT_CONTEXTS.length; i++) {
      next = patchAuditContext(next, filename, AUDIT_CONTEXTS[i]);
    }
    return next;
  }

  function fileNameFromModuleUrl(urlValue) {
    if (typeof urlValue !== "string" || !urlValue.startsWith("file:")) return "";
    try {
      return require("url").fileURLToPath(urlValue);
    } catch (_e) {
      return "";
    }
  }

  function sourceToText(source) {
    if (typeof source === "string") return source;
    if (typeof Buffer !== "undefined") {
      if (Buffer.isBuffer(source)) return source.toString("utf8");
      if (source instanceof Uint8Array) return Buffer.from(source).toString("utf8");
      if (source instanceof ArrayBuffer) return Buffer.from(source).toString("utf8");
    }
    return null;
  }

  function installPatch() {
    var Module = require("module");
    var fs = require("fs");
    var originalJsLoader = Module._extensions && Module._extensions[".js"];
    if (typeof originalJsLoader === "function") {
      Module._extensions[".js"] = function nemoclawMattermostTrustedEnvProxyJsLoader(
        mod,
        filename,
      ) {
        if (isOpenClawDistFile(filename)) {
          var source = fs.readFileSync(filename, "utf8");
          var patched = patchMattermostGuardedFetchSource(source, filename);
          if (patched !== source) {
            return mod._compile(patched, filename);
          }
        }
        return originalJsLoader.apply(this, arguments);
      };
    }

    if (typeof Module.registerHooks === "function") {
      Module.registerHooks({
        load: function nemoclawMattermostTrustedEnvProxyLoadHook(urlValue, context, nextLoad) {
          var result = nextLoad(urlValue, context);
          var filename = fileNameFromModuleUrl(urlValue);
          if (!isOpenClawDistFile(filename)) return result;
          var sourceText = sourceToText(result && result.source);
          if (sourceText === null) return result;
          var patched = patchMattermostGuardedFetchSource(sourceText, filename);
          if (patched === sourceText) return result;
          return Object.assign({}, result, { source: patched });
        },
      });
    }
  }

  installPatch();
})();
