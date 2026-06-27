#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[install]${NC} $1"; }
warn() { echo -e "${YELLOW}[install]${NC} $1"; }
fail() {
  echo -e "${RED}[install]${NC} $1" >&2
  exit 1
}

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin) OS_LABEL="macOS" ;;
  Linux) OS_LABEL="Linux" ;;
  *) fail "Unsupported OS: $OS" ;;
esac

case "$ARCH" in
  x86_64 | amd64) ARCH_LABEL="x86_64" ;;
  aarch64 | arm64) ARCH_LABEL="aarch64" ;;
  *) fail "Unsupported architecture: $ARCH" ;;
esac

info "Detected $OS_LABEL ($ARCH_LABEL)"

# Minimum version required for native messaging credential rewrite plus
# MCP/JSON-RPC L7 policy enforcement (NVIDIA/OpenShell#1865).
MIN_VERSION="0.0.72"
# Maximum version validated for this NemoClaw release. Newer OpenShell builds
# may change sandbox semantics; upgrade NemoClaw before upgrading past this.
MAX_VERSION="0.0.72"
# Pin fresh installs to this version. The TS installer normally overrides this
# via NEMOCLAW_OPENSHELL_PIN_VERSION after resolving the highest published
# OpenShell release that satisfies the blueprint's max_openshell_version
# (see #3404). The hardcoded value is the fallback for offline runs.
PIN_VERSION="$MAX_VERSION"
DEV_MIN_VERSION="0.0.44"

CHANNEL="${NEMOCLAW_OPENSHELL_CHANNEL:-auto}"
case "$CHANNEL" in
  stable | dev | artifact | auto) ;;
  *) fail "NEMOCLAW_OPENSHELL_CHANNEL must be one of: stable, dev, artifact, auto" ;;
esac

FORCE_INSTALL="${NEMOCLAW_OPENSHELL_FORCE_INSTALL:-0}"
case "$FORCE_INSTALL" in
  0 | 1) ;;
  *) fail "NEMOCLAW_OPENSHELL_FORCE_INSTALL must be 0 or 1." ;;
esac

if [ "$CHANNEL" = "auto" ]; then
  RESOLVED_CHANNEL="stable"
else
  RESOLVED_CHANNEL="$CHANNEL"
fi

OPENSHELL_ARTIFACT_RUN_ID="${NEMOCLAW_OPENSHELL_ARTIFACT_RUN_ID:-}"
OPENSHELL_ARTIFACT_HEAD_SHA="${NEMOCLAW_OPENSHELL_ARTIFACT_HEAD_SHA:-}"
if [ "$RESOLVED_CHANNEL" = "artifact" ]; then
  if [[ ! "$OPENSHELL_ARTIFACT_RUN_ID" =~ ^[0-9]+$ ]]; then
    fail "NEMOCLAW_OPENSHELL_ARTIFACT_RUN_ID must be set to a numeric NVIDIA/OpenShell Actions run id when NEMOCLAW_OPENSHELL_CHANNEL=artifact."
  fi
  if [[ ! "$OPENSHELL_ARTIFACT_HEAD_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
    fail "NEMOCLAW_OPENSHELL_ARTIFACT_HEAD_SHA must be set to the expected 40-hex NVIDIA/OpenShell commit when NEMOCLAW_OPENSHELL_CHANNEL=artifact."
  fi
  OPENSHELL_ARTIFACT_HEAD_SHA="$(printf '%s' "$OPENSHELL_ARTIFACT_HEAD_SHA" | tr '[:upper:]' '[:lower:]')"
fi

# Honour the TS installer's blueprint-derived env overrides only on the stable
# channel — the dev channel installs from the `dev` tag and uses DEV_MIN_VERSION
# instead, so a malformed override should not abort a dev install (#3446 review).
# The TS layer passes MIN/MAX/PIN from the blueprint so a single source of truth
# (nemoclaw-blueprint/blueprint.yaml) drives the install (#3404).
#
# Validation is inlined (rather than wrapped in a helper that returns via
# $(...)) so a `fail` triggered here is not captured into the variable
# assignment. `fail` now writes to stderr (#3446 CodeRabbit), but keeping
# the validation outside of $(...) avoids relying on that.
if [ "$RESOLVED_CHANNEL" != "dev" ]; then
  if [ -n "${NEMOCLAW_OPENSHELL_MIN_VERSION:-}" ]; then
    if [[ "$NEMOCLAW_OPENSHELL_MIN_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      MIN_VERSION="$NEMOCLAW_OPENSHELL_MIN_VERSION"
    else
      fail "NEMOCLAW_OPENSHELL_MIN_VERSION='$NEMOCLAW_OPENSHELL_MIN_VERSION' is not a valid X.Y.Z version."
    fi
  fi
  if [ -n "${NEMOCLAW_OPENSHELL_MAX_VERSION:-}" ]; then
    if [[ "$NEMOCLAW_OPENSHELL_MAX_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      MAX_VERSION="$NEMOCLAW_OPENSHELL_MAX_VERSION"
      # Intentionally do NOT default PIN_VERSION to the overridden MAX here.
      # If the TS resolver couldn't reach GitHub (rate-limited / offline) it
      # only sets MIN/MAX, never PIN — falling through to the script's
      # hardcoded PIN_VERSION is the known-good safe path (#3446 CodeRabbit).
    else
      fail "NEMOCLAW_OPENSHELL_MAX_VERSION='$NEMOCLAW_OPENSHELL_MAX_VERSION' is not a valid X.Y.Z version."
    fi
  fi
  if [ -n "${NEMOCLAW_OPENSHELL_PIN_VERSION:-}" ]; then
    if [[ "$NEMOCLAW_OPENSHELL_PIN_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      PIN_VERSION="$NEMOCLAW_OPENSHELL_PIN_VERSION"
    else
      fail "NEMOCLAW_OPENSHELL_PIN_VERSION='$NEMOCLAW_OPENSHELL_PIN_VERSION' is not a valid X.Y.Z version."
    fi
  fi
fi

if [ "$RESOLVED_CHANNEL" = "dev" ]; then
  RELEASE_TAG="dev"
else
  RELEASE_TAG="v${PIN_VERSION}"
fi

version_gte() {
  # Returns 0 (true) if $1 >= $2 — portable, no sort -V (BSD compat)
  local IFS=.
  local -a a b
  read -r -a a <<<"$1"
  read -r -a b <<<"$2"
  for i in 0 1 2; do
    local ai=${a[$i]:-0} bi=${b[$i]:-0}
    if ((ai > bi)); then return 0; fi
    if ((ai < bi)); then return 1; fi
  done
  return 0
}

required_driver_bins_present() {
  case "$OS" in
    Linux)
      command -v openshell-gateway >/dev/null 2>&1 && command -v openshell-sandbox >/dev/null 2>&1
      ;;
    Darwin)
      command -v openshell-gateway >/dev/null 2>&1
      ;;
    *)
      return 0
      ;;
  esac
}

OPENSHELL_FEATURE_CHECK_ERROR=""

openshell_required_feature_strings() {
  local openshell_bin="$1"
  local dir resolved name candidate seen candidate_strings binary_strings
  local -a candidates

  candidates=("$openshell_bin")
  dir="$(cd "$(dirname "$openshell_bin")" 2>/dev/null && pwd -P || true)"
  if [ -n "$dir" ]; then
    candidates+=("$dir/openshell-gateway" "$dir/openshell-sandbox" "$dir/openshell-driver-vm")
  fi
  for name in openshell-gateway openshell-sandbox openshell-driver-vm; do
    resolved="$(command -v "$name" 2>/dev/null || true)"
    if [ -n "$resolved" ]; then
      candidates+=("$resolved")
    fi
  done

  seen=":"
  binary_strings=""
  for candidate in "${candidates[@]}"; do
    [ -n "$candidate" ] || continue
    [ -f "$candidate" ] || continue
    case "$seen" in
      *":$candidate:"*) continue ;;
    esac
    seen="${seen}${candidate}:"
    candidate_strings="$(strings "$candidate" 2>/dev/null || true)"
    binary_strings="${binary_strings}
${candidate_strings}"
    if [[ "$binary_strings" == *"request-body-credential-rewrite"* ]] \
      && [[ "$binary_strings" == *"websocket-credential-rewrite"* ]] \
      && [[ "$binary_strings" == *"allow_all_known_mcp_methods"* ]]; then
      break
    fi
  done
  printf '%s\n' "$binary_strings"
}

openshell_has_required_messaging_features() {
  local openshell_bin
  OPENSHELL_FEATURE_CHECK_ERROR=""
  openshell_bin="${1:-$(command -v openshell 2>/dev/null || true)}"
  if [ -z "$openshell_bin" ]; then
    OPENSHELL_FEATURE_CHECK_ERROR="openshell binary was not found."
    return 1
  fi
  if ! command -v strings >/dev/null 2>&1; then
    OPENSHELL_FEATURE_CHECK_ERROR="'strings' is required to verify OpenShell messaging credential rewrite support. Install binutils or an equivalent package and retry."
    return 2
  fi

  # Keep this independent of a live gateway. Some L7 enforcement strings live
  # in the gateway/sandbox sidecars, so inspect the installed OpenShell binary
  # set rather than only the CLI wrapper.
  local binary_strings
  binary_strings="$(openshell_required_feature_strings "$openshell_bin")"
  if [[ "$binary_strings" != *"request-body-credential-rewrite"* ]]; then
    OPENSHELL_FEATURE_CHECK_ERROR="OpenShell installed binaries are missing request-body-credential-rewrite support."
    return 1
  fi
  if [[ "$binary_strings" != *"websocket-credential-rewrite"* ]]; then
    OPENSHELL_FEATURE_CHECK_ERROR="OpenShell installed binaries are missing websocket-credential-rewrite support."
    return 1
  fi
  if [[ "$binary_strings" != *"allow_all_known_mcp_methods"* ]]; then
    OPENSHELL_FEATURE_CHECK_ERROR="OpenShell installed binaries are missing MCP/JSON-RPC L7 policy support."
    return 1
  fi
  return 0
}

require_openshell_messaging_features() {
  local openshell_bin="$1"
  openshell_has_required_messaging_features "$openshell_bin" \
    || fail "${OPENSHELL_FEATURE_CHECK_ERROR:-OpenShell binary is missing required messaging credential rewrite support.}"
}

macos_vm_driver_bin() {
  command -v openshell-driver-vm 2>/dev/null || true
}

macos_vm_driver_has_hypervisor_entitlement() {
  local bin="$1"
  [ "$OS" = "Darwin" ] || return 0
  [ -n "$bin" ] && [ -x "$bin" ] || return 1
  command -v codesign >/dev/null 2>&1 || return 1
  codesign -d --entitlements :- "$bin" 2>/dev/null \
    | grep -q "com.apple.security.hypervisor"
}

sign_macos_vm_driver() {
  local bin="$1"
  local use_sudo="${2:-0}"
  local entitlements

  [ "$OS" = "Darwin" ] || return 0
  [ -n "$bin" ] && [ -x "$bin" ] || return 0

  if macos_vm_driver_has_hypervisor_entitlement "$bin"; then
    return 0
  fi
  command -v codesign >/dev/null 2>&1 \
    || fail "codesign is required to prepare openshell-driver-vm for macOS Hypervisor.framework."

  entitlements="$(mktemp "${TMPDIR:-/tmp}/nemoclaw-openshell-driver-vm-entitlements.XXXXXX.plist")"
  cat >"$entitlements" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.hypervisor</key>
  <true/>
</dict>
</plist>
EOF

  info "Signing openshell-driver-vm with the macOS Hypervisor entitlement..."
  if [ "$use_sudo" = "1" ]; then
    sudo codesign --force --sign - --entitlements "$entitlements" "$bin" \
      || {
        rm -f "$entitlements"
        fail "Failed to sign openshell-driver-vm with the macOS Hypervisor entitlement."
      }
  else
    codesign --force --sign - --entitlements "$entitlements" "$bin" \
      || {
        rm -f "$entitlements"
        fail "Failed to sign openshell-driver-vm with the macOS Hypervisor entitlement."
      }
  fi
  rm -f "$entitlements"

  macos_vm_driver_has_hypervisor_entitlement "$bin" \
    || fail "openshell-driver-vm was signed but the macOS Hypervisor entitlement was not present afterward."
}

repair_existing_macos_vm_driver() {
  local bin
  [ "$OS" = "Darwin" ] || return 0
  bin="$(macos_vm_driver_bin)"
  [ -n "$bin" ] && [ -x "$bin" ] || return 1
  if macos_vm_driver_has_hypervisor_entitlement "$bin"; then
    return 0
  fi

  warn "openshell-driver-vm is missing the macOS Hypervisor entitlement — repairing..."
  if [ -w "$bin" ]; then
    sign_macos_vm_driver "$bin" 0
    return 0
  fi
  if [ "${NEMOCLAW_NON_INTERACTIVE:-}" != "1" ] && [ -t 0 ] && command -v sudo >/dev/null 2>&1; then
    sign_macos_vm_driver "$bin" 1
    return 0
  fi
  return 1
}

ACTIVE_OPENSHELL_BIN=""
if command -v openshell >/dev/null 2>&1; then
  ACTIVE_OPENSHELL_BIN="$(command -v openshell 2>/dev/null || true)"
  INSTALLED_VERSION_OUTPUT="$(openshell --version 2>&1 || true)"
  INSTALLED_VERSION="$(printf '%s\n' "$INSTALLED_VERSION_OUTPUT" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  [ -n "$INSTALLED_VERSION" ] || INSTALLED_VERSION="0.0.0"
  if [ "$RESOLVED_CHANNEL" = "artifact" ]; then
    warn "OpenShell artifact channel requested — installing workflow run ${OPENSHELL_ARTIFACT_RUN_ID} even though openshell is already present."
  elif [ "$RESOLVED_CHANNEL" = "dev" ]; then
    if version_gte "$INSTALLED_VERSION" "$DEV_MIN_VERSION" \
      && printf '%s\n' "$INSTALLED_VERSION_OUTPUT" | grep -qi 'dev'; then
      if openshell_has_required_messaging_features; then
        if [ "$FORCE_INSTALL" != "1" ]; then
          info "openshell already installed: $INSTALLED_VERSION_OUTPUT (dev channel)"
          exit 0
        fi
        warn "Current OpenShell dev build requested — refreshing the moving dev release instead of reusing the installed binary."
      else
        feature_status=$?
        if [ "$feature_status" = "2" ]; then
          fail "$OPENSHELL_FEATURE_CHECK_ERROR"
        fi
      fi
    fi
    if [ "$FORCE_INSTALL" != "1" ]; then
      warn "openshell $INSTALLED_VERSION is not the required dev-channel messaging-rewrite/MCP-L7 build — upgrading..."
    fi
  else
    if version_gte "$INSTALLED_VERSION" "$MIN_VERSION"; then
      if ! version_gte "$MAX_VERSION" "$INSTALLED_VERSION"; then
        warn "openshell $INSTALLED_VERSION is above the maximum ($MAX_VERSION) supported by this NemoClaw release — reinstalling pinned OpenShell ${PIN_VERSION}..."
      elif ! required_driver_bins_present; then
        warn "openshell $INSTALLED_VERSION is missing Docker-driver binaries — reinstalling pinned OpenShell ${PIN_VERSION}..."
      elif ! openshell_has_required_messaging_features; then
        fail "${OPENSHELL_FEATURE_CHECK_ERROR:-openshell $INSTALLED_VERSION is missing required messaging credential rewrite and MCP L7 policy support. Install an OpenShell build that includes provider aliases, WebSocket text rewrite, request-body credential rewrite, and MCP/JSON-RPC L7 policy enforcement.}"
      else
        info "openshell already installed: $INSTALLED_VERSION (>= $MIN_VERSION, <= $MAX_VERSION, messaging rewrite and MCP L7 capable)"
        exit 0
      fi
    else
      warn "openshell $INSTALLED_VERSION is below minimum $MIN_VERSION — upgrading..."
    fi
  fi
fi

if [ "$RESOLVED_CHANNEL" = "artifact" ]; then
  info "Installing OpenShell from OpenShell workflow artifacts run '$OPENSHELL_ARTIFACT_RUN_ID'..."
else
  info "Installing OpenShell from release '$RELEASE_TAG'..."

  case "$OS" in
    Darwin)
      case "$ARCH_LABEL" in
        x86_64) ASSET="openshell-x86_64-apple-darwin.tar.gz" ;;
        aarch64) ASSET="openshell-aarch64-apple-darwin.tar.gz" ;;
      esac
      ;;
    Linux)
      case "$ARCH_LABEL" in
        x86_64) ASSET="openshell-x86_64-unknown-linux-musl.tar.gz" ;;
        aarch64) ASSET="openshell-aarch64-unknown-linux-musl.tar.gz" ;;
      esac
      ;;
  esac

  declare -a ASSETS=("$ASSET")
  declare -a CHECKSUM_FILES=("openshell-checksums-sha256.txt")
  case "$OS" in
    Darwin)
      case "$ARCH_LABEL" in
        aarch64)
          ASSETS+=("openshell-gateway-aarch64-apple-darwin.tar.gz")
          CHECKSUM_FILES+=("openshell-gateway-checksums-sha256.txt")
          ;;
        x86_64)
          fail "OpenShell ${PIN_VERSION} does not publish macOS x86_64 standalone gateway assets."
          ;;
      esac
      ;;
    Linux)
      case "$ARCH_LABEL" in
        x86_64)
          ASSETS+=("openshell-gateway-x86_64-unknown-linux-gnu.tar.gz")
          ASSETS+=("openshell-sandbox-x86_64-unknown-linux-gnu.tar.gz")
          ;;
        aarch64)
          ASSETS+=("openshell-gateway-aarch64-unknown-linux-gnu.tar.gz")
          ASSETS+=("openshell-sandbox-aarch64-unknown-linux-gnu.tar.gz")
          ;;
      esac
      CHECKSUM_FILES+=("openshell-gateway-checksums-sha256.txt")
      CHECKSUM_FILES+=("openshell-sandbox-checksums-sha256.txt")
      ;;
  esac
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

select_sha_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then
    SHA_CMD="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    SHA_CMD="shasum -a 256"
  else
    fail "No SHA-256 tool available (sha256sum/shasum)"
  fi
}

validate_actions_artifact_run() {
  local metadata run_id workflow_id repository head_repository status conclusion event head_sha

  metadata="$(GH_PROMPT_DISABLED=1 GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}" gh api \
    "/repos/NVIDIA/OpenShell/actions/runs/${OPENSHELL_ARTIFACT_RUN_ID}" \
    --jq '[.id, .workflow_id, .repository.full_name, .head_repository.full_name, .status, .conclusion, .event, .head_sha] | map(if . == null then "" else tostring end) | join("|")')" \
    || fail "Failed to resolve OpenShell workflow run ${OPENSHELL_ARTIFACT_RUN_ID}."
  IFS='|' read -r run_id workflow_id repository head_repository status conclusion event head_sha <<<"$metadata"

  [ "$run_id" = "$OPENSHELL_ARTIFACT_RUN_ID" ] \
    || fail "OpenShell workflow run metadata did not match run ${OPENSHELL_ARTIFACT_RUN_ID}."
  [ "$workflow_id" = "246342097" ] \
    || fail "OpenShell workflow run ${OPENSHELL_ARTIFACT_RUN_ID} was not produced by the trusted Branch E2E workflow."
  [ "$repository" = "NVIDIA/OpenShell" ] && [ "$head_repository" = "NVIDIA/OpenShell" ] \
    || fail "OpenShell workflow run ${OPENSHELL_ARTIFACT_RUN_ID} was not produced from NVIDIA/OpenShell."
  [ "$status" = "completed" ] && [ "$conclusion" = "success" ] \
    || fail "OpenShell workflow run ${OPENSHELL_ARTIFACT_RUN_ID} must be completed successfully."
  case "$event" in
    push | workflow_dispatch) ;;
    *) fail "OpenShell workflow run ${OPENSHELL_ARTIFACT_RUN_ID} has unsupported event '$event'." ;;
  esac
  head_sha="$(printf '%s' "$head_sha" | tr '[:upper:]' '[:lower:]')"
  [ "$head_sha" = "$OPENSHELL_ARTIFACT_HEAD_SHA" ] \
    || fail "OpenShell workflow run ${OPENSHELL_ARTIFACT_RUN_ID} head SHA '$head_sha' did not match expected '$OPENSHELL_ARTIFACT_HEAD_SHA'."
}

download_verified_actions_artifact() {
  local artifact_name="$1"
  local binary_name="$2"
  local artifact_dir="$3"
  local metadata total_count returned_count artifact_id resolved_name artifact_digest artifact_expired
  local expected_digest actual_digest zip_path archive_entries entry_mode binary_path

  case "$artifact_name" in
    *[!A-Za-z0-9._-]*)
      fail "Invalid OpenShell artifact name '$artifact_name'."
      ;;
  esac

  metadata="$(GH_PROMPT_DISABLED=1 GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}" gh api --method GET \
    "/repos/NVIDIA/OpenShell/actions/runs/${OPENSHELL_ARTIFACT_RUN_ID}/artifacts" \
    -f "name=${artifact_name}" -F per_page=100 \
    --jq '[.total_count, (.artifacts | length), .artifacts[0].id, .artifacts[0].name, .artifacts[0].digest, .artifacts[0].expired] | map(if . == null then "" else tostring end) | join("|")')" \
    || fail "Failed to resolve OpenShell artifact metadata for '$artifact_name'."
  IFS='|' read -r total_count returned_count artifact_id resolved_name artifact_digest artifact_expired <<<"$metadata"
  [ "$total_count" = "1" ] && [ "$returned_count" = "1" ] \
    || fail "Expected exactly one OpenShell artifact named '$artifact_name' in workflow run ${OPENSHELL_ARTIFACT_RUN_ID}, found ${total_count:-0}."
  [ "$resolved_name" = "$artifact_name" ] \
    || fail "OpenShell artifact metadata name '$resolved_name' did not match expected '$artifact_name'."
  [[ "$artifact_id" =~ ^[0-9]+$ ]] \
    || fail "OpenShell artifact '$artifact_name' has an invalid artifact id."
  [ "$artifact_expired" = "false" ] \
    || fail "OpenShell artifact '$artifact_name' from run ${OPENSHELL_ARTIFACT_RUN_ID} is expired or has invalid expiry metadata."
  [[ "$artifact_digest" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail "OpenShell artifact '$artifact_name' is missing valid GitHub SHA-256 digest metadata."
  expected_digest="${artifact_digest#sha256:}"

  zip_path="$tmpdir/${artifact_name}.zip"
  GH_PROMPT_DISABLED=1 GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}" gh api \
    "/repos/NVIDIA/OpenShell/actions/artifacts/${artifact_id}/zip" >"$zip_path" \
    || fail "Failed to download OpenShell artifact archive '$artifact_name' from run ${OPENSHELL_ARTIFACT_RUN_ID}."
  actual_digest="$($SHA_CMD "$zip_path" | awk '{ print tolower($1) }')"
  [ "$actual_digest" = "$expected_digest" ] \
    || fail "OpenShell artifact '$artifact_name' digest mismatch. Expected ${expected_digest}, got ${actual_digest}."

  archive_entries="$(unzip -Z -1 "$zip_path")" \
    || fail "Failed to inspect OpenShell artifact archive '$artifact_name'."
  [ "$archive_entries" = "$binary_name" ] \
    || fail "OpenShell artifact '$artifact_name' must contain exactly one root file named '$binary_name'."
  entry_mode="$(unzip -Z -s "$zip_path" "$binary_name" | awk 'NR == 1 { print $1 }')" \
    || fail "Failed to inspect OpenShell artifact entry '$binary_name'."
  case "$entry_mode" in
    -*) ;;
    *) fail "OpenShell artifact '$artifact_name' entry '$binary_name' is not a regular file." ;;
  esac

  mkdir -p "$artifact_dir"
  binary_path="$artifact_dir/$binary_name"
  unzip -p "$zip_path" "$binary_name" >"$binary_path" \
    || fail "Failed to extract OpenShell artifact entry '$binary_name'."
  [ -s "$binary_path" ] \
    || fail "OpenShell artifact '$artifact_name' entry '$binary_name' is empty."
  chmod 755 "$binary_path"
}

clear_github_token_environment() {
  unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_RUNTIME_TOKEN
  unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN
  unset NEMOCLAW_INSTALL_OPENSHELL_GH_TOKEN
}

download_from_actions_artifacts() {
  local cli_artifact gateway_artifact sandbox_artifact

  [ "$OS" = "Linux" ] \
    || fail "OpenShell artifact channel currently supports Linux runners only."
  [ "$ARCH_LABEL" = "x86_64" ] \
    || fail "OpenShell artifact channel currently supports Linux x86_64 runners only."
  command -v gh >/dev/null 2>&1 \
    || fail "gh CLI is required to install OpenShell from workflow artifacts."
  command -v unzip >/dev/null 2>&1 \
    || fail "unzip is required to install OpenShell from workflow artifacts."
  select_sha_cmd

  validate_actions_artifact_run

  cli_artifact="rust-binary-cli-cli-linux-amd64"
  gateway_artifact="rust-binary-gateway-gateway-linux-amd64"
  sandbox_artifact="rust-binary-supervisor-sandbox-linux-amd64"

  info "Downloading OpenShell workflow artifacts from run ${OPENSHELL_ARTIFACT_RUN_ID}..."
  download_verified_actions_artifact "$cli_artifact" "openshell" "$tmpdir/artifact-cli"
  download_verified_actions_artifact "$gateway_artifact" "openshell-gateway" "$tmpdir/artifact-gateway"
  download_verified_actions_artifact "$sandbox_artifact" "openshell-sandbox" "$tmpdir/artifact-sandbox"
  clear_github_token_environment

  cp "$tmpdir/artifact-cli/openshell" "$tmpdir/openshell"
  cp "$tmpdir/artifact-gateway/openshell-gateway" "$tmpdir/openshell-gateway"
  cp "$tmpdir/artifact-sandbox/openshell-sandbox" "$tmpdir/openshell-sandbox"
  chmod 755 "$tmpdir/openshell" "$tmpdir/openshell-gateway" "$tmpdir/openshell-sandbox"
}

download_with_curl() {
  local name
  local -a curl_progress
  # Show a live progress bar on a terminal so the (often slow) release download
  # is not a silent gap; stay quiet (errors only) when non-interactive. (#4431)
  if [ -t 1 ] || [ -t 2 ]; then
    curl_progress=(--progress-bar)
  else
    curl_progress=(-sS)
  fi
  for name in "${ASSETS[@]}" "${CHECKSUM_FILES[@]}"; do
    curl -fL "${curl_progress[@]}" "https://github.com/NVIDIA/OpenShell/releases/download/${RELEASE_TAG}/$name" \
      -o "$tmpdir/$name"
  done
}

if [ "$RESOLVED_CHANNEL" = "artifact" ]; then
  download_from_actions_artifacts
else
  info "Downloading OpenShell release assets (this may take a minute)..."
  if command -v gh >/dev/null 2>&1; then
    gh_ok=1
    for name in "${ASSETS[@]}" "${CHECKSUM_FILES[@]}"; do
      if ! GH_PROMPT_DISABLED=1 GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}" gh release download "$RELEASE_TAG" --repo NVIDIA/OpenShell \
        --pattern "$name" --dir "$tmpdir" --clobber 2>/dev/null; then
        gh_ok=0
        break
      fi
    done
    if [ "$gh_ok" = "1" ]; then
      : # gh succeeded
    else
      warn "gh CLI download failed (auth may not be configured) — falling back to curl"
      rm -f "$tmpdir"/*
      download_with_curl
    fi
  else
    download_with_curl
  fi

  info "Verifying SHA-256 checksum..."
  select_sha_cmd
  for i in "${!ASSETS[@]}"; do
    asset_name="${ASSETS[$i]}"
    checksum_file="${CHECKSUM_FILES[$i]}"
    (cd "$tmpdir" && grep -F "$asset_name" "$checksum_file" | $SHA_CMD -c -) \
      || fail "SHA-256 checksum verification failed for $asset_name"
  done

  for asset_name in "${ASSETS[@]}"; do
    tar xzf "$tmpdir/$asset_name" -C "$tmpdir"
  done
fi

target_dir="/usr/local/bin"
if [[ -n "$ACTIVE_OPENSHELL_BIN" && "$ACTIVE_OPENSHELL_BIN" = /* ]]; then
  active_dir="$(dirname "$ACTIVE_OPENSHELL_BIN")"
  if [ -d "$active_dir" ] && [ -w "$active_dir" ]; then
    target_dir="$active_dir"
  fi
fi

install_bins() {
  local dir="$1"
  install -m 755 "$tmpdir/openshell" "$dir/openshell"
  if [ -x "$tmpdir/openshell-gateway" ]; then
    install -m 755 "$tmpdir/openshell-gateway" "$dir/openshell-gateway"
  fi
  if [ -x "$tmpdir/openshell-sandbox" ]; then
    install -m 755 "$tmpdir/openshell-sandbox" "$dir/openshell-sandbox"
  fi
  if [ -x "$tmpdir/openshell-driver-vm" ]; then
    install -m 755 "$tmpdir/openshell-driver-vm" "$dir/openshell-driver-vm"
    sign_macos_vm_driver "$dir/openshell-driver-vm" 0
  fi
}

if [ -w "$target_dir" ]; then
  install_bins "$target_dir"
elif [ "${NEMOCLAW_NON_INTERACTIVE:-}" = "1" ] || [ ! -t 0 ]; then
  target_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
  mkdir -p "$target_dir"
  install_bins "$target_dir"
  warn "Installed openshell to $target_dir/openshell (user-local path)"
  warn "For future shells, run: export PATH=\"$target_dir:\$PATH\""
  warn "Add that export to your shell profile, or open a new shell before using openshell directly."
else
  sudo install -m 755 "$tmpdir/openshell" "$target_dir/openshell"
  if [ -x "$tmpdir/openshell-gateway" ]; then
    sudo install -m 755 "$tmpdir/openshell-gateway" "$target_dir/openshell-gateway"
  fi
  if [ -x "$tmpdir/openshell-sandbox" ]; then
    sudo install -m 755 "$tmpdir/openshell-sandbox" "$target_dir/openshell-sandbox"
  fi
  if [ -x "$tmpdir/openshell-driver-vm" ]; then
    sudo install -m 755 "$tmpdir/openshell-driver-vm" "$target_dir/openshell-driver-vm"
    sign_macos_vm_driver "$target_dir/openshell-driver-vm" 1
  fi
fi

require_openshell_messaging_features "$target_dir/openshell"

info "$("$target_dir/openshell" --version 2>&1 || echo openshell) installed"
