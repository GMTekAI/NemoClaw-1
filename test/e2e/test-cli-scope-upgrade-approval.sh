#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# CLI scope-upgrade approval E2E:
#
# Build a real NemoClaw/OpenClaw sandbox, create a low-scope CLI device
# approval, trigger the later `openclaw agent` operator.write scope upgrade, and
# then run in one of two modes:
#
#   approval     Approve the pending request through the fixed proxy-env guard,
#                verify the request is no longer pending, and verify the next
#                `openclaw agent` turn stays on the gateway path.
#   legacy-repro Characterize the old gateway-pinned approve path. Current
#                OpenClaw builds may return a pending-scope failure, return a replacement
#                request id, time out, succeed cleanly, or apply approval before
#                reporting failure. If the request remains pending, recover
#                through the fixed proxy-env guard so the sandbox is not left
#                dirty. This mode is diagnostic, not the fix gate.
#
# Prerequisites:
#   - Docker running
#   - NVIDIA_INFERENCE_API_KEY set
#   - NEMOCLAW_NON_INTERACTIVE=1
#   - NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1

# shellcheck disable=SC2016,SC2030,SC2031
# SC2016: remote sandbox scripts intentionally expand inside the sandbox.
# SC2030/SC2031: Phase 7 spawns subshells purely to scope onboarding env
# overrides; the variables are never read back outside the subshell.

set -uo pipefail

export NEMOCLAW_E2E_DEFAULT_TIMEOUT="${NEMOCLAW_E2E_DEFAULT_TIMEOUT:-2700}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=test/e2e/e2e-timeout.sh
. "${SCRIPT_DIR}/e2e-timeout.sh"

PASS=0
FAIL=0
TOTAL=0

pass() {
  ((PASS++))
  ((TOTAL++))
  printf '\033[32m  PASS: %s\033[0m\n' "$1"
}

fail() {
  ((FAIL++))
  ((TOTAL++))
  printf '\033[31m  FAIL: %s\033[0m\n' "$1"
}

section() {
  echo ""
  printf '\033[1;36m=== %s ===\033[0m\n' "$1"
}

info() { printf '\033[1;34m  [info]\033[0m %s\n' "$1"; }

finish_success() {
  section "Summary"
  echo ""
  printf '  Total: %d | \033[32mPass: %d\033[0m | \033[31mFail: %d\033[0m\n' \
    "$TOTAL" "$PASS" "$FAIL"
  echo ""
  echo "$1"
  exit 0
}

if [ -d /workspace ] && [ -f /workspace/install.sh ]; then
  REPO="/workspace"
elif [ -f "$(cd "${SCRIPT_DIR}/../.." && pwd)/install.sh" ]; then
  REPO="$(cd "${SCRIPT_DIR}/../.." && pwd)"
else
  echo "ERROR: Cannot find repo root." >&2
  exit 1
fi

E2E_DIR="${SCRIPT_DIR}"
SANDBOX_NAME="${NEMOCLAW_SANDBOX_NAME:-e2e-cli-scope-upgrade}"
OPENSHELL_BIN="${NEMOCLAW_OPENSHELL_BIN:-openshell}"
TEST_MODE="${NEMOCLAW_CLI_SCOPE_MODE:-approval}"
case "$TEST_MODE" in
  approval | legacy-repro) ;;
  *)
    fail "Unknown NEMOCLAW_CLI_SCOPE_MODE=${TEST_MODE}; expected approval or legacy-repro"
    exit 1
    ;;
esac
INSTALL_LOG="${NEMOCLAW_CLI_SCOPE_INSTALL_LOG:-/tmp/nemoclaw-e2e-cli-scope-upgrade-install.log}"
APPROVAL_LOG="${NEMOCLAW_CLI_SCOPE_APPROVAL_LOG:-/tmp/nemoclaw-cli-scope-upgrade-approval.log}"
AGENT_LOG="${NEMOCLAW_CLI_SCOPE_AGENT_LOG:-/tmp/nemoclaw-cli-scope-upgrade-agent.log}"
STATE_LOG="${NEMOCLAW_CLI_SCOPE_STATE_LOG:-/tmp/nemoclaw-cli-scope-upgrade-state.log}"
INSTALL_TIMEOUT_SECONDS="${NEMOCLAW_E2E_INSTALL_TIMEOUT_SECONDS:-1800}"

AUTO_PAIR_FAST_DEADLINE_DEFAULT="3"
AUTO_PAIR_DEADLINE_DEFAULT="30"
AUTO_PAIR_SLOW_INTERVAL_DEFAULT="5"
AUTO_PAIR_RUN_TIMEOUT_DEFAULT="10"
if [ "$TEST_MODE" = "legacy-repro" ]; then
  AUTO_PAIR_FAST_DEADLINE_DEFAULT="1"
  AUTO_PAIR_DEADLINE_DEFAULT="12"
  AUTO_PAIR_SLOW_INTERVAL_DEFAULT="1"
  AUTO_PAIR_RUN_TIMEOUT_DEFAULT="2"
fi
AUTO_PAIR_FAST_DEADLINE_SECS="${NEMOCLAW_CLI_SCOPE_AUTO_PAIR_FAST_DEADLINE_SECS:-${NEMOCLAW_AUTO_PAIR_FAST_DEADLINE_SECS:-$AUTO_PAIR_FAST_DEADLINE_DEFAULT}}"
AUTO_PAIR_DEADLINE_SECS="${NEMOCLAW_CLI_SCOPE_AUTO_PAIR_DEADLINE_SECS:-${NEMOCLAW_AUTO_PAIR_DEADLINE_SECS:-$AUTO_PAIR_DEADLINE_DEFAULT}}"
AUTO_PAIR_SLOW_INTERVAL_SECS="${NEMOCLAW_CLI_SCOPE_AUTO_PAIR_SLOW_INTERVAL_SECS:-${NEMOCLAW_AUTO_PAIR_SLOW_INTERVAL_SECS:-$AUTO_PAIR_SLOW_INTERVAL_DEFAULT}}"
AUTO_PAIR_RUN_TIMEOUT_SECS="${NEMOCLAW_CLI_SCOPE_AUTO_PAIR_RUN_TIMEOUT_SECS:-${NEMOCLAW_AUTO_PAIR_RUN_TIMEOUT_SECS:-$AUTO_PAIR_RUN_TIMEOUT_DEFAULT}}"
# Current onboard finalization may warm up and approve the CLI operator.read/write
# scope-upgrade before this E2E inspects the intermediate low-scope state. That
# is an acceptable final authorization state only if operator.admin is absent;
# the script must still prove the final agent turn stays on the gateway path.
# In legacy-repro mode, a preapproved state or an agent trigger that succeeds
# without producing a pending upgrade leaves no gateway-pinned approve request
# to characterize, so the final result calls that out explicitly instead of
# claiming the legacy approval behavior was exercised.
SCOPE_UPGRADE_ALREADY_SATISFIED=0
LEGACY_SCOPE_UPGRADE_NOT_REPRODUCED=0

# shellcheck source=test/e2e/lib/sandbox-teardown.sh
. "${E2E_DIR}/lib/sandbox-teardown.sh"
# shellcheck source=test/e2e/lib/install-path-refresh.sh
. "${E2E_DIR}/lib/install-path-refresh.sh"
# shellcheck source=test/e2e/lib/openclaw-json.sh
. "${E2E_DIR}/lib/openclaw-json.sh"
register_sandbox_for_teardown "$SANDBOX_NAME"

quote_for_remote_sh() {
  local value="${1:-}"
  printf "'%s'" "$(printf '%s' "$value" | sed "s/'/'\\\\''/g")"
}

sandbox_exec_sh_script() {
  local seconds="$1"
  local script="$2"
  shift 2
  local encoded remote_cmd arg
  encoded="$(printf '%s' "$script" | base64 | tr -d '\n')"
  remote_cmd="tmp=\$(mktemp); trap 'rm -f \"\$tmp\"' EXIT; printf %s $(quote_for_remote_sh "$encoded") | base64 -d > \"\$tmp\"; bash \"\$tmp\""
  for arg in "$@"; do
    remote_cmd+=" $(quote_for_remote_sh "$arg")"
  done
  run_with_timeout "$seconds" "$OPENSHELL_BIN" sandbox exec --name "$SANDBOX_NAME" -- sh -lc "$remote_cmd"
}

extract_json_doc() {
  python3 -c '
import json
import sys

raw = sys.stdin.read()
decoder = json.JSONDecoder()
for idx, char in enumerate(raw):
    if char != "{":
        continue
    try:
        doc, _end = decoder.raw_decode(raw[idx:])
    except Exception:
        continue
    print(json.dumps(doc, sort_keys=True))
    raise SystemExit(0)
raise SystemExit(1)
'
}

json_field() {
  local field="$1"
  python3 -c '
import json
import sys

field = sys.argv[1]
doc = json.load(sys.stdin)
value = doc
for part in field.split("."):
    if not isinstance(value, dict):
        value = None
        break
    value = value.get(part)
if isinstance(value, (dict, list)):
    print(json.dumps(value, sort_keys=True))
elif value is not None:
    print(value)
' "$field"
}

extract_scope_request_id_from_output() {
  sed -nE 's/.*requestId: ([[:alnum:]_-]+).*/\1/p' | head -1
}

device_state_json() {
  local output rc
  output=$(sandbox_exec_sh_script 60 '
set -u
if [ -r /tmp/nemoclaw-proxy-env.sh ]; then
  # shellcheck source=/dev/null
  . /tmp/nemoclaw-proxy-env.sh
fi
python3 - <<'"'"'PY'"'"'
import json
import os
from pathlib import Path

root = Path(os.environ.get("OPENCLAW_STATE_DIR") or "/sandbox/.openclaw") / "devices"

def load(name):
    path = root / name
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(value, dict):
        return {}
    return value

pending = load("pending.json")
paired = load("paired.json")
print(json.dumps({
    "pending": list(pending.values()),
    "paired": list(paired.values()),
    "paths": {
        "pending": str(root / "pending.json"),
        "paired": str(root / "paired.json"),
    },
}, sort_keys=True))
PY
' 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    printf '%s\n' "$output"
    return "$rc"
  fi
  printf '%s\n' "$output" | extract_json_doc
}

summarize_device_state() {
  local state_doc
  state_doc="$(cat)"
  OPENCLAW_CLI_SCOPE_DEVICE_STATE="$state_doc" python3 - <<'PY'
import json
import os
import sys

raw = os.environ.get("OPENCLAW_CLI_SCOPE_DEVICE_STATE") or "{}"
doc = json.loads(raw)
pending = doc.get("pending") or []
paired = doc.get("paired") or []

def norm(value):
    return str(value or "").strip()

def is_cli(entry):
    mode = norm(entry.get("clientMode")).lower()
    client = norm(entry.get("clientId")).lower()
    return mode == "cli" or "cli" in client

def scope_list(entry, *keys):
    out = []
    seen = set()
    for key in keys:
        for scope in entry.get(key) or []:
            scope = norm(scope)
            if scope and scope not in seen:
                out.append(scope)
                seen.add(scope)
    return out

def fmt(values):
    return ",".join(values) if values else "-"

print(f"pending={len(pending)} paired={len(paired)}")
for label, rows in (("pending", pending), ("paired", paired)):
    for row in rows:
        if not isinstance(row, dict) or not is_cli(row):
            continue
        request_id = row.get("requestId") or "-"
        device_id = row.get("deviceId") or "-"
        approved = scope_list(row, "approvedScopes")
        if label == "paired":
            approved = approved or scope_list(row, "scopes")
        requested = scope_list(row, "scopes", "requestedScopes")
        print(
            f"{label}: pendingCount={len(pending)} requestId={request_id} "
            f"deviceId={device_id} approvedScopes={fmt(approved)} "
            f"requestedScopes={fmt(requested)}"
        )
PY
}

select_cli_request() {
  local kind="$1"
  python3 -c '
import json
import sys

kind = sys.argv[1]
doc = json.load(sys.stdin)
pending = [p for p in doc.get("pending") or [] if isinstance(p, dict)]
paired = [p for p in doc.get("paired") or [] if isinstance(p, dict)]

def norm(value):
    return str(value or "").strip()

def is_cli(entry):
    return norm(entry.get("clientMode")).lower() == "cli" or "cli" in norm(entry.get("clientId")).lower()

def roles(entry):
    out = set()
    role = norm(entry.get("role"))
    if role:
        out.add(role)
    for role in entry.get("roles") or []:
        role = norm(role)
        if role:
            out.add(role)
    return out

def scopes(entry):
    return {norm(scope) for scope in (entry.get("scopes") or []) if norm(scope)}

def approved_scopes(entry):
    return {norm(scope) for scope in (entry.get("approvedScopes") or entry.get("scopes") or []) if norm(scope)}

paired_by_device = {norm(item.get("deviceId")): item for item in paired if norm(item.get("deviceId"))}

for req in sorted(pending, key=lambda item: item.get("ts") or 0, reverse=True):
    if not is_cli(req) or not norm(req.get("requestId")):
        continue
    paired_entry = paired_by_device.get(norm(req.get("deviceId")))
    requested = scopes(req)
    approved = approved_scopes(paired_entry or {})
    if kind == "new" and not paired_entry:
        print(req["requestId"])
        raise SystemExit(0)
    if kind == "scope-upgrade" and paired_entry and roles(req).issubset(roles(paired_entry) or roles(req)):
        # OpenClaw 2026.5.27 may create a follow-on operator.admin request after
        # the write/read request has already been applied. Keep this selector
        # focused on the NemoClaw gateway-mode upgrade contract.
        if {"operator.write", "operator.read"}.intersection(requested) and not requested.issubset(approved):
            print(req["requestId"])
            raise SystemExit(0)
raise SystemExit(1)
' "$kind"
}

select_cli_paired_without_write() {
  python3 -c '
import json
import sys

doc = json.load(sys.stdin)
paired = [p for p in doc.get("paired") or [] if isinstance(p, dict)]

def norm(value):
    return str(value or "").strip()

def is_cli(entry):
    return norm(entry.get("clientMode")).lower() == "cli" or "cli" in norm(entry.get("clientId")).lower()

def scopes(entry):
    return {norm(scope) for scope in (entry.get("approvedScopes") or entry.get("scopes") or []) if norm(scope)}

for device in sorted(paired, key=lambda item: item.get("approvedAtMs") or 0, reverse=True):
    if not is_cli(device):
        continue
    approved = scopes(device)
    if "operator.pairing" in approved and "operator.write" not in approved and "operator.admin" not in approved:
        print(norm(device.get("deviceId")) or "cli-device")
        raise SystemExit(0)
raise SystemExit(1)
'
}

select_cli_paired_with_agent_scopes() {
  python3 -c '
import json
import sys

doc = json.load(sys.stdin)
paired = [p for p in doc.get("paired") or [] if isinstance(p, dict)]

def norm(value):
    return str(value or "").strip()

def is_cli(entry):
    return norm(entry.get("clientMode")).lower() == "cli" or "cli" in norm(entry.get("clientId")).lower()

def scopes(entry):
    return {norm(scope) for scope in (entry.get("approvedScopes") or entry.get("scopes") or []) if norm(scope)}

for device in sorted(paired, key=lambda item: item.get("approvedAtMs") or 0, reverse=True):
    if not is_cli(device):
        continue
    approved = scopes(device)
    if {"operator.write", "operator.read"}.issubset(approved):
        print(norm(device.get("deviceId")) or "cli-device")
        raise SystemExit(0)
raise SystemExit(1)
'
}

select_cli_paired_with_admin() {
  python3 -c '
import json
import sys

doc = json.load(sys.stdin)
paired = [p for p in doc.get("paired") or [] if isinstance(p, dict)]

def norm(value):
    return str(value or "").strip()

def is_cli(entry):
    return norm(entry.get("clientMode")).lower() == "cli" or "cli" in norm(entry.get("clientId")).lower()

def scopes(entry):
    return {norm(scope) for scope in (entry.get("approvedScopes") or entry.get("scopes") or []) if norm(scope)}

for device in sorted(paired, key=lambda item: item.get("approvedAtMs") or 0, reverse=True):
    if is_cli(device) and "operator.admin" in scopes(device):
        print(norm(device.get("deviceId")) or "cli-device")
        raise SystemExit(0)
raise SystemExit(1)
'
}

approve_request() {
  local request_id="$1"
  local label="$2"
  local allow_already_approved="${3:-0}"
  local output rc approve_json approved_id before_url before_port before_token after_url after_port after_token approve_env state_after_approve approved_after_approve pending_after_approve
  output=$(sandbox_exec_sh_script 90 '
	set -u
	request_id="$1"
	real_openclaw="$(command -v openclaw || true)"
	if [ -z "$real_openclaw" ]; then
	  echo "missing real openclaw binary" >&2
	  exit 2
	fi
	if [ ! -r /tmp/nemoclaw-proxy-env.sh ]; then
	  echo "missing /tmp/nemoclaw-proxy-env.sh" >&2
	  exit 2
	fi
	# shellcheck source=/dev/null
	. /tmp/nemoclaw-proxy-env.sh
	probe_dir="$(mktemp -d /tmp/nemoclaw-approve-env.XXXXXX)"
	probe_log="$probe_dir/env.log"
	cat >"$probe_dir/openclaw" <<'"'"'PROBESH'"'"'
#!/bin/sh
token_state="$([ "${OPENCLAW_GATEWAY_TOKEN+x}" = x ] && printf set || printf unset)"
printf "__APPROVE_SUBPROCESS_ENV__=%s:%s:%s\n" "${OPENCLAW_GATEWAY_URL-unset}" "${OPENCLAW_GATEWAY_PORT-unset}" "$token_state" >>"$NEMOCLAW_CLI_SCOPE_APPROVE_ENV_LOG"
exec "$NEMOCLAW_CLI_SCOPE_REAL_OPENCLAW" "$@"
PROBESH
	chmod +x "$probe_dir/openclaw"
	export NEMOCLAW_CLI_SCOPE_REAL_OPENCLAW="$real_openclaw"
	export NEMOCLAW_CLI_SCOPE_APPROVE_ENV_LOG="$probe_log"
	PATH="$probe_dir:$PATH"
	printf "__URL_BEFORE__=%s\n" "${OPENCLAW_GATEWAY_URL-unset}"
	printf "__PORT_BEFORE__=%s\n" "${OPENCLAW_GATEWAY_PORT-unset}"
	printf "__TOKEN_BEFORE__=%s\n" "$([ "${OPENCLAW_GATEWAY_TOKEN+x}" = x ] && printf set || printf unset)"
	set +e
	approve_output="$(openclaw devices approve "$request_id" --json 2>&1)"
	approve_rc=$?
	set -e
	printf "__APPROVE_RC__=%s\n" "$approve_rc"
	printf "__APPROVE_OUTPUT_BEGIN__\n%s\n__APPROVE_OUTPUT_END__\n" "$approve_output"
	if [ -r "$probe_log" ]; then
	  cat "$probe_log"
	else
	  printf "__APPROVE_SUBPROCESS_ENV__=missing:missing:missing\n"
	fi
	printf "__URL_AFTER__=%s\n" "${OPENCLAW_GATEWAY_URL-unset}"
	printf "__PORT_AFTER__=%s\n" "${OPENCLAW_GATEWAY_PORT-unset}"
	printf "__TOKEN_AFTER__=%s\n" "$([ "${OPENCLAW_GATEWAY_TOKEN+x}" = x ] && printf set || printf unset)"
	rm -rf "$probe_dir"
	exit "$approve_rc"
	' "$request_id" 2>&1)
  rc=$?
  {
    printf '=== approve %s request=%s rc=%s ===\n' "$label" "$request_id" "$rc"
    printf '%s\n' "$output"
  } >>"$APPROVAL_LOG"
  if [ "$rc" -ne 0 ]; then
    if [ "$allow_already_approved" = "1" ]; then
      state_after_approve="$(device_state_json 2>&1)" || state_after_approve=""
      if [ -n "$state_after_approve" ]; then
        printf '=== state after failed approve %s request=%s ===\n%s\n' "$label" "$request_id" "$state_after_approve" >>"$STATE_LOG"
        approved_after_approve=$(printf '%s' "$state_after_approve" | select_cli_paired_with_agent_scopes 2>/dev/null) || approved_after_approve=""
        pending_after_approve=$(printf '%s' "$state_after_approve" | select_cli_request scope-upgrade 2>/dev/null) || pending_after_approve=""
        if [ -n "$approved_after_approve" ] && [ -z "$pending_after_approve" ]; then
          pass "${label}: request was already approved when fixed approve retried (${approved_after_approve})"
          return 0
        fi
      fi
    fi
    fail "${label}: openclaw devices approve failed for ${request_id}: ${output:0:500}"
    return 1
  fi
  before_url=$(sed -n 's/^__URL_BEFORE__=//p' <<<"$output" | tail -1)
  before_port=$(sed -n 's/^__PORT_BEFORE__=//p' <<<"$output" | tail -1)
  before_token=$(sed -n 's/^__TOKEN_BEFORE__=//p' <<<"$output" | tail -1)
  after_url=$(sed -n 's/^__URL_AFTER__=//p' <<<"$output" | tail -1)
  after_port=$(sed -n 's/^__PORT_AFTER__=//p' <<<"$output" | tail -1)
  after_token=$(sed -n 's/^__TOKEN_AFTER__=//p' <<<"$output" | tail -1)
  approve_env=$(sed -n 's/^__APPROVE_SUBPROCESS_ENV__=//p' <<<"$output" | tail -1)
  if [[ "$before_url" != ws://127.0.0.1:* ]] && [[ "$before_url" != ws://localhost:* ]]; then
    fail "${label}: proxy env did not expose a loopback OPENCLAW_GATEWAY_URL before approve (${before_url:-empty})"
    return 1
  fi
  if [ -z "$before_port" ] || [ "$before_port" = "unset" ] || [ "$before_token" != "set" ]; then
    fail "${label}: proxy env did not expose OPENCLAW_GATEWAY_PORT/TOKEN before approve (port=${before_port:-empty} token_state=${before_token:-empty})"
    return 1
  fi
  if [ "$after_url" != "$before_url" ]; then
    fail "${label}: devices approve leaked OPENCLAW_GATEWAY_URL mutation into caller shell (${before_url} -> ${after_url})"
    return 1
  fi
  if [ "$after_port" != "$before_port" ] || [ "$after_token" != "$before_token" ]; then
    fail "${label}: devices approve leaked gateway port/token mutation into caller shell (port ${before_port} -> ${after_port}; token changed=$([ "$after_token" != "$before_token" ] && printf yes || printf no))"
    return 1
  fi
  if [ "$approve_env" != "unset:unset:unset" ]; then
    fail "${label}: devices approve subprocess retained gateway env (${approve_env:-empty})"
    return 1
  fi
  approve_json=$(sed -n '/^__APPROVE_OUTPUT_BEGIN__$/,/^__APPROVE_OUTPUT_END__$/p' <<<"$output" | sed '1d;$d' | extract_json_doc 2>/dev/null) || approve_json=""
  if [ -z "$approve_json" ]; then
    fail "${label}: approve output did not contain JSON: ${output:0:500}"
    return 1
  fi
  approved_id=$(printf '%s' "$approve_json" | json_field requestId)
  if [ "$approved_id" != "$request_id" ]; then
    fail "${label}: approve returned requestId=${approved_id:-empty}, expected ${request_id}"
    return 1
  fi
  pass "${label}: openclaw devices approve ${request_id} --json succeeded with caller gateway URL preserved"
}

legacy_gateway_pinned_approval_characterization() {
  local request_id="$1"
  local output legacy_rc before_url legacy_approve_output legacy_failure_request_id state pending_after approved_after recovery_request_id
  output=$(sandbox_exec_sh_script 90 '
set -u
request_id="$1"
if [ ! -r /tmp/nemoclaw-proxy-env.sh ]; then
  echo "missing /tmp/nemoclaw-proxy-env.sh" >&2
  exit 2
fi
# shellcheck source=/dev/null
. /tmp/nemoclaw-proxy-env.sh
printf "__URL_FOR_LEGACY_APPROVE__=%s\n" "${OPENCLAW_GATEWAY_URL-unset}"
OPENCLAW_CLI_SCOPE_REQUEST_ID="$request_id" python3 - <<'"'"'PY'"'"'
import os
import subprocess

request_id = os.environ["OPENCLAW_CLI_SCOPE_REQUEST_ID"]
env = os.environ.copy()
try:
    proc = subprocess.run(
        ["openclaw", "devices", "approve", request_id, "--json"],
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
    )
    print(f"__LEGACY_APPROVE_RC__={proc.returncode}")
    print("__LEGACY_APPROVE_OUTPUT_BEGIN__")
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="")
    print("\n__LEGACY_APPROVE_OUTPUT_END__")
except subprocess.TimeoutExpired as exc:
    print("__LEGACY_APPROVE_RC__=124")
    print("__LEGACY_APPROVE_OUTPUT_BEGIN__")
    if exc.stdout:
        print(exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode(), end="")
    if exc.stderr:
        print(exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode(), end="")
    print("\nTIMEOUT waiting for gateway-pinned devices approve")
    print("__LEGACY_APPROVE_OUTPUT_END__")
PY
printf "__URL_AFTER_LEGACY_APPROVE__=%s\n" "${OPENCLAW_GATEWAY_URL-unset}"
exit 0
' "$request_id" 2>&1)
  {
    printf '=== legacy gateway-pinned approve request=%s ===\n' "$request_id"
    printf '%s\n' "$output"
  } >>"$APPROVAL_LOG"
  before_url=$(sed -n 's/^__URL_FOR_LEGACY_APPROVE__=//p' <<<"$output" | tail -1)
  if [[ "$before_url" != ws://127.0.0.1:* ]] && [[ "$before_url" != ws://localhost:* ]]; then
    fail "legacy characterization did not run with gateway URL pinned (${before_url:-empty})"
    return 1
  fi
  legacy_rc=$(sed -n 's/^__LEGACY_APPROVE_RC__=//p' <<<"$output" | tail -1)
  if [ -z "$legacy_rc" ]; then
    fail "legacy characterization did not report approve rc: ${output:0:500}"
    return 1
  fi
  legacy_approve_output=$(sed -n '/^__LEGACY_APPROVE_OUTPUT_BEGIN__$/,/^__LEGACY_APPROVE_OUTPUT_END__$/p' <<<"$output" | sed '1d;$d')
  if [ "$legacy_rc" = "0" ]; then
    pass "legacy gateway-pinned devices approve now exits successfully"
  elif [ "$legacy_rc" = "124" ]; then
    pass "legacy gateway-pinned devices approve timed out before approval could complete"
  elif grep -Fq "GatewayClientRequestError" <<<"$legacy_approve_output" \
    && grep -Fq "scope upgrade pending approval" <<<"$legacy_approve_output"; then
    legacy_failure_request_id=$(printf '%s' "$legacy_approve_output" | extract_scope_request_id_from_output) || legacy_failure_request_id=""
    if [ -z "$legacy_failure_request_id" ]; then
      fail "legacy gateway-pinned devices approve did not report a requestId: ${legacy_approve_output:0:500}"
      return 1
    fi
    if [ "$legacy_failure_request_id" = "$request_id" ]; then
      pass "legacy gateway-pinned devices approve returns the pending-scope failure for the requested id"
    else
      pass "legacy gateway-pinned devices approve returns the pending-scope failure for replacement id ${legacy_failure_request_id}"
    fi
  else
    pass "legacy gateway-pinned devices approve returned nonzero without the known pending-scope signature"
  fi

  state="$(device_state_json 2>&1)" || {
    fail "Could not read OpenClaw device state after legacy approve failure: ${state:0:500}"
    return 1
  }
  printf '=== state after legacy gateway-pinned approve failure ===\n%s\n' "$state" >>"$STATE_LOG"
  pending_after=$(printf '%s' "$state" | select_cli_request scope-upgrade 2>/dev/null) || pending_after=""
  approved_after=$(printf '%s' "$state" | select_cli_paired_with_agent_scopes 2>/dev/null) || approved_after=""
  if [ -n "$pending_after" ]; then
    pass "legacy gateway-pinned approve leaves the CLI scope-upgrade request pending"
    recovery_request_id="$pending_after"
    approve_request "$recovery_request_id" "recovery after legacy characterization" 1 || return 1
    pass "fixed devices approve path recovers the pending legacy request"
    return 0
  fi
  if [ -n "$approved_after" ]; then
    pass "legacy gateway-pinned approve returned failure after applying the scope upgrade (${approved_after})"
    return 0
  fi
  fail "legacy gateway-pinned characterization left neither pending nor approved CLI scope-upgrade state: $(printf '%s' "$state" | summarize_device_state)"
  return 1
}

wait_for_auto_pair_watcher_inactive() {
  local output rc
  for _attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    output=$(sandbox_exec_sh_script 20 '
set -u
find_auto_pair_pids() {
  for proc in /proc/[0-9]*; do
    pid="${proc##*/}"
    [ "$pid" = "$$" ] && continue
    [ -r "$proc/cmdline" ] || continue
    cmd="$(tr "\000" " " <"$proc/cmdline" 2>/dev/null || true)"
    case "$cmd" in
      *"python3 -"*)
        fd1="$(readlink "$proc/fd/1" 2>/dev/null || true)"
        fd2="$(readlink "$proc/fd/2" 2>/dev/null || true)"
        case "${fd1} ${fd2}" in
          *"/tmp/auto-pair.log"*) printf "%s\n" "$pid" ;;
        esac
        ;;
    esac
  done | sort -u
}
if [ -r /tmp/auto-pair.log ]; then
  if grep -F "[auto-pair] watcher deadline reached" /tmp/auto-pair.log >/dev/null; then
    echo "__AUTO_PAIR_WATCHER__=deadline-reached"
    tail -20 /tmp/auto-pair.log
    exit 0
  fi
  pids="$(find_auto_pair_pids)"
  if [ -z "$pids" ]; then
    echo "__AUTO_PAIR_WATCHER__=inactive"
    tail -20 /tmp/auto-pair.log || true
    exit 0
  fi
  echo "__AUTO_PAIR_WATCHER__=still-waiting"
  printf "__AUTO_PAIR_PIDS__=%s\n" "$(printf "%s" "$pids" | tr "\n" " ")"
  tail -20 /tmp/auto-pair.log || true
else
  echo "__AUTO_PAIR_WATCHER__=missing-log"
fi
exit 1
' 2>&1)
    rc=$?
    printf '=== auto-pair watcher inactivity probe rc=%s ===\n%s\n' "$rc" "$output" >>"$STATE_LOG"
    if [ "$rc" -eq 0 ]; then
      pass "auto-pair watcher reached its deadline before legacy scope-upgrade trigger"
      return 0
    fi
    sleep 2
  done
  output=$(sandbox_exec_sh_script 30 '
set -u
find_auto_pair_pids() {
  for proc in /proc/[0-9]*; do
    pid="${proc##*/}"
    [ "$pid" = "$$" ] && continue
    [ -r "$proc/cmdline" ] || continue
    cmd="$(tr "\000" " " <"$proc/cmdline" 2>/dev/null || true)"
    case "$cmd" in
      *"python3 -"*)
        fd1="$(readlink "$proc/fd/1" 2>/dev/null || true)"
        fd2="$(readlink "$proc/fd/2" 2>/dev/null || true)"
        case "${fd1} ${fd2}" in
          *"/tmp/auto-pair.log"*) printf "%s\n" "$pid" ;;
        esac
        ;;
    esac
  done | sort -u
}
pids="$(find_auto_pair_pids)"
if [ -z "$pids" ]; then
  echo "__AUTO_PAIR_WATCHER__=inactive-before-stop"
  exit 0
fi
printf "__AUTO_PAIR_STOPPING_PIDS__=%s\n" "$(printf "%s" "$pids" | tr "\n" " ")"
kill $pids 2>/dev/null || true
sleep 2
remaining="$(find_auto_pair_pids)"
if [ -n "$remaining" ]; then
  printf "__AUTO_PAIR_KILLING_PIDS__=%s\n" "$(printf "%s" "$remaining" | tr "\n" " ")"
  kill -KILL $remaining 2>/dev/null || true
  sleep 1
fi
remaining="$(find_auto_pair_pids)"
if [ -n "$remaining" ]; then
  printf "__AUTO_PAIR_WATCHER__=still-active pids=%s\n" "$(printf "%s" "$remaining" | tr "\n" " ")"
  exit 1
fi
echo "__AUTO_PAIR_WATCHER__=stopped"
tail -20 /tmp/auto-pair.log 2>/dev/null || true
' 2>&1)
  rc=$?
  printf '=== auto-pair watcher forced stop rc=%s ===\n%s\n' "$rc" "$output" >>"$STATE_LOG"
  if [ "$rc" -eq 0 ]; then
    pass "auto-pair watcher is inactive before legacy scope-upgrade trigger"
    return 0
  fi
  fail "auto-pair watcher was still active before legacy scope-upgrade trigger: ${output:0:500}"
  return 1
}

section "Phase 0: Preflight"

if [ -z "${NVIDIA_INFERENCE_API_KEY:-}" ]; then
  fail "NVIDIA_INFERENCE_API_KEY not set"
  exit 1
fi
pass "NVIDIA_INFERENCE_API_KEY is set"

if ! docker info >/dev/null 2>&1; then
  fail "Docker is not running"
  exit 1
fi
pass "Docker is running"

command -v python3 >/dev/null 2>&1 || {
  fail "python3 is required"
  exit 1
}
pass "python3 is available"

info "Repo: ${REPO}"
info "Sandbox name: ${SANDBOX_NAME}"
info "Mode: ${TEST_MODE}"
info "Logs: ${INSTALL_LOG}, ${APPROVAL_LOG}, ${AGENT_LOG}, ${STATE_LOG}"
info "Auto-pair timing: fast=${AUTO_PAIR_FAST_DEADLINE_SECS}s deadline=${AUTO_PAIR_DEADLINE_SECS}s slow=${AUTO_PAIR_SLOW_INTERVAL_SECS}s run-timeout=${AUTO_PAIR_RUN_TIMEOUT_SECS}s"
: >"$APPROVAL_LOG"
: >"$AGENT_LOG"
: >"$STATE_LOG"

section "Phase 1: Install real NemoClaw/OpenClaw sandbox"

cd "$REPO" || {
  fail "Could not cd to repo root"
  exit 1
}

info "Pre-cleanup"
if command -v nemoclaw >/dev/null 2>&1; then
  run_with_timeout 120 nemoclaw "$SANDBOX_NAME" destroy --yes >/dev/null 2>&1 || true
fi
if command -v "$OPENSHELL_BIN" >/dev/null 2>&1 || [ "$OPENSHELL_BIN" != "openshell" ]; then
  run_with_timeout 60 "$OPENSHELL_BIN" sandbox delete "$SANDBOX_NAME" >/dev/null 2>&1 || true
  if [[ "${CI:-}" = "true" || "${NEMOCLAW_E2E_DESTROY_GATEWAY:-}" = "1" ]]; then
    run_with_timeout 60 "$OPENSHELL_BIN" gateway destroy -g nemoclaw >/dev/null 2>&1 || true
  fi
fi
pass "Pre-cleanup complete"

info "Running install.sh --non-interactive"
(
  export NEMOCLAW_SANDBOX_NAME="$SANDBOX_NAME"
  export NEMOCLAW_RECREATE_SANDBOX=1
  export NEMOCLAW_FRESH=1
  export NEMOCLAW_NON_INTERACTIVE=1
  export NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1
  export NEMOCLAW_AUTO_PAIR_FAST_DEADLINE_SECS="$AUTO_PAIR_FAST_DEADLINE_SECS"
  export NEMOCLAW_AUTO_PAIR_DEADLINE_SECS="$AUTO_PAIR_DEADLINE_SECS"
  export NEMOCLAW_AUTO_PAIR_SLOW_INTERVAL_SECS="$AUTO_PAIR_SLOW_INTERVAL_SECS"
  export NEMOCLAW_AUTO_PAIR_RUN_TIMEOUT_SECS="$AUTO_PAIR_RUN_TIMEOUT_SECS"
  run_with_timeout "$INSTALL_TIMEOUT_SECONDS" bash install.sh --non-interactive --yes-i-accept-third-party-software
) >"$INSTALL_LOG" 2>&1
install_rc=$?

nemoclaw_refresh_install_env
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
# shellcheck source=/dev/null
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
nemoclaw_ensure_local_bin_on_path
hash -r

if [ "$install_rc" -ne 0 ]; then
  fail "install.sh failed with exit ${install_rc}; see ${INSTALL_LOG}"
  tail -40 "$INSTALL_LOG" || true
  exit 1
fi
pass "NemoClaw installed and onboarded"

command -v nemoclaw >/dev/null 2>&1 || {
  fail "nemoclaw not found on PATH after install"
  exit 1
}
command -v "$OPENSHELL_BIN" >/dev/null 2>&1 || {
  fail "${OPENSHELL_BIN} not found on PATH after install"
  exit 1
}
pass "nemoclaw and openshell are available"

section "Phase 2: Verify in-sandbox proxy env guard"

guard_probe=$(sandbox_exec_sh_script 60 '
set -u
if [ ! -r /tmp/nemoclaw-proxy-env.sh ]; then
  echo "MISSING_PROXY_ENV"
  exit 2
fi
# shellcheck source=/dev/null
. /tmp/nemoclaw-proxy-env.sh
printf "OPENCLAW_GATEWAY_URL=%s\n" "${OPENCLAW_GATEWAY_URL-unset}"
type openclaw 2>/dev/null | sed -n "1,12p"
grep -F "unset OPENCLAW_GATEWAY_URL OPENCLAW_GATEWAY_PORT OPENCLAW_GATEWAY_TOKEN; command openclaw" /tmp/nemoclaw-proxy-env.sh >/dev/null \
  && echo "APPROVE_GUARD_PRESENT"
' 2>&1)
guard_rc=$?
printf '%s\n' "$guard_probe" >>"$STATE_LOG"
if [ "$guard_rc" -ne 0 ]; then
  fail "Could not source /tmp/nemoclaw-proxy-env.sh: ${guard_probe:0:400}"
  exit 1
fi
if grep -q '^OPENCLAW_GATEWAY_URL=ws://127\.0\.0\.1:' <<<"$guard_probe" \
  && grep -q '^APPROVE_GUARD_PRESENT$' <<<"$guard_probe"; then
  pass "proxy env preserves gateway URL and contains devices approve guard"
else
  fail "proxy env missing gateway URL or approve guard: ${guard_probe:0:600}"
  exit 1
fi

section "Phase 3: Establish low-scope CLI device approval"

info "Creating initial CLI pairing request with openclaw devices list"
initial_list=$(sandbox_exec_sh_script 60 '
set -u
# shellcheck source=/dev/null
. /tmp/nemoclaw-proxy-env.sh
set +e
openclaw devices list --json
rc=$?
set -e
printf "__LIST_RC__=%s\n" "$rc" >&2
exit 0
' 2>&1)
printf '=== initial devices list ===\n%s\n' "$initial_list" >>"$STATE_LOG"

state="$(device_state_json 2>&1)" || {
  fail "Could not read OpenClaw device state after initial list: ${state:0:500}"
  exit 1
}
printf '=== state after initial list ===\n%s\n' "$state" >>"$STATE_LOG"
summary=$(printf '%s' "$state" | summarize_device_state)
info "$summary"

initial_request_id=$(printf '%s' "$state" | select_cli_request new 2>/dev/null) || initial_request_id=""
if [ -n "$initial_request_id" ]; then
  pass "pending low-scope CLI pairing request exists (${initial_request_id})"
  approve_request "$initial_request_id" "initial CLI pairing" || exit 1
else
  paired_without_write=$(printf '%s' "$state" | select_cli_paired_without_write 2>/dev/null) || paired_without_write=""
  if [ -n "$paired_without_write" ]; then
    pass "CLI device is already paired with low scope (${paired_without_write})"
  else
    paired_with_agent_scopes=$(printf '%s' "$state" | select_cli_paired_with_agent_scopes 2>/dev/null) || paired_with_agent_scopes=""
    paired_with_admin=$(printf '%s' "$state" | select_cli_paired_with_admin 2>/dev/null) || paired_with_admin=""
    if [ -n "$paired_with_agent_scopes" ] && [ -z "$paired_with_admin" ]; then
      pass "CLI device already has operator.read/operator.write without operator.admin (${paired_with_agent_scopes})"
      SCOPE_UPGRADE_ALREADY_SATISFIED=1
    else
      fail "No pending or paired low-scope CLI device found after devices list: ${summary}"
      exit 1
    fi
  fi
fi

state="$(device_state_json 2>&1)" || {
  fail "Could not read OpenClaw device state after initial approval: ${state:0:500}"
  exit 1
}
printf '=== state after initial approval ===\n%s\n' "$state" >>"$STATE_LOG"
if [ "$SCOPE_UPGRADE_ALREADY_SATISFIED" = "1" ]; then
  pass "initial approval check skipped because CLI scope-upgrade is already satisfied"
else
  paired_without_write=$(printf '%s' "$state" | select_cli_paired_without_write 2>/dev/null) || paired_without_write=""
  if [ -n "$paired_without_write" ]; then
    pass "CLI device is paired with operator.pairing but not operator.write"
  else
    fail "Initial approval did not leave a low-scope CLI device: $(printf '%s' "$state" | summarize_device_state)"
    exit 1
  fi
fi

gateway_list=$(sandbox_exec_sh_script 60 '
set -u
# shellcheck source=/dev/null
. /tmp/nemoclaw-proxy-env.sh
printf "__URL_FOR_LIST__=%s\n" "${OPENCLAW_GATEWAY_URL-unset}" >&2
openclaw devices list --json
' 2>&1)
gateway_list_rc=$?
printf '=== gateway devices list after initial approval rc=%s ===\n%s\n' "$gateway_list_rc" "$gateway_list" >>"$STATE_LOG"
if [ "$gateway_list_rc" -eq 0 ] && grep -q '^__URL_FOR_LIST__=ws://' <<<"$gateway_list"; then
  pass "openclaw devices list observes device state while OPENCLAW_GATEWAY_URL is set"
else
  fail "devices list did not work with gateway URL after initial approval: ${gateway_list:0:500}"
  exit 1
fi

if [ "$TEST_MODE" = "legacy-repro" ] && [ "$SCOPE_UPGRADE_ALREADY_SATISFIED" != "1" ]; then
  wait_for_auto_pair_watcher_inactive || exit 1
fi

section "Phase 4: Trigger and approve CLI scope upgrade"

if [ "$SCOPE_UPGRADE_ALREADY_SATISFIED" = "1" ]; then
  info "Skipping trigger/approval because CLI operator.read/operator.write scopes were already approved"
else
  info "Triggering agent operator.write scope upgrade"
  trigger_output=$(sandbox_exec_sh_script 120 '
set -u
# shellcheck source=/dev/null
. /tmp/nemoclaw-proxy-env.sh
session_id="cli-scope-upgrade-trigger-$(date +%s)-$$"
rm -f "/sandbox/.openclaw/agents/main/sessions/${session_id}.jsonl.lock" \
      "/sandbox/.openclaw/agents/main/sessions/${session_id}.trajectory.jsonl" 2>/dev/null || true
printf "__URL_FOR_TRIGGER_AGENT__=%s\n" "${OPENCLAW_GATEWAY_URL-unset}"
set +e
openclaw agent --agent main --json --session-id "$session_id" \
  -m "What is 6 multiplied by 7? Reply with only the integer, no extra words."
agent_rc=$?
set -e
printf "__TRIGGER_AGENT_RC__=%s\n" "$agent_rc"
exit 0
' 2>&1)
  printf '=== trigger agent output ===\n%s\n' "$trigger_output" >>"$AGENT_LOG"

  scope_request_id=""
  auto_approved_device=""
  for _attempt in 1 2 3 4 5; do
    state="$(device_state_json 2>&1)" || state=""
    if [ -n "$state" ]; then
      printf '=== state while waiting for scope upgrade ===\n%s\n' "$state" >>"$STATE_LOG"
      scope_request_id=$(printf '%s' "$state" | select_cli_request scope-upgrade 2>/dev/null) || scope_request_id=""
      auto_approved_device=$(printf '%s' "$state" | select_cli_paired_with_agent_scopes 2>/dev/null) || auto_approved_device=""
    fi
    [ -n "$scope_request_id" ] && break
    if [ "$TEST_MODE" = "approval" ] && [ -n "$auto_approved_device" ]; then
      break
    fi
    sleep 2
  done

  if [ -z "$scope_request_id" ] && [ "$TEST_MODE" = "legacy-repro" ]; then
    scope_request_id=$(printf '%s' "$trigger_output" | extract_scope_request_id_from_output) || scope_request_id=""
  fi

  if [ -n "$scope_request_id" ]; then
    pass "pending CLI scope-upgrade request exists (${scope_request_id})"
  elif [ "$TEST_MODE" = "approval" ] && [ -n "$auto_approved_device" ]; then
    pass "auto-pair watcher approved the CLI scope upgrade before pending inspection (${auto_approved_device})"
  elif [ "$TEST_MODE" = "legacy-repro" ] \
    && grep -q '^__URL_FOR_TRIGGER_AGENT__=ws://' <<<"$trigger_output" \
    && grep -q '^__TRIGGER_AGENT_RC__=0$' <<<"$trigger_output" \
    && ! grep -Eiq 'EMBEDDED FALLBACK|scope upgrade pending approval|pairing required|fallbackFrom[": ]+gateway|transport[": ]+embedded' <<<"$trigger_output"; then
    pass "legacy gateway-pinned scope-upgrade was not reproducible because trigger agent completed through gateway mode"
    LEGACY_SCOPE_UPGRADE_NOT_REPRODUCED=1
  else
    fail "No pending CLI scope-upgrade request appeared after agent trigger. State: $(printf '%s' "${state:-{}}" | summarize_device_state 2>/dev/null || true). Trigger: ${trigger_output:0:500}"
    exit 1
  fi

  if [ "$TEST_MODE" = "legacy-repro" ] && [ "$LEGACY_SCOPE_UPGRADE_NOT_REPRODUCED" != "1" ]; then
    legacy_gateway_pinned_approval_characterization "$scope_request_id" || exit 1
    if [ "$FAIL" -gt 0 ]; then
      section "Summary"
      echo ""
      printf '  Total: %d | \033[32mPass: %d\033[0m | \033[31mFail: %d\033[0m\n' \
        "$TOTAL" "$PASS" "$FAIL"
      echo ""
      echo "RESULT: FAILED - ${FAIL} test(s) failed"
      exit 1
    fi
    finish_success "RESULT: PASSED - legacy gateway-pinned approval behaviour characterised and final state handled"
  fi

  if [ -n "$scope_request_id" ]; then
    approve_request "$scope_request_id" "CLI scope upgrade" 1 || exit 1
  else
    info "Skipping manual scope-upgrade approval because the auto-pair watcher already granted it"
  fi
fi

state="$(device_state_json 2>&1)" || {
  fail "Could not read OpenClaw device state after scope-upgrade approval: ${state:0:500}"
  exit 1
}
printf '=== state after scope-upgrade approval ===\n%s\n' "$state" >>"$STATE_LOG"
pending_after_approval=$(printf '%s' "$state" | select_cli_request scope-upgrade 2>/dev/null) || pending_after_approval=""
paired_with_agent_scopes=$(printf '%s' "$state" | select_cli_paired_with_agent_scopes 2>/dev/null) || paired_with_agent_scopes=""
paired_with_admin=$(printf '%s' "$state" | select_cli_paired_with_admin 2>/dev/null) || paired_with_admin=""
if [ -n "$pending_after_approval" ]; then
  fail "Scope-upgrade request is still pending after approval (${pending_after_approval})"
  exit 1
fi
if [ -z "$paired_with_agent_scopes" ] && [ "$LEGACY_SCOPE_UPGRADE_NOT_REPRODUCED" != "1" ]; then
  fail "No CLI paired device has operator.write and operator.read after approval: $(printf '%s' "$state" | summarize_device_state)"
  exit 1
fi
if [ -n "$paired_with_admin" ]; then
  fail "Unexpected operator.admin approval for CLI device (${paired_with_admin})"
  exit 1
fi
if [ "$SCOPE_UPGRADE_ALREADY_SATISFIED" = "1" ]; then
  pass "preapproved CLI scope-upgrade state has operator.write/operator.read without operator.admin"
elif [ "$LEGACY_SCOPE_UPGRADE_NOT_REPRODUCED" = "1" ]; then
  pass "legacy repro trigger left no pending scope-upgrade and no operator.admin grant"
else
  pass "scope-upgrade approval grants the CLI device operator.write and operator.read without approving operator.admin"
fi

section "Phase 5: Verify agent stays on gateway path"

agent_ok=0
last_agent_detail=""
for attempt in 1 2; do
  info "Running approved openclaw agent turn (attempt ${attempt}/2)"
  final_output=$(sandbox_exec_sh_script 180 '
set -u
# shellcheck source=/dev/null
. /tmp/nemoclaw-proxy-env.sh
session_id="cli-scope-upgrade-fixed-$(date +%s)-$$"
rm -f "/sandbox/.openclaw/agents/main/sessions/${session_id}.jsonl.lock" \
      "/sandbox/.openclaw/agents/main/sessions/${session_id}.trajectory.jsonl" 2>/dev/null || true
printf "__URL_FOR_FINAL_AGENT__=%s\n" "${OPENCLAW_GATEWAY_URL-unset}"
openclaw agent --agent main --json --session-id "$session_id" \
  -m "What is 6 multiplied by 7? Reply with only the integer, no extra words."
' 2>&1)
  final_rc=$?
  printf '=== final agent attempt %s rc=%s ===\n%s\n' "$attempt" "$final_rc" "$final_output" >>"$AGENT_LOG"
  reply=$(printf '%s' "$final_output" | parse_openclaw_agent_text 2>/dev/null) || reply=""
  if grep -Eiq 'EMBEDDED FALLBACK|scope upgrade pending approval|pairing required|fallbackFrom[": ]+gateway|transport[": ]+embedded' <<<"$final_output"; then
    last_agent_detail="agent output contained fallback or pairing marker: ${final_output:0:500}"
  elif [ "$final_rc" -ne 0 ]; then
    last_agent_detail="agent exited ${final_rc}: ${final_output:0:500}"
  elif ! grep -q '^__URL_FOR_FINAL_AGENT__=ws://' <<<"$final_output"; then
    last_agent_detail="agent command did not preserve OPENCLAW_GATEWAY_URL: ${final_output:0:500}"
  elif e2e_text_contains_integer_42 "$reply"; then
    agent_ok=1
    pass "approved openclaw agent turn answered through gateway mode"
    break
  else
    last_agent_detail="expected reply 42, got reply='${reply:0:200}', raw='${final_output:0:400}'"
  fi
  sleep 5
done

if [ "$agent_ok" -ne 1 ]; then
  fail "Final approved agent turn did not prove gateway-mode success: ${last_agent_detail}"
  exit 1
fi

pass "approved agent output contains no fallback or pairing markers"

if [ "$TEST_MODE" = "legacy-repro" ] && [ "$SCOPE_UPGRADE_ALREADY_SATISFIED" = "1" ]; then
  if [ "$FAIL" -gt 0 ]; then
    section "Summary"
    echo ""
    printf '  Total: %d | \033[32mPass: %d\033[0m | \033[31mFail: %d\033[0m\n' \
      "$TOTAL" "$PASS" "$FAIL"
    echo ""
    echo "RESULT: FAILED - ${FAIL} test(s) failed"
    exit 1
  fi
  finish_success "RESULT: PASSED - legacy gateway-pinned approval characterisation skipped because scope-upgrade was already satisfied; final gateway path verified"
fi
if [ "$TEST_MODE" = "legacy-repro" ] && [ "$LEGACY_SCOPE_UPGRADE_NOT_REPRODUCED" = "1" ]; then
  if [ "$FAIL" -gt 0 ]; then
    section "Summary"
    echo ""
    printf '  Total: %d | \033[32mPass: %d\033[0m | \033[31mFail: %d\033[0m\n' \
      "$TOTAL" "$PASS" "$FAIL"
    echo ""
    echo "RESULT: FAILED - ${FAIL} test(s) failed"
    exit 1
  fi
  finish_success "RESULT: PASSED - legacy gateway-pinned approval characterisation skipped because trigger agent completed without a pending scope-upgrade; final gateway path verified"
fi

section "Phase 6: Verify watcher emits slow-mode fast-reentry instrumentation"

# Once the watcher converges (fast-deadline elapsed or paired devices seen
# for several quiet polls) it transitions to slow-mode keepalive. A late
# allowlisted scope upgrade arriving after that point must drop polling
# back to a bounded fast-reentry window so the OpenClaw client does not
# time out and fall back to embedded mode. Phases 3-5 leave at least one
# paired device in the sandbox and the in-sandbox watcher runs with a
# tight SLOW_INTERVAL (AUTO_PAIR_SLOW_INTERVAL_DEFAULT), so the watcher
# normally observes one of the pending allowlisted requests and records
# the fast-reentry marker before the explicit approve_request wins the
# race; the prior explicit approve calls tolerate watcher-wins via
# allow_already_approved=1. The slow-mode transition is asserted
# strictly. The fast-reentry marker is informational only: when the
# explicit approve_request wins the race the watcher never attempts an
# approve for that requestId and the marker is never emitted, yet the
# user-facing path still works correctly (gated end-to-end by the agent
# success and fallback-marker checks in Phase 5, and deterministically
# by the unit test under test/nemoclaw-start.test.ts).

# Convergence requires QUIET_POLLS >= 4 in the watcher loop with a 5s
# inter-poll cadence when at least one device is already paired (the
# common CI case where onboard preapproves CLI scopes), so the slow-mode
# marker normally appears 15–25s after the watcher launches. Phase 1's
# install/onboard can finish well before that 25s window, so a single
# snapshot here races the watcher. Poll the log for up to
# slow_mode_wait_secs until any of the convergence markers appears
# (covers fast-mode deadline, browser convergence, devices-paired
# convergence, and non-browser convergence). The strict-fail behaviour
# is preserved — the test only passes once the marker is observed.
slow_mode_wait_secs=45
slow_mode_observed=0
auto_pair_log_snapshot=""
slow_mode_start=$SECONDS
while [ $((SECONDS - slow_mode_start)) -lt "$slow_mode_wait_secs" ]; do
  auto_pair_log_snapshot=$(sandbox_exec_sh_script 20 '
set -u
cat /tmp/auto-pair.log 2>/dev/null || true
' 2>&1)
  if grep -F '[auto-pair] fast-mode deadline reached; switching to slow-mode' <<<"$auto_pair_log_snapshot" >/dev/null \
    || grep -F '[auto-pair] browser pairing converged; entering slow-mode' <<<"$auto_pair_log_snapshot" >/dev/null \
    || grep -F '[auto-pair] devices paired ' <<<"$auto_pair_log_snapshot" >/dev/null \
    || grep -F '[auto-pair] non-browser pairing converged; entering slow-mode' <<<"$auto_pair_log_snapshot" >/dev/null; then
    slow_mode_observed=1
    break
  fi
  sleep 3
done
auto_pair_diag=$(sandbox_exec_sh_script 20 '
set -u
echo "--- ls /tmp/auto-pair.log ---"
ls -la /tmp/auto-pair.log 2>&1 || true
echo "--- ls /tmp/gateway.log ---"
ls -la /tmp/gateway.log 2>&1 || true
echo "--- pgrep python3 ---"
pgrep -af python3 2>&1 || true
echo "--- last 80 lines /tmp/gateway.log ---"
tail -n 80 /tmp/gateway.log 2>&1 || true
' 2>&1)
printf '=== auto-pair diagnostic ===\n%s\n' "$auto_pair_diag" >>"$STATE_LOG"
printf '=== /tmp/auto-pair.log snapshot (waited %ss) ===\n%s\n' "$((SECONDS - slow_mode_start))" "$auto_pair_log_snapshot" >>"$STATE_LOG"

if [ "$slow_mode_observed" -eq 1 ]; then
  pass "watcher reached slow-mode keepalive within ${slow_mode_wait_secs}s"
else
  fail "watcher did not record any slow-mode transition within ${slow_mode_wait_secs}s"
fi

if grep -F '[auto-pair] fast-reentry bumped' <<<"$auto_pair_log_snapshot" >/dev/null; then
  pass "watcher logged fast-reentry marker on at least one allowlisted approval attempt"
else
  info "watcher did not log a fast-reentry marker (explicit approve_request won the race against the watcher poll cadence; the user-facing path is gated by Phase 5 and unit test/nemoclaw-start.test.ts)"
fi

section "Phase 7: Verify two-sandbox concurrent gateway-backed agent turns"

# Targets the multi-sandbox half of the linked issue: two sandboxes running
# allowlisted CLI clients through the shared OpenShell gateway concurrently
# must each get their late scope upgrade approved by their own in-sandbox
# auto-pair watcher with no scope-upgrade, pairing, or embedded-fallback
# markers. CI has only one inference provider key available, so both
# sandboxes share the same NVIDIA Cloud provider; the property being
# validated — independent per-sandbox watchers + concurrent gateway use —
# is the same whether providers differ or match. Per-sandbox gateway URL
# pinning below (sandbox A → :18789, sandbox B → :18790) covers the
# routing-isolation half of the expected result; the differing-providers
# half cannot be exercised without a second provider key in CI.

SANDBOX_NAME_B="${SANDBOX_NAME}-b"
register_sandbox_for_teardown "$SANDBOX_NAME_B"

info "Onboarding second sandbox: ${SANDBOX_NAME_B}"
# shellcheck disable=SC2030,SC2031
(
  export NEMOCLAW_SANDBOX_NAME="$SANDBOX_NAME_B"
  export NEMOCLAW_RECREATE_SANDBOX=1
  export NEMOCLAW_FRESH=1
  export NEMOCLAW_NON_INTERACTIVE=1
  export NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1
  # Second sandbox needs its own dashboard port; the first sandbox uses
  # 18789 by default, so pin the sibling to 18790 to avoid a collision.
  export NEMOCLAW_DASHBOARD_PORT=18790
  export NEMOCLAW_AUTO_PAIR_FAST_DEADLINE_SECS="$AUTO_PAIR_FAST_DEADLINE_SECS"
  export NEMOCLAW_AUTO_PAIR_DEADLINE_SECS="$AUTO_PAIR_DEADLINE_SECS"
  export NEMOCLAW_AUTO_PAIR_SLOW_INTERVAL_SECS="$AUTO_PAIR_SLOW_INTERVAL_SECS"
  export NEMOCLAW_AUTO_PAIR_RUN_TIMEOUT_SECS="$AUTO_PAIR_RUN_TIMEOUT_SECS"
  run_with_timeout 900 nemoclaw onboard --non-interactive --fresh
) >>"$INSTALL_LOG" 2>&1
onboard_b_rc=$?
if [ "$onboard_b_rc" -ne 0 ]; then
  fail "second sandbox onboard failed with exit ${onboard_b_rc}; see ${INSTALL_LOG}"
  exit 1
fi
pass "second sandbox onboarded"

sandbox_b_exec_sh_script() {
  local seconds="$1"
  local script="$2"
  shift 2
  local encoded remote_cmd arg
  encoded="$(printf '%s' "$script" | base64 | tr -d '\n')"
  remote_cmd="tmp=\$(mktemp); trap 'rm -f \"\$tmp\"' EXIT; printf %s $(quote_for_remote_sh "$encoded") | base64 -d > \"\$tmp\"; bash \"\$tmp\""
  for arg in "$@"; do
    remote_cmd+=" $(quote_for_remote_sh "$arg")"
  done
  run_with_timeout "$seconds" "$OPENSHELL_BIN" sandbox exec --name "$SANDBOX_NAME_B" -- sh -lc "$remote_cmd"
}

info "Running concurrent openclaw agent turns in both sandboxes"

multi_agent_script='
set -u
# shellcheck source=/dev/null
. /tmp/nemoclaw-proxy-env.sh
session_id="cli-scope-multi-$(date +%s)-$$"
rm -f "/sandbox/.openclaw/agents/main/sessions/${session_id}.jsonl.lock" \
      "/sandbox/.openclaw/agents/main/sessions/${session_id}.trajectory.jsonl" 2>/dev/null || true
printf "__URL_FOR_MULTI_AGENT__=%s\n" "${OPENCLAW_GATEWAY_URL-unset}"
openclaw agent --agent main --json --session-id "$session_id" \
  -m "What is 2 plus 2? Reply with only the integer, no extra words."
'

multi_out_a="$(mktemp)"
multi_out_b="$(mktemp)"

(sandbox_exec_sh_script 240 "$multi_agent_script" >"$multi_out_a" 2>&1) &
multi_pid_a=$!
(sandbox_b_exec_sh_script 240 "$multi_agent_script" >"$multi_out_b" 2>&1) &
multi_pid_b=$!

wait "$multi_pid_a"
multi_rc_a=$?
wait "$multi_pid_b"
multi_rc_b=$?

{
  printf '=== sandbox A concurrent agent (rc=%s) ===\n' "$multi_rc_a"
  cat "$multi_out_a"
  printf '=== sandbox B concurrent agent (rc=%s) ===\n' "$multi_rc_b"
  cat "$multi_out_b"
} >>"$AGENT_LOG"

multi_marker_re='EMBEDDED FALLBACK|scope upgrade pending approval|pairing required|fallbackFrom[": ]+gateway|transport[": ]+embedded'

multi_pass=1
if [ "$multi_rc_a" -ne 0 ]; then
  fail "sandbox A concurrent agent exited ${multi_rc_a}: $(head -c 400 "$multi_out_a")"
  multi_pass=0
fi
if [ "$multi_rc_b" -ne 0 ]; then
  fail "sandbox B concurrent agent exited ${multi_rc_b}: $(head -c 400 "$multi_out_b")"
  multi_pass=0
fi
if grep -Eiq "$multi_marker_re" "$multi_out_a"; then
  fail "sandbox A concurrent agent output contained scope-upgrade or fallback marker"
  multi_pass=0
fi
if grep -Eiq "$multi_marker_re" "$multi_out_b"; then
  fail "sandbox B concurrent agent output contained scope-upgrade or fallback marker"
  multi_pass=0
fi
multi_url_a="$(grep -m1 '^__URL_FOR_MULTI_AGENT__=' "$multi_out_a" | sed 's/^__URL_FOR_MULTI_AGENT__=//')"
multi_url_b="$(grep -m1 '^__URL_FOR_MULTI_AGENT__=' "$multi_out_b" | sed 's/^__URL_FOR_MULTI_AGENT__=//')"

case "$multi_url_a" in
  ws://*:18789) : ;;
  *)
    fail "sandbox A concurrent agent gateway URL did not pin to :18789 (got: ${multi_url_a:-unset})"
    multi_pass=0
    ;;
esac
case "$multi_url_b" in
  ws://*:18790) : ;;
  *)
    fail "sandbox B concurrent agent gateway URL did not pin to :18790 (got: ${multi_url_b:-unset})"
    multi_pass=0
    ;;
esac
if [ -n "$multi_url_a" ] && [ "$multi_url_a" = "$multi_url_b" ]; then
  fail "sandboxes shared one OPENCLAW_GATEWAY_URL (${multi_url_a}); per-sandbox routing isolation broken"
  multi_pass=0
fi

rm -f "$multi_out_a" "$multi_out_b"

if [ "$multi_pass" -eq 1 ]; then
  pass "both sandboxes ran concurrent openclaw agent turns gateway-backed (sandbox A → :18789, sandbox B → :18790, distinct URLs, no scope-upgrade, pairing, or EMBEDDED FALLBACK markers)"
fi

if [ "$FAIL" -gt 0 ]; then
  section "Summary"
  echo ""
  printf '  Total: %d | \033[32mPass: %d\033[0m | \033[31mFail: %d\033[0m\n' \
    "$TOTAL" "$PASS" "$FAIL"
  echo ""
  echo "RESULT: FAILED - ${FAIL} test(s) failed"
  exit 1
fi

finish_success "RESULT: PASSED - CLI scope-upgrade approval stays on the gateway path"
