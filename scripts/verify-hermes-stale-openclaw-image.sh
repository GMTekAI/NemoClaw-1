#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

LOG_PATH="${NEMOCLAW_HERMES_STALE_OPENCLAW_IMAGE_LOG:-/tmp/nemoclaw-hermes-stale-openclaw-image.log}"
: >"$LOG_PATH"
exec > >(tee -a "$LOG_PATH") 2>&1

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
fail() {
  echo -e "${RED}[FAIL]${NC} $1" >&2
  exit 1
}

require_docker() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker info >/dev/null 2>&1 || fail "docker daemon is not available"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUN_ID="${GITHUB_RUN_ID:-local}-$$"
BASE_IMAGE="${NEMOCLAW_HERMES_BASE_IMAGE:-${HERMES_BASE_IMAGE:-}}"
BASE_IMAGE="${BASE_IMAGE:-$(sed -nE 's/^ARG BASE_IMAGE=(.*)$/\1/p' "${REPO_ROOT}/agents/hermes/Dockerfile" | head -n 1)}"
STALE_DIR_BASE="nemoclaw-hermes-stale-openclaw-dir-base:${RUN_ID}"
STALE_DIR_IMAGE="nemoclaw-hermes-stale-openclaw-dir:${RUN_ID}"
STALE_LINK_BASE="nemoclaw-hermes-stale-openclaw-link-base:${RUN_ID}"
STALE_LINK_IMAGE="nemoclaw-hermes-stale-openclaw-link:${RUN_ID}"
SYMLINK_BUILD_LOG="$(mktemp -t nemoclaw-hermes-stale-openclaw-build.XXXXXX.log)"

cleanup() {
  rm -f "$SYMLINK_BUILD_LOG"
  docker rmi -f "$STALE_DIR_IMAGE" "$STALE_DIR_BASE" "$STALE_LINK_BASE" "$STALE_LINK_IMAGE" \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT

build_stale_dir_base() {
  info "Building stale Hermes base with /sandbox/.openclaw directory from ${BASE_IMAGE}"
  docker build -f - --build-arg "BASE_IMAGE=${BASE_IMAGE}" -t "$STALE_DIR_BASE" "$REPO_ROOT" <<'DOCKERFILE' || fail "failed to build stale-directory Hermes base"
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
RUN rm -rf /sandbox/.openclaw \
    && mkdir -p /sandbox/.openclaw \
    && printf '{}\n' > /sandbox/.openclaw/openclaw.json
DOCKERFILE
}

build_stale_link_base() {
  info "Building stale Hermes base with symlinked /sandbox/.openclaw from ${BASE_IMAGE}"
  docker build -f - --build-arg "BASE_IMAGE=${BASE_IMAGE}" -t "$STALE_LINK_BASE" "$REPO_ROOT" <<'DOCKERFILE' || fail "failed to build stale-symlink Hermes base"
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
RUN rm -rf /sandbox/.openclaw \
    && mkdir -p /tmp/stale-openclaw-target \
    && printf 'keep\n' > /tmp/stale-openclaw-target/sentinel \
    && ln -s /tmp/stale-openclaw-target /sandbox/.openclaw
DOCKERFILE
}

verify_stale_dir_final_image() {
  info "Building Hermes final image from stale-directory base"
  docker build -f "${REPO_ROOT}/agents/hermes/Dockerfile" \
    --build-arg "BASE_IMAGE=${STALE_DIR_BASE}" \
    -t "$STALE_DIR_IMAGE" \
    "$REPO_ROOT" \
    || fail "Hermes final image did not build from stale-directory base"

  docker run --rm --entrypoint sh "$STALE_DIR_IMAGE" -lc '
    set -eu
    test ! -e /sandbox/.openclaw
    test "$(stat -c "%a" /sandbox/.hermes/runtime)" = "2770"
    test "$(readlink /sandbox/.hermes/gateway_state.json)" = "runtime/gateway_state.json"
  ' || fail "stale-directory Hermes final image layout assertions failed"
  pass "Hermes final image removes stale /sandbox/.openclaw directory"
}

verify_stale_link_final_image_fails() {
  info "Building Hermes final image from stale-symlink base; this must fail closed"
  set +e
  docker build -f "${REPO_ROOT}/agents/hermes/Dockerfile" \
    --build-arg "BASE_IMAGE=${STALE_LINK_BASE}" \
    -t "$STALE_LINK_IMAGE" \
    "$REPO_ROOT" \
    >"$SYMLINK_BUILD_LOG" 2>&1
  local status="$?"
  set -e

  if [ "$status" -eq 0 ]; then
    cat "$SYMLINK_BUILD_LOG" >&2
    fail "Hermes final image unexpectedly built from stale-symlink base"
  fi
  grep -F ".openclaw is a symlink" "$SYMLINK_BUILD_LOG" >/dev/null \
    || {
      cat "$SYMLINK_BUILD_LOG" >&2
      fail "symlink failure did not mention .openclaw"
    }
  docker run --rm --entrypoint sh "$STALE_LINK_BASE" -lc \
    'test "$(cat /tmp/stale-openclaw-target/sentinel)" = "keep"' \
    || fail "stale-symlink base sentinel was not preserved"
  pass "Hermes final image refuses symlinked stale /sandbox/.openclaw"
}

require_docker
build_stale_dir_base
verify_stale_dir_final_image
build_stale_link_base
verify_stale_link_final_image_fails
