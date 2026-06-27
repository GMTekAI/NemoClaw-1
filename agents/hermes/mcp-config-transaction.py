#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Transactional Hermes MCP config mutation and in-sandbox reload control.

This helper never proxies MCP traffic and never handles raw service
credentials. The root entrypoint runs its small Unix control service only to
serialize validated config/hash mutations and signal the Hermes gateway.
Ordinary OpenShell sandbox exec remains privilege-dropped to the sandbox user.
"""

from __future__ import annotations

import argparse
import http.client
import importlib.util
import ipaddress
import json
import os
import grp
import pwd
import re
import signal
import socket
import stat
import struct
import sys
import time
from types import ModuleType
from urllib.parse import urlsplit

import yaml


CONFIG_PATH = "/sandbox/.hermes/config.yaml"
HERMES_DIR = "/sandbox/.hermes"
STRICT_HASH_PATH = "/etc/nemoclaw/hermes.config-hash"
GUARD_PATH = "/usr/local/lib/nemoclaw/hermes-runtime-config-guard.py"
CONTROL_DIR = "/run/nemoclaw"
CONTROL_SOCKET_PATH = f"{CONTROL_DIR}/hermes-mcp-control.sock"
MAX_REQUEST_BYTES = 64 * 1024
RELOAD_TIMEOUT_SECONDS = 300
CONTROL_REQUEST_TIMEOUT_SECONDS = RELOAD_TIMEOUT_SECONDS * 2 + 30
SERVER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
ENV_PLACEHOLDER_RE = re.compile(r"^Bearer openshell:resolve:env:[A-Za-z_][A-Za-z0-9_]{0,127}$")
BLOCKED_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)


def _load_guard() -> ModuleType:
    spec = importlib.util.spec_from_file_location("nemoclaw_hermes_runtime_guard", GUARD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Hermes runtime config guard could not be loaded")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves the defining module through sys.modules while the
    # guard is executing, so register it before exec_module().
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _assert_mutable_snapshot(snapshot: object) -> None:
    mode = int(getattr(snapshot, "mode"))
    uid = int(getattr(snapshot, "uid"))
    gid = int(getattr(snapshot, "gid"))
    if os.geteuid() == 0:
        expected_uid = pwd.getpwnam("sandbox").pw_uid
        expected_gid = grp.getgrnam("sandbox").gr_gid
        owner_matches = uid == expected_uid and gid == expected_gid
    else:
        owner_matches = uid == os.geteuid()
    if not owner_matches or not (mode & stat.S_IWUSR):
        raise RuntimeError(
            "Hermes config is locked or is not owned by the sandbox identity. "
            "Lower shields before changing managed MCP servers."
        )


def _parse_payload(raw: str) -> dict[str, object]:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("MCP mutation payload must be an object")
    return payload


def _validate_payload(action: str, payload: dict[str, object]) -> None:
    allowed = {"server", "url", "headers"}
    allowed.add("replace_existing" if action == "add" else "force")
    unexpected = sorted(set(payload) - allowed)
    if unexpected:
        raise ValueError(
            f"MCP mutation payload contains unsupported fields: {', '.join(unexpected)}"
        )
    server = payload.get("server")
    if not isinstance(server, str) or not SERVER_NAME_RE.fullmatch(server):
        raise ValueError("MCP mutation payload has an invalid server name")
    raw_url = payload.get("url")
    if not isinstance(raw_url, str) or len(raw_url) > 2048:
        raise ValueError("MCP mutation payload has an invalid URL")
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("MCP mutation payload URL must be HTTP or HTTPS")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("MCP mutation payload URL contains forbidden components")
    hostname = parsed.hostname.lower().rstrip(".")
    if ":" in hostname:
        raise ValueError("IPv6-literal MCP URLs are not supported")
    if not hostname.isascii() or any(char in hostname for char in "*?[]{};"):
        raise ValueError("MCP mutation payload URL has a non-literal hostname")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("MCP mutation payload URL has an invalid port") from error
    if port == 0:
        raise ValueError("MCP mutation payload URL port must be nonzero")
    host_alias = hostname in {
        "host.openshell.internal",
        "host.docker.internal",
        "host.containers.internal",
    }
    if not host_alias and (
        hostname in {"localhost", "local", "internal", "metadata"}
        or any(
            hostname.endswith(f".{suffix}")
            for suffix in ("localhost", "local", "internal", "metadata")
        )
    ):
        raise ValueError("MCP mutation payload URL uses a reserved hostname")
    if parsed.scheme != "https" and not host_alias:
        raise ValueError("Public MCP mutation payload URLs must use HTTPS")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is None and re.fullmatch(
        r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*",
        hostname,
    ):
        raise ValueError("MCP mutation payload URL uses an ambiguous numeric host")
    if address is not None and (
        not address.is_global
        or any(address in network for network in BLOCKED_IPV4_NETWORKS)
    ):
        raise ValueError("MCP mutation payload URL uses a non-global address")
    path = parsed.path or "/"
    if not path.startswith("/") or any(
        char in path for char in ("%", "\\", ";", "*", "?", "[", "]", "{", "}")
    ):
        raise ValueError("MCP mutation payload URL path must be literal and canonical")
    default_port = 443 if parsed.scheme == "https" else 80
    authority = hostname if port in {None, default_port} else f"{hostname}:{port}"
    canonical = f"{parsed.scheme}://{authority}{path}"
    if raw_url != canonical:
        raise ValueError("MCP mutation payload URL must be canonical")
    flag_name = "replace_existing" if action == "add" else "force"
    if flag_name in payload and not isinstance(payload[flag_name], bool):
        raise ValueError(f"MCP mutation payload {flag_name} must be boolean")
    headers = payload.get("headers")
    if not isinstance(headers, dict) or set(headers) != {"Authorization"}:
        raise ValueError("MCP mutation payload must contain one Authorization header")
    authorization = headers.get("Authorization")
    if not isinstance(authorization, str) or not ENV_PLACEHOLDER_RE.fullmatch(
        authorization
    ):
        raise ValueError(
            "Hermes MCP Authorization must contain an OpenShell environment placeholder"
        )


def _managed_candidate(payload: dict[str, object]) -> dict[str, object]:
    headers = payload.get("headers")
    if not isinstance(headers, dict):
        raise ValueError("MCP mutation payload headers must be an object")
    candidate: dict[str, object] = {
        "url": payload.get("url"),
        "enabled": True,
        "timeout": 120,
        "connect_timeout": 60,
        "tools": {"resources": True, "prompts": True},
    }
    if headers:
        candidate["headers"] = headers
    return candidate


def _mutate(data: object, action: str, payload: dict[str, object]) -> tuple[dict, bool]:
    if not isinstance(data, dict):
        raise ValueError("Invalid Hermes config: expected a YAML object")
    server_name = payload.get("server")
    if not isinstance(server_name, str) or not server_name:
        raise ValueError("MCP mutation payload has no server name")

    servers = data.get("mcp_servers")
    if servers is None:
        servers = {}
        data["mcp_servers"] = servers
    if not isinstance(servers, dict):
        raise ValueError("Invalid Hermes config: mcp_servers must be an object")

    if action == "add":
        replace = payload.get("replace_existing") is True
        if server_name in servers and not replace:
            raise ValueError(
                f"MCP server '{server_name}' already exists in Hermes config and is not managed by NemoClaw."
            )
        candidate = _managed_candidate(payload)
        if servers.get(server_name) == candidate:
            return data, False
        servers[server_name] = candidate
        return data, True

    if action != "remove":
        raise ValueError(f"Unsupported MCP config action '{action}'")
    if server_name not in servers:
        return data, False
    current = servers.get(server_name)
    managed = current == _managed_candidate(payload)
    if not managed and payload.get("force") is not True:
        raise ValueError(
            f"Refusing to remove modified Hermes MCP server '{server_name}'. Use --force to remove it."
        )
    servers.pop(server_name, None)
    if not servers:
        data.pop("mcp_servers", None)
    return data, True


def _managed_hash_paths(privileged: bool) -> tuple[str, ...]:
    compatibility = os.path.join(HERMES_DIR, ".config-hash")
    return (STRICT_HASH_PATH, compatibility) if privileged else (compatibility,)


def _refresh_and_verify_hashes(guard: ModuleType, privileged: bool) -> None:
    if privileged:
        guard.refresh_hashes(HERMES_DIR, STRICT_HASH_PATH, "strict")
    guard.refresh_hashes(HERMES_DIR, STRICT_HASH_PATH, "compat")
    compat_text, _ = guard._read_text(os.path.join(HERMES_DIR, ".config-hash"))
    expected_text, _, _ = guard._hash_text(
        os.path.join(HERMES_DIR, "config.yaml"),
        os.path.join(HERMES_DIR, ".env"),
    )
    if compat_text != expected_text:
        raise RuntimeError("Hermes compatibility config hash is stale")
    if privileged:
        strict_text, _ = guard._read_text(STRICT_HASH_PATH)
    else:
        strict_text = compat_text
    if strict_text != compat_text:
        raise RuntimeError("Hermes strict and compatibility config hashes differ")


def _restore_hash_snapshots(
    guard: ModuleType, originals: dict[str, tuple[str, object]]
) -> None:
    for path, (original_text, original_snapshot) in originals.items():
        _, current_snapshot = guard._read_text(path)
        guard._write_existing(
            path,
            original_text,
            current_snapshot,
            mode=int(getattr(original_snapshot, "mode")),
        )
        restored_text, _ = guard._read_text(path)
        if restored_text != original_text:
            raise RuntimeError(f"Failed to restore Hermes hash file {path}")


def apply_transaction(action: str, payload: dict[str, object]) -> bool:
    _validate_payload(action, payload)
    privileged = os.geteuid() == 0
    guard = _load_guard()
    original_text, original_snapshot = guard._read_text(CONFIG_PATH)
    _assert_mutable_snapshot(original_snapshot)
    hash_originals = {
        path: guard._read_text(path)
        for path in _managed_hash_paths(privileged)
    }
    parsed = yaml.safe_load(original_text) or {}
    updated, changed = _mutate(parsed, action, payload)
    if not changed:
        try:
            _refresh_and_verify_hashes(guard, privileged)
        except Exception as hash_error:
            try:
                _restore_hash_snapshots(guard, hash_originals)
            except Exception as rollback_error:
                raise RuntimeError(
                    f"Hermes MCP hash refresh failed ({hash_error}); "
                    f"hash rollback also failed ({rollback_error})"
                ) from rollback_error
            raise
        return False

    updated_text = yaml.safe_dump(updated, sort_keys=False)
    replacement_snapshot = None
    try:
        guard._write_existing(
            CONFIG_PATH,
            updated_text,
            original_snapshot,
            mode=original_snapshot.mode,
        )
        _, replacement_snapshot = guard._read_text(CONFIG_PATH)
        _refresh_and_verify_hashes(guard, privileged)
    except Exception as mutation_error:
        if replacement_snapshot is None:
            raise
        try:
            guard._write_existing(
                CONFIG_PATH,
                original_text,
                replacement_snapshot,
                mode=original_snapshot.mode,
            )
            _refresh_and_verify_hashes(guard, privileged)
        except Exception as rollback_error:
            raise RuntimeError(
                f"Hermes MCP config update failed ({mutation_error}); rollback also failed ({rollback_error})"
            ) from rollback_error
        raise
    return True


def apply_transaction_and_reload(
    action: str, payload: dict[str, object]
) -> dict[str, object]:
    """Commit config+hashes and runtime reload as one recoverable operation."""
    _validate_payload(action, payload)
    privileged = os.geteuid() == 0
    guard = _load_guard()
    original_text, original_snapshot = guard._read_text(CONFIG_PATH)
    hash_originals = {
        path: guard._read_text(path)
        for path in _managed_hash_paths(privileged)
    }
    parsed = yaml.safe_load(original_text) or {}
    expected_data, expected_changed = _mutate(parsed, action, payload)
    expected_text = (
        yaml.safe_dump(expected_data, sort_keys=False)
        if expected_changed
        else original_text
    )

    changed = apply_transaction(action, payload)
    try:
        reloaded = reload_gateway()
    except Exception as reload_error:
        if not changed:
            raise RuntimeError(
                f"Hermes MCP runtime reload failed with unchanged config ({reload_error})"
            ) from reload_error
        rollback_errors: list[str] = []
        try:
            current_text, current_snapshot = guard._read_text(CONFIG_PATH)
            if current_text != expected_text:
                raise RuntimeError(
                    "Hermes config changed concurrently after MCP mutation; refusing rollback"
                )
            guard._write_existing(
                CONFIG_PATH,
                original_text,
                current_snapshot,
                mode=int(getattr(original_snapshot, "mode")),
            )
            try:
                _refresh_and_verify_hashes(guard, privileged)
            except Exception:
                _restore_hash_snapshots(guard, hash_originals)
                raise
        except Exception as rollback_error:
            rollback_errors.append(f"config/hash rollback failed: {rollback_error}")
        else:
            try:
                rollback_reloaded = reload_gateway()
                if not rollback_reloaded:
                    rollback_errors.append(
                        "old-config runtime reload was not verified because the gateway stopped"
                    )
            except Exception as rollback_reload_error:
                rollback_errors.append(
                    f"old-config runtime reload failed: {rollback_reload_error}"
                )
        detail = "; ".join(rollback_errors) or "config and hashes were restored"
        raise RuntimeError(
            f"Hermes MCP runtime reload failed ({reload_error}); {detail}"
        ) from reload_error
    return {"ok": True, "changed": changed, "reloaded": reloaded}


def _gateway_identity() -> tuple[int, object] | None:
    os.environ["HERMES_HOME"] = HERMES_DIR
    from gateway.status import get_process_start_time, get_running_pid

    pid = get_running_pid(cleanup_stale=False)
    if not pid:
        return None
    try:
        owner_uid = os.stat(f"/proc/{int(pid)}").st_uid
    except FileNotFoundError:
        return None
    expected_uid = (
        pwd.getpwnam("gateway").pw_uid if os.geteuid() == 0 else os.geteuid()
    )
    if owner_uid != expected_uid:
        expected_identity = "gateway" if os.geteuid() == 0 else "sandbox"
        raise PermissionError(
            f"Hermes gateway is not owned by the expected {expected_identity} identity"
        )
    return int(pid), get_process_start_time(pid)


def _gateway_healthy() -> bool:
    connection = http.client.HTTPConnection("127.0.0.1", 18642, timeout=2)
    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        response.read()
        return response.status in {200, 401}
    except OSError:
        return False
    finally:
        connection.close()


def reload_gateway() -> bool:
    previous = _gateway_identity()
    if previous is None:
        return False
    try:
        os.kill(previous[0], signal.SIGUSR1)
    except ProcessLookupError:
        if _gateway_identity() is None:
            return False
        raise

    deadline = time.monotonic() + RELOAD_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        current = _gateway_identity()
        if current is not None and current != previous and _gateway_healthy():
            return True
        time.sleep(1)
    raise TimeoutError("Hermes gateway did not complete its managed MCP reload")


def _receive_bounded(
    connection: socket.socket, timeout_seconds: float | None = None
) -> bytes:
    chunks: list[bytes] = []
    size = 0
    deadline = (
        time.monotonic() + timeout_seconds if timeout_seconds is not None else None
    )
    while True:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Hermes MCP control request timed out")
            connection.settimeout(remaining)
        chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_REQUEST_BYTES:
            raise ValueError("Hermes MCP control request is too large")
    return b"".join(chunks)


def _sandbox_peer(connection: socket.socket) -> bool:
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("SO_PEERCRED is required for Hermes MCP control")
    credentials = connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    _, uid, gid = struct.unpack("3i", credentials)
    sandbox = pwd.getpwnam("sandbox")
    return uid == sandbox.pw_uid and gid in {
        sandbox.pw_gid,
        grp.getgrnam("sandbox").gr_gid,
    }


def _handle_control_request(raw: bytes) -> dict[str, object]:
    request = json.loads(raw.decode("utf-8"))
    if not isinstance(request, dict) or set(request) != {"action", "payload"}:
        raise ValueError("Invalid Hermes MCP control request schema")
    action = request.get("action")
    payload = request.get("payload")
    if action not in {"add", "remove"} or not isinstance(payload, dict):
        raise ValueError("Invalid Hermes MCP control action")
    return apply_transaction_and_reload(str(action), payload)


def _prepare_control_socket() -> socket.socket:
    sandbox = pwd.getpwnam("sandbox")
    try:
        os.mkdir(CONTROL_DIR, 0o750)
    except FileExistsError:
        pass
    directory = os.lstat(CONTROL_DIR)
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0:
        raise RuntimeError(f"Unsafe Hermes MCP control directory: {CONTROL_DIR}")
    os.chown(CONTROL_DIR, 0, sandbox.pw_gid)
    os.chmod(CONTROL_DIR, 0o750)
    try:
        existing = os.lstat(CONTROL_SOCKET_PATH)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != 0:
            raise RuntimeError(
                f"Refusing unsafe Hermes MCP control socket: {CONTROL_SOCKET_PATH}"
            )
        os.unlink(CONTROL_SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(CONTROL_SOCKET_PATH)
    os.chown(CONTROL_SOCKET_PATH, 0, sandbox.pw_gid)
    os.chmod(CONTROL_SOCKET_PATH, 0o660)
    server.listen(4)
    server.settimeout(1)
    return server


def serve() -> int:
    if os.geteuid() != 0:
        raise PermissionError("Hermes MCP control service must run as root")
    server = _prepare_control_socket()
    stopping = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopping:
            try:
                connection, _ = server.accept()
            except TimeoutError:
                continue
            with connection:
                response: dict[str, object]
                try:
                    if not _sandbox_peer(connection):
                        raise PermissionError(
                            "Hermes MCP control rejected a non-sandbox peer"
                        )
                    response = _handle_control_request(
                        _receive_bounded(connection, timeout_seconds=5)
                    )
                except Exception as error:
                    response = {"ok": False, "error": str(error)}
                try:
                    connection.sendall(
                        json.dumps(response, sort_keys=True).encode("utf-8") + b"\n"
                    )
                except OSError:
                    # A disconnected client must not terminate the root-owned
                    # lifecycle service or strand future host operations.
                    pass
    finally:
        server.close()
        try:
            socket_stat = os.lstat(CONTROL_SOCKET_PATH)
            if stat.S_ISSOCK(socket_stat.st_mode) and socket_stat.st_uid == 0:
                os.unlink(CONTROL_SOCKET_PATH)
        except FileNotFoundError:
            pass
    return 0


def request_control(action: str, payload: dict[str, object]) -> dict[str, object]:
    request = json.dumps(
        {"action": action, "payload": payload},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(request) > MAX_REQUEST_BYTES:
        raise ValueError("Hermes MCP control request is too large")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # A failed forward reload performs one bounded old-config reload after
    # restoring config+hashes, so the transport must cover both windows.
    client.settimeout(CONTROL_REQUEST_TIMEOUT_SECONDS)
    try:
        client.connect(CONTROL_SOCKET_PATH)
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        raw = _receive_bounded(client)
    finally:
        client.close()
    response = json.loads(raw.decode("utf-8"))
    if not isinstance(response, dict) or response.get("ok") is not True:
        detail = response.get("error") if isinstance(response, dict) else None
        raise RuntimeError(str(detail or "Hermes MCP control request failed"))
    return response


def execute(action: str, payload: dict[str, object]) -> dict[str, object]:
    _validate_payload(action, payload)
    if os.geteuid() == 0:
        return apply_transaction_and_reload(action, payload)
    if os.path.exists(CONTROL_SOCKET_PATH):
        return request_control(action, payload)
    try:
        control_dir = os.lstat(CONTROL_DIR)
    except FileNotFoundError:
        control_dir = None
    if control_dir is not None and control_dir.st_uid == 0:
        raise RuntimeError(
            "Hermes MCP control service is unavailable in this root-managed sandbox"
        )
    return apply_transaction_and_reload(action, payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("add", "remove", "serve"))
    parser.add_argument("--payload")
    args = parser.parse_args()
    try:
        if args.action == "serve":
            if args.payload is not None:
                raise ValueError("Hermes MCP control service takes no payload")
            return serve()
        if args.payload is None:
            raise ValueError("Hermes MCP mutation requires --payload")
        result = execute(args.action, _parse_payload(args.payload))
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
