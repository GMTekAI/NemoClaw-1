# OpenShell 0.0.67 Gateway Auth Review

Review date: 2026-06-22

Scope: NemoClaw Docker-driver gateway config generated for OpenShell `0.0.67`.

## Source Review

Reviewed upstream source at `NVIDIA/OpenShell@v0.0.67` (`ce788b50f9b1f977a4327e4484c5b663013dd9a5`):

- `crates/openshell-core/src/config.rs`: `GatewayAuthConfig.allow_unauthenticated_users` is documented as an unsafe local-development escape hatch for user/CLI calls; sandbox supervisor calls still use gateway-minted sandbox JWTs.
- `crates/openshell-server/src/lib.rs`: when `gateway_jwt` is configured, OpenShell reads the configured signing key, public key, and kid, then installs both `SandboxJwtIssuer` and `SandboxJwtAuthenticator`.
- `crates/openshell-server/src/config_file.rs`: OpenShell loads the gateway tables from config files through `openshell_server::config_file::load()`.
- `crates/openshell-server/src/lib.rs`: the server binds the configured main listener plus compute-driver `gateway_bind_addresses`, skipping only driver addresses already covered by a wildcard listener.
- `crates/openshell-server/src/auth/sandbox_jwt.rs`: sandbox JWTs are Ed25519/EdDSA, require the configured `kid`, `iss`, `aud`, and `sub`, and reject expired tokens while allowing non-matching `kid` values to fall through to other authenticators.
- `crates/openshell-driver-docker/src/lib.rs`: Docker-driver sandboxes see loopback and arbitrary hostnames rewritten to `host.openshell.internal:<gateway-port>`, and native Linux Docker gets a bridge-gateway bind address such as `<docker-bridge-gateway-ip>:<gateway-port>`.
- `crates/openshell-server/src/multiplex.rs`: a local unauthenticated user principal is allowed only when `allow_unauthenticated_users` is true; user principals are rejected from sandbox-only methods with `permission_denied`, while sandbox principals are checked against the sandbox method allowlist.

## NemoClaw Boundary

NemoClaw generates `gateway_jwt` config for sandbox supervisor callbacks while preserving `allow_unauthenticated_users = true` so host-side OpenShell CLI user calls remain available. OpenShell 0.0.67 still expects local user calls such as `openshell sandbox list` and `openshell sandbox delete` to work without an explicit bearer token. A full fail-closed user-auth boundary is therefore not claimed by this PR; it should move to a follow-up once OpenShell provides a trusted local-user auth path or NemoClaw can send user auth for host-side provider registration.

The Docker-hosted compatibility gateway keeps the main OpenShell listener on `127.0.0.1`. Sandbox callback reachability is preserved by OpenShell's Docker driver: it rewrites the sandbox-facing endpoint to `host.openshell.internal:<gateway-port>` and the OpenShell server adds the computed Docker bridge listener when that route is needed. `NEMOCLAW_OPENSHELL_GATEWAY_COMPAT_BIND_ADDRESS=0.0.0.0` is rejected because unauthenticated local-user fallback remains enabled for host CLI compatibility.

Package-managed Docker-driver gateways also reject `NEMOCLAW_GATEWAY_BIND_ADDRESS=0.0.0.0` while the 0.0.67 Docker-driver config is active. Use the dashboard bind setting for remote dashboard exposure instead of widening the OpenShell gateway surface.

## Upstream Contract Coverage

No repo-local live source-contract scenario is claimed by this PR. The source review above was performed directly against `NVIDIA/OpenShell@v0.0.67`, and the local unit coverage below models the relevant OpenShell 0.0.67 auth-router behavior with NemoClaw's generated config.

Local run against `NVIDIA/OpenShell@v0.0.67`:

- `cargo test -p openshell-server sandbox_jwt -- --nocapture`: passed 7 sandbox JWT tests, including `mint_and_validate_round_trip`, `token_signed_by_other_key_is_rejected`, `malformed_token_is_rejected`, and `expired_token_is_rejected`.
- `cargo test -p openshell-server unauthenticated_dev_user -- --nocapture`: passed `unauthenticated_dev_user_fills_missing_principal_when_enabled` and `unauthenticated_dev_user_authenticates_without_chain_when_enabled`.
- `cargo test -p openshell-server sandbox_principal_can_call_allowlisted_method -- --nocapture`: passed.
- `cargo test -p openshell-server user_principal_is_denied_on_sandbox_only_methods -- --nocapture`: passed.
- `cargo test -p openshell-server gateway_listener_addresses -- --nocapture`: passed `gateway_listener_addresses_include_driver_address_on_distinct_ip` and `gateway_listener_addresses_skip_driver_address_covered_by_wildcard`.
- `cargo test -p openshell-driver-docker container_visible_endpoint_rewrites_loopback_hosts -- --nocapture`: passed.
- `cargo test -p openshell-driver-docker docker_gateway_route_uses_bridge_gateway_for_linux_docker -- --nocapture`: passed.

## Local Coverage

- `src/lib/onboard/docker-driver-gateway-config.test.ts` verifies the generated TOML/JWT bundle, valid bundle reuse, invalid complete bundle regeneration, wrong kid, wrong gateway id, expired token rejection, host-side local-user compatibility, and the OpenShell 0.0.67 auth-router contract for sandbox principals.
- `src/lib/onboard/docker-driver-gateway-env.test.ts` verifies package-managed Docker-driver gateway startup rejects wildcard binds while gateway JWT auth is active.
- `src/lib/onboard/docker-driver-gateway-launch.test.ts` verifies loopback main binding, digest-pinned compatibility image selection, wildcard override rejection, stale auth-disable env scrubbing, and generated `OPENSHELL_GATEWAY_CONFIG`.
