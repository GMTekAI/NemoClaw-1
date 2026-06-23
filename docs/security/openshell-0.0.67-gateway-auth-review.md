# OpenShell 0.0.67 Gateway Auth Review

Review date: 2026-06-22

Scope: NemoClaw Docker-driver gateway config generated for OpenShell `0.0.67`.

## Source Review

Reviewed upstream source at `NVIDIA/OpenShell@v0.0.67` (`ce788b50f9b1f977a4327e4484c5b663013dd9a5`):

- `crates/openshell-core/src/config.rs`: `GatewayAuthConfig.allow_unauthenticated_users` is documented as an unsafe local-development escape hatch for user/CLI calls; sandbox supervisor calls still use gateway-minted sandbox JWTs.
- `crates/openshell-server/src/lib.rs`: when `gateway_jwt` is configured, OpenShell reads the configured signing key, public key, and kid, then installs both `SandboxJwtIssuer` and `SandboxJwtAuthenticator`.
- `crates/openshell-server/src/auth/sandbox_jwt.rs`: sandbox JWTs are Ed25519/EdDSA, require the configured `kid`, `iss`, `aud`, and `sub`, and reject expired tokens while allowing non-matching `kid` values to fall through to other authenticators.
- `crates/openshell-server/src/multiplex.rs`: a local unauthenticated user principal is allowed only when `allow_unauthenticated_users` is true; user principals are rejected from sandbox-only methods with `permission_denied`, while sandbox principals are checked against the sandbox method allowlist.

## NemoClaw Boundary

NemoClaw keeps `allow_unauthenticated_users = true` so local OpenShell CLI/API provider-registration calls remain compatible with OpenShell 0.0.67. The generated `gateway_jwt` bundle remains the sandbox supervisor auth path, and stale `OPENSHELL_DISABLE_GATEWAY_AUTH` env is scrubbed before launch.

The Docker-hosted compatibility gateway now defaults to `127.0.0.1`. Binding the compatibility gateway to `0.0.0.0` is an explicit operator override via `NEMOCLAW_OPENSHELL_GATEWAY_COMPAT_BIND_ADDRESS=0.0.0.0`, because OpenShell 0.0.67 does not distinguish a local unauthenticated user caller from a remote unauthenticated caller once the socket is reachable.

## Local Coverage

- `src/lib/onboard/docker-driver-gateway-config.test.ts` verifies the generated TOML/JWT bundle, key reuse/regeneration, wrong kid, wrong gateway id, expired token rejection, and the OpenShell 0.0.67 auth-router contract for local user versus sandbox principals.
- `src/lib/onboard/docker-driver-gateway-launch.test.ts` verifies loopback default binding, explicit wildcard override, stale auth-disable env scrubbing, generated `OPENSHELL_GATEWAY_CONFIG`, and the wildcard warning log.
