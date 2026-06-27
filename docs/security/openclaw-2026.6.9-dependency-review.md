# OpenClaw 2026.6.9 Dependency Review

Review date: 2026-06-22

Scope: NemoClaw runtime pin `openclaw@2026.6.9`, runtime helper pin `@zed-industries/codex-acp@0.11.1`, optional OpenClaw plugins, and built-in messaging OpenClaw plugins.

## Package Identity

- npm package: `openclaw@2026.6.9`
- npm tarball: `https://registry.npmjs.org/openclaw/-/openclaw-2026.6.9.tgz`
- npm integrity: `sha512-y0PGUdE87S8QtQXABPDL0CjNKhH3q/R1h9/WiRQkhVCGSBVhs63/M1iZn2DYVyJCAbDyMz3KNyAE0WzSQIWCRg==`
- npm publish time: `2026-06-21T01:37:53.047Z`
- Codex ACP runtime helper package: `@zed-industries/codex-acp@0.11.1`
- Codex ACP runtime helper npm tarball: `https://registry.npmjs.org/@zed-industries/codex-acp/-/codex-acp-0.11.1.tgz`
- Codex ACP runtime helper npm integrity: `sha512-My2VSlBtvJipJhImHjFDej2ut/p00QqOISRnZgLgLrSIzjgvdcQvAhaZviWj7XPhk4UIdIb0OoA+Lrls824uiQ==`
- Diagnostics OTEL plugin package: `@openclaw/diagnostics-otel@2026.6.9`
- Diagnostics OTEL plugin npm integrity: `sha512-jU2q4L6L3qdZZDEIDXrWgwCWOGUaTSF+YzUlfgHED42TB4N3maF6seYchFpwKLB8neOzIDpnzMagEMjxZ/7Wqw==`
- Brave search plugin package: `@openclaw/brave-plugin@2026.6.9`
- Brave search plugin npm integrity: `sha512-8HawXB5ylo+vkvkmDJZAE9uhOtm0l9YtzrVqJdM4UqwXeF4uGAkVEOrR3Hxy0sI3Moi5ZBzq2Jx/K5ZQKdiWjQ==`
- Discord channel plugin package: `@openclaw/discord@2026.6.9`
- Discord channel plugin npm integrity: `sha512-esFhwYW0nrFQvBhkPeK/1qmvumlVAY8ddhYBt7geIYLlBriwPJRwtnVLLfp0n1LbS0/XVZ0ORqlvkWq8Vv61vg==`
- Slack channel plugin package: `@openclaw/slack@2026.6.9`
- Slack channel plugin npm integrity: `sha512-JZHc0L3s6s+yBsWowZtE/DWZJOuy4lTE6uTuUbF5QNjUvQQUlCHMFrwPycrXLesVq1il5yAvo82VbERRsIzgxQ==`
- WhatsApp channel plugin package: `@openclaw/whatsapp@2026.6.9`
- WhatsApp channel plugin npm integrity: `sha512-HWz9CryGcSk5ork03DlESVlRcDBnwuXPEKgqdSz/Qt0OnQ2Z1wqNGpwVlAqngvDQDH2AzkNXWuTu2M0C16R8vA==`
- Microsoft Teams channel plugin package: `@openclaw/msteams@2026.6.9`
- Microsoft Teams channel plugin npm integrity: `sha512-Ye1nf2fZYGM3lqQJ/zGlhToThyz1lLZE7HqR2F31iWcD5pV89+eEyRFNNH2FrwYeDVjw+EyWpQh2RkN1r867qg==`
- WeChat channel plugin package: `@tencent-weixin/openclaw-weixin@2.4.3`
- WeChat channel plugin npm integrity: `sha512-dPQbidUNWigC6V10vGW4i+GLH09x+6zUhafZRjuxkJ9GDu8o62WBsnUTojp4KqUH756hz+t2v9khiCRSi0dBDw==`

NemoClaw enforces the main `openclaw@2026.6.9`, `@zed-industries/codex-acp@0.11.1`, and each reviewed npm plugin registry integrity, including optional OTEL/brave plugins and messaging plugins, before install. The Dockerfile and messaging build applier then run `npm pack --json`, require the downloaded tarball integrity to match the committed SRI, and install from the verified local `.tgz` archive. Codex ACP and OpenClaw core also verify that registry metadata still reports the reviewed npm tarball URL before packing that URL.

## Advisory Check

Command run from a temporary directory:

```bash
npm init -y
npm install --package-lock-only --ignore-scripts --no-fund --no-audit \
  openclaw@2026.6.9 \
  @zed-industries/codex-acp@0.11.1 \
  @openclaw/diagnostics-otel@2026.6.9 \
  @openclaw/brave-plugin@2026.6.9 \
  @openclaw/discord@2026.6.9 \
  @openclaw/slack@2026.6.9 \
  @openclaw/whatsapp@2026.6.9 \
  @openclaw/msteams@2026.6.9 \
  @tencent-weixin/openclaw-weixin@2.4.3
npm audit --omit=dev --json
```

Result: npm audit exited `0` and reported `0` info, `0` low, `0` moderate, `0` high, and `0` critical vulnerabilities across `763` total dependencies.
The local install emitted npm `EBADENGINE` warnings under Node `22.16.0` for packages that require newer Node `22.x` builds; the audit still completed and is used here only as advisory vulnerability evidence for the locked dependency graph.

This review is an advisory snapshot for the direct OpenClaw runtime package, Codex ACP runtime helper, optional plugins, messaging plugins, and their npm dependency graphs at review time. It complements, but does not replace, the committed npm integrity pins, Dockerfile install-time registry integrity checks, and plugin install-time registry integrity checks.

## Slack Source Review

The main `openclaw@2026.6.9` package excludes `dist/extensions/slack/**`; its channel catalog points Slack installs to the external npm plugin `@openclaw/slack`. The reviewed `@openclaw/slack@2026.6.9` artifact exposes:

- `dist/runtime-api.js`, which exports `sendMessageSlack`;
- `dist/pipeline.runtime-*.js`, which exports `prepareSlackMessage`; and
- the denied channel-user gate containing `Blocked unauthorized slack sender ${senderId} (not in channel users)`, which NemoClaw's `slack-channel-guard` preload patches to emit one bounded sender-facing denial notice for explicit `app_mention` events.

The retained Slack proof scripts now import the installed external `@openclaw/slack@2026.6.9` runtime files when the older private `test-api.js` facade is absent. The installed-runtime proof exercises `prepareSlackMessage` from `dist/pipeline.runtime-*.js`, verifies an allowed channel `app_mention`, verifies a denied channel user receives exactly one bounded sender-facing feedback action, and sends through `sendMessageSlack` from `dist/runtime-api.js` against the hermetic fake Slack API.

## Telegram Source Review

The main `openclaw@2026.6.9` package no longer includes `dist/extensions/telegram/test-api.js`. Its bundled Telegram channel still exposes `dist/extensions/telegram/runtime-api.js`, which exports `sendMessageTelegram` and accepts NemoClaw's hermetic fake Telegram API override for send proof.

The retained Telegram proof script now resolves the installed `openclaw/dist/extensions/telegram/runtime-api.js` file, verifies that `sendMessageTelegram` is exported, sends through that runtime API against the host-side fake Telegram Bot API, and keeps the OpenShell REST policy, token rewrite assertion, chat/text capture, and placeholder-leak checks unchanged.

## PR Review Follow-ups

### Installer Integrity Transaction Boundary

`Dockerfile`, `Dockerfile.base`, optional OpenClaw plugin installs, and `src/lib/messaging/applier/build/messaging-build-applier.mts` now bind reviewed npm installs to verified local archives. The install blocks first verify `npm view ... dist.integrity` against the committed SRI. Codex ACP and OpenClaw core also verify `npm view ... dist.tarball` against the reviewed tarball URL. The actual install input is then produced by `npm pack --json`; the reported downloaded tarball integrity must match the committed SRI before `npm install -g <local .tgz>` or `openclaw plugins install <local .tgz> --pin` runs.

Invalid state: `npm view` returns the reviewed SRI but the downloaded artifact used for install has different bytes. Source boundary: Dockerfile npm install blocks, `Dockerfile.base`, optional plugin install blocks, and `src/lib/messaging/applier/build/messaging-build-applier.mts`. Source-fix constraint: npm package installation must stay artifact-bound for reviewed pins rather than reverting to a later floating package-spec transaction. Regression test: `test/openclaw-integrity-pin.test.ts` exercises registry drift, reviewed tarball URL drift, and local archive install behavior; `test/messaging-build-applier.test.ts` verifies messaging plugins run through `npm pack --json` and install the verified archive path; `test/messaging-build-applier-integrity.test.ts` verifies the messaging plugin install fails closed when packed archive integrity drifts. Removal condition: keep this archive verification until the repo moves the OpenClaw/plugin dependency set to a lockfile path where npm enforces the committed SRI directly.

### OpenClaw Compiled-Dist Patch Runtime Boundary

The OpenClaw 2026.6.9 compiled-dist patches are localized compatibility patches for sandbox fetch routing, cron preflight proxying, `host.openshell.internal` web_fetch scoping, unconfigured strict-fetch managed-proxy activation, and `chat.send`/`get-reply` correlation. The long-term source of truth for these behaviors remains upstream OpenClaw; NemoClaw's Dockerfile and patch scripts carry fail-closed version-shape patches only so the reviewed package can run inside the current NemoClaw/OpenShell sandbox contract.

Invalid state: a real installed `openclaw@2026.6.9` dist changes semantics while fixture-compatible recognizers still pass. Source boundary: the installed OpenClaw generated `dist` files, the Dockerfile fetch-guard patch block, and `scripts/patch-openclaw-chat-send.js`. Source-fix constraint: upstream OpenClaw should own permanent fixes; NemoClaw patches must stay version-scoped, fail closed on unknown shapes, and be removed when upstream ships reviewed behavior. Regression tests: `test/fetch-guard-patch-regression.test.ts` and `test/openclaw-chat-send-patch.test.ts` execute patched fixtures for the reviewed shapes, while the PR CI image builds and focused/full nightly E2Es provide built-image runtime smoke on the exact head.

Accepted residual risk: this dependency bump does not add a separate checked-in real-package runtime harness that imports the patched `openclaw@2026.6.9` dist after Dockerfile mutation for every patched path. That gap is accepted for this bump only with exact-head CI image builds, focused nightly proof for the affected E2Es, and final full nightly proof before merge. Removal condition: delete the localized patches when OpenClaw ships the behavior, or add a real-package/built-image runtime harness if NemoClaw keeps carrying these patches beyond this reviewed bump.

#### OpenClaw Patch Source-of-Truth Table

| Patch | Invalid state | Source boundary | Why upstream/source cannot be fixed here | Regression test | Removal condition |
|---|---|---|---|---|---|
| Patch 2: `assertExplicitProxyAllowed` env-gated bypass | Proxy validation rejects the OpenShell-managed env proxy inside an `OPENSHELL_SANDBOX=1` sandbox, or the bypass applies outside that explicit sandbox boundary. | Reviewed `openclaw@2026.6.9` fetch-guard dist files containing `async function assertExplicitProxyAllowed`; NemoClaw Dockerfile only adds the sandbox env gate. | The validator is generated OpenClaw compiled dist from the npm package. This PR can only adapt the installed artifact for the NemoClaw/OpenShell sandbox contract; the durable behavior belongs upstream. | `test/fetch-guard-patch-regression.test.ts` executes the reviewed shape, verifies the env-gated bypass, and fails closed on unreviewed proxy-validator shapes. | Remove the patch when OpenClaw natively treats the OpenShell sandbox env proxy as allowed, or when NemoClaw no longer uses this env-proxy path. |
| Patch 2b: `host.openshell.internal` web_fetch trusted env-proxy policy | `host.openshell.internal` becomes reachable through strict fetch, through a broad `.internal` bypass, or without `useEnvProxy`; conversely, legitimate web_fetch traffic through the trusted env proxy is blocked. | Reviewed `fetchWithWebToolsNetworkGuard` and SSRF policy helpers in `openclaw@2026.6.9`; the Dockerfile patch adds exact `allowedHostnames` policy only for `useEnvProxy` and the exact host. | The host-gateway exception is a NemoClaw/OpenShell integration policy. Upstream OpenClaw owns generic web_fetch and SSRF semantics and should not receive a NemoClaw-specific hostname carveout without a broader design. | `test/fetch-guard-patch-regression.test.ts` covers trusted env-proxy host-gateway scoping, strict-mode blocking, and the reviewed `allowedHostnames` private-network boundary. | Remove the patch when OpenClaw exposes an upstream supported policy hook for this host-gateway use case or NemoClaw stops routing web_fetch through the OpenShell host gateway. |
| Patch 4: managed-proxy activation for `OPENSHELL_SANDBOX=1` | Unconfigured strict fetches in the sandbox bypass the OpenShell L7 proxy, or explicit dispatcher/direct policies are overwritten by the fallback. | Reviewed fetch-guard managed-proxy gate in `openclaw@2026.6.9`; the Dockerfile patch extends activation only when `OPENSHELL_SANDBOX=1` and no explicit `dispatcherPolicy` is present. | The compiled dist is package output. NemoClaw can keep sandbox egress compatible for this bump, but upstream OpenClaw should own a first-class managed-proxy behavior for sandboxed runtimes. | `test/fetch-guard-patch-regression.test.ts` asserts the unconfigured strict-fetch fallback while preserving explicit dispatcher policy behavior. | Remove the patch when OpenClaw routes sandbox strict fetches through the configured env proxy without NemoClaw mutation, or when sandbox egress no longer depends on that proxy. |
| Patch 6: cron model-provider preflight trusted env-proxy mode | Cron preflight resolves `inference.local` directly and fails with DNS/egress errors, or the rewrite widens multiple call sites without a reviewed shape. | Reviewed cron isolated-agent preflight call in `openclaw@2026.6.9` that uses `auditContext: "cron-model-provider-preflight"` with `fetchWithSsrFGuard` and `buildLocalProviderSsrFPolicy`. | The preflight call site lives in upstream OpenClaw source; NemoClaw only patches the reviewed compiled call site so scheduled runs can reach the OpenShell-managed inference route. | `test/fetch-guard-patch-regression.test.ts` guards the single-callsite shape, exact trusted-env-proxy insertion, and ambiguous multi-callsite failure mode. | Remove the patch when OpenClaw sets `mode: "trusted_env_proxy"` or equivalent env-proxy routing for managed inference preflight. |

### OpenClaw Diagnostics OTEL Host Gateway Boundary

The default `NEMOCLAW_OPENCLAW_OTEL_ENDPOINT=http://host.openshell.internal:4318` is scoped to the local OTLP traces collector and requires the dedicated `openclaw-diagnostics-otel-local` policy preset. That preset allows only `POST /v1/traces` and `POST /v1/traces/**` to `host.openshell.internal:4318` for the OpenClaw/node binaries, separate from the `web_fetch` host-gateway exception in Patch 2b.

The reviewed `@openclaw/diagnostics-otel@2026.6.9` package dist imports `OTLPTraceExporter` from `@opentelemetry/exporter-trace-otlp-proto`, resolves the configured OTLP endpoint, and contains no `web_fetch`, `fetchWithSsrFGuard`, or `withTrustedEnvProxy` references. That source boundary keeps diagnostics export traffic on the OpenTelemetry OTLP exporter path rather than NemoClaw's patched OpenClaw `web_fetch` helper. Removal condition: re-audit this boundary on the next diagnostics plugin bump or if the OTEL plugin starts routing exports through OpenClaw tool/web fetch APIs.

### Legacy Fixture Pins

The legacy `2026.3.11` and `2026.4.24` OpenClaw pins are retained only for stale-upgrade fixture builds. Production Dockerfile install blocks now reject those versions unless `NEMOCLAW_E2E_FIXTURE_LEGACY_OPENCLAW=1` is set explicitly. The E2E-scoped name is intentionally noisy so production build workflows do not treat it as a general override. Production image workflows run `scripts/check-production-build-args.sh` before production Docker builds so the fixture flag cannot be passed through production build args. The stale-upgrade E2E build contexts pass that flag when they intentionally build an old base image, and `test/openclaw-integrity-pin.test.ts` verifies the default rejection, the explicit fixture opt-in, and the workflow guard.

Invalid state: a production image build overriding `OPENCLAW_VERSION` to an old fixture pin while still passing integrity checks. Source boundary: Dockerfile and Dockerfile.base install blocks. Source-fix constraint: keep stale-upgrade E2Es able to build old images without normalizing those pins as production targets. Regression test: `test/openclaw-integrity-pin.test.ts` rejects legacy pins without the fixture flag. Removal condition: delete the legacy pins and fixture flag after the stale-upgrade/rebuild E2Es no longer need old OpenClaw base images.

### Slack Inbound `app_mention`

The external `@openclaw/slack@2026.6.9` package no longer needs to be treated as package-shape-only evidence. `test/e2e/lib/slack-api-proof.sh` discovers the installed external runtime files, imports the hashed pipeline runtime for `prepareSlackMessage`, imports the runtime API for `sendMessageSlack`, and only reports `openclaw-pipeline-runtime` after allowed prepare, denied prepare, bounded denied-user feedback, and fake Slack send evidence all pass.

Invalid state: claiming `openclaw-pipeline-runtime` inbound proof without both checked-in import logic and fake Slack capture evidence. Source boundary: `test/e2e/lib/slack-api-proof.sh` and `test/e2e/test-messaging-providers.sh`. Source-fix constraint: send-only `runtime-api.js` coverage is not enough for inbound authorization coverage. Regression test: a fake installed `@openclaw/slack` with `dist/pipeline.runtime-fixture.js` and no `test-api.js` must report full coverage only after allowed prepare, denied prepare, bounded denial feedback, and installed send evidence.

### Telegram Runtime Send

The bundled OpenClaw Telegram channel proof must use the current `dist/extensions/telegram/runtime-api.js` surface. `test/e2e/lib/telegram-api-proof.sh` fails closed if the installed runtime file is missing or if it stops exporting `sendMessageTelegram`, because falling back to the removed private `test-api.js` facade would make the 2026.6.9 package-shape proof stale.

Invalid state: a passing fake Telegram proof that imports `dist/extensions/telegram/test-api.js` or bypasses OpenClaw's installed runtime send helper. Source boundary: `test/e2e/lib/telegram-api-proof.sh` and `test/e2e/test-messaging-providers.sh`. Source-fix constraint: keep the host-side fake Telegram API, request-body credential rewrite policy, token rewrite assertion, chat/text capture, and placeholder-leak checks intact. Regression test: the OpenClaw compatibility guard must require `runtime-api.js`, `sendMessageTelegram`, the Slack installed-runtime proof, Teams integrity metadata, optional plugin integrity pins, and chat-send patch recognizers.

### Issue #4434 TUI Unreachable Inference

The #4434 live guards in this version-bump PR are partial regression guards. They prove OpenClaw 2026.6.9 no longer leaves the TUI in the broken spinner-plus-connected state when sandbox egress to NVIDIA inference is blocked, and they require a visible `run error`, a concrete unreachable-inference cause token, a recognizable final status line, and final `| error` status inside the default 180-second timeout.

They intentionally do not require the full #4434 acceptance clauses for a gateway/upstream reporting layer or a one-line recovery hint, because OpenClaw 2026.6.9 does not emit those fields for the synthetic DOCKER-USER iptables outage. Tighten both `test/e2e/test-issue-4434-tui-unreachable-inference.sh` and `test/e2e-scenario/live/issue-4434-tui-unreachable-inference.test.ts` once the upstream output includes that layer and recovery hint.

Invalid state: treating the partial #4434 guard as full acceptance after upstream starts emitting HTTP status/cause, gateway/upstream layer attribution, or a recovery hint. Source boundary: OpenClaw TUI/chat error output captured by the #4434 live repros. Source-fix constraint: NemoClaw can guard against the old broken spinner state, but the missing diagnostic fields must come from OpenClaw output before the live assertions can require them. Regression detection: `test/issue-4434-error-fields.test.ts` classifies the current reviewed output shape and a future complete-output shape so an OpenClaw bump review has a focused fail signal when those fields appear. Removal condition: when the detector shows all fields present for the reviewed OpenClaw output, tighten both live guards and remove the partial-acceptance wording here.

### Microsoft Teams Live E2E Disposition

The Teams manifest is intentionally documented as experimental channel support. Full Teams onboarding and message round-trip proof requires a real Microsoft tenant, Bot Framework app credentials, an app password, allowed user object IDs, and a public HTTPS webhook that forwards to the sandbox `/api/messages` endpoint. Those prerequisites cannot run in default PR CI without tenant-owned secrets and public ingress.

Follow-up lane: `test/e2e-scenario/live/teams-message-round-trip.test.ts` is a credential-gated live skeleton. It skips unless `MSTEAMS_E2E=1`, `NEMOCLAW_RUN_E2E_SCENARIOS=1`, `NVIDIA_INFERENCE_API_KEY`, `MSTEAMS_APP_ID`, `MSTEAMS_APP_PASSWORD`, `MSTEAMS_TENANT_ID`, `MSTEAMS_ALLOWED_USERS`, `MSTEAMS_PUBLIC_WEBHOOK_URL`, and tenant-owned `MSTEAMS_E2E_ACTIVITY_JSON` are present. The scenario invokes the checked-in TypeScript driver `test/e2e-scenario/live/teams-message-round-trip-driver.ts` with an allowlisted environment containing only those `NVIDIA_*` and `MSTEAMS_*` variables; it does not pass the full runner environment or execute env-provided shell text. The skeleton records the expected proof boundary and keeps default CI from pretending that manifest rendering, package integrity, or local port-forward checks prove a real Teams tenant round trip.

### Release Checklist for Accepted Residual Risk

- [x] OpenClaw patched-dist runtime harness gap: accepted for this dependency bump only. Before merge, use exact-head CI image builds plus focused/full nightly proof as the runtime evidence boundary; do not claim this PR adds a checked-in real-package harness for every Dockerfile-mutated OpenClaw dist path.
- [x] Issue #4434 partial acceptance: accepted for OpenClaw 2026.6.9 only. This PR must not claim full #4434 closure; it only proves the old spinner-plus-connected failure is gone. Keep the partial-scope wording until reviewed OpenClaw output includes HTTP status/cause, gateway/upstream layer attribution, and a recovery hint.
- [x] Future #4434 tightening trigger: `test/issue-4434-error-fields.test.ts` must be updated with the reviewed captured output on the next relevant OpenClaw bump; when that detector shows all three fields present, tighten both live guards and remove the partial-acceptance wording in the same change.

### Advisor Disposition

- `src/lib/messaging/channels/manifests.test.ts` remains below the shared `test-size:check` threshold and does not need extraction in this dependency bump.
- The npm audit result in this note is a manual snapshot for the reviewed lock-only graph. It is not a new CI gate; rerun the command in the Advisory Check section on the next OpenClaw/plugin bump or if npm advisory state changes before merge. Follow-up automation should add a CI job for `npm install --package-lock-only --ignore-scripts && npm audit --omit=dev --json` on the reviewed OpenClaw/plugin graph.
- The stale nonterminal rebuild-resume repair in `src/lib/actions/sandbox/rebuild-resume-session.ts` remains a migration compatibility shim tracked against #4533's onboard FSM/resume compatibility boundary. Its removal condition is to delete it after a session-version migration proves recreate sessions are always persisted at a resumable pre-sandbox boundary; `src/lib/actions/sandbox/rebuild-resume-session.test.ts` covers the helper directly, `test/onboard-resume-provider-recovery.test.ts` carries the onboard-suite producer-level regression for `machine.state='openclaw'`, and `src/lib/actions/sandbox/rebuild-resume-snapshot.test.ts` owns the rebuild handoff regression.
- Production OpenClaw image build paths call `scripts/check-production-build-args.sh` before production `docker build` or `docker/build-push-action` use. `test/openclaw-dependency-review.test.ts` keeps that workflow contract documented.
- Each OpenClaw `messaging-build-applier.mts --agent openclaw` Dockerfile phase receives `OPENCLAW_VERSION="${OPENCLAW_VERSION}"` from the Dockerfile build arg before rendering or installing messaging plugins.
- The integrity pin, messaging render-safety, and provider-recovery follow-ups are covered by `test/openclaw-integrity-pin.test.ts`, `test/messaging-build-applier-render-safety.test.ts`, and `test/onboard-resume-provider-recovery.test.ts`.
