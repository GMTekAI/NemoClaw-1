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

NemoClaw enforces the main `openclaw@2026.6.9`, `@zed-industries/codex-acp@0.11.1`, and each reviewed npm plugin registry integrity, including optional OTEL/brave plugins and messaging plugins, before install. The Dockerfile and messaging build applier then run `npm pack --json`, require the downloaded tarball integrity to match the committed SRI, reject reported archive filenames that are absolute, contain path separators, equal `.` or `..`, include `..` path segments, or resolve outside the fresh pack directory, and install from the verified local `.tgz` archive. Codex ACP and OpenClaw core also verify that registry metadata still reports the reviewed npm tarball URL before packing that URL.

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

`Dockerfile`, `Dockerfile.base`, optional OpenClaw plugin installs, and `src/lib/messaging/applier/build/messaging-build-applier.mts` now bind reviewed npm installs to verified local archives. The install blocks first verify `npm view ... dist.integrity` against the committed SRI. Codex ACP and OpenClaw core also verify `npm view ... dist.tarball` against the reviewed tarball URL. The actual install input is then produced by `npm pack --json`; the reported downloaded tarball integrity must match the committed SRI and the reported filename must be contained inside the freshly created pack directory before `npm install -g <local .tgz>` or `openclaw plugins install <local .tgz> --pin` runs.

Invalid state: `npm view` returns the reviewed SRI but the downloaded artifact used for install has different bytes, or `npm pack --json` reports a filename such as `../package.tgz`, `/tmp/package.tgz`, or a name containing path separators so the later install consumes a path outside the fresh pack directory. Source boundary: Dockerfile npm install blocks, `Dockerfile.base`, optional plugin install blocks, and `src/lib/messaging/applier/build/messaging-build-applier.mts`. Source-fix constraint: npm package installation must stay artifact-bound for reviewed pins rather than reverting to a later floating package-spec transaction, and local archive path validation must be enforced at NemoClaw's install boundary because npm's JSON filename is untrusted input. Regression test: `test/openclaw-integrity-pin.test.ts` exercises registry drift, reviewed tarball URL drift, local archive install behavior, and unsafe reported archive filenames for Dockerfile core, codex-acp, base, and optional plugin pack helpers; `test/messaging-build-applier.test.ts` verifies messaging plugins run through `npm pack --json` and install the verified archive path; `test/messaging-build-applier-integrity.test.ts` verifies the messaging plugin install fails closed when packed archive integrity drifts or the reported archive filename escapes the pack directory. Removal condition: keep this archive verification until the repo moves the OpenClaw/plugin dependency set to a lockfile path where npm enforces the committed SRI directly and no installer code consumes raw `npm pack --json` filenames.

### OpenClaw Compiled-Dist Patch Runtime Boundary

The OpenClaw 2026.6.9 compiled-dist patches are localized compatibility patches for sandbox fetch routing, cron preflight proxying, `host.openshell.internal` web_fetch scoping, unconfigured strict-fetch managed-proxy activation, `chat.send`/`get-reply` correlation, and #4434 TUI unreachable-inference diagnostics. The long-term source of truth for these behaviors remains upstream OpenClaw; NemoClaw's Dockerfile and patch scripts carry fail-closed version-shape patches only so the reviewed package can run inside the current NemoClaw/OpenShell sandbox contract.

Invalid state: a real installed `openclaw@2026.6.9` dist changes semantics while fixture-compatible recognizers still pass. Source boundary: the installed OpenClaw generated `dist` files, the Dockerfile fetch-guard patch block, `scripts/patch-openclaw-chat-send.js`, and `scripts/patch-openclaw-issue-4434-diagnostics.ts`. Source-fix constraint: upstream OpenClaw should own permanent fixes; NemoClaw patches must stay version-scoped, fail closed on unknown shapes, and be removed when upstream ships reviewed behavior. Regression tests: `test/fetch-guard-patch-regression.test.ts`, `test/openclaw-chat-send-patch.test.ts`, and `test/openclaw-issue-4434-diagnostics-patch.test.ts` execute patched fixtures for the reviewed shapes. `test/openclaw-real-patched-dist-harness.test.ts` is the checked-in real-package harness: when run with `NEMOCLAW_REAL_OPENCLAW_DIST_HARNESS=1`, it downloads the reviewed tarball URL, verifies the committed SRI, extracts the actual `openclaw@2026.6.9` dist, applies the Dockerfile patch block, runs `scripts/patch-openclaw-chat-send.js`, runs `scripts/patch-openclaw-issue-4434-diagnostics.ts`, and audits the mutated dist for Patch 2, Patch 2b, Patch 4, Patch 6, Patch 7, chat-send/get-reply/followup-runner markers, and the #4434 assistant-error formatter marker.

Remaining accepted residual risk: the real-package harness is intentionally opt-in because it downloads a large npm tarball and takes roughly a minute on a fast workstation; default PR CI still relies on fixture recognizers plus exact-head image builds. The harness proves the reviewed package can be materialized and mutated by the same Dockerfile patch block, but it is not a substitute for focused nightly E2E proof of the affected runtime workflows or final full nightly proof before merge. Removal condition: delete the localized patches when OpenClaw ships the behavior, or promote this harness to a built-image/default-CI gate if NemoClaw keeps carrying these patches beyond this reviewed bump.

#### OpenClaw Patch Source-of-Truth Table

| Patch | Invalid state | Source boundary | Why upstream/source cannot be fixed here | Regression test | Removal condition |
|---|---|---|---|---|---|
| Patch 2: `assertExplicitProxyAllowed` env-gated bypass | Proxy validation rejects the OpenShell-managed env proxy inside an `OPENSHELL_SANDBOX=1` sandbox, or the bypass applies outside that explicit sandbox boundary. | Reviewed `openclaw@2026.6.9` fetch-guard dist files containing `async function assertExplicitProxyAllowed`; NemoClaw Dockerfile only adds the sandbox env gate. | The validator is generated OpenClaw compiled dist from the npm package. This PR can only adapt the installed artifact for the NemoClaw/OpenShell sandbox contract; the durable behavior belongs upstream. | `test/fetch-guard-patch-regression.test.ts` executes the reviewed shape, verifies the env-gated bypass, and fails closed on unreviewed proxy-validator shapes. | Remove the patch when OpenClaw natively treats the OpenShell sandbox env proxy as allowed, or when NemoClaw no longer uses this env-proxy path. |
| Patch 2b: `host.openshell.internal` web_fetch trusted env-proxy policy | `host.openshell.internal` becomes reachable through strict fetch, through a broad `.internal` bypass, or without `useEnvProxy`; conversely, legitimate web_fetch traffic through the trusted env proxy is blocked. | Reviewed `fetchWithWebToolsNetworkGuard` and SSRF policy helpers in `openclaw@2026.6.9`; the Dockerfile patch adds exact `allowedHostnames` policy only for `useEnvProxy` and the exact host. | The host-gateway exception is a NemoClaw/OpenShell integration policy. Upstream OpenClaw owns generic web_fetch and SSRF semantics and should not receive a NemoClaw-specific hostname carveout without a broader design. | `test/fetch-guard-patch-regression.test.ts` covers trusted env-proxy host-gateway scoping, strict-mode blocking, and the reviewed `allowedHostnames` private-network boundary. | Remove the patch when OpenClaw exposes an upstream supported policy hook for this host-gateway use case or NemoClaw stops routing web_fetch through the OpenShell host gateway. |
| Patch 4: managed-proxy activation for `OPENSHELL_SANDBOX=1` | Unconfigured strict fetches in the sandbox bypass the OpenShell L7 proxy, or explicit dispatcher/direct policies are overwritten by the fallback. | Reviewed fetch-guard managed-proxy gate in `openclaw@2026.6.9`; the Dockerfile patch extends activation only when `OPENSHELL_SANDBOX=1` and no explicit `dispatcherPolicy` is present. | The compiled dist is package output. NemoClaw can keep sandbox egress compatible for this bump, but upstream OpenClaw should own a first-class managed-proxy behavior for sandboxed runtimes. | `test/fetch-guard-patch-regression.test.ts` asserts the unconfigured strict-fetch fallback while preserving explicit dispatcher policy behavior. | Remove the patch when OpenClaw routes sandbox strict fetches through the configured env proxy without NemoClaw mutation, or when sandbox egress no longer depends on that proxy. |
| Patch 6: cron model-provider preflight trusted env-proxy mode | Cron preflight resolves `inference.local` directly and fails with DNS/egress errors, or the rewrite widens multiple call sites without a reviewed shape. | Reviewed cron isolated-agent preflight call in `openclaw@2026.6.9` that uses `auditContext: "cron-model-provider-preflight"` with `fetchWithSsrFGuard` and `buildLocalProviderSsrFPolicy`. | The preflight call site lives in upstream OpenClaw source; NemoClaw only patches the reviewed compiled call site so scheduled runs can reach the OpenShell-managed inference route. | `test/fetch-guard-patch-regression.test.ts` guards the single-callsite shape, exact trusted-env-proxy insertion, and ambiguous multi-callsite failure mode. | Remove the patch when OpenClaw sets `mode: "trusted_env_proxy"` or equivalent env-proxy routing for managed inference preflight. |
| Patch 7: #4434 TUI fetch-failed diagnostic enrichment | The TUI reports only `TypeError: fetch failed` for blocked sandbox inference egress, or enrichment applies outside `OPENSHELL_SANDBOX=1`. | Reviewed assistant error formatter dist file containing `formatRawAssistantErrorForUi`; `scripts/patch-openclaw-issue-4434-diagnostics.ts` adds missing cause, gateway/upstream reporting, and recovery hint fields. | The formatter source lives in upstream OpenClaw. NemoClaw can patch the reviewed compiled artifact for the OpenShell sandbox contract, but the durable fix belongs upstream. | `test/openclaw-issue-4434-diagnostics-patch.test.ts` verifies env gating, partial-field completion, full-message preservation, and fail-closed selectors; the #4434 live guards require all fields. | Remove the patch when OpenClaw emits HTTP/cause, gateway/upstream layer, and recovery hint directly for unreachable inference errors. |

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

The #4434 live guards in this version-bump PR are full live acceptance guards for the reviewed NemoClaw/OpenShell runtime boundary. NemoClaw now applies `scripts/patch-openclaw-issue-4434-diagnostics.ts` after installing `openclaw@2026.6.9`; the script patches the reviewed `formatRawAssistantErrorForUi` dist shape to enrich sandbox-only `fetch failed` TUI errors with:

- `Cause: fetch failed while reaching the upstream API.`
- `Reporting layer: gateway proxy / upstream API.`
- `Recovery hint: check sandbox egress and provider reachability, then retry.`

The enrichment is gated by `process.env.OPENSHELL_SANDBOX === "1"` and only matches `fetch failed` errors. Non-sandbox OpenClaw output keeps upstream behavior, and already structured upstream output is preserved or completed without duplicating fields. The unpatched upstream `openclaw@2026.6.9` #4434 output remains accepted only as the source-level removal trigger: `test/issue-4434-error-fields.test.ts` verifies that upstream-shaped `TypeError: fetch failed` output is missing all three required acceptance fields while the NemoClaw-patched runtime output has all three. Both `test/e2e/test-issue-4434-tui-unreachable-inference.sh` and `test/e2e-scenario/live/issue-4434-tui-unreachable-inference.test.ts` now fail unless the captured TUI output includes an HTTP status or cause, a gateway/upstream reporting layer, a recovery hint, a visible error, a recognizable final status line, and final `| error` status inside the default 180-second timeout.

Invalid state: the TUI returns to the spinner-plus-connected signature, the structured fields are missing from the captured live output, or the formatter patch applies outside the OpenShell sandbox boundary. Source boundary: OpenClaw TUI/chat error output captured by the #4434 live repros plus the reviewed assistant error formatter dist file patched by `scripts/patch-openclaw-issue-4434-diagnostics.ts`. Source-fix constraint: the durable source fix belongs upstream OpenClaw; this PR carries a fail-closed compiled-dist shim so the reviewed package satisfies the NemoClaw/OpenShell runtime acceptance contract now. Regression detection: `test/issue-4434-error-fields.test.ts` classifies the reviewed patched output and rejects the old partial output; `test/openclaw-issue-4434-diagnostics-patch.test.ts` verifies the patch behavior and selectors. Removal condition: remove the patch script and keep the full live assertions when upstream OpenClaw emits equivalent HTTP/cause, gateway/upstream layer attribution, and recovery hint fields directly.

Merge disposition for this OpenClaw 2026.6.9 bump: #4434 TUI unreachable-inference acceptance is code-backed for the reviewed `openclaw@2026.6.9` artifact via a NemoClaw compatibility shim. Release notes or merge context should describe that boundary precisely: this PR closes the NemoClaw runtime acceptance gap, while upstream OpenClaw still owns the permanent source-level diagnostic behavior.

### Microsoft Teams Live E2E Disposition

The Teams manifest is intentionally documented as experimental channel support. Full Teams onboarding and message round-trip proof requires a real Microsoft tenant, Bot Framework app credentials, an app password, allowed user object IDs, and a public HTTPS webhook that forwards to the sandbox `/api/messages` endpoint. Those prerequisites cannot run in default PR CI without tenant-owned secrets and public ingress.

Follow-up lane: `test/e2e-scenario/live/teams-message-round-trip.test.ts` is a credential-gated live skeleton. It skips unless `MSTEAMS_E2E=1`, `NEMOCLAW_RUN_E2E_SCENARIOS=1`, `NVIDIA_INFERENCE_API_KEY`, `MSTEAMS_APP_ID`, `MSTEAMS_APP_PASSWORD`, `MSTEAMS_TENANT_ID`, `MSTEAMS_ALLOWED_USERS`, `MSTEAMS_PUBLIC_WEBHOOK_URL`, and tenant-owned `MSTEAMS_E2E_ACTIVITY_JSON` are present. The scenario invokes the checked-in TypeScript driver `test/e2e-scenario/live/teams-message-round-trip-driver.ts` with an allowlisted environment containing only those `NVIDIA_*` and `MSTEAMS_*` variables; it does not pass the full runner environment or execute env-provided shell text. The skeleton records the expected proof boundary and keeps default CI from pretending that manifest rendering, package integrity, or local port-forward checks prove a real Teams tenant round trip.

### Release Checklist for Accepted Residual Risk

- [x] OpenClaw real patched-dist harness: `NEMOCLAW_REAL_OPENCLAW_DIST_HARNESS=1 npm test -- --run test/openclaw-real-patched-dist-harness.test.ts` materializes the reviewed tarball, verifies SRI, applies the Dockerfile patch block, and audits chat-send/get-reply/followup-runner markers. Before merge, keep exact-head CI image builds plus focused/full nightly proof as the workflow runtime evidence boundary.
- [x] Issue #4434 full live acceptance: `scripts/patch-openclaw-issue-4434-diagnostics.ts` enriches the reviewed OpenClaw formatter for sandbox-only `fetch failed` errors, and both live guards require HTTP/cause, gateway/upstream layer attribution, and a recovery hint.
- [x] Future #4434 upstream-removal trigger: on the next relevant OpenClaw bump, rerun `test/openclaw-issue-4434-diagnostics-patch.test.ts` and the real patched-dist harness. If upstream emits equivalent fields directly, remove the shim while preserving full live assertions.

### Advisor Disposition

- `PRA-5` #4434 partial acceptance is explicitly accepted for this OpenClaw 2026.6.9 PR only: `test/issue-4434-error-fields.test.ts` verifies 3/3 fields are present in the NemoClaw-patched runtime output and 3/3 fields are missing in the upstream-shaped `openclaw@2026.6.9` output. On the next OpenClaw bump that emits equivalent fields upstream, remove `scripts/patch-openclaw-issue-4434-diagnostics.ts` in the same change and keep the full live assertions.
- `src/lib/messaging/channels/manifests.test.ts` remains below the shared `test-size:check` threshold and does not need extraction in this dependency bump.
- The npm audit result in this note is a manual snapshot for the reviewed lock-only graph. It is not a new CI gate; rerun the command in the Advisory Check section on the next OpenClaw/plugin bump or if npm advisory state changes before merge. Follow-up automation should add a CI job for `npm install --package-lock-only --ignore-scripts && npm audit --omit=dev --json` on the reviewed OpenClaw/plugin graph.
- The stale nonterminal rebuild-resume repair in `src/lib/actions/sandbox/rebuild-resume-session.ts` remains a migration compatibility shim tracked against #4533's onboard FSM/resume compatibility boundary. Its removal condition is to delete it after a session-version migration proves recreate sessions are always persisted at a resumable pre-sandbox boundary; `src/lib/actions/sandbox/rebuild-resume-session.test.ts` covers the helper directly, `test/onboard-resume-provider-recovery.test.ts` carries the onboard-suite producer-level regression for `machine.state='openclaw'`, and `src/lib/actions/sandbox/rebuild-resume-snapshot.test.ts` owns the rebuild handoff regression.
- Production OpenClaw image build paths call `scripts/check-production-build-args.sh` before production `docker build` or `docker/build-push-action` use. `test/openclaw-dependency-review.test.ts` keeps that workflow contract documented.
- Each OpenClaw `messaging-build-applier.mts --agent openclaw` Dockerfile phase receives `OPENCLAW_VERSION="${OPENCLAW_VERSION}"` from the Dockerfile build arg before rendering or installing messaging plugins.
- The integrity pin, messaging render-safety, and provider-recovery follow-ups are covered by `test/openclaw-integrity-pin.test.ts`, `test/messaging-build-applier-render-safety.test.ts`, and `test/onboard-resume-provider-recovery.test.ts`.
