// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

const SCRIPT = path.join(import.meta.dirname, "..", "scripts", "install-openshell.sh");
const REQUIRED_OPENSHELL_VERSION = "0.0.72";
const LEGACY_OPENSHELL_VERSION = "0.0.44";
const OPENSHELL_REWRITE_FEATURE_MARKERS =
  "request-body-credential-rewrite websocket-credential-rewrite";
const OPENSHELL_MCP_FEATURE_MARKER = "allow_all_known_mcp_methods";
const OPENSHELL_FEATURE_MARKERS = `${OPENSHELL_REWRITE_FEATURE_MARKERS} ${OPENSHELL_MCP_FEATURE_MARKER}`;
const OPENSHELL_ARTIFACT_RUN_ID = "28267935010";
const OPENSHELL_ARTIFACT_HEAD_SHA = "f5dbcc50553a05f0b9083dd35789c89d1ce08371";
type OpenShellFeaturePlacement = "openshell" | "gateway" | "split-mcp-gateway" | "none";

function writeExecutable(target: string, contents: string) {
  fs.writeFileSync(target, contents, { mode: 0o755 });
}

type ArtifactInstallFixtureOptions = {
  arch?: string;
  artifactCount?: number;
  artifactDigest?: string;
  extraArchiveEntry?: boolean;
  expectedHeadSha?: string;
  runConclusion?: string;
  runEvent?: string;
  runHeadRepository?: string;
  runHeadSha?: string;
  runRepository?: string;
  runStatus?: string;
  runWorkflowId?: string;
};

function runArtifactInstallFixture(options: ArtifactInstallFixtureOptions = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-openshell-artifacts-"));
  try {
    const fakeBin = path.join(tmp, "bin");
    const installDir = path.join(tmp, "install-bin");
    const artifactLog = path.join(tmp, "artifacts.log");
    const artifactRoot = path.join(tmp, "artifact-zips");
    fs.mkdirSync(fakeBin);
    fs.mkdirSync(installDir);
    fs.mkdirSync(artifactRoot);

    writeExecutable(
      path.join(fakeBin, "uname"),
      `#!/usr/bin/env bash
if [ "\${1:-}" = "-m" ]; then echo "${options.arch ?? "x86_64"}"; else echo "Linux"; fi`,
    );
    writeExecutable(
      path.join(installDir, "openshell"),
      `#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then echo "openshell 0.0.71"; exit 0; fi
exit 0`,
    );

    const artifacts = [
      {
        id: "1001",
        name: "rust-binary-cli-cli-linux-amd64",
        binary: "openshell",
        contents: `#!/usr/bin/env bash
if [ -n "\${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}\${ACTIONS_RUNTIME_TOKEN:-}\${GH_TOKEN:-}\${GITHUB_TOKEN:-}\${GH_ENTERPRISE_TOKEN:-}\${GITHUB_ENTERPRISE_TOKEN:-}\${NEMOCLAW_INSTALL_OPENSHELL_GH_TOKEN:-}" ]; then
  echo "downloaded OpenShell observed a GitHub token" >&2
  exit 91
fi
if [ "\${1:-}" = "--version" ]; then echo "openshell 0.0.72-dev+artifact"; exit 0; fi
# ${OPENSHELL_REWRITE_FEATURE_MARKERS}
exit 0
`,
      },
      {
        id: "1002",
        name: "rust-binary-gateway-gateway-linux-amd64",
        binary: "openshell-gateway",
        contents: `#!/usr/bin/env bash
# ${OPENSHELL_MCP_FEATURE_MARKER}
exit 0
`,
      },
      {
        id: "1003",
        name: "rust-binary-supervisor-sandbox-linux-amd64",
        binary: "openshell-sandbox",
        contents: `#!/usr/bin/env bash
# JSON-RPC MCP ${OPENSHELL_MCP_FEATURE_MARKER}
exit 0
`,
      },
    ].map((artifact, index) => {
      const dir = path.join(artifactRoot, artifact.id);
      const zip = path.join(artifactRoot, `${artifact.id}.zip`);
      fs.mkdirSync(dir);
      writeExecutable(path.join(dir, artifact.binary), artifact.contents);
      const zipEntries = [artifact.binary];
      if (index === 0 && options.extraArchiveEntry) {
        fs.writeFileSync(path.join(dir, "unexpected"), "unexpected\n");
        zipEntries.push("unexpected");
      }
      const zipped = spawnSync("zip", ["-q", zip, ...zipEntries], {
        cwd: dir,
        encoding: "utf8",
      });
      if (zipped.status !== 0) {
        throw new Error(`failed to build artifact fixture: ${zipped.stderr}`);
      }
      return {
        ...artifact,
        digest: crypto.createHash("sha256").update(fs.readFileSync(zip)).digest("hex"),
        zip,
      };
    });

    const artifactCases = artifacts
      .map(
        (artifact) => `
    ${artifact.name})
      artifact_id=${artifact.id}
      artifact_digest=${options.artifactDigest ?? `sha256:${artifact.digest}`}
      ;;`,
      )
      .join("");
    const downloadCases = artifacts
      .map(
        (artifact) => `
    /repos/NVIDIA/OpenShell/actions/artifacts/${artifact.id}/zip)
      cat ${JSON.stringify(artifact.zip)}
      ;;`,
      )
      .join("");

    writeExecutable(
      path.join(fakeBin, "gh"),
      `#!/usr/bin/env bash
set -euo pipefail
endpoint=""
artifact_name=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    /repos/*) endpoint="$1" ;;
    -f|--raw-field)
      shift
      case "\${1:-}" in name=*) artifact_name="\${1#name=}" ;; esac
      ;;
    -F|--field|--method|--jq) shift ;;
  esac
  shift || true
done
printf '%s %s\n' "$endpoint" "$artifact_name" >> ${JSON.stringify(artifactLog)}
case "$endpoint" in
  /repos/NVIDIA/OpenShell/actions/runs/${OPENSHELL_ARTIFACT_RUN_ID})
    printf '%s\n' '${OPENSHELL_ARTIFACT_RUN_ID}|${options.runWorkflowId ?? "246342097"}|${options.runRepository ?? "NVIDIA/OpenShell"}|${options.runHeadRepository ?? "NVIDIA/OpenShell"}|${options.runStatus ?? "completed"}|${options.runConclusion ?? "success"}|${options.runEvent ?? "push"}|${options.runHeadSha ?? OPENSHELL_ARTIFACT_HEAD_SHA}'
    ;;
  /repos/NVIDIA/OpenShell/actions/runs/${OPENSHELL_ARTIFACT_RUN_ID}/artifacts)
    artifact_id=""
    artifact_digest=""
    case "$artifact_name" in${artifactCases}
      *) exit 7 ;;
    esac
    printf '%s|%s|%s|%s|%s|false\n' '${options.artifactCount ?? 1}' '${options.artifactCount ?? 1}' "$artifact_id" "$artifact_name" "$artifact_digest"
    ;;${downloadCases}
  *) exit 8 ;;
esac
`,
    );

    const result = spawnSync("bash", [SCRIPT], {
      env: {
        ...process.env,
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "fixture-actions-id-token",
        ACTIONS_RUNTIME_TOKEN: "fixture-actions-runtime-token",
        GH_ENTERPRISE_TOKEN: "fixture-gh-enterprise-token",
        GH_TOKEN: "fixture-gh-token",
        GITHUB_ENTERPRISE_TOKEN: "fixture-github-enterprise-token",
        GITHUB_TOKEN: "fixture-github-token",
        HOME: tmp,
        XDG_BIN_HOME: installDir,
        NEMOCLAW_INSTALL_OPENSHELL_GH_TOKEN: "fixture-handoff-token",
        NEMOCLAW_NON_INTERACTIVE: "1",
        NEMOCLAW_OPENSHELL_CHANNEL: "artifact",
        NEMOCLAW_OPENSHELL_ARTIFACT_RUN_ID: OPENSHELL_ARTIFACT_RUN_ID,
        NEMOCLAW_OPENSHELL_ARTIFACT_HEAD_SHA:
          options.expectedHeadSha ?? OPENSHELL_ARTIFACT_HEAD_SHA,
        PATH: `${fakeBin}:${installDir}:/usr/bin:/bin`,
      },
      encoding: "utf8",
    });

    return {
      artifactLog: fs.existsSync(artifactLog) ? fs.readFileSync(artifactLog, "utf8") : "",
      installedCli: fs.readFileSync(path.join(installDir, "openshell"), "utf8"),
      installedGateway: fs.existsSync(path.join(installDir, "openshell-gateway")),
      installedSandbox: fs.existsSync(path.join(installDir, "openshell-sandbox")),
      result,
    };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Run install-openshell.sh with a fake `openshell` binary that reports the
 * given version. The download/install code path is never reached because we
 * either exit early (version + capability ok / missing capability)
 * or hit an upgrade/reinstall warn and then the script tries to download — so we stub
 * curl and gh to fail fast.
 */
function runWithInstalledVersion(
  version: string,
  extraEnv: NodeJS.ProcessEnv = {},
  options: {
    capability?: boolean;
    featurePlacement?: OpenShellFeaturePlacement;
    driverBins?: boolean | "gateway" | "gateway-vm";
    os?: string;
    arch?: string;
  } = {},
) {
  const capability = options.capability ?? true;
  const featurePlacement: OpenShellFeaturePlacement = capability
    ? (options.featurePlacement ?? "openshell")
    : "none";
  const openshellMarkers =
    featurePlacement === "openshell"
      ? OPENSHELL_FEATURE_MARKERS
      : featurePlacement === "split-mcp-gateway"
        ? OPENSHELL_REWRITE_FEATURE_MARKERS
        : "";
  const gatewayMarkers =
    featurePlacement === "gateway"
      ? OPENSHELL_FEATURE_MARKERS
      : featurePlacement === "split-mcp-gateway"
        ? OPENSHELL_MCP_FEATURE_MARKER
        : "";
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-openshell-ver-"));
  try {
    const fakeBin = path.join(tmp, "bin");
    fs.mkdirSync(fakeBin);

    writeExecutable(
      path.join(fakeBin, "uname"),
      `#!/usr/bin/env bash
if [ "\${1:-}" = "-m" ]; then echo "${options.arch ?? "x86_64"}"; else echo "${options.os ?? "Linux"}"; fi`,
    );

    // Fake openshell that reports the given version
    writeExecutable(
      path.join(fakeBin, "openshell"),
      `#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then echo "openshell ${version}"; exit 0; fi
${openshellMarkers ? `# ${openshellMarkers}` : ""}
exit 99`,
    );

    if (options.driverBins !== false) {
      writeExecutable(
        path.join(fakeBin, "openshell-gateway"),
        `#!/usr/bin/env bash
# ${gatewayMarkers}
exit 0`,
      );
    }
    if (options.driverBins !== false && options.driverBins !== "gateway") {
      writeExecutable(
        path.join(fakeBin, "openshell-sandbox"),
        `#!/usr/bin/env bash
exit 0`,
      );
    }
    if (options.driverBins === "gateway-vm") {
      writeExecutable(
        path.join(fakeBin, "openshell-driver-vm"),
        `#!/usr/bin/env bash
exit 0`,
      );
    }

    // Stub curl to fail so the install path exits without doing real network I/O
    writeExecutable(
      path.join(fakeBin, "curl"),
      `#!/usr/bin/env bash
echo "curl stub: $*" >&2
exit 1`,
    );

    // Stub gh CLI similarly
    writeExecutable(
      path.join(fakeBin, "gh"),
      `#!/usr/bin/env bash
exit 1`,
    );

    if ((options.os ?? "Linux") === "Darwin") {
      writeExecutable(
        path.join(fakeBin, "codesign"),
        `#!/usr/bin/env bash
state="\${NEMOCLAW_FAKE_CODESIGN_STATE:-}"
if [ "\${1:-}" = "-d" ]; then
  if [ "\${NEMOCLAW_FAKE_CODESIGN_HAS_ENTITLEMENT:-1}" = "1" ] || { [ -n "$state" ] && [ -f "$state" ]; }; then
    printf '%s\\n' '<plist version="1.0"><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>'
  fi
  exit 0
fi
if [ -n "\${NEMOCLAW_FAKE_CODESIGN_LOG:-}" ]; then
  printf '%s\\n' "$*" >> "$NEMOCLAW_FAKE_CODESIGN_LOG"
fi
if [ -n "$state" ]; then
  : > "$state"
fi
exit 0`,
      );
    }

    return spawnSync("bash", [SCRIPT], {
      env: {
        ...process.env,
        NEMOCLAW_OPENSHELL_CHANNEL: "stable",
        ...extraEnv,
        PATH: `${fakeBin}:/usr/bin:/bin`,
      },
      encoding: "utf8",
    });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

describe("install-openshell.sh version check", { timeout: 15_000 }, () => {
  it("exits cleanly when the required OpenShell and driver binaries are already installed", () => {
    const result = runWithInstalledVersion(REQUIRED_OPENSHELL_VERSION);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`already installed: ${REQUIRED_OPENSHELL_VERSION}`);
  });

  it("accepts MCP L7 support from the installed gateway sidecar", () => {
    const result = runWithInstalledVersion(
      REQUIRED_OPENSHELL_VERSION,
      {},
      { featurePlacement: "split-mcp-gateway" },
    );
    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(result.stdout).toContain(`already installed: ${REQUIRED_OPENSHELL_VERSION}`);
  });

  it("triggers reinstall when the required OpenShell is missing Docker-driver binaries", () => {
    const result = runWithInstalledVersion(
      REQUIRED_OPENSHELL_VERSION,
      {},
      { driverBins: false, os: "Linux" },
    );
    expect(result.status).not.toBe(0);
    expect(result.stdout).toMatch(/missing Docker-driver binaries/);
    expect(result.stdout).toContain(
      `Installing OpenShell from release 'v${REQUIRED_OPENSHELL_VERSION}'`,
    );
  });

  it("fails closed when the required OpenShell lacks required messaging rewrite support", () => {
    const result = runWithInstalledVersion(REQUIRED_OPENSHELL_VERSION, {}, { capability: false });
    expect(result.status).toBe(1);
    // `fail()` writes to stderr as of #3446; previously stdout.
    expect(result.stderr).toMatch(/missing request-body-credential-rewrite support/);
  });

  it("accepts macOS OpenShell when the gateway binary is installed", () => {
    const result = runWithInstalledVersion(
      REQUIRED_OPENSHELL_VERSION,
      {},
      {
        driverBins: "gateway",
        os: "Darwin",
        arch: "arm64",
      },
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`already installed: ${REQUIRED_OPENSHELL_VERSION}`);
  });

  it("does not require the macOS VM driver entitlement for Docker-driver onboarding", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-openshell-codesign-"));
    try {
      const state = path.join(tmp, "codesign-state");
      const log = path.join(tmp, "codesign.log");
      const result = runWithInstalledVersion(
        REQUIRED_OPENSHELL_VERSION,
        {
          NEMOCLAW_FAKE_CODESIGN_HAS_ENTITLEMENT: "0",
          NEMOCLAW_FAKE_CODESIGN_STATE: state,
          NEMOCLAW_FAKE_CODESIGN_LOG: log,
        },
        {
          driverBins: "gateway-vm",
          os: "Darwin",
          arch: "arm64",
        },
      );

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(result.stdout).toContain(`already installed: ${REQUIRED_OPENSHELL_VERSION}`);
      expect(result.stdout).not.toMatch(/missing the macOS Hypervisor entitlement/);
      expect(result.stdout).not.toMatch(/Signing openshell-driver-vm/);
      expect(result.stdout).not.toMatch(/Installing OpenShell from release/);
      expect(fs.existsSync(log) ? fs.readFileSync(log, "utf-8") : "").toBe("");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("triggers reinstall on macOS when OpenShell is missing required gateway binaries", () => {
    const result = runWithInstalledVersion(
      REQUIRED_OPENSHELL_VERSION,
      {},
      {
        driverBins: false,
        os: "Darwin",
        arch: "arm64",
      },
    );
    expect(result.status).not.toBe(0);
    expect(result.stdout).toMatch(/missing Docker-driver binaries/);
    expect(result.stdout).toContain(
      `Installing OpenShell from release 'v${REQUIRED_OPENSHELL_VERSION}'`,
    );
  });

  it("downloads the macOS arm64 gateway asset during reinstall", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-openshell-macos-assets-"));
    try {
      const fakeBin = path.join(tmp, "bin");
      const downloadLog = path.join(tmp, "downloads.log");
      fs.mkdirSync(fakeBin);

      writeExecutable(
        path.join(fakeBin, "uname"),
        `#!/usr/bin/env bash
if [ "\${1:-}" = "-m" ]; then echo "arm64"; else echo "Darwin"; fi`,
      );
      writeExecutable(
        path.join(fakeBin, "openshell"),
        `#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then echo "openshell 0.0.36"; exit 0; fi
exit 99`,
      );
      writeExecutable(
        path.join(fakeBin, "gh"),
        `#!/usr/bin/env bash
exit 1`,
      );
      writeExecutable(
        path.join(fakeBin, "curl"),
        `#!/usr/bin/env bash
echo "$@" >> ${JSON.stringify(downloadLog)}
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    shift
    out="$1"
  fi
  shift || true
done
if [ -n "$out" ]; then
  case "$(basename "$out")" in
  openshell-checksums-sha256.txt)
    printf '%s\n' \
      'ignored  openshell-aarch64-apple-darwin.tar.gz' > "$out"
    ;;
  openshell-gateway-checksums-sha256.txt)
    printf '%s\n' \
      'ignored  openshell-gateway-aarch64-apple-darwin.tar.gz' > "$out"
    ;;
  *)
    : > "$out"
    ;;
  esac
fi
exit 0`,
      );
      writeExecutable(
        path.join(fakeBin, "sha256sum"),
        `#!/usr/bin/env bash
cat >/dev/null
echo "checksum OK"
exit 0`,
      );
      writeExecutable(
        path.join(fakeBin, "tar"),
        `#!/usr/bin/env bash
exit 0`,
      );
      writeExecutable(
        path.join(fakeBin, "install"),
        `#!/usr/bin/env bash
dest="\${@: -1}"
mkdir -p "$(dirname "$dest")"
cat > "$dest" <<'EOF'
#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then echo "openshell ${REQUIRED_OPENSHELL_VERSION}"; exit 0; fi
# ${OPENSHELL_FEATURE_MARKERS}
exit 0
EOF
chmod +x "$dest"
exit 0`,
      );

      const result = spawnSync("bash", [SCRIPT], {
        env: {
          ...process.env,
          HOME: tmp,
          XDG_BIN_HOME: path.join(tmp, "local-bin"),
          NEMOCLAW_OPENSHELL_CHANNEL: "stable",
          PATH: `${fakeBin}:/usr/bin:/bin`,
        },
        encoding: "utf8",
      });

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      const downloads = fs.readFileSync(downloadLog, "utf-8");
      expect(downloads).toContain("openshell-aarch64-apple-darwin.tar.gz");
      expect(downloads).toContain("openshell-gateway-aarch64-apple-darwin.tar.gz");
      expect(downloads).not.toContain("openshell-driver-vm-aarch64-apple-darwin.tar.gz");
      expect(downloads).toContain("openshell-gateway-checksums-sha256.txt");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("upgrades into the active writable openshell directory to avoid PATH shadowing", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-openshell-active-dir-"));
    try {
      const activeBin = path.join(tmp, "active-bin");
      const fakeBin = path.join(tmp, "fake-bin");
      const installLog = path.join(tmp, "install.log");
      fs.mkdirSync(activeBin);
      fs.mkdirSync(fakeBin);

      writeExecutable(
        path.join(activeBin, "openshell"),
        `#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then echo "openshell 0.0.36"; exit 0; fi
exit 99`,
      );

      writeExecutable(
        path.join(fakeBin, "uname"),
        `#!/usr/bin/env bash
if [ "\${1:-}" = "-m" ]; then echo "x86_64"; else echo "Linux"; fi`,
      );
      writeExecutable(
        path.join(fakeBin, "gh"),
        `#!/usr/bin/env bash
exit 1`,
      );
      writeExecutable(
        path.join(fakeBin, "curl"),
        `#!/usr/bin/env bash
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    shift
    out="$1"
  fi
  shift || true
done
if [ -n "$out" ]; then
  case "$(basename "$out")" in
  openshell-checksums-sha256.txt)
    printf '%s\n' 'ignored  openshell-x86_64-unknown-linux-musl.tar.gz' > "$out"
    ;;
  openshell-gateway-checksums-sha256.txt)
    printf '%s\n' 'ignored  openshell-gateway-x86_64-unknown-linux-gnu.tar.gz' > "$out"
    ;;
  openshell-sandbox-checksums-sha256.txt)
    printf '%s\n' 'ignored  openshell-sandbox-x86_64-unknown-linux-gnu.tar.gz' > "$out"
    ;;
  *)
    : > "$out"
    ;;
  esac
fi
exit 0`,
      );
      writeExecutable(
        path.join(fakeBin, "sha256sum"),
        `#!/usr/bin/env bash
cat >/dev/null
echo "checksum OK"
exit 0`,
      );
      writeExecutable(
        path.join(fakeBin, "tar"),
        `#!/usr/bin/env bash
outdir=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-C" ]; then
    outdir="$arg"
    break
  fi
  prev="$arg"
done
[ -n "$outdir" ] || exit 1
case "$*" in
*openshell-gateway*) name="openshell-gateway" ;;
*openshell-sandbox*) name="openshell-sandbox" ;;
*) name="openshell" ;;
esac
printf '#!/usr/bin/env bash\\nexit 0\\n' > "$outdir/$name"
chmod 755 "$outdir/$name"
exit 0`,
      );
      writeExecutable(
        path.join(fakeBin, "install"),
        `#!/usr/bin/env bash
dest="\${@: -1}"
printf '%s\\n' "$dest" >> ${JSON.stringify(installLog)}
mkdir -p "$(dirname "$dest")"
case "$(basename "$dest")" in
openshell)
  printf '#!/usr/bin/env bash\\nif [ "$1" = "--version" ]; then echo "openshell ${REQUIRED_OPENSHELL_VERSION}"; else exit 0; fi\\n# ${OPENSHELL_FEATURE_MARKERS}\\n' > "$dest"
  ;;
*)
  printf '#!/usr/bin/env bash\\nexit 0\\n' > "$dest"
  ;;
esac
chmod 755 "$dest"
exit 0`,
      );

      const result = spawnSync("bash", [SCRIPT], {
        env: {
          ...process.env,
          HOME: tmp,
          NEMOCLAW_OPENSHELL_CHANNEL: "stable",
          PATH: `${fakeBin}:${activeBin}:/usr/bin:/bin`,
        },
        encoding: "utf8",
      });

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      const installedTargets = fs.readFileSync(installLog, "utf-8");
      expect(installedTargets).toContain(path.join(activeBin, "openshell"));
      expect(installedTargets).toContain(path.join(activeBin, "openshell-gateway"));
      expect(installedTargets).toContain(path.join(activeBin, "openshell-sandbox"));
      expect(installedTargets).not.toContain("/usr/local/bin/openshell");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("triggers upgrade when openshell 0.0.38 is installed (below current floor)", () => {
    const result = runWithInstalledVersion("0.0.38");
    expect(result.status).not.toBe(0);
    expect(result.stdout).toMatch(/below minimum.*upgrading/);
  });

  it("triggers upgrade when openshell 0.0.28 is installed (below MIN_VERSION)", () => {
    const result = runWithInstalledVersion("0.0.28");
    // Script should warn about upgrade then fail at the download step (curl stub fails)
    expect(result.status).not.toBe(0);
    expect(result.stdout).toMatch(/below minimum.*upgrading/);
  });

  it("triggers upgrade when openshell 0.0.26 is installed (Landlock-vulnerable version)", () => {
    const result = runWithInstalledVersion("0.0.26");
    expect(result.status).not.toBe(0);
    expect(result.stdout).toMatch(/below minimum.*upgrading/);
  });

  it("triggers upgrade when openshell 0.0.24 is installed (old minimum)", () => {
    const result = runWithInstalledVersion("0.0.24");
    expect(result.status).not.toBe(0);
    expect(result.stdout).toMatch(/below minimum.*upgrading/);
  });

  it("reinstalls the pinned release when openshell is above MAX_VERSION", () => {
    const result = runWithInstalledVersion("0.0.73");
    expect(result.status).not.toBe(0);
    expect(result.stdout).toContain(
      `above the maximum (${REQUIRED_OPENSHELL_VERSION}) supported by this NemoClaw release`,
    );
    expect(result.stdout).toContain(`reinstalling pinned OpenShell ${REQUIRED_OPENSHELL_VERSION}`);
    expect(result.stdout).toContain(
      `Installing OpenShell from release 'v${REQUIRED_OPENSHELL_VERSION}'`,
    );
    expect(result.stderr).not.toMatch(/Upgrade NemoClaw first/);
  });

  it("reinstalls the pinned release when openshell is at a much newer version", () => {
    const result = runWithInstalledVersion("0.1.0");
    expect(result.status).not.toBe(0);
    expect(result.stdout).toContain(
      `above the maximum (${REQUIRED_OPENSHELL_VERSION}) supported by this NemoClaw release`,
    );
    expect(result.stdout).toContain(`reinstalling pinned OpenShell ${REQUIRED_OPENSHELL_VERSION}`);
    expect(result.stdout).toContain(
      `Installing OpenShell from release 'v${REQUIRED_OPENSHELL_VERSION}'`,
    );
    expect(result.stderr).not.toMatch(/Upgrade NemoClaw first/);
  });

  it("accepts an installed OpenShell dev-channel Docker-driver build", () => {
    const result = runWithInstalledVersion(`${LEGACY_OPENSHELL_VERSION}.dev84+g6b2180425`, {
      NEMOCLAW_OPENSHELL_CHANNEL: "dev",
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/dev channel/);
  });

  it("refreshes an installed dev build when current main is required", () => {
    const result = runWithInstalledVersion(`${LEGACY_OPENSHELL_VERSION}.dev84+g6b2180425`, {
      NEMOCLAW_OPENSHELL_CHANNEL: "dev",
      NEMOCLAW_OPENSHELL_FORCE_INSTALL: "1",
    });
    expect(result.status).not.toBe(0);
    expect(result.stdout).toContain("refreshing the moving dev release");
    expect(result.stdout).toContain("Installing OpenShell from release 'dev'");
  });

  it("upgrades stable OpenShell when the dev channel is requested", () => {
    const result = runWithInstalledVersion("0.0.36", {
      NEMOCLAW_OPENSHELL_CHANNEL: "dev",
    });
    expect(result.status).not.toBe(0);
    expect(result.stdout).toMatch(/required dev-channel messaging-rewrite\/MCP-L7 build/);
  });

  it("installs one-file OpenShell workflow artifacts with verified provenance", () => {
    const fixture = runArtifactInstallFixture();

    expect(fixture.result.status, `${fixture.result.stdout}\n${fixture.result.stderr}`).toBe(0);
    expect(fixture.result.stdout).toContain(
      `Installing OpenShell from OpenShell workflow artifacts run '${OPENSHELL_ARTIFACT_RUN_ID}'`,
    );
    expect(`${fixture.result.stdout}\n${fixture.result.stderr}`).not.toContain(
      "observed a GitHub token",
    );
    expect(fixture.installedCli).toContain("0.0.72-dev+artifact");
    expect(fixture.installedGateway).toBe(true);
    expect(fixture.installedSandbox).toBe(true);
    expect(fixture.artifactLog).toContain(
      `/repos/NVIDIA/OpenShell/actions/runs/${OPENSHELL_ARTIFACT_RUN_ID} `,
    );
    for (const name of [
      "rust-binary-cli-cli-linux-amd64",
      "rust-binary-gateway-gateway-linux-amd64",
      "rust-binary-supervisor-sandbox-linux-amd64",
    ]) {
      expect(fixture.artifactLog).toContain(
        `/repos/NVIDIA/OpenShell/actions/runs/${OPENSHELL_ARTIFACT_RUN_ID}/artifacts ${name}`,
      );
    }
  });

  it("requires an expected artifact head SHA", () => {
    const fixture = runArtifactInstallFixture({ expectedHeadSha: "" });

    expect(fixture.result.status).toBe(1);
    expect(fixture.result.stderr).toContain(
      "NEMOCLAW_OPENSHELL_ARTIFACT_HEAD_SHA must be set to the expected 40-hex",
    );
    expect(fixture.artifactLog).toBe("");
  });

  it("rejects artifact runs whose head does not match the expected commit", () => {
    const fixture = runArtifactInstallFixture({
      runHeadSha: "1111111111111111111111111111111111111111",
    });

    expect(fixture.result.status).toBe(1);
    expect(fixture.result.stderr).toContain("did not match expected");
    expect(fixture.installedCli).not.toContain("0.0.72-dev+artifact");
  });

  it("rejects duplicate artifact names instead of choosing one", () => {
    const fixture = runArtifactInstallFixture({ artifactCount: 2 });

    expect(fixture.result.status).toBe(1);
    expect(fixture.result.stderr).toContain("Expected exactly one OpenShell artifact");
    expect(fixture.result.stderr).toContain("found 2");
  });

  it("rejects malformed GitHub artifact digest metadata", () => {
    const fixture = runArtifactInstallFixture({ artifactDigest: "sha256:not-a-digest" });

    expect(fixture.result.status).toBe(1);
    expect(fixture.result.stderr).toContain("missing valid GitHub SHA-256 digest metadata");
  });

  it("rejects artifact archives with anything except the expected root file", () => {
    const fixture = runArtifactInstallFixture({ extraArchiveEntry: true });

    expect(fixture.result.status).toBe(1);
    expect(fixture.result.stderr).toContain("must contain exactly one root file named 'openshell'");
    expect(fixture.installedCli).not.toContain("0.0.72-dev+artifact");
  });

  it("rejects artifact-channel installs on Linux arm64", () => {
    const fixture = runArtifactInstallFixture({ arch: "arm64" });

    expect(fixture.result.status).toBe(1);
    expect(fixture.result.stderr).toContain(
      "artifact channel currently supports Linux x86_64 runners only",
    );
    expect(fixture.artifactLog).toBe("");
  });

  it("proceeds to install when openshell is not present", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-openshell-noop-"));
    try {
      const fakeBin = path.join(tmp, "bin");
      fs.mkdirSync(fakeBin);

      // No openshell binary — just stub curl/gh to fail fast
      writeExecutable(
        path.join(fakeBin, "curl"),
        `#!/usr/bin/env bash
echo "curl stub: $*" >&2
exit 1`,
      );
      writeExecutable(
        path.join(fakeBin, "gh"),
        `#!/usr/bin/env bash
exit 1`,
      );

      const result = spawnSync("bash", [SCRIPT], {
        env: {
          ...process.env,
          NEMOCLAW_OPENSHELL_CHANNEL: "stable",
          PATH: `${fakeBin}:/usr/bin:/bin`,
        },
        encoding: "utf8",
      });

      // Should attempt install (not exit 0 early) and fail at the download step
      expect(result.stdout).toMatch(/Installing OpenShell from release/);
      expect(result.status).not.toBe(0);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
