// hub#476 / planning/58 §5.2, §6.2, §6.3 — the eleven self-hosted server ops (agency Worker side).
//
// SSH OPS (host-ssh-check, host-bootstrap, host-repair). The Worker logs in to the agency's server with the agency's
// own key, the Worker secret SELF_HOSTED_<keyIndex>_SSH_KEY (an unencrypted OpenSSH ed25519 key). Three pins, each
// checked BEFORE the Worker connects, so a signed job alone can aim nothing:
//   1. the host key — the job's hostKeyFingerprint must equal the agency's own SELF_HOSTED_<keyIndex>_HOST_KEY, and
//      the server must then present exactly that key (ssh-client.ts stops before it authenticates);
//   2. the key — the secret must exist and parse;
//   3. (bootstrap/repair) the installer — the job's installerUrl and installerSha256 must match the agency's own
//      HOST_INSTALLER_ORIGIN and HOST_INSTALLER_SHA256S.
// The key is used by these three ops only. It is never logged, returned or put in a detail string.
//
// THE REMOTE COMMANDS ARE FIXED TEXT IN THIS FILE. No job value is on a command line. host-ssh-check pipes a fixed
// read-only script to `/bin/sh -s`. host-bootstrap/-repair run a fixed stub with `/bin/sh -c`; the stub reads ONE
// JSON line from stdin, downloads the installer, checks its sha256, and runs it with that same line on the
// installer's own stdin. The host-agent token and the tunnel connector token travel only inside that stdin line.
//
// THE INSTALLER CONTRACT (the infra host child implements the installer side):
//   stdin   one JSON line: { op, mode, installerUrl, installerSha256, cellId, label, subnet, networkName, sftpPort,
//           hostAgentHost, tunnelId } plus, for mode "start" only, hostAgentToken (64 hex = the 32-byte AES key of
//           §5.2) and tunnelToken (the cell's cloudflared connector token). `op` is host-bootstrap, host-repair or
//           host-enroll (the manual path, enroll-host.ts).
//   stdout  its LAST non-empty line is one JSON object: { state: running|done|failed|none, step, detail,
//           hypervisor?, hostAgentVersion? } (the result fields of §6.2).
//   argv    none. The installer elevates itself (sudo on Ubuntu; an admin user on macOS).
//
// HOST-AGENT OPS (host-network-ensure, host-vm-*). The Worker reaches the host-agent through the cell's tunnel at the
// job's hostAgentUrl. The host-agent token = HKDF-SHA256(HOST_AGENT_MASTER_KEY, salt "doubleyoup-host-agent/v1\n" +
// cellId, info "host-agent-token", 32 bytes). It is never sent: it is the AES-256-GCM key of the request and of the
// answer (§5.2). An answer that does not open with it is refused as `host-agent-unverified`, so a host that is not
// the real host-agent cannot fake a success, and a request sent to the wrong host gives that host only ciphertext.

import type { Env } from "./env.js";
import { substituteMetadataPlaceholders, resolveAccountId, fetchCfTunnelToken, CF_TUNNEL_UNAUTHORIZED_HINT } from "./actuate.js";
import { isConnectorTokenForTunnel } from "./actuate-p47.js";
import {
  HOST_KEY_FINGERPRINT_RE,
  HOST_SHA256_RE,
  isHostAgentUrl,
  type HostAgentOp,
  type HostBootstrapParams,
  type HostNetworkEnsureParams,
  type HostSshCheckParams,
  type HostSshOp,
  type HostSshTargetParams,
  type HostVmCreateParams,
  type HostVmDeleteParams,
  type HostVmGetParams,
  type HostVmListParams,
  type HostVmRestartParams,
  type HostVmSetBootScriptParams,
  type HostVmSnapshotParams,
} from "./dispatch-params-host.js";
import { SshError, parseOpenSshEd25519PrivateKey, sshExec, type SshExecResult, type SshPrivateKey } from "./ssh-client.js";
import { base64Decode, base64Encode, concatBytes, hexEncode, utf8Bytes, utf8Text } from "./ssh-wire.js";

// ── result types ──────────────────────────────────────────────────────────────────────────────────

/** The stable failure codes of planning/58 §6.2 and §6.3, plus the Worker-side configuration codes. */
export type HostOpFailureCode =
  | "unreachable"
  | "host-key-mismatch"
  | "host-key-not-pinned"
  | "auth-failed"
  | "ssh-key-missing"
  | "ssh-failed"
  | "preflight-failed"
  | "installer-not-pinned"
  | "installer-not-allowed"
  | "installer-download-failed"
  | "installer-sha256-mismatch"
  | "installer-failed"
  | "host-agent-key-missing"
  | "tunnel-token-failed"
  | "boot-script-refused"
  | "host-agent-unreachable"
  | "host-agent-unauthorized"
  | "host-agent-cell-unknown"
  | "host-agent-unverified";

export interface HostOpFailure {
  ok: false;
  op: HostSshOp | HostAgentOp;
  code: HostOpFailureCode | string;
  detail: string;
}

export interface HostPreflightFacts {
  os: string;
  osVersion: string;
  arch: string;
  cpuCount: number;
  memoryMiB: number;
  diskFreeGiB: number;
  virtualization: "kvm" | "multipass" | "none";
  isRoot: boolean;
  canSudo: boolean;
}

export type HostSshCheckResult =
  | ({ ok: true; op: "host-ssh-check" } & HostPreflightFacts)
  | (HostOpFailure & { op: "host-ssh-check"; facts?: HostPreflightFacts; problems?: string[] });

export const HOST_INSTALL_STATES = ["running", "done", "failed", "none"] as const;
export const HOST_INSTALL_STEPS = ["preflight", "hypervisor", "service-user", "host-agent", "network", "cloudflared", "sftp-forward", "verify"] as const;

export type HostBootstrapResult =
  | {
      ok: true;
      op: "host-bootstrap" | "host-repair";
      mode: "start" | "poll";
      state: (typeof HOST_INSTALL_STATES)[number];
      step?: (typeof HOST_INSTALL_STEPS)[number];
      detail: string;
      hypervisor?: "libvirt" | "multipass";
      hostAgentVersion?: string;
    }
  | (HostOpFailure & { op: "host-bootstrap" | "host-repair" });

/** A host-agent answer, as the host-agent sealed it. Its fields are the §6.3 result shape of the op. */
export type HostAgentResult = { ok: boolean; op: HostAgentOp; [field: string]: unknown } | (HostOpFailure & { op: HostAgentOp });

export type HostOpResult = HostSshCheckResult | HostBootstrapResult | HostAgentResult;

// ── timing ────────────────────────────────────────────────────────────────────────────────────────
const SSH_CONNECT_TIMEOUT_MS = 10_000;
const SSH_CHECK_TOTAL_TIMEOUT_MS = 45_000;
// A bootstrap call downloads the installer and starts (or reads) a detached run, so it ends in well under this.
const SSH_INSTALL_TOTAL_TIMEOUT_MS = 120_000;
const HOST_AGENT_TIMEOUT_MS = 60_000;
const DETAIL_MAX_LENGTH = 300;

// ── the preflight floor of host-ssh-check ─────────────────────────────────────────────────────────
// planning/58 §4.3/§11: one cell needs about 7-8 GiB RAM, 4 vCPU and 80 GB disk (targets the infra spike measures).
// host-ssh-check refuses only a server that cannot run a cell at all; the installer's own preflight checks the
// sizes of the real request.
export const HOST_SUPPORTED_OS = ["ubuntu", "debian", "macos"] as const;
export const HOST_SUPPORTED_ARCH = ["x86_64", "arm64"] as const;
export const HOST_MIN_CPU_COUNT = 2;
export const HOST_MIN_MEMORY_MIB = 4096;
export const HOST_MIN_DISK_FREE_GIB = 40;

/** The read-only script host-ssh-check pipes to `/bin/sh -s`. POSIX sh; the same text on Linux and macOS. */
export const HOST_SSH_CHECK_SCRIPT = `set -u
os=unknown
os_version=unknown
arch=$(uname -m)
cpu=0
mem_mib=0
virt=none
if [ "$(uname -s)" = Darwin ]; then
  os=macos
  os_version=$(sw_vers -productVersion 2>/dev/null || echo unknown)
  cpu=$(sysctl -n hw.ncpu 2>/dev/null || echo 0)
  mem_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
  mem_mib=$((mem_bytes / 1048576))
  # An SSH exec session has only the default PATH; Multipass lives in the Homebrew or pkg install folders.
  if PATH="$PATH:/usr/local/bin:/opt/homebrew/bin" command -v multipass >/dev/null 2>&1; then virt=multipass; fi
else
  if [ -r /etc/os-release ]; then
    os=$(. /etc/os-release && echo "\${ID:-unknown}")
    os_version=$(. /etc/os-release && echo "\${VERSION_ID:-unknown}")
  fi
  cpu=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0)
  mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  mem_mib=$((mem_kib / 1024))
  if [ -e /dev/kvm ]; then virt=kvm; fi
fi
disk_kib=$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}')
disk_gib=$((\${disk_kib:-0} / 1048576))
if [ "$(id -u)" = 0 ]; then
  is_root=true
  can_sudo=true
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  is_root=false
  can_sudo=true
else
  is_root=false
  can_sudo=false
fi
printf 'dy-preflight-v1\\nos=%s\\nos_version=%s\\narch=%s\\ncpu=%s\\nmem_mib=%s\\ndisk_gib=%s\\nvirt=%s\\nis_root=%s\\ncan_sudo=%s\\n' \\
  "$os" "$os_version" "$arch" "$cpu" "$mem_mib" "$disk_gib" "$virt" "$is_root" "$can_sudo"
`;

/**
 * The fixed stub host-bootstrap/-repair run with `/bin/sh -c`. It has no single quote, so it fits in one
 * single-quoted argument. Exit codes 90-92 are the stub's own; any other code is the installer's.
 */
export const HOST_INSTALL_STUB = [
  "set -eu",
  "umask 077",
  "IFS= read -r job_line || true",
  `installer_url=$(printf "%s\\n" "$job_line" | sed -n "s/.*\\"installerUrl\\":\\"\\([^\\"]*\\)\\".*/\\1/p")`,
  `installer_sha256=$(printf "%s\\n" "$job_line" | sed -n "s/.*\\"installerSha256\\":\\"\\([0-9a-f]*\\)\\".*/\\1/p")`,
  `if [ -z "$installer_url" ] || [ "\${#installer_sha256}" -ne 64 ]; then echo "dy-stub: the job line has no installer" >&2; exit 90; fi`,
  `work_dir=$(mktemp -d "\${TMPDIR:-/tmp}/dy-host-install.XXXXXX")`,
  `trap "rm -rf \\"$work_dir\\"" EXIT`,
  `if ! curl -fsSL --proto =https --max-time 90 -o "$work_dir/host-install.sh" "$installer_url"; then echo "dy-stub: the installer download failed" >&2; exit 91; fi`,
  `if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$work_dir/host-install.sh"); else actual=$(shasum -a 256 "$work_dir/host-install.sh"); fi`,
  `actual=\${actual%% *}`,
  `if [ "$actual" != "$installer_sha256" ]; then echo "dy-stub: the installer sha256 is $actual, not the pinned one" >&2; exit 92; fi`,
  `printf "%s\\n" "$job_line" | /bin/sh "$work_dir/host-install.sh"`,
].join("\n");

const STUB_EXIT_NO_INSTALLER = 90;
const STUB_EXIT_DOWNLOAD_FAILED = 91;
const STUB_EXIT_SHA_MISMATCH = 92;

// ── env helpers ───────────────────────────────────────────────────────────────────────────────────

function envText(env: Env, name: string): string | undefined {
  const value = (env as unknown as Record<string, unknown>)[name];
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  if (trimmed === "") {
    return undefined;
  }
  return trimmed;
}

export function sshKeySecretName(keyIndex: number): string {
  return `SELF_HOSTED_${keyIndex}_SSH_KEY`;
}

export function hostKeyPinName(keyIndex: number): string {
  return `SELF_HOSTED_${keyIndex}_HOST_KEY`;
}

function shortText(text: string): string {
  return text.slice(0, DETAIL_MAX_LENGTH);
}

// ── host-agent token (HKDF) ───────────────────────────────────────────────────────────────────────

export const HOST_AGENT_MASTER_KEY_MIN_LENGTH = 32;
const HOST_AGENT_TOKEN_SALT_PREFIX = "doubleyoup-host-agent/v1\n";
const HOST_AGENT_TOKEN_INFO = "host-agent-token";

/** HKDF-SHA256(ikm = master key, salt = prefix + cellId, info = "host-agent-token", L = 32). */
export async function deriveHostAgentToken(masterKey: string, cellId: string): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey("raw", utf8Bytes(masterKey), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: utf8Bytes(HOST_AGENT_TOKEN_SALT_PREFIX + cellId), info: utf8Bytes(HOST_AGENT_TOKEN_INFO) },
    keyMaterial,
    256,
  );
  return new Uint8Array(bits);
}

/** The master key, or the reason it cannot be used. */
export function hostAgentMasterKey(env: Env): { ok: true; masterKey: string } | { ok: false; detail: string } {
  const masterKey = env.HOST_AGENT_MASTER_KEY;
  if (typeof masterKey !== "string" || masterKey.length < HOST_AGENT_MASTER_KEY_MIN_LENGTH) {
    return {
      ok: false,
      detail: `HOST_AGENT_MASTER_KEY is not set on this Worker (or is shorter than ${HOST_AGENT_MASTER_KEY_MIN_LENGTH} characters). Set it with \`wrangler secret put HOST_AGENT_MASTER_KEY\` (openssl rand -hex 32).`,
    };
  }
  return { ok: true, masterKey };
}

// ── the agency's pins ─────────────────────────────────────────────────────────────────────────────

/** Check the job's host-key fingerprint against the agency's own pin. Runs before any connection. */
function hostKeyPinFailure(env: Env, target: HostSshTargetParams): { code: HostOpFailureCode; detail: string } | null {
  const pinName = hostKeyPinName(target.keyIndex);
  const pinned = envText(env, pinName);
  if (pinned === undefined) {
    return {
      code: "host-key-not-pinned",
      detail: `${pinName} is not set on this Worker. Set it to the server's ED25519 host-key fingerprint (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) with \`wrangler secret put ${pinName}\`.`,
    };
  }
  if (!HOST_KEY_FINGERPRINT_RE.test(pinned)) {
    return {
      code: "host-key-not-pinned",
      detail: `${pinName} is not an OpenSSH fingerprint (SHA256:<43 base64 chars>); set only the SHA256:… part of the ED25519 host key.`,
    };
  }
  if (pinned !== target.hostKeyFingerprint) {
    return {
      code: "host-key-mismatch",
      detail: `the job's host-key fingerprint ${target.hostKeyFingerprint} is not the one this Worker pins in ${pinName} (${pinned}); refusing to connect. Give the ED25519 fingerprint in both places.`,
    };
  }
  return null;
}

async function loadSshKey(env: Env, keyIndex: number): Promise<{ ok: true; key: SshPrivateKey } | { ok: false; code: HostOpFailureCode; detail: string }> {
  const secretName = sshKeySecretName(keyIndex);
  const pem = envText(env, secretName);
  if (pem === undefined) {
    return { ok: false, code: "ssh-key-missing", detail: `${secretName} is not set on this Worker. Put the server's ed25519 private key there with \`wrangler secret put ${secretName}\`.` };
  }
  const parsed = await parseOpenSshEd25519PrivateKey(pem);
  if (!parsed.ok) {
    return { ok: false, code: "ssh-key-missing", detail: `${secretName} cannot be used: ${parsed.reason}.` };
  }
  return { ok: true, key: parsed.key };
}

export const HOST_INSTALLER_SHA256S_MAX = 4;
export const HOST_INSTALLER_PATH_PREFIX = "/self-hosted/host-install-";

export interface InstallerPin {
  origin: string;
  sha256s: string[];
}

/** Read HOST_INSTALLER_ORIGIN and HOST_INSTALLER_SHA256S. Null + reason when either is unset or malformed. */
export function readInstallerPin(env: Env): { ok: true; pin: InstallerPin } | { ok: false; detail: string } {
  const origin = envText(env, "HOST_INSTALLER_ORIGIN");
  const shaList = envText(env, "HOST_INSTALLER_SHA256S");
  const howTo =
    "Set HOST_INSTALLER_ORIGIN (https://<host> that serves /self-hosted/host-install-<sha256>.sh) and HOST_INSTALLER_SHA256S (1-4 accepted installer sha256 values, comma-separated) with `wrangler secret put`.";
  if (origin === undefined || shaList === undefined) {
    return { ok: false, detail: `the installer is not pinned on this Worker. ${howTo}` };
  }
  if (!isHostAgentUrl(origin)) {
    return { ok: false, detail: `HOST_INSTALLER_ORIGIN must be exactly https://<lowercase host> with no path. ${howTo}` };
  }
  const sha256s: string[] = [];
  for (const entry of shaList.split(",")) {
    const value = entry.trim();
    if (!HOST_SHA256_RE.test(value)) {
      return { ok: false, detail: `HOST_INSTALLER_SHA256S holds a value that is not 64 lowercase hex characters. ${howTo}` };
    }
    sha256s.push(value);
  }
  if (sha256s.length === 0 || sha256s.length > HOST_INSTALLER_SHA256S_MAX) {
    return { ok: false, detail: `HOST_INSTALLER_SHA256S must hold 1-${HOST_INSTALLER_SHA256S_MAX} values. ${howTo}` };
  }
  return { ok: true, pin: { origin, sha256s } };
}

/** The content-addressed installer URL of planning/58 §6.2 and §7.4. */
export function pinnedInstallerUrl(origin: string, sha256: string): string {
  return `${origin}${HOST_INSTALLER_PATH_PREFIX}${sha256}.sh`;
}

function installerPinFailure(env: Env, params: HostBootstrapParams): { code: HostOpFailureCode; detail: string } | null {
  const pin = readInstallerPin(env);
  if (!pin.ok) {
    return { code: "installer-not-pinned", detail: pin.detail };
  }
  if (!pin.pin.sha256s.includes(params.installerSha256)) {
    return { code: "installer-not-allowed", detail: `the installer sha256 ${params.installerSha256} is not in this Worker's HOST_INSTALLER_SHA256S; refusing to run it. Add it there once you have read that release.` };
  }
  if (params.installerUrl !== pinnedInstallerUrl(pin.pin.origin, params.installerSha256)) {
    return { code: "installer-not-allowed", detail: `the installer URL is not ${pinnedInstallerUrl(pin.pin.origin, params.installerSha256)} (HOST_INSTALLER_ORIGIN); refusing to run it.` };
  }
  return null;
}

// ── SSH failure mapping ───────────────────────────────────────────────────────────────────────────

function sshFailure(error: unknown, target: HostSshTargetParams): { code: HostOpFailureCode; detail: string } {
  if (!(error instanceof SshError)) {
    throw error;
  }
  if (error.code === "unreachable") {
    return {
      code: "unreachable",
      detail: shortText(
        `${error.message}. The server must accept SSH from the internet on ${target.host}:${target.port}. A server behind NAT (for example a Mac on a LAN) cannot be reached from Cloudflare: use the manual enrol path (your Worker's /enroll-host page).`,
      ),
    };
  }
  if (error.code === "host-key-mismatch") {
    return { code: "host-key-mismatch", detail: shortText(error.message) };
  }
  if (error.code === "auth-failed") {
    return { code: "auth-failed", detail: shortText(error.message) };
  }
  return { code: "ssh-failed", detail: shortText(`the SSH session to ${target.host}:${target.port} failed: ${error.message}`) };
}

function logHostOpFailure(op: string, code: string, target: string): void {
  // A log line for every refusal or failure: the op, the code and the target. Never a key, token or script.
  console.warn(`${op}: failed with code ${code} for ${target}`);
}

// ── host-ssh-check ────────────────────────────────────────────────────────────────────────────────

function parsePreflightOutput(stdout: string): HostPreflightFacts | null {
  const lines = stdout.split("\n");
  const markerAt = lines.indexOf("dy-preflight-v1");
  if (markerAt === -1) {
    return null;
  }
  const values: Record<string, string> = {};
  for (const line of lines.slice(markerAt + 1)) {
    const equalsAt = line.indexOf("=");
    if (equalsAt <= 0) {
      continue;
    }
    values[line.slice(0, equalsAt)] = line.slice(equalsAt + 1).trim();
  }
  let arch = values.arch ?? "unknown";
  if (arch === "aarch64") {
    arch = "arm64";
  }
  if (arch === "amd64") {
    arch = "x86_64";
  }
  let virtualization: HostPreflightFacts["virtualization"] = "none";
  if (values.virt === "kvm" || values.virt === "multipass") {
    virtualization = values.virt;
  }
  return {
    os: shortText(values.os ?? "unknown").slice(0, 32),
    osVersion: shortText(values.os_version ?? "unknown").slice(0, 32),
    arch: arch.slice(0, 32),
    cpuCount: Number.parseInt(values.cpu ?? "0", 10) || 0,
    memoryMiB: Number.parseInt(values.mem_mib ?? "0", 10) || 0,
    diskFreeGiB: Number.parseInt(values.disk_gib ?? "0", 10) || 0,
    virtualization,
    isRoot: values.is_root === "true",
    canSudo: values.can_sudo === "true",
  };
}

/** Every way the server is below the floor, as short sentences. Empty = the server can run a cell. */
export function preflightProblems(facts: HostPreflightFacts): string[] {
  const problems: string[] = [];
  if (!(HOST_SUPPORTED_OS as readonly string[]).includes(facts.os)) {
    problems.push(`the OS is ${facts.os}; supported are Ubuntu, Debian and macOS`);
  }
  if (!(HOST_SUPPORTED_ARCH as readonly string[]).includes(facts.arch)) {
    problems.push(`the CPU architecture is ${facts.arch}; supported are x86_64 and arm64`);
  }
  // On macOS the installer installs Multipass itself (planning/58 §5.1), so a missing Multipass is not below the
  // floor; `virtualization` is reported for information only. On Linux, KVM is hardware the installer cannot add.
  if (facts.virtualization === "none" && facts.os !== "macos") {
    problems.push("KVM is not available (/dev/kvm is missing)");
  }
  if (facts.cpuCount < HOST_MIN_CPU_COUNT) {
    problems.push(`the server has ${facts.cpuCount} CPUs; at least ${HOST_MIN_CPU_COUNT} are needed`);
  }
  if (facts.memoryMiB < HOST_MIN_MEMORY_MIB) {
    problems.push(`the server has ${facts.memoryMiB} MiB of RAM; at least ${HOST_MIN_MEMORY_MIB} MiB are needed`);
  }
  if (facts.diskFreeGiB < HOST_MIN_DISK_FREE_GIB) {
    problems.push(`the server has ${facts.diskFreeGiB} GiB free on /; at least ${HOST_MIN_DISK_FREE_GIB} GiB are needed`);
  }
  if (!facts.isRoot && !facts.canSudo && facts.os !== "macos") {
    problems.push("the login is not root and cannot run sudo without a password");
  }
  return problems;
}

export async function actuateHostSshCheck(params: HostSshCheckParams, env: Env): Promise<HostSshCheckResult> {
  const op = "host-ssh-check" as const;
  const targetText = `${params.user}@${params.host}:${params.port}`;
  const failure = (code: HostOpFailureCode, detail: string): HostSshCheckResult => {
    logHostOpFailure(op, code, targetText);
    return { ok: false, op, code, detail };
  };

  const pinProblem = hostKeyPinFailure(env, params);
  if (pinProblem !== null) {
    return failure(pinProblem.code, pinProblem.detail);
  }
  const key = await loadSshKey(env, params.keyIndex);
  if (!key.ok) {
    return failure(key.code, key.detail);
  }

  let execResult: SshExecResult;
  try {
    execResult = await sshExec({
      hostname: params.host,
      port: params.port,
      username: params.user,
      privateKey: key.key,
      hostKeyFingerprint: params.hostKeyFingerprint,
      command: "/bin/sh -s",
      stdin: utf8Bytes(HOST_SSH_CHECK_SCRIPT),
      connectTimeoutMs: SSH_CONNECT_TIMEOUT_MS,
      totalTimeoutMs: SSH_CHECK_TOTAL_TIMEOUT_MS,
    });
  } catch (error) {
    const mapped = sshFailure(error, params);
    return failure(mapped.code, mapped.detail);
  }

  const facts = parsePreflightOutput(utf8Text(execResult.stdout));
  if (facts === null) {
    return failure("ssh-failed", `the read-out command did not answer as expected (exit status ${execResult.exitCode}); the login shell must be able to run /bin/sh`);
  }
  const problems = preflightProblems(facts);
  if (problems.length > 0) {
    logHostOpFailure(op, "preflight-failed", targetText);
    return { ok: false, op, code: "preflight-failed", detail: shortText(`the server is below the floor: ${problems.join("; ")}`), facts, problems };
  }
  return { ok: true, op, ...facts };
}

// ── host-bootstrap / host-repair ──────────────────────────────────────────────────────────────────

/** The JSON line the installer reads. `secrets` only for mode "start" (and the manual enrol). */
export function installerJobLine(
  op: "host-bootstrap" | "host-repair" | "host-enroll",
  facts: Omit<HostBootstrapParams, "host" | "port" | "user" | "keyIndex" | "hostKeyFingerprint">,
  secrets: { hostAgentToken: string; tunnelToken: string } | null,
): string {
  const line: Record<string, unknown> = {
    op,
    mode: facts.mode,
    installerUrl: facts.installerUrl,
    installerSha256: facts.installerSha256,
    cellId: facts.cellId,
    label: facts.label,
    subnet: facts.subnet,
    networkName: facts.networkName,
    sftpPort: facts.sftpPort,
    hostAgentHost: facts.hostAgentHost,
    tunnelId: facts.tunnelId,
  };
  if (secrets !== null) {
    line.hostAgentToken = secrets.hostAgentToken;
    line.tunnelToken = secrets.tunnelToken;
  }
  return JSON.stringify(line);
}

/** Fetch the cell's connector token from the agency's own Cloudflare account, checked to be for this tunnel. */
export async function fetchConnectorToken(env: Env, tunnelId: string): Promise<{ ok: true; token: string } | { ok: false; detail: string }> {
  const apiToken = env.CF_DNS_API_TOKEN;
  if (!apiToken) {
    return { ok: false, detail: "CF_DNS_API_TOKEN is not configured on this Worker, so it cannot read the cell's tunnel connector token." };
  }
  const account = await resolveAccountId(apiToken, CF_TUNNEL_UNAUTHORIZED_HINT);
  if ("error" in account) {
    return { ok: false, detail: account.error };
  }
  const connector = await fetchCfTunnelToken(apiToken, account.id, tunnelId);
  if ("error" in connector) {
    return { ok: false, detail: connector.error };
  }
  if (!isConnectorTokenForTunnel(connector.token, tunnelId)) {
    return { ok: false, detail: "Cloudflare answered with a value that is not a connector token for this tunnel." };
  }
  return { ok: true, token: connector.token };
}

function redact(text: string, secrets: string[]): string {
  let redacted = text;
  for (const secret of secrets) {
    if (secret.length > 0) {
      redacted = redacted.split(secret).join("[redacted]");
    }
  }
  return redacted;
}

function lastJsonLine(stdout: string): Record<string, unknown> | null {
  const lines = stdout.split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
  if (lines.length === 0) {
    return null;
  }
  const lastLine = lines[lines.length - 1];
  let parsed: unknown;
  try {
    parsed = JSON.parse(lastLine);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  return parsed as Record<string, unknown>;
}

export async function actuateHostInstall(op: "host-bootstrap" | "host-repair", params: HostBootstrapParams, env: Env): Promise<HostBootstrapResult> {
  const targetText = `${params.user}@${params.host}:${params.port} (cell ${params.cellId})`;
  const failure = (code: HostOpFailureCode, detail: string): HostBootstrapResult => {
    logHostOpFailure(op, code, targetText);
    return { ok: false, op, code, detail };
  };

  const pinProblem = hostKeyPinFailure(env, params);
  if (pinProblem !== null) {
    return failure(pinProblem.code, pinProblem.detail);
  }
  const installerProblem = installerPinFailure(env, params);
  if (installerProblem !== null) {
    return failure(installerProblem.code, installerProblem.detail);
  }
  const key = await loadSshKey(env, params.keyIndex);
  if (!key.ok) {
    return failure(key.code, key.detail);
  }

  // Only "start" carries the two secrets: a poll reads the run's state and must not hand the server anything.
  let secrets: { hostAgentToken: string; tunnelToken: string } | null = null;
  if (params.mode === "start") {
    const master = hostAgentMasterKey(env);
    if (!master.ok) {
      return failure("host-agent-key-missing", master.detail);
    }
    const connector = await fetchConnectorToken(env, params.tunnelId);
    if (!connector.ok) {
      return failure("tunnel-token-failed", connector.detail);
    }
    const tokenBytes = await deriveHostAgentToken(master.masterKey, params.cellId);
    secrets = { hostAgentToken: hexEncode(tokenBytes), tunnelToken: connector.token };
  }

  const jobLine = installerJobLine(op, params, secrets);
  let execResult: SshExecResult;
  try {
    execResult = await sshExec({
      hostname: params.host,
      port: params.port,
      username: params.user,
      privateKey: key.key,
      hostKeyFingerprint: params.hostKeyFingerprint,
      command: `/bin/sh -c '${HOST_INSTALL_STUB}'`,
      stdin: utf8Bytes(`${jobLine}\n`),
      connectTimeoutMs: SSH_CONNECT_TIMEOUT_MS,
      totalTimeoutMs: SSH_INSTALL_TOTAL_TIMEOUT_MS,
    });
  } catch (error) {
    const mapped = sshFailure(error, params);
    return failure(mapped.code, mapped.detail);
  }

  const secretValues: string[] = [];
  if (secrets !== null) {
    secretValues.push(secrets.hostAgentToken, secrets.tunnelToken);
  }
  const stderrTail = shortText(redact(utf8Text(execResult.stderr), secretValues).trim().split("\n").slice(-3).join(" | "));
  if (execResult.exitCode === STUB_EXIT_NO_INSTALLER) {
    return failure("installer-failed", `the stub did not receive the installer facts: ${stderrTail}`);
  }
  if (execResult.exitCode === STUB_EXIT_DOWNLOAD_FAILED) {
    return failure("installer-download-failed", `the server could not download ${params.installerUrl}: ${stderrTail}`);
  }
  if (execResult.exitCode === STUB_EXIT_SHA_MISMATCH) {
    return failure("installer-sha256-mismatch", `the downloaded installer does not match the pinned sha256; nothing ran. ${stderrTail}`);
  }

  const answer = lastJsonLine(redact(utf8Text(execResult.stdout), secretValues));
  if (answer === null || !(HOST_INSTALL_STATES as readonly unknown[]).includes(answer.state)) {
    return failure("installer-failed", `the installer gave no result line (exit status ${execResult.exitCode}): ${stderrTail}`);
  }
  if (execResult.exitCode !== 0) {
    // The installer printed a result line and then ended badly. The answer stands; the next poll shows the real
    // state, but the log keeps the exit status for the operator.
    logHostOpFailure(op, `installer exit status ${execResult.exitCode} after result line`, targetText);
  }
  const result: HostBootstrapResult = {
    ok: true,
    op,
    mode: params.mode,
    state: answer.state as (typeof HOST_INSTALL_STATES)[number],
    detail: typeof answer.detail === "string" ? shortText(answer.detail) : "",
  };
  if ((HOST_INSTALL_STEPS as readonly unknown[]).includes(answer.step)) {
    result.step = answer.step as (typeof HOST_INSTALL_STEPS)[number];
  }
  if (answer.hypervisor === "libvirt" || answer.hypervisor === "multipass") {
    result.hypervisor = answer.hypervisor;
  }
  if (typeof answer.hostAgentVersion === "string" && /^[A-Za-z0-9._+-]{1,64}$/.test(answer.hostAgentVersion)) {
    result.hostAgentVersion = answer.hostAgentVersion;
  }
  if (result.state === "failed") {
    logHostOpFailure(op, `installer state failed at step ${result.step ?? "unknown"}`, targetText);
  }
  return result;
}

// ── host-agent requests (§5.2) ────────────────────────────────────────────────────────────────────

const HOST_AGENT_PROTOCOL = "dy-host-agent/v1";
const GCM_IV_LENGTH = 12;

export function hostAgentRequestAad(op: string, cellId: string, time: string, nonce: string): Uint8Array {
  return utf8Bytes(`${HOST_AGENT_PROTOCOL}\nreq\n${op}\n${cellId}\n${time}\n${nonce}`);
}

export function hostAgentAnswerAad(op: string, cellId: string, nonce: string): Uint8Array {
  return utf8Bytes(`${HOST_AGENT_PROTOCOL}\nres\n${op}\n${cellId}\n${nonce}`);
}

async function importTokenKey(token: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", token, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** base64(iv ‖ AES-256-GCM(key, iv, plaintext)) with the given additional data. */
export async function sealHostAgentBody(key: CryptoKey, plaintext: Uint8Array, additionalData: Uint8Array): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_LENGTH));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, key, plaintext));
  return base64Encode(concatBytes([iv, sealed]), true);
}

/** Open a sealed body, or null when it does not open with this key and additional data. */
export async function openHostAgentBody(key: CryptoKey, body: string, additionalData: Uint8Array): Promise<Uint8Array | null> {
  const bytes = base64Decode(body.trim());
  if (bytes === null || bytes.length < GCM_IV_LENGTH + 16) {
    return null;
  }
  try {
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.subarray(0, GCM_IV_LENGTH), additionalData }, key, bytes.subarray(GCM_IV_LENGTH));
    return new Uint8Array(plaintext);
  } catch {
    return null;
  }
}

/**
 * Send one sealed request to the cell's host-agent and open its sealed answer. `body` is the op's params without
 * hostAgentUrl (the host-agent never needs to know where it was reached).
 */
export async function callHostAgent(op: HostAgentOp, cellId: string, hostAgentUrl: string, body: Record<string, unknown>, env: Env): Promise<HostAgentResult> {
  const targetText = `${hostAgentUrl} (cell ${cellId})`;
  const failure = (code: HostOpFailureCode, detail: string): HostAgentResult => {
    logHostOpFailure(op, code, targetText);
    return { ok: false, op, code, detail };
  };

  const master = hostAgentMasterKey(env);
  if (!master.ok) {
    return failure("host-agent-key-missing", master.detail);
  }
  const key = await importTokenKey(await deriveHostAgentToken(master.masterKey, cellId));
  const time = String(Math.floor(Date.now() / 1000));
  const nonce = hexEncode(crypto.getRandomValues(new Uint8Array(16)));
  const sealedRequest = await sealHostAgentBody(key, utf8Bytes(JSON.stringify(body)), hostAgentRequestAad(op, cellId, time, nonce));

  let response: Response;
  try {
    response = await fetch(`${hostAgentUrl}/v1/${op}`, {
      method: "POST",
      headers: { "content-type": "text/plain", "x-dy-cell": cellId, "x-dy-time": time, "x-dy-nonce": nonce },
      body: sealedRequest,
      signal: AbortSignal.timeout(HOST_AGENT_TIMEOUT_MS),
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return failure("host-agent-unreachable", shortText(`could not reach the host-agent at ${hostAgentUrl}: ${reason}. Is the server on, and is its tunnel connector running?`));
  }
  const responseText = await response.text().catch(() => "");
  const opened = await openHostAgentBody(key, responseText, hostAgentAnswerAad(op, cellId, nonce));
  if (opened === null) {
    if (response.status === 401) {
      return failure("host-agent-unauthorized", "the host-agent refused the request (401): its token for this cell differs from this Worker's (run host-repair after a HOST_AGENT_MASTER_KEY change), or the clocks differ by more than 120 s.");
    }
    if (response.status === 404) {
      return failure("host-agent-cell-unknown", "the host-agent holds no entry for this cell (404): run host-bootstrap for it first.");
    }
    return failure("host-agent-unverified", `the answer (HTTP ${response.status}) did not open with this cell's host-agent token, so it is not from the real host-agent; nothing in it is trusted.`);
  }
  let answer: unknown;
  try {
    answer = JSON.parse(utf8Text(opened));
  } catch {
    return failure("host-agent-unverified", "the host-agent's sealed answer is not JSON.");
  }
  if (answer === null || typeof answer !== "object" || Array.isArray(answer) || typeof (answer as { ok?: unknown }).ok !== "boolean") {
    return failure("host-agent-unverified", "the host-agent's sealed answer has no boolean ok field.");
  }
  const result = { ...(answer as Record<string, unknown>), op } as HostAgentResult;
  if (result.ok === false) {
    logHostOpFailure(op, `host-agent ${String((answer as { code?: unknown }).code ?? "error")}`, targetText);
  }
  return result;
}

/** Substitute the @@DY_*@@ placeholders, as gcp-instance-set-metadata does. A refusal names the placeholder only. */
function renderScript(value: string, env: Env, what: string): { ok: true; value: string } | { ok: false; detail: string } {
  const rendered = substituteMetadataPlaceholders(value, env);
  if (!rendered.ok) {
    return { ok: false, detail: `${what}: ${rendered.detail}` };
  }
  return { ok: true, value: rendered.value };
}

function withoutUrl<P extends { hostAgentUrl: string }>(params: P): Record<string, unknown> {
  const body: Record<string, unknown> = { ...params };
  delete body.hostAgentUrl;
  return body;
}

export function actuateHostNetworkEnsure(params: HostNetworkEnsureParams, env: Env): Promise<HostAgentResult> {
  return callHostAgent("host-network-ensure", params.cellId, params.hostAgentUrl, withoutUrl(params), env);
}

export async function actuateHostVmCreate(params: HostVmCreateParams, env: Env): Promise<HostAgentResult> {
  const body = withoutUrl(params);
  if (params.startupScript !== undefined) {
    const rendered = renderScript(params.startupScript, env, "startupScript");
    if (!rendered.ok) {
      logHostOpFailure("host-vm-create", "boot-script-refused", params.name);
      return { ok: false, op: "host-vm-create", code: "boot-script-refused", detail: rendered.detail };
    }
    body.startupScript = rendered.value;
  }
  return callHostAgent("host-vm-create", params.cellId, params.hostAgentUrl, body, env);
}

export function actuateHostVmGet(params: HostVmGetParams, env: Env): Promise<HostAgentResult> {
  return callHostAgent("host-vm-get", params.cellId, params.hostAgentUrl, withoutUrl(params), env);
}

export function actuateHostVmList(params: HostVmListParams, env: Env): Promise<HostAgentResult> {
  return callHostAgent("host-vm-list", params.cellId, params.hostAgentUrl, withoutUrl(params), env);
}

export function actuateHostVmDelete(params: HostVmDeleteParams, env: Env): Promise<HostAgentResult> {
  return callHostAgent("host-vm-delete", params.cellId, params.hostAgentUrl, withoutUrl(params), env);
}

export function actuateHostVmRestart(params: HostVmRestartParams, env: Env): Promise<HostAgentResult> {
  return callHostAgent("host-vm-restart", params.cellId, params.hostAgentUrl, withoutUrl(params), env);
}

export function actuateHostVmSnapshot(params: HostVmSnapshotParams, env: Env): Promise<HostAgentResult> {
  return callHostAgent("host-vm-snapshot", params.cellId, params.hostAgentUrl, withoutUrl(params), env);
}

export async function actuateHostVmSetBootScript(params: HostVmSetBootScriptParams, env: Env): Promise<HostAgentResult> {
  const body = withoutUrl(params);
  const renderedItems: Array<{ key: string; value: string }> = [];
  for (const item of params.items) {
    const rendered = renderScript(item.value, env, `items key "${item.key}"`);
    if (!rendered.ok) {
      logHostOpFailure("host-vm-set-boot-script", "boot-script-refused", params.name);
      return { ok: false, op: "host-vm-set-boot-script", code: "boot-script-refused", detail: rendered.detail };
    }
    renderedItems.push({ key: item.key, value: rendered.value });
  }
  body.items = renderedItems;
  return callHostAgent("host-vm-set-boot-script", params.cellId, params.hostAgentUrl, body, env);
}
