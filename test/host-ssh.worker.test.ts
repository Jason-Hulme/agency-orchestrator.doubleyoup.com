// hub#476 / planning/58 §6.2 — the Worker's SSH ops against a REAL OpenSSH server, under the real workerd runtime.
//
// test/host-sshd.global-setup.mjs starts test/fixtures/host-sshd (Debian 12, OpenSSH, a sudo login, an HTTPS
// server for the stub installer) and provides its facts. These tests prove, end to end:
//   - the spike: an SSH exec session from workerd works (cloudflare:sockets connect() + the Web Crypto client of
//     src/ssh-client.ts: curve25519-sha256, ssh-ed25519, aes256-gcm@openssh.com, publickey auth, stdin);
//   - host-ssh-check logs in, checks the pinned host key and returns the preflight read-out;
//   - a mismatched or unpinned host key is refused BEFORE the key is used, and an unreachable host fails clearly;
//   - host-bootstrap downloads the stub installer, checks its sha256, runs it with the params and the host-agent
//     token on stdin (never argv), and the start/poll contract converges on "done";
//   - a tampered installer and an installer outside the agency's pin are refused.
// Only the Cloudflare API call for the tunnel connector token is mocked. Without Docker the suite is skipped.

import { describe, it, expect, inject, vi, afterEach } from "vitest";
import type { Env } from "../src/env.js";
import { actuateHostInstall, actuateHostSshCheck, deriveHostAgentToken, pinnedInstallerUrl } from "../src/actuate-host.js";
import type { HostBootstrapParams, HostSshCheckParams } from "../src/dispatch-params-host.js";
import { parseOpenSshEd25519PrivateKey, sshExec } from "../src/ssh-client.js";
import { hexEncode } from "../src/ssh-wire.js";

const sshd = inject("hostSshd");
const describeWithSshd = sshd.available ? describe : describe.skip;

const KEY_INDEX = 7;
const CELL_ID = "clh476testcell000000000001";
const TUNNEL_ID = "0123456789abcdef0123456789abcdef";
const MASTER_KEY = "test-master-key-0123456789abcdef0123456789";
const ACCOUNT_ID = "acct476";
const CONNECTOR_TOKEN = btoa(JSON.stringify({ a: ACCOUNT_ID, t: TUNNEL_ID, s: "c2VjcmV0LXR1bm5lbC1zZWNyZXQ=" }));

function facts() {
  if (!sshd.available) {
    throw new Error("unreachable: the suite is skipped without Docker");
  }
  return sshd;
}

function env(overrides: Record<string, string | undefined> = {}): Env {
  const server = facts();
  return {
    APP_BASE_URL: "https://app.example",
    NONCE_STORE: undefined as unknown as Env["NONCE_STORE"],
    CF_DNS_API_TOKEN: "cf-token",
    HOST_AGENT_MASTER_KEY: MASTER_KEY,
    HOST_INSTALLER_ORIGIN: server.installerOrigin,
    HOST_INSTALLER_SHA256S: server.installerSha256,
    [`SELF_HOSTED_${KEY_INDEX}_SSH_KEY`]: server.privateKeyPem,
    [`SELF_HOSTED_${KEY_INDEX}_HOST_KEY`]: server.hostKeyFingerprint,
    ...overrides,
  } as unknown as Env;
}

function checkParams(overrides: Partial<HostSshCheckParams> = {}): HostSshCheckParams {
  const server = facts();
  // 127.0.0.1 is refused by the param validator (not a public address); the actuator is called directly here.
  return { host: "127.0.0.1", port: server.port, user: server.login, keyIndex: KEY_INDEX, hostKeyFingerprint: server.hostKeyFingerprint, ...overrides };
}

function bootstrapParams(overrides: Partial<HostBootstrapParams> = {}): HostBootstrapParams {
  const server = facts();
  return {
    ...checkParams(),
    cellId: CELL_ID,
    label: "office",
    subnet: "10.40.3.0/24",
    networkName: "dy-cell-office",
    sftpPort: 2222,
    hostAgentHost: "cell-office-host.agency.example",
    tunnelId: TUNNEL_ID,
    mode: "start",
    installerUrl: pinnedInstallerUrl(server.installerOrigin, server.installerSha256),
    installerSha256: server.installerSha256,
    ...overrides,
  };
}

function mockCloudflareTunnelToken(): void {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.includes("/accounts?per_page=1")) {
      return Response.json({ success: true, result: [{ id: ACCOUNT_ID }] });
    }
    if (url.endsWith(`/cfd_tunnel/${TUNNEL_ID}/token`)) {
      return Response.json({ success: true, result: CONNECTOR_TOKEN });
    }
    return new Response("unexpected", { status: 500 });
  });
}

/** Run a fixed read command on the test server as the test login (the spike's own client, not an op). */
async function readOnServer(command: string): Promise<string> {
  const server = facts();
  const parsed = await parseOpenSshEd25519PrivateKey(server.privateKeyPem);
  if (!parsed.ok) {
    throw new Error(parsed.reason);
  }
  const result = await sshExec({
    hostname: "127.0.0.1",
    port: server.port,
    username: server.login,
    privateKey: parsed.key,
    hostKeyFingerprint: server.hostKeyFingerprint,
    command,
    stdin: new Uint8Array(0),
    connectTimeoutMs: 5000,
    totalTimeoutMs: 20000,
  });
  return new TextDecoder().decode(result.stdout);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describeWithSshd("the spike: an SSH exec session from workerd", () => {
  it("runs one command with stdin and returns stdout, stderr and the exit status", async () => {
    const server = facts();
    const parsed = await parseOpenSshEd25519PrivateKey(server.privateKeyPem);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) {
      return;
    }
    // 300 KB of stdin: more than one channel window and many packets, so the window handling is exercised.
    const stdinText = "line of stdin for the spike\n".repeat(11_000);
    const result = await sshExec({
      hostname: "127.0.0.1",
      port: server.port,
      username: server.login,
      privateKey: parsed.key,
      hostKeyFingerprint: server.hostKeyFingerprint,
      command: "wc -c; echo to-stderr >&2; exit 3",
      stdin: new TextEncoder().encode(stdinText),
      connectTimeoutMs: 5000,
      totalTimeoutMs: 20000,
    });
    expect(result.exitCode).toBe(3);
    expect(new TextDecoder().decode(result.stdout).trim()).toBe(String(stdinText.length));
    expect(new TextDecoder().decode(result.stderr).trim()).toBe("to-stderr");
  });
});

describeWithSshd("host-ssh-check against a real sshd", () => {
  it("logs in, checks the pinned host key and returns the preflight read-out", async () => {
    const result = await actuateHostSshCheck(checkParams(), env());
    // The container is Debian 12 with no /dev/kvm, so the floor check reports KVM: that proves the read-out ran.
    expect(result.ok).toBe(false);
    if (result.ok || !("facts" in result) || result.facts === undefined) {
      throw new Error(`expected a preflight read-out, got ${JSON.stringify(result)}`);
    }
    expect(result.code).toBe("preflight-failed");
    expect(result.facts.os).toBe("debian");
    expect(result.facts.osVersion).toBe("12");
    expect(["x86_64", "arm64"]).toContain(result.facts.arch);
    expect(result.facts.cpuCount).toBeGreaterThan(0);
    expect(result.facts.memoryMiB).toBeGreaterThan(0);
    expect(result.facts.isRoot).toBe(false);
    expect(result.facts.canSudo).toBe(true);
    expect(result.problems).toContain("KVM is not available (/dev/kvm is missing)");
  });

  it("refuses a server that presents another host key, before the key is used", async () => {
    const otherFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const result = await actuateHostSshCheck(
      checkParams({ hostKeyFingerprint: otherFingerprint }),
      env({ [`SELF_HOSTED_${KEY_INDEX}_HOST_KEY`]: otherFingerprint }),
    );
    expect(result).toMatchObject({ ok: false, code: "host-key-mismatch" });
    expect(JSON.stringify(result)).toContain(facts().hostKeyFingerprint);
    expect(JSON.stringify(result)).not.toContain("OPENSSH PRIVATE KEY");
  });

  it("refuses an unpinned host key without connecting", async () => {
    const result = await actuateHostSshCheck(checkParams(), env({ [`SELF_HOSTED_${KEY_INDEX}_HOST_KEY`]: undefined }));
    expect(result).toMatchObject({ ok: false, code: "host-key-not-pinned" });
  });

  it("refuses a job whose fingerprint differs from the agency's pin", async () => {
    const result = await actuateHostSshCheck(checkParams({ hostKeyFingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" }), env());
    expect(result).toMatchObject({ ok: false, code: "host-key-mismatch" });
  });

  it("fails as auth-failed when the server does not accept the key", async () => {
    const result = await actuateHostSshCheck(checkParams(), env({ [`SELF_HOSTED_${KEY_INDEX}_SSH_KEY`]: facts().unauthorizedKeyPem }));
    expect(result).toMatchObject({ ok: false, code: "auth-failed" });
  });

  it("fails as unreachable with the manual-enrol hint when nothing listens", async () => {
    const result = await actuateHostSshCheck(checkParams({ port: 1 }), env());
    expect(result).toMatchObject({ ok: false, code: "unreachable" });
    if (!result.ok) {
      expect(result.detail).toContain("/enroll-host");
    }
  });
});

describeWithSshd("host-bootstrap against a real sshd: the stub installer", () => {
  it("runs the pinned installer with the params and the token on stdin, then polls to done", async () => {
    mockCloudflareTunnelToken();
    const started = await actuateHostInstall("host-bootstrap", bootstrapParams(), env());
    expect(started).toMatchObject({ ok: true, op: "host-bootstrap", mode: "start", state: "running", step: "preflight" });

    // What the installer got: the full job line on stdin, with the derived token and the connector token.
    const stdinLine = (await readOnServer(`cat .dy-test-install/${CELL_ID}.start.stdin`)).trim();
    const received = JSON.parse(stdinLine) as Record<string, unknown>;
    const expectedToken = hexEncode(await deriveHostAgentToken(MASTER_KEY, CELL_ID));
    expect(received).toMatchObject({
      op: "host-bootstrap",
      mode: "start",
      cellId: CELL_ID,
      label: "office",
      subnet: "10.40.3.0/24",
      networkName: "dy-cell-office",
      sftpPort: 2222,
      hostAgentHost: "cell-office-host.agency.example",
      tunnelId: TUNNEL_ID,
      hostAgentToken: expectedToken,
      tunnelToken: CONNECTOR_TOKEN,
    });
    // ...and nothing on argv.
    expect((await readOnServer(`cat .dy-test-install/${CELL_ID}.argc`)).trim()).toBe("0");
    // The answer never carries the tokens.
    expect(JSON.stringify(started)).not.toContain(expectedToken);
    expect(JSON.stringify(started)).not.toContain(CONNECTOR_TOKEN);

    let polled = await actuateHostInstall("host-bootstrap", bootstrapParams({ mode: "poll" }), env());
    for (let attempt = 0; attempt < 20 && polled.ok && polled.state === "running"; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 250));
      polled = await actuateHostInstall("host-bootstrap", bootstrapParams({ mode: "poll" }), env());
    }
    expect(polled).toMatchObject({ ok: true, mode: "poll", state: "done", hypervisor: "libvirt", hostAgentVersion: "0.0.0-stub" });
    // A poll hands the server no secret.
    const pollLine = JSON.parse((await readOnServer(`cat .dy-test-install/${CELL_ID}.poll.stdin`)).trim()) as Record<string, unknown>;
    expect(pollLine.hostAgentToken).toBeUndefined();
    expect(pollLine.tunnelToken).toBeUndefined();

    // A second start on a done run changes nothing (host-repair uses the same contract).
    const repaired = await actuateHostInstall("host-repair", bootstrapParams(), env());
    expect(repaired).toMatchObject({ ok: true, op: "host-repair", state: "done" });
  });

  it("refuses to run an installer whose bytes do not match the pinned sha256", async () => {
    mockCloudflareTunnelToken();
    const server = facts();
    const result = await actuateHostInstall(
      "host-bootstrap",
      bootstrapParams({ cellId: "clh476tamperedcell0000001", installerSha256: server.tamperedSha256, installerUrl: pinnedInstallerUrl(server.installerOrigin, server.tamperedSha256) }),
      env({ HOST_INSTALLER_SHA256S: `${server.installerSha256},${server.tamperedSha256}` }),
    );
    expect(result).toMatchObject({ ok: false, code: "installer-sha256-mismatch" });
    expect(await readOnServer("ls .dy-test-install")).not.toContain("clh476tamperedcell0000001");
  });

  it("refuses an installer outside the agency's pin, before it connects", async () => {
    const otherSha = "f".repeat(64);
    const notAllowed = await actuateHostInstall("host-bootstrap", bootstrapParams({ installerSha256: otherSha, installerUrl: pinnedInstallerUrl(facts().installerOrigin, otherSha) }), env());
    expect(notAllowed).toMatchObject({ ok: false, code: "installer-not-allowed" });
    const otherOrigin = await actuateHostInstall("host-bootstrap", bootstrapParams({ installerUrl: pinnedInstallerUrl("https://evil.example", facts().installerSha256) }), env());
    expect(otherOrigin).toMatchObject({ ok: false, code: "installer-not-allowed" });
    const unpinned = await actuateHostInstall("host-bootstrap", bootstrapParams(), env({ HOST_INSTALLER_SHA256S: undefined }));
    expect(unpinned).toMatchObject({ ok: false, code: "installer-not-pinned" });
  });
});
