// hub#476 / planning/58 §6 — the eleven self-hosted server ops, Worker side (Node project; fetch mocked).
//
// What these tests pin:
//   - the twin block is unchanged (the sha256 pin below; app and the orchestrator pin the SAME value when they add
//     their twins);
//   - the eleven op names are allowlisted and registered, exactly as planning/58 names them;
//   - each validator returns only known keys and refuses an unknown or missing key and a value outside its grammar
//     (private hosts, a non-pool subnet, a networkName that is not dy-cell-<label>, unknown boot-script keys...);
//   - the host-agent token is HKDF(HOST_AGENT_MASTER_KEY, cellId), and a host-agent call is sealed both ways: the
//     token is never on the wire, a forged answer is refused as host-agent-unverified, placeholders are substituted;
//   - /enroll-host renders the command only from the Worker's own pin, and the POST checks the one-time code.
// The SSH ops against a real sshd are in test/host-ssh.worker.test.ts.

import { describe, it, expect, vi, afterEach } from "vitest";
// @ts-ignore — Vite's `?raw` suffix gives the module source as text, for the twin-block pin.
import rawHostParamsSource from "../src/dispatch-params-host.ts?raw";
import worker from "../src/index.js";
import type { Env } from "../src/env.js";
import { DISPATCH_OPS } from "../src/dispatch-verify.js";
import { DISPATCH_OP_REGISTRY } from "../src/ops.js";
import {
  HOST_AGENT_OPS,
  HOST_SSH_OPS,
  isSshHost,
  validateHostBootstrapParams,
  validateHostNetworkEnsureParams,
  validateHostSshCheckParams,
  validateHostVmCreateParams,
  validateHostVmListParams,
  validateHostVmSetBootScriptParams,
  validateHostVmSnapshotParams,
} from "../src/dispatch-params-host.js";
import {
  actuateHostSshCheck,
  actuateHostVmCreate,
  actuateHostVmSetBootScript,
  callHostAgent,
  deriveHostAgentToken,
  hostAgentAnswerAad,
  hostAgentRequestAad,
  openHostAgentBody,
  preflightProblems,
  sealHostAgentBody,
  HOST_INSTALL_STUB,
} from "../src/actuate-host.js";
import { decodeEnrolFacts, manualEnrolCommand } from "../src/enroll-host.js";
import { hexEncode } from "../src/ssh-wire.js";

const hostParamsSource: string = rawHostParamsSource as string;
const TWIN_BLOCK_START_MARKER = "// ── self-hosted server ops (hub#476): twin block start";
const TWIN_BLOCK_END_MARKER = "// ── self-hosted server ops (hub#476): twin block end";
const TWIN_BLOCK_SHA256 = "3e7642cc9cd177e6937491c5dc9dd54d668e6988a199eb3a2f9e11ff3e88afb4";

const CELL_ID = "clh476testcell000000000001";
const MASTER_KEY = "test-master-key-0123456789abcdef0123456789";
const HOST_AGENT_URL = "https://cell-office-host.agency.example";
const TUNNEL_ID = "0123456789abcdef0123456789abcdef";
const FINGERPRINT = "SHA256:EEwlbFVfDUBDgFFVXnxL5EWC7A6uSrdZ1jNgE3qo3jA";
const INSTALLER_SHA = "a".repeat(64);

const SSH_TARGET = { host: "server.agency.example", port: 22, user: "dyadmin", keyIndex: 1, hostKeyFingerprint: FINGERPRINT };
const BOOTSTRAP = {
  ...SSH_TARGET,
  cellId: CELL_ID,
  label: "office",
  subnet: "10.40.3.0/24",
  networkName: "dy-cell-office",
  sftpPort: 2222,
  hostAgentHost: "cell-office-host.agency.example",
  tunnelId: TUNNEL_ID,
  mode: "start",
  installerUrl: `https://bundles.example/self-hosted/host-install-${INSTALLER_SHA}.sh`,
  installerSha256: INSTALLER_SHA,
};

function env(overrides: Record<string, unknown> = {}): Env {
  return {
    APP_BASE_URL: "https://app.example",
    NONCE_STORE: undefined as unknown as Env["NONCE_STORE"],
    HOST_AGENT_MASTER_KEY: MASTER_KEY,
    ...overrides,
  } as unknown as Env;
}

afterEach(() => {
  vi.restoreAllMocks();
});

async function sha256Hex(text: string): Promise<string> {
  return hexEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}

describe("self-hosted twin block and registration", () => {
  it("is unchanged (pinned sha256: change every twin and every pin together)", async () => {
    const start = hostParamsSource.indexOf(TWIN_BLOCK_START_MARKER);
    const end = hostParamsSource.indexOf(TWIN_BLOCK_END_MARKER, start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    expect(await sha256Hex(hostParamsSource.slice(start, end))).toBe(TWIN_BLOCK_SHA256);
  });

  it("names exactly the eleven ops of planning/58, all allowlisted and registered", () => {
    expect([...HOST_SSH_OPS, ...HOST_AGENT_OPS]).toEqual([
      "host-ssh-check",
      "host-bootstrap",
      "host-repair",
      "host-network-ensure",
      "host-vm-create",
      "host-vm-get",
      "host-vm-list",
      "host-vm-delete",
      "host-vm-restart",
      "host-vm-snapshot",
      "host-vm-set-boot-script",
    ]);
    for (const op of [...HOST_SSH_OPS, ...HOST_AGENT_OPS]) {
      expect(DISPATCH_OPS).toContain(op);
      expect(typeof DISPATCH_OP_REGISTRY[op].validateParams).toBe("function");
      expect(typeof DISPATCH_OP_REGISTRY[op].actuate).toBe("function");
    }
  });
});

describe("self-hosted op params", () => {
  it("host-ssh-check accepts the five facts and refuses unknown or missing keys", () => {
    expect(validateHostSshCheckParams(SSH_TARGET)).toEqual({ ok: true, params: SSH_TARGET });
    expect(validateHostSshCheckParams({ ...SSH_TARGET, extra: 1 }).ok).toBe(false);
    const { user: _user, ...missingUser } = SSH_TARGET;
    expect(validateHostSshCheckParams(missingUser).ok).toBe(false);
  });

  it("host refuses private, loopback, link-local and CGNAT literals; accepts a public IPv4 or a DNS name", () => {
    for (const bad of ["10.0.0.5", "172.16.0.1", "172.31.255.255", "192.168.1.10", "127.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "Server.example", "server", "1.2.3", "01.2.3.4", "1.2.3.256"]) {
      expect(isSshHost(bad), bad).toBe(false);
      expect(validateHostSshCheckParams({ ...SSH_TARGET, host: bad }).ok, bad).toBe(false);
    }
    for (const good of ["203.0.113.7", "172.32.0.1", "100.128.0.1", "server.agency.example"]) {
      expect(isSshHost(good), good).toBe(true);
    }
  });

  it("refuses a bad port, user, keyIndex or fingerprint", () => {
    for (const patch of [
      { port: 0 },
      { port: 65536 },
      { port: "22" },
      { user: "Root" },
      { user: "a b" },
      { keyIndex: 0 },
      { keyIndex: 100 },
      { keyIndex: 1.5 },
      { hostKeyFingerprint: "MD5:aa:bb" },
      { hostKeyFingerprint: `${FINGERPRINT}=` },
    ]) {
      expect(validateHostSshCheckParams({ ...SSH_TARGET, ...patch }).ok, JSON.stringify(patch)).toBe(false);
    }
  });

  it("host-bootstrap ties networkName and hostAgentHost to the label and checks the pool, mode and installer", () => {
    expect(validateHostBootstrapParams(BOOTSTRAP)).toEqual({ ok: true, params: BOOTSTRAP });
    for (const patch of [
      { networkName: "dy-cell-other" },
      { hostAgentHost: "cell-other-host.agency.example" },
      { subnet: "10.20.3.0/24" },
      { subnet: "10.40.256.0/24" },
      { subnet: "10.40.03.0/24" },
      { sftpPort: 22 },
      { mode: "run" },
      { tunnelId: "not-a-tunnel" },
      { cellId: "Short" },
      { label: "Office" },
      { installerUrl: "http://bundles.example/x.sh" },
      { installerUrl: "https://bundles.example/x.sh?y=1" },
      { installerUrl: "https://bundles.example/../x.sh" },
      { installerUrl: "https://bundles.example/x'.sh" },
      { installerSha256: "A".repeat(64) },
    ]) {
      expect(validateHostBootstrapParams({ ...BOOTSTRAP, ...patch }).ok, JSON.stringify(patch)).toBe(false);
    }
  });

  it("host-network-ensure and host-vm-list take only their own keys", () => {
    const network = { cellId: CELL_ID, hostAgentUrl: HOST_AGENT_URL, desired: "present", networkName: "dy-cell-office", subnet: "10.40.3.0/24", sftpPort: 2222 };
    expect(validateHostNetworkEnsureParams(network)).toEqual({ ok: true, params: network });
    expect(validateHostNetworkEnsureParams({ ...network, desired: "gone" }).ok).toBe(false);
    expect(validateHostNetworkEnsureParams({ ...network, hostAgentUrl: `${HOST_AGENT_URL}/path` }).ok).toBe(false);
    expect(validateHostNetworkEnsureParams({ ...network, hostAgentUrl: "https://cell-office-host.agency.example:8443" }).ok).toBe(false);
    expect(validateHostVmListParams({ cellId: CELL_ID, hostAgentUrl: HOST_AGENT_URL })).toEqual({ ok: true, params: { cellId: CELL_ID, hostAgentUrl: HOST_AGENT_URL } });
    expect(validateHostVmListParams({ cellId: CELL_ID, hostAgentUrl: HOST_AGENT_URL, project: "x" }).ok).toBe(false);
  });

  it("host-vm-create checks role, size, ip, disks and the image", () => {
    const create = { cellId: CELL_ID, hostAgentUrl: HOST_AGENT_URL, name: "dy-file-office-1", role: "file", size: "dy-m", ip: "10.40.3.3", bootDiskGb: 20, image: "debian-12", dataDiskGb: 50 };
    expect(validateHostVmCreateParams(create)).toEqual({ ok: true, params: create });
    for (const patch of [
      { role: "router" },
      { size: "e2-medium" },
      { ip: "10.40.3.1" },
      { ip: "10.40.3.255" },
      { ip: "10.40.3.0" },
      { ip: "192.168.1.3" },
      { bootDiskGb: 9 },
      { bootDiskGb: 501 },
      { image: "https://evil.example/image.qcow2" },
      { role: "web", dataDiskGb: 50 },
      { startupScript: "" },
    ]) {
      expect(validateHostVmCreateParams({ ...create, ...patch }).ok, JSON.stringify(patch)).toBe(false);
    }
  });

  it("host-vm-snapshot and host-vm-set-boot-script validate names, keys and sizes", () => {
    expect(validateHostVmSnapshotParams({ cellId: CELL_ID, hostAgentUrl: HOST_AGENT_URL, name: "dy-web-office-1", snapshotName: "pre-update-1" }).ok).toBe(true);
    expect(validateHostVmSnapshotParams({ cellId: CELL_ID, hostAgentUrl: HOST_AGENT_URL, name: "dy-web-office-1", snapshotName: "Pre" }).ok).toBe(false);
    const base = { cellId: CELL_ID, hostAgentUrl: HOST_AGENT_URL, name: "dy-web-office-1" };
    expect(validateHostVmSetBootScriptParams({ ...base, items: [{ key: "startup-script", value: "#!/bin/sh\n" }, { key: "dy-update-hold", value: "1" }], expectedFingerprint: "abc=" }).ok).toBe(true);
    expect(validateHostVmSetBootScriptParams({ ...base, items: [{ key: "ssh-keys", value: "x" }] }).ok).toBe(false);
    expect(validateHostVmSetBootScriptParams({ ...base, items: [{ key: "startup-script", value: "a" }, { key: "startup-script", value: "b" }] }).ok).toBe(false);
    expect(validateHostVmSetBootScriptParams({ ...base, items: [] }).ok).toBe(false);
    expect(validateHostVmSetBootScriptParams({ ...base, items: [{ key: "startup-script", value: "x".repeat(256 * 1024 + 1) }] }).ok).toBe(false);
    expect(validateHostVmSetBootScriptParams({ ...base, items: [{ key: "startup-script", value: "x", extra: 1 }] }).ok).toBe(false);
  });
});

describe("host-ssh-check refusals before any connection", () => {
  it("refuses an unpinned host key, a job that differs from the pin, and a missing key", async () => {
    const unpinned = await actuateHostSshCheck(SSH_TARGET, env({ SELF_HOSTED_1_SSH_KEY: "x" }));
    expect(unpinned).toMatchObject({ ok: false, code: "host-key-not-pinned" });
    const differs = await actuateHostSshCheck(SSH_TARGET, env({ SELF_HOSTED_1_HOST_KEY: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" }));
    expect(differs).toMatchObject({ ok: false, code: "host-key-mismatch" });
    const noKey = await actuateHostSshCheck(SSH_TARGET, env({ SELF_HOSTED_1_HOST_KEY: FINGERPRINT }));
    expect(noKey).toMatchObject({ ok: false, code: "ssh-key-missing" });
    const encrypted = await actuateHostSshCheck(SSH_TARGET, env({ SELF_HOSTED_1_HOST_KEY: FINGERPRINT, SELF_HOSTED_1_SSH_KEY: "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----" }));
    expect(encrypted).toMatchObject({ ok: false, code: "ssh-key-missing" });
    expect(JSON.stringify(encrypted)).not.toContain("abc");
  });

  it("the preflight floor names each problem", () => {
    const base = { os: "ubuntu", osVersion: "24.04", arch: "x86_64", cpuCount: 8, memoryMiB: 16384, diskFreeGiB: 200, virtualization: "kvm" as const, isRoot: false, canSudo: true };
    expect(preflightProblems(base)).toEqual([]);
    expect(preflightProblems({ ...base, os: "centos" })).toHaveLength(1);
    expect(preflightProblems({ ...base, virtualization: "none" })).toEqual(["KVM is not available (/dev/kvm is missing)"]);
    expect(preflightProblems({ ...base, memoryMiB: 1024, cpuCount: 1, diskFreeGiB: 5 })).toHaveLength(3);
    expect(preflightProblems({ ...base, canSudo: false })).toEqual(["the login is not root and cannot run sudo without a password"]);
  });

  it("the install stub has no single quote, so it fits one quoted argument with no job value in it", () => {
    expect(HOST_INSTALL_STUB).not.toContain("'");
  });
});

describe("host-agent sealed requests", () => {
  it("the token is HKDF-SHA256(master key, salt + cellId), 32 bytes, distinct per cell", async () => {
    const tokenA = await deriveHostAgentToken(MASTER_KEY, CELL_ID);
    const tokenB = await deriveHostAgentToken(MASTER_KEY, "clh476othercell0000000001");
    expect(tokenA).toHaveLength(32);
    expect(hexEncode(tokenA)).not.toBe(hexEncode(tokenB));
    // Recompute with an independent HKDF call to pin the parameters.
    const ikm = await crypto.subtle.importKey("raw", new TextEncoder().encode(MASTER_KEY), "HKDF", false, ["deriveBits"]);
    const expected = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode(`doubleyoup-host-agent/v1\n${CELL_ID}`), info: new TextEncoder().encode("host-agent-token") },
      ikm,
      256,
    );
    expect(hexEncode(tokenA)).toBe(hexEncode(new Uint8Array(expected)));
  });

  /** A fake host-agent: opens the request with the cell's token and seals `answer` back. */
  function fakeHostAgent(answer: (op: string, body: Record<string, unknown>) => Record<string, unknown>, seen: Array<{ url: string; body: Record<string, unknown>; raw: string }>) {
    return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      const headers = new Headers(init?.headers);
      const cellId = headers.get("x-dy-cell") ?? "";
      const time = headers.get("x-dy-time") ?? "";
      const nonce = headers.get("x-dy-nonce") ?? "";
      const op = url.slice(url.lastIndexOf("/") + 1);
      const key = await crypto.subtle.importKey("raw", await deriveHostAgentToken(MASTER_KEY, cellId), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
      const raw = String(init?.body);
      const opened = await openHostAgentBody(key, raw, hostAgentRequestAad(op, cellId, time, nonce));
      if (opened === null) {
        return new Response("", { status: 401 });
      }
      const body = JSON.parse(new TextDecoder().decode(opened)) as Record<string, unknown>;
      seen.push({ url, body, raw });
      const sealed = await sealHostAgentBody(key, new TextEncoder().encode(JSON.stringify(answer(op, body))), hostAgentAnswerAad(op, cellId, nonce));
      return new Response(sealed, { status: 200 });
    });
  }

  it("seals the request, never sends the token, and opens the sealed answer", async () => {
    const seen: Array<{ url: string; body: Record<string, unknown>; raw: string }> = [];
    fakeHostAgent((op) => ({ ok: true, op, vms: [{ name: "dy-web-office-1", role: "web", state: "running", ip: "10.40.3.10" }] }), seen);
    const result = await callHostAgent("host-vm-list", CELL_ID, HOST_AGENT_URL, { cellId: CELL_ID }, env());
    expect(result).toMatchObject({ ok: true, op: "host-vm-list", vms: [{ name: "dy-web-office-1" }] });
    expect(seen[0].url).toBe(`${HOST_AGENT_URL}/v1/host-vm-list`);
    const token = hexEncode(await deriveHostAgentToken(MASTER_KEY, CELL_ID));
    expect(seen[0].raw).not.toContain(token);
    expect(seen[0].raw).not.toContain(CELL_ID);
  });

  it("refuses an answer that is not sealed with the cell's token (a fake host cannot fake a success)", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ ok: true, op: "host-vm-delete", state: "deleted" }), { status: 200 }));
    const result = await callHostAgent("host-vm-delete", CELL_ID, HOST_AGENT_URL, { cellId: CELL_ID, name: "dy-web-office-1" }, env());
    expect(result).toMatchObject({ ok: false, code: "host-agent-unverified" });
  });

  it("maps 401 and 404 and an unreachable host to clear codes", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response("", { status: 401 }));
    expect(await callHostAgent("host-vm-list", CELL_ID, HOST_AGENT_URL, {}, env())).toMatchObject({ ok: false, code: "host-agent-unauthorized" });
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response("", { status: 404 }));
    expect(await callHostAgent("host-vm-list", CELL_ID, HOST_AGENT_URL, {}, env())).toMatchObject({ ok: false, code: "host-agent-cell-unknown" });
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("connection refused"));
    expect(await callHostAgent("host-vm-list", CELL_ID, HOST_AGENT_URL, {}, env())).toMatchObject({ ok: false, code: "host-agent-unreachable" });
  });

  it("refuses without HOST_AGENT_MASTER_KEY and calls nothing", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const result = await callHostAgent("host-vm-list", CELL_ID, HOST_AGENT_URL, {}, env({ HOST_AGENT_MASTER_KEY: undefined }));
    expect(result).toMatchObject({ ok: false, code: "host-agent-key-missing" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("substitutes the object-store placeholders in a startup script, and refuses an unknown one", async () => {
    const seen: Array<{ url: string; body: Record<string, unknown>; raw: string }> = [];
    fakeHostAgent((op, body) => ({ ok: true, op, name: body.name, created: true }), seen);
    const objectStore = { S3_ACCESS_KEY_ID: "AKIAEXAMPLE", S3_SECRET_ACCESS_KEY: "secret-value", S3_REGION: "auto", S3_BUCKET: "backups", S3_ENDPOINT: "https://s3.example" };
    const created = await actuateHostVmCreate(
      { cellId: CELL_ID, hostAgentUrl: HOST_AGENT_URL, name: "dy-file-office-1", role: "file", size: "dy-m", ip: "10.40.3.3", bootDiskGb: 20, image: "debian-12", startupScript: "key=@@DY_T2_S3_ACCESS_KEY_ID@@\n" },
      env(objectStore),
    );
    expect(created).toMatchObject({ ok: true, created: true });
    expect(seen[0].body.startupScript).toBe("key=AKIAEXAMPLE\n");
    expect(seen[0].body.hostAgentUrl).toBeUndefined();

    const refused = await actuateHostVmSetBootScript({ cellId: CELL_ID, hostAgentUrl: HOST_AGENT_URL, name: "dy-file-office-1", items: [{ key: "startup-script", value: "@@DY_OTHER@@" }] }, env(objectStore));
    expect(refused).toMatchObject({ ok: false, code: "boot-script-refused" });
    expect(seen).toHaveLength(1);
  });

  it("every host-agent op dispatches through the registry to /v1/<op>", async () => {
    const seen: Array<{ url: string; body: Record<string, unknown>; raw: string }> = [];
    fakeHostAgent((op) => ({ ok: true, op }), seen);
    const base = { cellId: CELL_ID, hostAgentUrl: HOST_AGENT_URL };
    const paramsByOp: Record<string, Record<string, unknown>> = {
      "host-network-ensure": { ...base, desired: "present", networkName: "dy-cell-office", subnet: "10.40.3.0/24", sftpPort: 2222 },
      "host-vm-create": { ...base, name: "dy-web-office-1", role: "web", size: "dy-m", ip: "10.40.3.10", bootDiskGb: 20, image: "debian-12" },
      "host-vm-get": { ...base, name: "dy-web-office-1" },
      "host-vm-list": { ...base },
      "host-vm-delete": { ...base, name: "dy-web-office-1" },
      "host-vm-restart": { ...base, name: "dy-web-office-1" },
      "host-vm-snapshot": { ...base, name: "dy-web-office-1", snapshotName: "snap-1" },
      "host-vm-set-boot-script": { ...base, name: "dy-web-office-1", items: [{ key: "dy-update-hold", value: "1" }] },
    };
    for (const op of HOST_AGENT_OPS) {
      const entry = DISPATCH_OP_REGISTRY[op];
      const verdict = entry.validateParams(paramsByOp[op]);
      expect(verdict.ok, op).toBe(true);
      if (!verdict.ok) {
        continue;
      }
      expect(await entry.actuate(verdict.params, env()), op).toMatchObject({ ok: true, op });
    }
    expect(seen.map((call) => call.url)).toEqual(HOST_AGENT_OPS.map((op) => `${HOST_AGENT_URL}/v1/${op}`));
  });
});

describe("/enroll-host", () => {
  const FACTS = { cellId: CELL_ID, label: "office", subnet: "10.40.3.0/24", networkName: "dy-cell-office", sftpPort: 2222, hostAgentHost: "cell-office-host.agency.example", tunnelId: TUNNEL_ID };
  const BLOB = `dyenrol2.${btoa(JSON.stringify(FACTS)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
  const CODE = "c".repeat(64);
  const CONNECTOR_TOKEN = btoa(JSON.stringify({ a: "acct", t: TUNNEL_ID, s: "c2VjcmV0" }));
  const PIN = { HOST_INSTALLER_ORIGIN: "https://bundles.example", HOST_INSTALLER_SHA256S: `${"b".repeat(64)},${INSTALLER_SHA}` };

  function memoryStore() {
    const used = new Set<string>();
    return {
      used,
      binding: {
        idFromName: (name: string) => name,
        get: (id: string) => ({
          consume: async (nonce: string) => {
            const key = `${id}/${nonce}`;
            if (used.has(key)) {
              return "replay" as const;
            }
            used.add(key);
            return "fresh" as const;
          },
        }),
      } as unknown as Env["NONCE_STORE"],
    };
  }

  function mockTunnelToken() {
    return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("/accounts?per_page=1")) {
        return Response.json({ success: true, result: [{ id: "acct" }] });
      }
      if (url.endsWith(`/cfd_tunnel/${TUNNEL_ID}/token`)) {
        return Response.json({ success: true, result: CONNECTOR_TOKEN });
      }
      return new Response("", { status: 404 });
    });
  }

  function post(body: unknown, environment: Env) {
    return worker.fetch(new Request("https://agency-worker.example/enroll-host", { method: "POST", body: JSON.stringify(body) }), environment);
  }

  it("GET renders the command from the Worker's own pin and origin only", async () => {
    const response = await worker.fetch(new Request("https://agency-worker.example/enroll-host"), env(PIN));
    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain(`https://bundles.example/self-hosted/host-install-${INSTALLER_SHA}.sh`);
    expect(html).toContain("https://agency-worker.example/enroll-host");
    expect(html).not.toContain("b".repeat(64));
    expect(manualEnrolCommand(`https://bundles.example/self-hosted/host-install-${INSTALLER_SHA}.sh`, INSTALLER_SHA, "https://w.example/enroll-host")).toContain(`[ "$s" = '${INSTALLER_SHA}' ]`);
  });

  it("GET shows no command when the installer is not pinned", async () => {
    const html = await (await worker.fetch(new Request("https://agency-worker.example/enroll-host"), env())).text();
    expect(html).toContain("No command yet");
    expect(html).not.toContain("curl");
  });

  it("POST returns the bootstrap material once, then refuses the same code", async () => {
    mockTunnelToken();
    const store = memoryStore();
    const environment = env({ ...PIN, HOST_ENROLL_CODE: CODE, CF_DNS_API_TOKEN: "cf", NONCE_STORE: store.binding });
    const first = await post({ enrolCode: CODE, enrolFacts: BLOB }, environment);
    expect(first.status).toBe(200);
    const body = (await first.json()) as { ok: boolean; job: Record<string, unknown> };
    expect(body.job).toMatchObject({
      ...FACTS,
      op: "host-enroll",
      mode: "start",
      installerSha256: INSTALLER_SHA,
      hostAgentToken: hexEncode(await deriveHostAgentToken(MASTER_KEY, CELL_ID)),
      tunnelToken: CONNECTOR_TOKEN,
    });
    const second = await post({ enrolCode: CODE, enrolFacts: BLOB }, environment);
    expect(second.status).toBe(409);
    expect(await second.json()).toMatchObject({ code: "enroll-code-used" });
  });

  it("POST refuses a wrong code, an unset code, and bad facts, returning nothing", async () => {
    const fetchSpy = mockTunnelToken();
    const store = memoryStore();
    const environment = env({ ...PIN, HOST_ENROLL_CODE: CODE, CF_DNS_API_TOKEN: "cf", NONCE_STORE: store.binding });
    const wrong = await post({ enrolCode: "d".repeat(64), enrolFacts: BLOB }, environment);
    expect(wrong.status).toBe(401);
    expect(await wrong.text()).not.toContain("hostAgentToken");
    const unset = await post({ enrolCode: CODE, enrolFacts: BLOB }, env({ ...PIN, NONCE_STORE: store.binding }));
    expect(unset.status).toBe(503);
    const badFacts = await post({ enrolCode: CODE, enrolFacts: "dyenrol2.e30" }, environment);
    expect(badFacts.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(store.used.size).toBe(0);
  });

  it("POST does not burn the code when the tunnel is not the agency's own", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      if (String(input).includes("/accounts?per_page=1")) {
        return Response.json({ success: true, result: [{ id: "acct" }] });
      }
      return Response.json({ success: false, errors: [{ message: "tunnel not found" }] }, { status: 404 });
    });
    const store = memoryStore();
    const response = await post({ enrolCode: CODE, enrolFacts: BLOB }, env({ ...PIN, HOST_ENROLL_CODE: CODE, CF_DNS_API_TOKEN: "cf", NONCE_STORE: store.binding }));
    expect(response.status).toBe(502);
    expect(store.used.size).toBe(0);
  });

  it("decodeEnrolFacts refuses unknown fields and a wrong prefix", () => {
    expect(decodeEnrolFacts(BLOB)).toEqual({ ok: true, facts: FACTS });
    expect(decodeEnrolFacts(`dyenrol1.${BLOB.slice(9)}`).ok).toBe(false);
    const extra = `dyenrol2.${btoa(JSON.stringify({ ...FACTS, hostAgentToken: "x" })).replace(/=+$/, "")}`;
    expect(decodeEnrolFacts(extra).ok).toBe(false);
  });
});
