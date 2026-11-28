// hub#618 — the manual enrol path against the PUBLISHED installer's own request and its own reading of the answer.
//
// test/fixtures/host-install-enroll.py is the enrol python of `enroll_and_build_params`, copied byte for byte from
// infra self-hosted/host-install.sh at 987e808 (lines 934-977). It runs under python3 with ONLY urllib.request.urlopen
// stubbed (test/fixtures/run-installer-enroll.py); the stub sends the request to a local HTTP server that hands it to
// the real Worker handler (worker.fetch). What the python prints is what the installer would install from.
// The python3 test is skipped where python3 is missing; the exact-body test below always runs.

import { describe, it, expect, vi, afterEach } from "vitest";
import worker from "../src/index.js";
import type { Env } from "../src/env.js";
import { deriveHostAgentToken } from "../src/actuate-host.js";
import { hexEncode } from "../src/ssh-wire.js";
import { hasPython3, runInstallerEnrol } from "./fixtures/run-installer-enroll.mjs";

const WORKER_ORIGIN = "https://agency-worker.example";
const CELL_ID = "clh618testcell000000000001";
const TUNNEL_ID = "0123456789abcdef0123456789abcdef";
const MASTER_KEY = "test-master-key-0123456789abcdef0123456789";
const INSTALLER_SHA = "a".repeat(64);
const CODE = "c".repeat(64);
const CONNECTOR_TOKEN = btoa(JSON.stringify({ a: "acct", t: TUNNEL_ID, s: "c2VjcmV0" }));
const FACTS = {
  cellId: CELL_ID,
  label: "office",
  subnet: "10.40.3.0/24",
  networkName: "dy-cell-office",
  sftpPort: 2222,
  hostAgentHost: "cell-office-host.agency.example",
  tunnelId: TUNNEL_ID,
};

function encodeFactsBlob(facts: unknown): string {
  const base64url = btoa(JSON.stringify(facts)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `dyenrol2.${base64url}`;
}

function memoryStore() {
  const used = new Set<string>();
  const binding = {
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
  } as unknown as Env["NONCE_STORE"];
  return { used, binding };
}

function workerEnv(store: ReturnType<typeof memoryStore>): Env {
  return {
    APP_BASE_URL: "https://app.example",
    NONCE_STORE: store.binding,
    HOST_AGENT_MASTER_KEY: MASTER_KEY,
    HOST_ENROLL_CODE: CODE,
    CF_DNS_API_TOKEN: "cf",
    HOST_INSTALLER_ORIGIN: "https://bundles.example",
    HOST_INSTALLER_SHA256S: INSTALLER_SHA,
  } as unknown as Env;
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

afterEach(() => {
  vi.restoreAllMocks();
});

describe("the published installer's enrol step against the real Worker handler", () => {
  it.skipIf(!hasPython3())("the installer's python gets the install params and both tokens", async () => {
    mockTunnelToken();
    const store = memoryStore();
    const environment = workerEnv(store);
    const handler = (request: Request) => worker.fetch(request, environment);
    const result = await runInstallerEnrol({ origin: WORKER_ORIGIN, handler, factsBlob: encodeFactsBlob(FACTS), code: CODE });
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    const params = JSON.parse(result.stdout);
    expect(params).toEqual({
      ...FACTS,
      op: "host-enroll",
      mode: "start",
      installerUrl: `https://bundles.example/self-hosted/host-install-${INSTALLER_SHA}.sh`,
      installerSha256: INSTALLER_SHA,
      hostAgentToken: hexEncode(await deriveHostAgentToken(MASTER_KEY, CELL_ID)),
      tunnelToken: CONNECTOR_TOKEN,
    });
    expect(params.hostAgentToken).toMatch(/^[0-9a-f]{64}$/);
    expect(store.used.size).toBe(1);
  });

  it.skipIf(!hasPython3())("the installer's python stops with the Worker's refusal on a wrong code", async () => {
    mockTunnelToken();
    const store = memoryStore();
    const environment = workerEnv(store);
    const handler = (request: Request) => worker.fetch(request, environment);
    const result = await runInstallerEnrol({ origin: WORKER_ORIGIN, handler, factsBlob: encodeFactsBlob(FACTS), code: "d".repeat(64) });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("HTTP 401");
    expect(result.stderr).toContain("enroll-code-wrong");
    expect(result.stdout).toBe("");
    expect(store.used.size).toBe(0);
  });

  it("accepts the exact body bytes the installer builds, and answers the way lines 970-976 read it", async () => {
    mockTunnelToken();
    const store = memoryStore();
    // json.dumps({"facts": facts, "code": code}) with Python's default separators (", " and ": ").
    const factsText = Object.entries(FACTS)
      .map(([key, value]) => `${JSON.stringify(key)}: ${JSON.stringify(value)}`)
      .join(", ");
    const exactBody = `{"facts": {${factsText}}, "code": ${JSON.stringify(CODE)}}`;
    const response = await worker.fetch(
      new Request(`${WORKER_ORIGIN}/enroll-host`, { method: "POST", headers: { "Content-Type": "application/json" }, body: exactBody }),
      workerEnv(store),
    );
    expect(response.status).toBe(200);
    const material = (await response.json()) as Record<string, unknown>;
    // params = material.get("params"), must be a dict; the tokens are read from the top level of material.
    expect(typeof material.params).toBe("object");
    expect(material.params).not.toBeNull();
    expect(Array.isArray(material.params)).toBe(false);
    const installParams = {
      ...(material.params as Record<string, unknown>),
      hostAgentToken: material.hostAgentToken,
      tunnelToken: material.tunnelToken,
      mode: "start",
    };
    expect(installParams).toMatchObject({
      ...FACTS,
      mode: "start",
      hostAgentToken: hexEncode(await deriveHostAgentToken(MASTER_KEY, CELL_ID)),
      tunnelToken: CONNECTOR_TOKEN,
    });
  });
});
