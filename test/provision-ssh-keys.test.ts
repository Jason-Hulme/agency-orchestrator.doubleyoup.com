// agency-orchestrator#22 — provision-ssh-keys reaches the gateway of the site's OWN cell and keeps the
// generation fence end to end.
//
// What these request-capture tests pin, through the real POST /actuate route (signature, nonce, validator,
// actuator), with fetch captured:
//   - two cells under one agency: each key push goes to the gateway agent its signed job names, with that
//     job's token; wp-cli keeps going to the web node's CELL_AGENT_URL with CELL_AGENT_TOKEN;
//   - no web-target fallback: a job without the gateway pair is refused with no call at all;
//   - generation is relayed to the gateway, and ok:true needs an echo equal to the push and a count equal
//     to the set; a missing, different or malformed echo is ok:false; `superseded` passes through;
//   - empty sets (revocation), old replies (no echo), redirects, oversized replies, gateway errors;
//   - the token never appears in the gateway request body, in a detail or in the Worker's answer;
//   - a job signed with another agency's key, or naming a URL outside the grammar, is refused.

import { describe, it, expect, vi, afterEach, beforeAll } from "vitest";
import type { Env } from "../src/env.js";
import worker from "../src/index.js";
import { canonicalizeDispatchJob, type DispatchJob } from "../src/dispatch-verify.js";
import { validateProvisionSshKeysParams } from "../src/dispatch-params.js";

// ── keys and signing (as app signs: ed25519 over the canonical job bytes, base64) ─────────────────

interface Keypair {
  publicKeyPem: string;
  privateKey: CryptoKey;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function makeKeypair(): Promise<Keypair> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer);
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${bytesToBase64(spki)}\n-----END PUBLIC KEY-----\n`;
  return { publicKeyPem, privateKey: pair.privateKey };
}

async function signJob(job: DispatchJob, privateKey: CryptoKey): Promise<string> {
  const canonical = new TextEncoder().encode(canonicalizeDispatchJob(job));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, canonical));
  return bytesToBase64(signature);
}

// ── fixtures: one agency, two cells ─────────────────────────────────────────────────────────────

const ACCOUNT_ID = "acct_agency_1";
const WEB_AGENT_URL = "https://cell-region-a.agency.example";
const WEB_AGENT_TOKEN = "web-agent-token-must-not-reach-a-gateway";

const CELL_A_GATEWAY_URL = "https://cell-region-a-gw.agency.example";
const CELL_A_GATEWAY_TOKEN = "a".repeat(64);
const CELL_B_GATEWAY_URL = "https://cell-region-b-gw.agency.example";
const CELL_B_GATEWAY_TOKEN = "b".repeat(64);

const KEY_ONE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample000000000000000000000000000000000 dev@laptop";
const KEY_TWO = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample111111111111111111111111111111111 ops@desk";

const FREEZE_MS = Date.parse("2026-11-23T00:00:00.000Z");

let agencyKeys: Keypair;
let otherAgencyKeys: Keypair;
let nonceCounter = 0;

beforeAll(async () => {
  agencyKeys = await makeKeypair();
  otherAgencyKeys = await makeKeypair();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

// Every nonce is fresh: replay defence has its own tests (test/nonce-store.worker.test.ts).
const freshNonceStore = {
  idFromName: () => ({}),
  get: () => ({ consume: async () => "fresh" as const }),
} as unknown as Env["NONCE_STORE"];

function agencyEnv(overrides: Partial<Env> = {}): Env {
  return {
    APP_BASE_URL: "https://app.example.test",
    DY_CLIENT_ID: "client-abc",
    DY_CLIENT_SECRET: "secret-xyz",
    DY_SIGNING_PUBLIC_KEY: agencyKeys.publicKeyPem,
    CELL_AGENT_URL: WEB_AGENT_URL,
    CELL_AGENT_TOKEN: WEB_AGENT_TOKEN,
    NONCE_STORE: freshNonceStore,
    ...overrides,
  };
}

function nextNonce(): string {
  nonceCounter += 1;
  return nonceCounter.toString(16).padStart(32, "0");
}

function sshKeysParams(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    project: "agency-project-1",
    slug: "acme",
    authorizedKeys: [KEY_ONE],
    generation: 42,
    uid: 200123,
    gatewayAgentUrl: CELL_A_GATEWAY_URL,
    gatewayAgentToken: CELL_A_GATEWAY_TOKEN,
    ...overrides,
  };
}

function withoutKeys(params: Record<string, unknown>, keys: string[]): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...params };
  for (const key of keys) {
    delete copy[key];
  }
  return copy;
}

async function actuate(op: string, params: Record<string, unknown>, options: { signer?: Keypair; env?: Env } = {}): Promise<Response> {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date(FREEZE_MS));
  const job: DispatchJob = {
    op: op as DispatchJob["op"],
    params: JSON.stringify(params),
    accountId: ACCOUNT_ID,
    timestamp: new Date(FREEZE_MS).toISOString(),
    nonce: nextNonce(),
  };
  const signer = options.signer ?? agencyKeys;
  const signature = await signJob(job, signer.privateKey);
  const request = new Request("http://localhost/actuate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ job, signature }),
  });
  return worker.fetch(request, options.env ?? agencyEnv());
}

// ── request capture ─────────────────────────────────────────────────────────────────────────────

interface CapturedRequest {
  url: string;
  method: string;
  auth: string | null;
  redirect: string | undefined;
  rawBody: string;
  body: Record<string, unknown>;
}

type Reply = Response | (() => Response);

function captureFetch(replyFor: (request: CapturedRequest) => Reply): CapturedRequest[] {
  const captured: CapturedRequest[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    let url: string;
    if (typeof input === "string") {
      url = input;
    } else if (input instanceof URL) {
      url = input.toString();
    } else {
      url = input.url;
    }
    const rawBody = typeof init?.body === "string" ? init.body : "";
    let body: Record<string, unknown> = {};
    if (rawBody !== "") {
      body = JSON.parse(rawBody) as Record<string, unknown>;
    }
    const request: CapturedRequest = {
      url,
      method: init?.method ?? "GET",
      auth: new Headers(init?.headers).get("authorization"),
      redirect: init?.redirect,
      rawBody,
      body,
    };
    captured.push(request);
    const reply = replyFor(request);
    if (typeof reply === "function") {
      return reply();
    }
    return reply;
  });
  return captured;
}

function jsonReply(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** A gateway that writes what it is sent and echoes the push number, as infra's agent.php does. */
function confirmingGateway(request: CapturedRequest): Response {
  const keys = request.body.authorizedKeys as unknown[];
  return jsonReply({ ok: true, slug: request.body.slug, count: keys.length, generation: request.body.generation });
}

interface WorkerResult {
  ok: boolean;
  op: string;
  slug?: string;
  count?: number;
  generation?: number;
  superseded?: boolean;
  detail?: string;
}

async function resultOf(response: Response): Promise<WorkerResult> {
  expect(response.status).toBe(200);
  return (await response.json()) as WorkerResult;
}

// ── routing: two cells under one agency ─────────────────────────────────────────────────────────

describe("provision-ssh-keys routing (two cells, one agency)", () => {
  it("sends each site's keys to the gateway its job names, with that job's token, and wp-cli to the web node", async () => {
    const captured = captureFetch((request) => {
      if (request.url.endsWith("/provision-ssh-keys")) {
        return confirmingGateway(request);
      }
      if (request.url.endsWith("/exec")) {
        return jsonReply({ code: 0, stdout: "https://acme.example\n", stderr: "" });
      }
      throw new Error(`unexpected fetch ${request.url}`);
    });

    const onCellA = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));
    const onCellB = await resultOf(
      await actuate(
        "provision-ssh-keys",
        sshKeysParams({ slug: "beta", generation: 43, uid: 200456, gatewayAgentUrl: CELL_B_GATEWAY_URL, gatewayAgentToken: CELL_B_GATEWAY_TOKEN }),
      ),
    );
    const webOp = await resultOf(await actuate("wp-cli", { docroot: "/sites/acme/public", args: ["option", "get", "siteurl"] }));

    expect(onCellA).toEqual({ ok: true, op: "provision-ssh-keys", slug: "acme", count: 1, generation: 42 });
    expect(onCellB).toEqual({ ok: true, op: "provision-ssh-keys", slug: "beta", count: 1, generation: 43 });
    expect(webOp.ok).toBe(true);

    expect(captured.map((request) => request.url)).toEqual([
      `${CELL_A_GATEWAY_URL}/provision-ssh-keys`,
      `${CELL_B_GATEWAY_URL}/provision-ssh-keys`,
      `${WEB_AGENT_URL}/exec`,
    ]);
    expect(captured.map((request) => request.auth)).toEqual([
      `Bearer ${CELL_A_GATEWAY_TOKEN}`,
      `Bearer ${CELL_B_GATEWAY_TOKEN}`,
      `Bearer ${WEB_AGENT_TOKEN}`,
    ]);
    for (const request of captured) {
      expect(request.method).toBe("POST");
      expect(request.redirect).toBe("manual");
    }
  });

  it("relays exactly {slug, authorizedKeys, generation, uid}: no project, no gateway URL or token in the body", async () => {
    const captured = captureFetch(confirmingGateway);
    await actuate("provision-ssh-keys", sshKeysParams({ authorizedKeys: [KEY_ONE, KEY_TWO] }));

    expect(captured).toHaveLength(1);
    expect(captured[0].body).toEqual({ slug: "acme", authorizedKeys: [KEY_ONE, KEY_TWO], generation: 42, uid: 200123 });
    expect(captured[0].rawBody).not.toContain(CELL_A_GATEWAY_TOKEN);
  });

  it("leaves uid out of the gateway body when the job carries none", async () => {
    const captured = captureFetch(confirmingGateway);
    const result = await resultOf(await actuate("provision-ssh-keys", withoutKeys(sshKeysParams(), ["uid"])));

    expect(result.ok).toBe(true);
    expect(captured[0].body).toEqual({ slug: "acme", authorizedKeys: [KEY_ONE], generation: 42 });
  });

  it("refuses a job without the gateway pair with NO call, even though CELL_AGENT_URL / TOKEN are set (no web fallback)", async () => {
    const captured = captureFetch(confirmingGateway);
    const result = await resultOf(await actuate("provision-ssh-keys", withoutKeys(sshKeysParams(), ["gatewayAgentUrl", "gatewayAgentToken"])));

    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/names no gateway cell-agent/);
    expect(captured).toHaveLength(0);
  });

  it("refuses a job without the gateway pair with NO call when the Worker has no cell-agent secrets at all", async () => {
    const captured = captureFetch(confirmingGateway);
    const env = agencyEnv({ CELL_AGENT_URL: undefined, CELL_AGENT_TOKEN: undefined });
    const result = await resultOf(await actuate("provision-ssh-keys", withoutKeys(sshKeysParams(), ["gatewayAgentUrl", "gatewayAgentToken"]), { env }));

    expect(result.ok).toBe(false);
    expect(captured).toHaveLength(0);
  });

  it("does not need CELL_AGENT_URL / TOKEN when the job names the gateway", async () => {
    const captured = captureFetch(confirmingGateway);
    const env = agencyEnv({ CELL_AGENT_URL: undefined, CELL_AGENT_TOKEN: undefined });
    const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams(), { env }));

    expect(result.ok).toBe(true);
    expect(captured[0].url).toBe(`${CELL_A_GATEWAY_URL}/provision-ssh-keys`);
  });
});

// ── cross-agency and target grammar ─────────────────────────────────────────────────────────────

describe("provision-ssh-keys target checks", () => {
  it("refuses a job signed with another agency's key (401) and calls nothing", async () => {
    const captured = captureFetch(confirmingGateway);
    const response = await actuate("provision-ssh-keys", sshKeysParams(), { signer: otherAgencyKeys });

    expect(response.status).toBe(401);
    expect(captured).toHaveLength(0);
  });

  it("refuses a gateway URL outside https://<lowercase host> (400, no call), and never echoes the token", async () => {
    const badUrls = [
      "http://cell-region-a-gw.agency.example",
      "https://cell-region-a-gw.agency.example/",
      "https://cell-region-a-gw.agency.example/provision-ssh-keys",
      "https://cell-region-a-gw.agency.example:8443",
      "https://user@cell-region-a-gw.agency.example",
      "https://Cell-Region-A-GW.agency.example",
      "https://10.0.0.5",
      "https://cell-region-a-gw.agency.example?x=1",
      "https://localhost",
    ];
    for (const gatewayAgentUrl of badUrls) {
      const captured = captureFetch(confirmingGateway);
      const response = await actuate("provision-ssh-keys", sshKeysParams({ gatewayAgentUrl }));
      expect(response.status, gatewayAgentUrl).toBe(400);
      const text = await response.text();
      expect(text).toMatch(/gatewayAgentUrl must be exactly https:\/\/<lowercase DNS host>/);
      expect(text).not.toContain(CELL_A_GATEWAY_TOKEN);
      expect(captured).toHaveLength(0);
      vi.restoreAllMocks();
    }
  });

  it("refuses half a pair and a token outside 64 lowercase hex, naming the rule and never the value", () => {
    const urlOnly = validateProvisionSshKeysParams(withoutKeys(sshKeysParams(), ["gatewayAgentToken"]));
    const tokenOnly = validateProvisionSshKeysParams(withoutKeys(sshKeysParams(), ["gatewayAgentUrl"]));
    const shortToken = validateProvisionSshKeysParams(sshKeysParams({ gatewayAgentToken: "abc123" }));
    const upperToken = validateProvisionSshKeysParams(sshKeysParams({ gatewayAgentToken: "A".repeat(64) }));

    expect(urlOnly).toEqual({ ok: false, reason: expect.stringMatching(/^gatewayAgentToken must be 64 lowercase hex/) });
    expect(tokenOnly).toEqual({ ok: false, reason: expect.stringMatching(/^gatewayAgentUrl must be exactly/) });
    expect(shortToken.ok).toBe(false);
    expect(upperToken.ok).toBe(false);
    expect(JSON.stringify(upperToken)).not.toContain("A".repeat(64));
  });

  it("requires a generation and checks its range; checks uid's range; returns ONLY the known keys", () => {
    const missing = validateProvisionSshKeysParams(withoutKeys(sshKeysParams(), ["generation"]));
    expect(missing).toEqual({ ok: false, reason: expect.stringMatching(/^generation must be an integer 0-999999999999999 \(required\)/) });
    for (const generation of [-1, 1.5, "42", null, 1_000_000_000_000_000, Number.MAX_SAFE_INTEGER + 2]) {
      expect(validateProvisionSshKeysParams(sshKeysParams({ generation })).ok, String(generation)).toBe(false);
    }
    expect(validateProvisionSshKeysParams(sshKeysParams({ generation: 0 })).ok).toBe(true);
    expect(validateProvisionSshKeysParams(sshKeysParams({ generation: 999_999_999_999_999 })).ok).toBe(true);
    for (const uid of [99_999, 10_000_000, 200123.5, "200123", null]) {
      expect(validateProvisionSshKeysParams(sshKeysParams({ uid })).ok, String(uid)).toBe(false);
    }
    expect(validateProvisionSshKeysParams({ ...sshKeysParams(), extra: "dropped", cellId: "cell_b" })).toEqual({ ok: true, params: sshKeysParams() });
  });

  it("refuses an over-long key list before any call", async () => {
    const captured = captureFetch(confirmingGateway);
    const response = await actuate("provision-ssh-keys", sshKeysParams({ authorizedKeys: Array.from({ length: 51 }, () => KEY_ONE) }));
    expect(response.status).toBe(400);
    expect(captured).toHaveLength(0);
  });
});

// ── generation fence and confirmation ───────────────────────────────────────────────────────────

describe("provision-ssh-keys confirmation", () => {
  it("an EMPTY set (revocation) is relayed as [] and confirmed only by the echo of its own push", async () => {
    const captured = captureFetch(confirmingGateway);
    const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams({ authorizedKeys: [], generation: 99 })));

    expect(captured[0].body.authorizedKeys).toEqual([]);
    expect(captured[0].body.generation).toBe(99);
    expect(result).toEqual({ ok: true, op: "provision-ssh-keys", slug: "acme", count: 0, generation: 99 });
  });

  it("an old gateway reply without a generation echo is ok:false, never a confirmed revocation", async () => {
    captureFetch(() => jsonReply({ ok: true, slug: "acme", count: 0 }));
    const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams({ authorizedKeys: [] })));

    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/did not confirm which push it wrote/);
    expect(result.generation).toBeUndefined();
  });

  it("an echo of another push is ok:false", async () => {
    captureFetch(() => jsonReply({ ok: true, slug: "acme", count: 1, generation: 41 }));
    const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));

    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/confirmed push 41, not this push \(42\)/);
  });

  it("an echo that is not a number is ok:false", async () => {
    for (const generation of ["42", null, 42.5, true]) {
      captureFetch(() => jsonReply({ ok: true, slug: "acme", count: 1, generation }));
      const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));
      expect(result.ok, String(generation)).toBe(false);
      vi.restoreAllMocks();
    }
  });

  it("superseded passes through as ok:true + superseded with no generation, so app reads it as not confirmed", async () => {
    captureFetch(() => jsonReply({ ok: true, slug: "acme", count: 2, superseded: true }));
    const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams({ authorizedKeys: [] })));

    expect(result).toEqual({ ok: true, op: "provision-ssh-keys", slug: "acme", count: 2, superseded: true });
    expect(result.generation).toBeUndefined();
  });

  it("an answer with both superseded and a generation, or an invalid superseded flag, is ok:false", async () => {
    captureFetch(() => jsonReply({ ok: true, slug: "acme", count: 1, superseded: true, generation: 42 }));
    const both = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));
    expect(both.ok).toBe(false);
    vi.restoreAllMocks();

    captureFetch(() => jsonReply({ ok: true, slug: "acme", count: 1, superseded: "yes", generation: 42 }));
    const invalidFlag = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));
    expect(invalidFlag.ok).toBe(false);
  });

  it("an answer for another slug, without ok:true, or with a count that does not match the set is ok:false", async () => {
    const replies = [
      { ok: true, slug: "other", count: 1, generation: 42 },
      { ok: false, slug: "acme", count: 1, generation: 42 },
      { slug: "acme", count: 1, generation: 42 },
      { ok: true, slug: "acme", generation: 42 },
      { ok: true, slug: "acme", count: 2, generation: 42 },
      { ok: true, slug: "acme", count: -1, generation: 42 },
      { ok: true, slug: "acme", count: 51, generation: 42 },
    ];
    for (const reply of replies) {
      captureFetch(() => jsonReply(reply));
      const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));
      expect(result.ok, JSON.stringify(reply)).toBe(false);
      vi.restoreAllMocks();
    }
  });

  it("a body that is not a JSON object is ok:false", async () => {
    for (const text of ["not json", "[1,2]", "null", "42"]) {
      captureFetch(() => new Response(text, { status: 200 }));
      const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));
      expect(result.ok, text).toBe(false);
      vi.restoreAllMocks();
    }
  });
});

// ── transport failures ──────────────────────────────────────────────────────────────────────────

describe("provision-ssh-keys transport", () => {
  it("refuses to follow a 3xx redirect and never sends a second request", async () => {
    const captured = captureFetch(() => new Response(null, { status: 302, headers: { location: "https://attacker.example/provision-ssh-keys" } }));
    const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));

    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/redirected unexpectedly \(HTTP 302\) — refusing to follow/);
    expect(captured).toHaveLength(1);
    expect(captured[0].redirect).toBe("manual");
  });

  it("refuses workerd's opaque redirect (status 0)", async () => {
    const opaqueRedirect = { status: 0, ok: false, body: null } as unknown as Response;
    captureFetch(() => opaqueRedirect);
    const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));

    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/redirected unexpectedly \(HTTP 0\)/);
  });

  it("stops reading an oversized reply at the cap and reports ok:false", async () => {
    let bytesPulled = 0;
    const chunk = new Uint8Array(16 * 1024).fill(0x20);
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        bytesPulled += chunk.byteLength;
        controller.enqueue(chunk);
      },
    });
    captureFetch(() => new Response(endless, { status: 200 }));
    const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));

    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/exceeded 65536 bytes/);
    // The reader stopped soon after the 64 KiB cap instead of buffering an endless body.
    expect(bytesPulled).toBeLessThan(256 * 1024);
  });

  it("a 401 / 403 from the gateway names the job's token by its source, never by its value", async () => {
    for (const status of [401, 403]) {
      captureFetch(() => jsonReply({ error: "unauthorized" }, status));
      const response = await actuate("provision-ssh-keys", sshKeysParams());
      const text = await response.text();
      expect(text).toMatch(/rejected the gatewayAgentToken of the signed job/);
      expect(text).not.toContain(CELL_A_GATEWAY_TOKEN);
      vi.restoreAllMocks();
    }
  });

  it("a gateway 500 carries the agent's error text, capped, and is ok:false", async () => {
    captureFetch(() => jsonReply({ error: "ssh-keys script invalid generation confirmation" + "x".repeat(1000) }, 500));
    const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));

    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/failed with HTTP 500: ssh-keys script invalid generation confirmation/);
    expect((result.detail ?? "").length).toBeLessThan(500);
  });

  it("a network error is ok:false (the outcome is unknown, so it is never a confirmation)", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("connection reset"));
    const result = await resultOf(await actuate("provision-ssh-keys", sshKeysParams()));

    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/could not read the answer of the gateway cell-agent \/provision-ssh-keys: connection reset/);
    expect(result.detail).not.toContain(CELL_A_GATEWAY_TOKEN);
  });
});
