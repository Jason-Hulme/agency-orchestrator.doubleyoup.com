// hub#340 (boot-state design §5.3, §9 V6/V7) — gcp-instance-startup-script-pin, Worker side.
//
// V7 runs against a FAKED Compute API, with the REAL renderMetadataItems (placeholder substitution from
// the Worker's own S3_* secrets) and the REAL readonly-block parser. What these tests pin:
//   - a rotated agency S3 secret is refused by NAME, with no setMetadata call and neither the old nor the
//     new value (nor a sha256 of either) in the answer or in anything logged;
//   - an unchanged secret is written, with every readonly line byte-equal except the two bundle lines;
//   - a changed platform token, an added key with a placeholder, an unparseable line and a live script
//     without a readonly block are refused; an added key without a placeholder and a removed key are
//     written and named;
//   - an identical script is `unchanged` with no write; a stale fingerprint (V6) is `staleFingerprint`,
//     written once, never retried, and every unrelated key is sent back verbatim;
//   - the validator: four params, unknown params REFUSED (the app's twin carries the same cases).

import { describe, it, expect, vi, afterEach } from "vitest";
import type { Env } from "../src/env.js";
import { validateGcpInstanceStartupScriptPinParams } from "../src/dispatch-params.js";
import {
  actuateGcpInstanceStartupScriptPin,
  compareReadonlyBlocks,
  parseReadonlyBlock,
  type GcpInstanceStartupScriptPinResult,
} from "../src/actuate-startup-script-pin.js";
import { DISPATCH_OPS } from "../src/dispatch-verify.js";
import { DISPATCH_OP_REGISTRY } from "../src/ops.js";

const PROJECT = "example-agency-project";
const ZONE = "australia-southeast2-a";
const NODE = "dy-file-australia-southeast2-1";
const GCP_ACCESS_TOKEN = "ya29.must-not-be-echoed";
const COMPUTE = "https://compute.googleapis.com/compute/v1";
const INSTANCE_URL = `${COMPUTE}/projects/${PROJECT}/zones/${ZONE}/instances/${NODE}`;
const TOKEN_URL = "https://oauth2.googleapis.com/token";

const OLD_BUNDLE_URL = "https://bundles.example.test/cell-bundle-20261112-aaaaaaa.tar.gz";
const OLD_BUNDLE_SHA = "a".repeat(64);
const NEW_BUNDLE_URL = "https://bundles.example.test/cell-bundle-20261128-bbbbbbb.tar.gz";
const NEW_BUNDLE_SHA = "b".repeat(64);
const AGENT_TOKEN = "c".repeat(64);
const ROTATED_AGENT_TOKEN = "d".repeat(64);

// The agency's object-store secret before (X) and after (Y) a rotation in the Worker.
const SECRET_X = "secretXvalue+/=0123456789abcdefABCDEF";
const SECRET_Y = "secretYvalue+/=9876543210fedcbaFEDCBA";
const ACCESS_KEY_ID = "AKIAEXAMPLEKEYID0001";

function s3Env(secret: string): Partial<Env> {
  return {
    S3_ACCESS_KEY_ID: ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY: secret,
    S3_BUCKET: "agency-backups",
    S3_REGION: "auto",
    S3_ENDPOINT: "https://acct123.r2.example.test",
  };
}

interface ScriptParts {
  bundleUrl: string;
  bundleSha: string;
  agentToken: string;
  body: string;
  /** Extra readonly lines put after the standard ones (already formed). */
  extraLines?: string[];
  /** Standard keys left out. */
  omit?: string[];
}

/**
 * A file.sh-shaped script in the renderer's form. `secretAccessKey` / `accessKeyId` are either the
 * placeholders (the platform's render) or substituted values (what the node holds).
 */
function fileScript(parts: ScriptParts, s3: { accessKeyId: string; secretAccessKey: string; bucket: string; endpoint: string; region: string }): string {
  const standard: Array<[string, string]> = [
    ["DY_NODE_NAME", NODE],
    ["DY_SUBNET_CIDR", "10.20.0.0/24"],
    ["DY_BUNDLE_URL", parts.bundleUrl],
    ["DY_BUNDLE_SHA256", parts.bundleSha],
    ["DY_CELL_AGENT_TOKEN", parts.agentToken],
    ["DY_T2_S3_ACCESS_KEY_ID", s3.accessKeyId],
    ["DY_T2_S3_SECRET_ACCESS_KEY", s3.secretAccessKey],
    ["DY_T2_S3_ENDPOINT", s3.endpoint],
    ["DY_T2_S3_BUCKET", s3.bucket],
    ["DY_T2_S3_REGION", s3.region],
    ["DY_UPDATE_CHANNEL", "beta"],
  ];
  const omit = parts.omit ?? [];
  const lines: string[] = [];
  for (const [key, value] of standard) {
    if (omit.includes(key)) {
      continue;
    }
    lines.push(`readonly ${key}='${value}'`);
  }
  for (const extra of parts.extraLines ?? []) {
    lines.push(extra);
  }
  return [
    "#!/bin/bash",
    "set -euo pipefail",
    "# ── values injected by orchestrator cell-provision (cell-bootstrap.ts): shell-quoted, read-only ──",
    ...lines,
    parts.body,
    "",
  ].join("\n");
}

const PLACEHOLDERS = {
  accessKeyId: "@@DY_T2_S3_ACCESS_KEY_ID@@",
  secretAccessKey: "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
  bucket: "@@DY_T2_S3_BUCKET@@",
  endpoint: "@@DY_T2_S3_ENDPOINT@@",
  region: "@@DY_T2_S3_REGION@@",
};

function substitutedWith(secret: string) {
  return { accessKeyId: ACCESS_KEY_ID, secretAccessKey: secret, bucket: "agency-backups", endpoint: "https://acct123.r2.example.test", region: "auto" };
}

const OLD_PARTS: ScriptParts = { bundleUrl: OLD_BUNDLE_URL, bundleSha: OLD_BUNDLE_SHA, agentToken: AGENT_TOKEN, body: 'log "release R-1 body"' };
const NEW_PARTS: ScriptParts = { bundleUrl: NEW_BUNDLE_URL, bundleSha: NEW_BUNDLE_SHA, agentToken: AGENT_TOKEN, body: 'log "release R body"\nlog "a new step"' };

/** The node's live script: release R-1, substituted with secret X. */
const LIVE_SCRIPT = fileScript(OLD_PARTS, substitutedWith(SECRET_X));
/** The platform's render of release R, with placeholders: body AND bundle lines changed. */
const RENDER_R = fileScript(NEW_PARTS, PLACEHOLDERS);

const UNRELATED_ITEMS = [
  { key: "enable-oslogin", value: "TRUE" },
  { key: "dy-node-id", value: "node-7" },
];

async function sha256HexOf(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/** A REAL service-account key, so the RS256 mint runs; only the HTTP calls are faked. */
async function makeServiceAccountKey(projectId: string): Promise<string> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)) as ArrayBuffer);
  const pem = `-----BEGIN PRIVATE KEY-----\n${bytesToBase64(pkcs8).match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
  return JSON.stringify({
    type: "service_account",
    project_id: projectId,
    private_key: pem,
    client_email: `agency@${projectId}.iam.gserviceaccount.com`,
    token_uri: TOKEN_URL,
  });
}

let serviceAccountKey: string | null = null;
async function sharedServiceAccountKey(): Promise<string> {
  if (serviceAccountKey === null) {
    serviceAccountKey = await makeServiceAccountKey(PROJECT);
  }
  return serviceAccountKey;
}

interface RecordedCall {
  url: string;
  method: string;
  body: string | null;
}

interface FakeComputeOptions {
  items: Array<{ key: string; value: string }>;
  fingerprint?: string;
  /** The HTTP status the setMetadata POST answers. */
  writeStatus?: number;
}

/** A faked Compute API: the token mint, the instance read, setMetadata and its wait. Every console line is captured. */
async function fakeCompute(options: FakeComputeOptions, secret = SECRET_X) {
  const env = { GCP_SERVICE_ACCOUNT_KEY: await sharedServiceAccountKey(), ...s3Env(secret) } as Env;
  const calls: RecordedCall[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const call: RecordedCall = { url: String(input), method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : null };
    calls.push(call);
    let status = 200;
    let body: unknown = { error: { message: `unexpected ${call.method} ${call.url}` } };
    if (call.url === TOKEN_URL) {
      body = { access_token: GCP_ACCESS_TOKEN, expires_in: 3600, token_type: "Bearer" };
    } else if (call.url === INSTANCE_URL && call.method === "GET") {
      body = { name: NODE, status: "RUNNING", metadata: { fingerprint: options.fingerprint ?? "fp-read", items: options.items } };
    } else if (call.url === `${INSTANCE_URL}/setMetadata` && call.method === "POST") {
      status = options.writeStatus ?? 200;
      if (status === 412) {
        body = { error: { code: 412, message: "Supplied fingerprint does not match current metadata fingerprint." } };
      } else {
        body = { name: "operation-1", status: "RUNNING" };
      }
    } else if (call.url.endsWith("/operations/operation-1/wait")) {
      body = { name: "operation-1", status: "DONE" };
    } else {
      status = 500;
    }
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  });
  const logged: string[] = [];
  for (const method of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      logged.push(args.map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg))).join(" "));
    });
  }
  const googleCalls = () => calls.filter((call) => call.url !== TOKEN_URL);
  const writes = () => calls.filter((call) => call.url.endsWith("/setMetadata"));
  return { env, calls, googleCalls, writes, logged };
}

async function pin(env: Env, startupScript: string): Promise<GcpInstanceStartupScriptPinResult> {
  return actuateGcpInstanceStartupScriptPin({ project: PROJECT, zone: ZONE, name: NODE, startupScript }, env);
}

/** Neither secret, nor the sha256 of either, nor the sha256 of either readonly LINE, anywhere in `text`. */
async function expectNoSecretTrace(text: string): Promise<void> {
  for (const secret of [SECRET_X, SECRET_Y]) {
    expect(text).not.toContain(secret);
    expect(text).not.toContain(await sha256HexOf(secret));
    expect(text).not.toContain(await sha256HexOf(`readonly DY_T2_S3_SECRET_ACCESS_KEY='${secret}'`));
  }
  expect(text).not.toContain(ACCESS_KEY_ID);
  expect(text).not.toContain(GCP_ACCESS_TOKEN);
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ── Registration ─────────────────────────────────────────────────────────────────────

describe("gcp-instance-startup-script-pin registration", () => {
  it("is allowlisted and registered", () => {
    expect(DISPATCH_OPS).toContain("gcp-instance-startup-script-pin");
    expect(typeof DISPATCH_OP_REGISTRY["gcp-instance-startup-script-pin"].actuate).toBe("function");
    expect(DISPATCH_OP_REGISTRY["gcp-instance-startup-script-pin"].validateParams).toBe(validateGcpInstanceStartupScriptPinParams);
  });
});

// ── Validator (the app's twin carries the same cases) ────────────────────────────────

describe("validateGcpInstanceStartupScriptPinParams (twin of the app's rules)", () => {
  const BASE = { project: PROJECT, zone: ZONE, name: NODE, startupScript: "#!/bin/bash\nreadonly DY_BUNDLE_URL='x'\n" };

  it("accepts the four params and returns a fresh object of exactly them", () => {
    const verdict = validateGcpInstanceStartupScriptPinParams(BASE);
    expect(verdict).toEqual({ ok: true, params: BASE });
    if (verdict.ok) {
      expect(verdict.params).not.toBe(BASE);
    }
  });

  it("accepts a script with placeholders and one at the 256 KB cap", () => {
    expect(validateGcpInstanceStartupScriptPinParams({ ...BASE, startupScript: RENDER_R }).ok).toBe(true);
    expect(validateGcpInstanceStartupScriptPinParams({ ...BASE, startupScript: "a".repeat(256 * 1024) }).ok).toBe(true);
  });

  it("REFUSES an unknown param (never drops it), naming it — including set-metadata's own params", () => {
    for (const extra of [{ items: [] }, { expectedFingerprint: "fp" }, { allowedKeys: ["DY_CELL_AGENT_TOKEN"] }, { extra: 1 }]) {
      const verdict = validateGcpInstanceStartupScriptPinParams({ ...BASE, ...extra });
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) {
        expect(verdict.reason).toContain(`unknown param "${Object.keys(extra)[0]}"`);
      }
    }
  });

  it("refuses a missing or bad field, field by field", () => {
    const bad = (overrides: Record<string, unknown>) => validateGcpInstanceStartupScriptPinParams({ ...BASE, ...overrides });
    expect(validateGcpInstanceStartupScriptPinParams(null).ok).toBe(false);
    expect(validateGcpInstanceStartupScriptPinParams([]).ok).toBe(false);
    expect(validateGcpInstanceStartupScriptPinParams("x").ok).toBe(false);
    expect(validateGcpInstanceStartupScriptPinParams({}).ok).toBe(false);
    for (const project of [undefined, "", "UPPER", "a", "has space", 7]) {
      expect(bad({ project }).ok).toBe(false);
    }
    for (const zone of [undefined, "", "not a zone", "australia-southeast2", 7]) {
      expect(bad({ zone }).ok).toBe(false);
    }
    for (const name of [undefined, "", "Upper", "-lead", "a/b", 7]) {
      expect(bad({ name }).ok).toBe(false);
    }
    for (const startupScript of [undefined, "", 7, null, ["#!/bin/bash"], "a".repeat(256 * 1024 + 1), "é".repeat(128 * 1024 + 1)]) {
      const verdict = bad({ startupScript });
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) {
        expect(verdict.reason).toContain("startupScript");
      }
    }
  });
});

// ── The parser ───────────────────────────────────────────────────────────────────────

describe("parseReadonlyBlock", () => {
  it("reads every column-0 readonly line in the renderer's form, including an escaped quote", () => {
    const parsed = parseReadonlyBlock("#!/bin/bash\nreadonly A='1'\nreadonly B_2='it'\\''s'\nreadonly C=''\n  readonly D='indented is body'\necho readonly\n");
    expect(parsed.keys).toEqual(["A", "B_2", "C"]);
    expect(parsed.faults).toEqual([]);
  });

  it("an unparseable readonly line and a key named twice are faults, named by key and line", () => {
    const parsed = parseReadonlyBlock("#!/bin/bash\nreadonly A='1' # comment\nreadonly B=\"2\"\nreadonly C='3'\nreadonly C='4'\nreadonly lower='x'\nreadonly E='open\n");
    expect(parsed.keys).toEqual(["C"]);
    expect(parsed.faults).toEqual([
      { key: "A", line: 2, reason: "unparseable" },
      { key: "B", line: 3, reason: "unparseable" },
      { key: "C", line: 5, reason: "duplicate" },
      { key: null, line: 6, reason: "unparseable" },
      { key: "E", line: 7, reason: "unparseable" },
    ]);
  });
});

describe("compareReadonlyBlocks", () => {
  it("allows only the bundle lines to change; the body is free", () => {
    const verdict = compareReadonlyBlocks({
      liveScript: LIVE_SCRIPT,
      renderedScript: fileScript(NEW_PARTS, substitutedWith(SECRET_X)),
      templateScript: RENDER_R,
    });
    expect(verdict).toEqual({ allowed: true, changedKeys: ["DY_BUNDLE_URL", "DY_BUNDLE_SHA256"], addedKeys: [], removedKeys: [] });
  });
});

// ── V7 through the actuator, against the faked Compute API ───────────────────────────

describe("V7: credential preservation through the real comparison", () => {
  it("1. a ROTATED agency S3 secret (body and bundle changed too) is refused naming DY_T2_S3_SECRET_ACCESS_KEY — no write, no trace of X or Y", async () => {
    const live = [...UNRELATED_ITEMS, { key: "startup-script", value: LIVE_SCRIPT }];
    // The agency rotated S3_SECRET_ACCESS_KEY in the Worker from X to Y.
    const { env, googleCalls, writes, logged } = await fakeCompute({ items: live }, SECRET_Y);
    const result = await pin(env, RENDER_R);

    expect(result).toMatchObject({
      ok: false,
      op: "gcp-instance-startup-script-pin",
      instanceName: NODE,
      outcome: "refused",
      fingerprint: "fp-read",
      refusals: [{ key: "DY_T2_S3_SECRET_ACCESS_KEY", reason: "changed", side: "render" }],
    });
    if (!result.ok) {
      expect(result.detail).toContain("DY_T2_S3_SECRET_ACCESS_KEY: changed");
      expect(result.detail).toContain("nothing was written");
    }
    expect(writes()).toEqual([]);
    expect(googleCalls().map((call) => call.method)).toEqual(["GET"]);
    await expectNoSecretTrace(JSON.stringify(result));
    await expectNoSecretTrace(logged.join("\n"));
  });

  it("2. the secret UNCHANGED is written: readonly lines byte-equal except the bundle lines, body is R's, under the read fingerprint", async () => {
    const live = [UNRELATED_ITEMS[0]!, { key: "startup-script", value: LIVE_SCRIPT }, UNRELATED_ITEMS[1]!];
    const { env, writes, logged } = await fakeCompute({ items: live }, SECRET_X);
    const result = await pin(env, RENDER_R);

    const expectedWritten = fileScript(NEW_PARTS, substitutedWith(SECRET_X));
    expect(result).toEqual({
      ok: true,
      op: "gcp-instance-startup-script-pin",
      instanceName: NODE,
      outcome: "written",
      fingerprintBefore: "fp-read",
      valueSha256: await sha256HexOf(expectedWritten),
      changedKeys: ["DY_BUNDLE_URL", "DY_BUNDLE_SHA256"],
      addedKeys: [],
      removedKeys: [],
      placeholdersSubstituted: [
        "@@DY_T2_S3_ACCESS_KEY_ID@@",
        "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
        "@@DY_T2_S3_ENDPOINT@@",
        "@@DY_T2_S3_BUCKET@@",
        "@@DY_T2_S3_REGION@@",
      ],
      operationName: "operation-1",
    });
    expect(writes()).toHaveLength(1);
    const body = JSON.parse(writes()[0]!.body ?? "{}") as { fingerprint: string; items: Array<{ key: string; value: string }> };
    expect(body.fingerprint).toBe("fp-read");
    // startup-script replaced IN PLACE; every other key verbatim and in order.
    expect(body.items.map((item) => item.key)).toEqual(["enable-oslogin", "startup-script", "dy-node-id"]);
    expect(body.items[0]).toEqual(UNRELATED_ITEMS[0]);
    expect(body.items[2]).toEqual(UNRELATED_ITEMS[1]);

    const writtenScript = body.items[1]!.value;
    expect(writtenScript).toBe(expectedWritten);
    const liveLines = LIVE_SCRIPT.split("\n").filter((line) => line.startsWith("readonly "));
    const writtenLines = writtenScript.split("\n").filter((line) => line.startsWith("readonly "));
    expect(writtenLines).toHaveLength(liveLines.length);
    for (let index = 0; index < liveLines.length; index += 1) {
      const isBundleLine = liveLines[index]!.startsWith("readonly DY_BUNDLE_URL=") || liveLines[index]!.startsWith("readonly DY_BUNDLE_SHA256=");
      if (isBundleLine) {
        expect(writtenLines[index]).not.toBe(liveLines[index]);
      } else {
        expect(writtenLines[index]).toBe(liveLines[index]);
      }
    }
    expect(writtenScript).toContain('log "a new step"');
    // The answer carries the WHOLE script's hash only — never a value, never a line hash.
    await expectNoSecretTrace(JSON.stringify(result));
    await expectNoSecretTrace(logged.join("\n"));
  });

  it("3a. a changed PLATFORM token line is refused naming DY_CELL_AGENT_TOKEN", async () => {
    const { env, writes } = await fakeCompute({ items: [{ key: "startup-script", value: LIVE_SCRIPT }] });
    const result = await pin(env, fileScript({ ...NEW_PARTS, agentToken: ROTATED_AGENT_TOKEN }, PLACEHOLDERS));
    expect(result).toMatchObject({ ok: false, outcome: "refused", refusals: [{ key: "DY_CELL_AGENT_TOKEN", reason: "changed" }] });
    expect(JSON.stringify(result)).not.toContain(AGENT_TOKEN);
    expect(JSON.stringify(result)).not.toContain(ROTATED_AGENT_TOKEN);
    expect(writes()).toEqual([]);
  });

  it("3b. an ADDED key WITHOUT a placeholder is written and named in addedKeys", async () => {
    const { env, writes } = await fakeCompute({ items: [{ key: "startup-script", value: LIVE_SCRIPT }] });
    const render = fileScript({ ...NEW_PARTS, extraLines: ["readonly DY_ROUTER_DEFAULT_TARGET='router'"] }, PLACEHOLDERS);
    const result = await pin(env, render);
    expect(result).toMatchObject({ ok: true, outcome: "written", addedKeys: ["DY_ROUTER_DEFAULT_TARGET"], removedKeys: [] });
    expect(writes()).toHaveLength(1);
  });

  it("3c. an ADDED key WITH a placeholder is refused (a pin bump is never the first write of an agency value)", async () => {
    const live = fileScript(OLD_PARTS, substitutedWith(SECRET_X)).replace("readonly DY_T2_S3_REGION='auto'\n", "");
    const { env, writes } = await fakeCompute({ items: [{ key: "startup-script", value: live }] });
    const result = await pin(env, RENDER_R);
    expect(result).toMatchObject({ ok: false, outcome: "refused", refusals: [{ key: "DY_T2_S3_REGION", reason: "added", side: "render" }] });
    expect(JSON.stringify(result)).not.toContain("'auto'");
    expect(writes()).toEqual([]);
  });

  it("3d. a REMOVED key is written and named in removedKeys", async () => {
    const { env, writes } = await fakeCompute({ items: [{ key: "startup-script", value: LIVE_SCRIPT }] });
    const result = await pin(env, fileScript({ ...NEW_PARTS, omit: ["DY_UPDATE_CHANNEL"] }, PLACEHOLDERS));
    expect(result).toMatchObject({ ok: true, outcome: "written", addedKeys: [], removedKeys: ["DY_UPDATE_CHANNEL"] });
    expect(writes()).toHaveLength(1);
  });

  it("3e. an UNPARSEABLE readonly line — in the live script or in the render — is refused, naming the key and line", async () => {
    const brokenLive = LIVE_SCRIPT.replace("readonly DY_SUBNET_CIDR='10.20.0.0/24'", 'readonly DY_SUBNET_CIDR="10.20.0.0/24"');
    const live = await fakeCompute({ items: [{ key: "startup-script", value: brokenLive }] });
    const liveResult = await pin(live.env, RENDER_R);
    expect(liveResult).toMatchObject({ ok: false, outcome: "refused", refusals: [{ key: "DY_SUBNET_CIDR", reason: "unparseable", side: "live", line: 5 }] });
    expect(live.writes()).toEqual([]);
    vi.restoreAllMocks();

    const brokenRender = RENDER_R.replace("readonly DY_UPDATE_CHANNEL='beta'", "readonly DY_UPDATE_CHANNEL='beta' # trailing");
    const render = await fakeCompute({ items: [{ key: "startup-script", value: LIVE_SCRIPT }] });
    const renderResult = await pin(render.env, brokenRender);
    expect(renderResult).toMatchObject({ ok: false, outcome: "refused", refusals: [{ key: "DY_UPDATE_CHANNEL", reason: "unparseable", side: "render" }] });
    expect(render.writes()).toEqual([]);
  });

  it("3f. a live script with NO readonly block (a hand-built node) is refused", async () => {
    const { env, writes } = await fakeCompute({ items: [{ key: "startup-script", value: "#!/bin/bash\necho hand-built\n" }] });
    const result = await pin(env, RENDER_R);
    expect(result).toMatchObject({ ok: false, outcome: "refused", refusals: [{ key: null, reason: "no-readonly-block", side: "live" }] });
    if (!result.ok) {
      expect(result.detail).toContain("the live script has no readonly block");
    }
    expect(writes()).toEqual([]);
  });

  it("3g. no live startup-script, or a live startup-script-url, is refused by key name", async () => {
    const none = await fakeCompute({ items: UNRELATED_ITEMS });
    expect(await pin(none.env, RENDER_R)).toMatchObject({ ok: false, outcome: "refused", refusals: [{ key: "startup-script", reason: "no-startup-script" }] });
    expect(none.writes()).toEqual([]);
    vi.restoreAllMocks();

    const withUrl = await fakeCompute({ items: [{ key: "startup-script", value: LIVE_SCRIPT }, { key: "startup-script-url", value: "gs://bucket/x.sh" }] });
    const result = await pin(withUrl.env, RENDER_R);
    expect(result).toMatchObject({ ok: false, outcome: "refused", refusals: [{ key: "startup-script-url", reason: "startup-script-url" }] });
    expect(JSON.stringify(result)).not.toContain("gs://bucket");
    expect(withUrl.writes()).toEqual([]);
  });

  it("3h. several differing keys are all named in one refusal", async () => {
    const { env, writes } = await fakeCompute({ items: [{ key: "startup-script", value: LIVE_SCRIPT }] }, SECRET_Y);
    const result = await pin(env, fileScript({ ...NEW_PARTS, agentToken: ROTATED_AGENT_TOKEN }, PLACEHOLDERS));
    expect(result).toMatchObject({
      ok: false,
      outcome: "refused",
      refusals: [
        { key: "DY_CELL_AGENT_TOKEN", reason: "changed" },
        { key: "DY_T2_S3_SECRET_ACCESS_KEY", reason: "changed" },
      ],
    });
    expect(writes()).toEqual([]);
  });

  it("4. an IDENTICAL script is unchanged — no write", async () => {
    const current = fileScript(NEW_PARTS, substitutedWith(SECRET_X));
    const { env, googleCalls } = await fakeCompute({ items: [{ key: "startup-script", value: current }] });
    const result = await pin(env, RENDER_R);
    expect(result).toEqual({
      ok: true,
      op: "gcp-instance-startup-script-pin",
      instanceName: NODE,
      outcome: "unchanged",
      fingerprint: "fp-read",
      valueSha256: await sha256HexOf(current),
    });
    expect(googleCalls().map((call) => call.method)).toEqual(["GET"]);
  });

  it("5. V6: a fingerprint change between read and write is staleFingerprint — ONE write attempt, no retry, unrelated keys sent verbatim", async () => {
    const live = [...UNRELATED_ITEMS, { key: "startup-script", value: LIVE_SCRIPT }];
    const { env, googleCalls, writes } = await fakeCompute({ items: live, writeStatus: 412 });
    const result = await pin(env, RENDER_R);
    expect(result).toMatchObject({ ok: false, op: "gcp-instance-startup-script-pin", outcome: "staleFingerprint", staleFingerprint: true });
    if (!result.ok) {
      expect(result.detail).toContain("nothing was written");
    }
    // One read, one write attempt, no wait, no re-read.
    expect(googleCalls().map((call) => call.method)).toEqual(["GET", "POST"]);
    const body = JSON.parse(writes()[0]!.body ?? "{}") as { items: Array<{ key: string; value: string }> };
    expect(body.items.slice(0, 2)).toEqual(UNRELATED_ITEMS);
    await expectNoSecretTrace(JSON.stringify(result));
  });

  it("an unknown placeholder or a missing S3 secret fails before any Google call", async () => {
    const { env, calls } = await fakeCompute({ items: [{ key: "startup-script", value: LIVE_SCRIPT }] });
    const unknown = await pin(env, RENDER_R.replace("@@DY_T2_S3_REGION@@", "@@DY_OTHER@@"));
    expect(unknown).toMatchObject({ ok: false, outcome: "failed" });
    const missing = await pin({ ...env, S3_SECRET_ACCESS_KEY: undefined } as Env, RENDER_R);
    expect(missing).toMatchObject({ ok: false, outcome: "failed" });
    expect(calls).toEqual([]);
  });

  it("a read without a fingerprint fails with no write; a 5xx on the write is unconfirmed", async () => {
    const noFingerprint = await fakeCompute({ items: [{ key: "startup-script", value: LIVE_SCRIPT }], fingerprint: "" });
    expect(await pin(noFingerprint.env, RENDER_R)).toMatchObject({ ok: false, outcome: "failed" });
    expect(noFingerprint.writes()).toEqual([]);
    vi.restoreAllMocks();

    const serverError = await fakeCompute({ items: [{ key: "startup-script", value: LIVE_SCRIPT }], writeStatus: 503 });
    expect(await pin(serverError.env, RENDER_R)).toMatchObject({ ok: false, outcome: "failed", unconfirmed: true });
  });
});
