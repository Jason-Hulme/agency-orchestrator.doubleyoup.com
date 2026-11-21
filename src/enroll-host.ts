// hub#476 / planning/58 §7.4 — the manual enrol path, for a server that Cloudflare cannot reach over SSH
// (a server behind NAT, for example a Mac on an office LAN).
//
//   GET  /enroll-host   a page with the ONE command the agency runs on its server. Every value in it comes from
//                       this Worker's own configuration, which only the agency controls: the installer URL and
//                       sha256 from HOST_INSTALLER_ORIGIN / HOST_INSTALLER_SHA256S (the last entry), and the post
//                       target from this request's own origin. The app shows no command, so a compromised
//                       platform cannot point the agency at other root code or at a host of its own.
//   POST /enroll-host   the installer posts { enrolCode, enrolFacts }. enrolCode is the agency's one-time Worker
//                       secret HOST_ENROLL_CODE; enrolFacts is the non-secret `dyenrol2.<base64url(JSON)>` blob the
//                       app shows. On success the Worker returns the bootstrap material: the installer job line
//                       (the same JSON the SSH path pipes in), with the host-agent token and the tunnel connector
//                       token. Then the code is spent: a second use gets 409.
//
// Order of the checks on POST, each refusal with nothing returned: code configured (503), code equal in constant
// time (401), facts valid (400), the tunnel is one of this Worker's own account (its connector token is readable,
// 502 otherwise), then the code is consumed (409 when it was already used). The code is consumed LAST, so a
// transient Cloudflare failure does not burn it.

import type { Env } from "./env.js";
import { enrolFactsVerdict, HOST_ENROL_FACT_KEYS, type HostEnrolFacts } from "./dispatch-params-host.js";
import { deriveHostAgentToken, fetchConnectorToken, hostAgentMasterKey, installerJobLine, pinnedInstallerUrl, readInstallerPin } from "./actuate-host.js";
import { base64Decode, bytesEqual, hexEncode, sha256Bytes, utf8Bytes, utf8Text } from "./ssh-wire.js";

export const ENROLL_HOST_PATH = "/enroll-host";
export const HOST_ENROLL_CODE_MIN_LENGTH = 32;
export const ENROL_FACTS_PREFIX = "dyenrol2.";
const ENROLL_NONCE_INSTANCE = "host-enroll";
const ENROLL_CODE_RETENTION_MS = 400 * 24 * 60 * 60 * 1000;
const ENROLL_BODY_MAX_BYTES = 8 * 1024;

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8" } });
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/**
 * The command the agency runs on its server. It downloads the pinned installer, checks its sha256 (GNU sha256sum or
 * macOS shasum), and only then runs it. The installer prompts for the enrol facts and the enrol code on its stdin,
 * so neither lands in shell history. The URL and the sha256 are grammar-checked values from readInstallerPin, and
 * the Worker URL is this request's origin, so nothing in the command needs shell quoting beyond the single quotes.
 */
export function manualEnrolCommand(installerUrl: string, installerSha256: string, enrollUrl: string): string {
  return [
    `f=$(mktemp) && curl -fsSL --proto =https -o "$f" '${installerUrl}'`,
    `&& s=$( (sha256sum "$f" 2>/dev/null || shasum -a 256 "$f") | cut -d' ' -f1)`,
    `&& if [ "$s" = '${installerSha256}' ]; then DY_ENROLL_URL='${enrollUrl}' sh "$f"; else echo "the installer sha256 is $s, not the pinned one; nothing ran" >&2; fi;`,
    `rm -f "$f"`,
  ].join(" ");
}

export function handleEnrollHostPage(request: Request, env: Env): Response {
  const origin = new URL(request.url).origin;
  const pin = readInstallerPin(env);
  let body: string;
  if (!pin.ok) {
    body = `<p><strong>No command yet.</strong> ${escapeHtml(pin.detail)}</p>`;
  } else {
    const sha256 = pin.pin.sha256s[pin.pin.sha256s.length - 1];
    const command = manualEnrolCommand(pinnedInstallerUrl(pin.pin.origin, sha256), sha256, `${origin}${ENROLL_HOST_PATH}`);
    body = [
      "<ol>",
      "<li>Put a new one-time enrol code in this Worker: <code>openssl rand -hex 32</code>, then <code>wrangler secret put HOST_ENROLL_CODE</code>.</li>",
      "<li>On the server, as the admin login (root or a sudo user on Ubuntu, an admin user on macOS), run:</li>",
      "</ol>",
      `<pre>${escapeHtml(command)}</pre>`,
      "<p>The installer asks for the enrol facts (the <code>dyenrol2.…</code> text the doubleyoup app shows for the server) and the enrol code. Paste them at the prompts, not on the command line.</p>",
      `<p>Installer sha256: <code>${escapeHtml(sha256)}</code> (from this Worker's HOST_INSTALLER_SHA256S).</p>`,
    ].join("\n");
  }
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Enrol a self-hosted server</title></head><body><h1>Enrol a self-hosted server</h1>\n${body}\n</body></html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}

/** Decode `dyenrol2.<base64url(JSON)>` into the seven validated facts, or the refusal reason. */
export function decodeEnrolFacts(blob: unknown): { ok: true; facts: HostEnrolFacts } | { ok: false; reason: string } {
  if (typeof blob !== "string" || !blob.startsWith(ENROL_FACTS_PREFIX) || blob.length > 4096) {
    return { ok: false, reason: `enrolFacts must be the ${ENROL_FACTS_PREFIX}… text the app shows` };
  }
  const base64url = blob.slice(ENROL_FACTS_PREFIX.length);
  if (!/^[A-Za-z0-9_-]+$/.test(base64url)) {
    return { ok: false, reason: "enrolFacts is not base64url" };
  }
  let standard = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (standard.length % 4 !== 0) {
    standard += "=";
  }
  const bytes = base64Decode(standard);
  if (bytes === null) {
    return { ok: false, reason: "enrolFacts is not base64url" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Text(bytes));
  } catch {
    return { ok: false, reason: "enrolFacts does not hold JSON" };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, reason: "enrolFacts does not hold a JSON object" };
  }
  const object = parsed as Record<string, unknown>;
  for (const key of Object.keys(object)) {
    if (!(HOST_ENROL_FACT_KEYS as readonly string[]).includes(key)) {
      return { ok: false, reason: `enrolFacts has the unknown field "${key}"` };
    }
  }
  const verdict = enrolFactsVerdict(object);
  if (!verdict.ok) {
    return { ok: false, reason: verdict.reason };
  }
  return { ok: true, facts: verdict.params };
}

async function codesEqual(expected: string, given: string): Promise<boolean> {
  // Compare digests, so the time taken does not depend on where the two values first differ or on their lengths.
  const expectedDigest = await sha256Bytes(utf8Bytes(expected));
  const givenDigest = await sha256Bytes(utf8Bytes(given));
  return bytesEqual(expectedDigest, givenDigest);
}

export async function handleEnrollHostPost(request: Request, env: Env): Promise<Response> {
  const code = env.HOST_ENROLL_CODE;
  if (typeof code !== "string" || code.length < HOST_ENROLL_CODE_MIN_LENGTH) {
    console.warn("enroll-host: refused, HOST_ENROLL_CODE is not set");
    return json(
      { ok: false, code: "enroll-code-not-set", detail: `HOST_ENROLL_CODE is not set on this Worker (at least ${HOST_ENROLL_CODE_MIN_LENGTH} characters). Put a new one with \`wrangler secret put HOST_ENROLL_CODE\`.` },
      503,
    );
  }

  const bodyText = await request.text();
  if (utf8Bytes(bodyText).length > ENROLL_BODY_MAX_BYTES) {
    return json({ ok: false, code: "bad-request", detail: "the request body is too large" }, 400);
  }
  let body: unknown;
  try {
    body = JSON.parse(bodyText);
  } catch {
    return json({ ok: false, code: "bad-request", detail: "the body must be JSON { enrolCode, enrolFacts }" }, 400);
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return json({ ok: false, code: "bad-request", detail: "the body must be JSON { enrolCode, enrolFacts }" }, 400);
  }
  const { enrolCode, enrolFacts } = body as { enrolCode?: unknown; enrolFacts?: unknown };
  if (typeof enrolCode !== "string" || !(await codesEqual(code, enrolCode))) {
    console.warn("enroll-host: refused a wrong enrol code");
    return json({ ok: false, code: "enroll-code-wrong" }, 401);
  }

  const facts = decodeEnrolFacts(enrolFacts);
  if (!facts.ok) {
    return json({ ok: false, code: "bad-facts", detail: facts.reason }, 400);
  }
  const pin = readInstallerPin(env);
  if (!pin.ok) {
    console.warn("enroll-host: refused, the installer is not pinned");
    return json({ ok: false, code: "installer-not-pinned", detail: pin.detail }, 503);
  }
  const master = hostAgentMasterKey(env);
  if (!master.ok) {
    console.warn("enroll-host: refused, HOST_AGENT_MASTER_KEY is not set");
    return json({ ok: false, code: "host-agent-key-missing", detail: master.detail }, 503);
  }
  // Reading the connector token through the agency's own token proves the tunnel is in the agency's own account.
  const connector = await fetchConnectorToken(env, facts.facts.tunnelId);
  if (!connector.ok) {
    console.warn(`enroll-host: could not read the connector token of tunnel ${facts.facts.tunnelId}`);
    return json({ ok: false, code: "tunnel-token-failed", detail: connector.detail }, 502);
  }

  const codeKey = `host-enroll:${hexEncode(await sha256Bytes(utf8Bytes(code)))}`;
  const store = env.NONCE_STORE.get(env.NONCE_STORE.idFromName(ENROLL_NONCE_INSTANCE));
  const outcome = await store.consume(codeKey, Date.now() + ENROLL_CODE_RETENTION_MS);
  if (outcome === "replay") {
    console.warn("enroll-host: refused an enrol code that was already used");
    return json({ ok: false, code: "enroll-code-used", detail: "this enrol code was already used. Put a new HOST_ENROLL_CODE for the next enrolment." }, 409);
  }

  const sha256 = pin.pin.sha256s[pin.pin.sha256s.length - 1];
  const hostAgentToken = hexEncode(await deriveHostAgentToken(master.masterKey, facts.facts.cellId));
  const jobLine = installerJobLine(
    "host-enroll",
    { ...facts.facts, mode: "start", installerUrl: pinnedInstallerUrl(pin.pin.origin, sha256), installerSha256: sha256 },
    { hostAgentToken, tunnelToken: connector.token },
  );
  console.log(`enroll-host: enrolled cell ${facts.facts.cellId} (label ${facts.facts.label})`);
  return new Response(JSON.stringify({ ok: true, job: JSON.parse(jobLine) }), {
    status: 200,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
