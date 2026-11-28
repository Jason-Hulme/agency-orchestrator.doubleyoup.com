// hub#340 (boot-state design §5.2 step 3, §5.3) — `gcp-instance-startup-script-pin`: the GUARDED write
// of a node's new `startup-script` when a release moves its boot pin.
//
// A release changes two things in a node's boot script: the script body (outside the readonly block) and
// the two bundle lines (`readonly DY_BUNDLE_URL='…'` / `readonly DY_BUNDLE_SHA256='…'`). Every other
// readonly line carries a value the node already holds — a platform token, the subnet, a host, or an
// agency secret that THIS Worker substituted. A pin bump must never rewrite one of those: an agency that
// rotated its S3 secret, or a platform value that moved, is a deliberate change that goes through the
// hand publish, not a side effect of a release.
//
// So, all inside the Worker, in this order:
//   1. SUBSTITUTE the placeholders in the render (renderMetadataItems, the same code set-metadata runs),
//      before any token is minted, so a render this Worker will not stand behind fails with no call made.
//   2. GET the instance: its fingerprint, the live `startup-script`, every other item.
//   3. When the substituted render is byte-identical to the live script: `unchanged`, nothing written.
//   4. PARSE the readonly block of the live script and of the render (parseReadonlyBlock) and compare by
//      key. Only DY_BUNDLE_URL and DY_BUNDLE_SHA256 may differ. A key the render ADDS is allowed only when
//      its template line carried no Worker placeholder (the platform rendered the value, so it is no
//      agency value); a key the render REMOVES is allowed (dropping a line rewrites no value). Anything
//      else is `refused`, naming the keys and a reason class, with nothing written.
//   5. WRITE `startup-script` only, merged with every other key verbatim (mergeMetadataItems), under the
//      fingerprint of step 2, ONCE (postInstanceMetadata). A stale fingerprint is `staleFingerprint`,
//      never retried here: the next run reads and compares again.
//
// NO VALUE LEAVES THIS FILE. The answer and the detail carry key NAMES, reason classes, line numbers and
// the sha256 of the WHOLE written script (what gcp-instance-get reports, for the caller's read-back) —
// never a readonly value and never a hash of one, because a hash of one short value would let the
// platform test guesses of an agency secret. Nothing here logs.

import type { Env } from "./env.js";
import type { GcpInstanceStartupScriptPinParams } from "./dispatch-params.js";
import {
  GCP_COMPUTE_API,
  mergeMetadataItems,
  mintPinnedGcpAccessToken,
  postInstanceMetadata,
  readComputeInstance,
  renderMetadataItems,
  utf8Sha256Hex,
} from "./actuate.js";

/** The ONE metadata key this op writes. */
const STARTUP_SCRIPT_KEY = "startup-script";
/** A live key that makes a boot run another script than `startup-script`: the op refuses such a node. */
const STARTUP_SCRIPT_URL_KEY = "startup-script-url";

/**
 * The readonly keys a pin bump may change. FIXED here, not a param, so no caller can widen it: these are
 * the platform's own public bundle pin (cell-bootstrap.ts CELL_BUNDLE_URL / CELL_BUNDLE_SHA256).
 */
export const PIN_BUMP_CHANGEABLE_KEYS: readonly string[] = ["DY_BUNDLE_URL", "DY_BUNDLE_SHA256"];

/** The sigil every Worker placeholder starts with (actuate.ts METADATA_PLACEHOLDER_NAMES). */
const PLACEHOLDER_SIGIL = "@@";

/** Every line at column 0 that starts with this is part of the readonly block and must parse. */
const READONLY_LINE_PREFIX = "readonly ";

/**
 * The renderer's exact line form (orchestrator cell-bootstrap.ts renderStartupScript + shellSingleQuote):
 * `readonly KEY='value'`, where a `'` inside the value is written as `'\''`. KEY is the template's
 * `# @inject` grammar. Nothing may follow the closing quote. The two alternatives inside the quotes start
 * with different characters, so the match is linear.
 */
const READONLY_LINE_RE = /^readonly ([A-Z][A-Z0-9_]*)='(?:[^']|'\\'')*'$/;
/** Only to NAME the key of a line that does not parse; a name of another shape is not echoed. */
const READONLY_KEY_PREFIX_RE = /^readonly ([A-Z][A-Z0-9_]*)=/;

/** One fault of a readonly block. `key` is null when the line has no key of the grammar. */
export interface ReadonlyBlockFault {
  key: string | null;
  /** 1-based line number in the script. */
  line: number;
  reason: "unparseable" | "duplicate";
}

export interface ParsedReadonlyBlock {
  /**
   * KEY -> the WHOLE line, byte for byte. Kept inside this file for the comparison only; it holds
   * substituted secrets and must never reach an answer, a detail or a log.
   */
  linesByKey: Map<string, string>;
  /** The keys in script order. */
  keys: string[];
  faults: ReadonlyBlockFault[];
}

/**
 * Parse the readonly block of one script: every line at column 0 that starts with `readonly `. PURE and
 * exported for the unit tests. A line that is not in the renderer's exact form, and a key named twice,
 * are faults: the comparison cannot say what such a line means, so the op refuses rather than guess.
 */
export function parseReadonlyBlock(script: string): ParsedReadonlyBlock {
  const linesByKey = new Map<string, string>();
  const keys: string[] = [];
  const faults: ReadonlyBlockFault[] = [];
  const lines = script.split("\n");

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] as string;
    if (!line.startsWith(READONLY_LINE_PREFIX)) {
      continue;
    }
    const lineNumber = index + 1;
    const match = READONLY_LINE_RE.exec(line);
    if (match === null) {
      const keyMatch = READONLY_KEY_PREFIX_RE.exec(line);
      let namedKey: string | null = null;
      if (keyMatch !== null && keyMatch[1] !== undefined) {
        namedKey = keyMatch[1];
      }
      faults.push({ key: namedKey, line: lineNumber, reason: "unparseable" });
      continue;
    }
    const key = match[1] as string;
    if (linesByKey.has(key)) {
      faults.push({ key, line: lineNumber, reason: "duplicate" });
      continue;
    }
    linesByKey.set(key, line);
    keys.push(key);
  }
  return { linesByKey, keys, faults };
}

/** Why one key, or the whole node, is refused. Names and classes only. */
export interface StartupScriptPinRefusal {
  /** The readonly key, the metadata key (no-startup-script / startup-script-url), or null (no key known). */
  key: string | null;
  reason: "changed" | "added" | "unparseable" | "duplicate" | "no-readonly-block" | "no-startup-script" | "startup-script-url";
  /** Which script the fault is in: the node's live script or the platform's render. */
  side: "live" | "render";
  /** 1-based line number, for unparseable / duplicate lines. */
  line?: number;
}

/** What the comparison of the two readonly blocks decided. */
export type ReadonlyBlockVerdict =
  | { allowed: true; changedKeys: string[]; addedKeys: string[]; removedKeys: string[] }
  | { allowed: false; refusals: StartupScriptPinRefusal[] };

/**
 * Compare the live block with the substituted render's block, by key (design §5.3). PURE and exported
 * for the unit tests. `templateScript` is the render BEFORE substitution: a key whose template line
 * carries a placeholder holds an agency value once substituted, and a pin bump must not be the first
 * write of an agency value.
 */
export function compareReadonlyBlocks(input: {
  liveScript: string;
  renderedScript: string;
  templateScript: string;
}): ReadonlyBlockVerdict {
  const live = parseReadonlyBlock(input.liveScript);
  const rendered = parseReadonlyBlock(input.renderedScript);
  const template = parseReadonlyBlock(input.templateScript);

  // Faults first: when either block cannot be read, a key-by-key comparison would be a guess.
  const faultRefusals: StartupScriptPinRefusal[] = [];
  for (const fault of live.faults) {
    faultRefusals.push({ key: fault.key, reason: fault.reason, side: "live", line: fault.line });
  }
  for (const fault of rendered.faults) {
    faultRefusals.push({ key: fault.key, reason: fault.reason, side: "render", line: fault.line });
  }
  if (live.keys.length === 0 && live.faults.length === 0) {
    // A hand-built node, or a script of another shape: there is no block to keep, so nothing proves
    // that a write keeps the node's values.
    faultRefusals.push({ key: null, reason: "no-readonly-block", side: "live" });
  }
  if (rendered.keys.length === 0 && rendered.faults.length === 0) {
    faultRefusals.push({ key: null, reason: "no-readonly-block", side: "render" });
  }
  if (faultRefusals.length > 0) {
    return { allowed: false, refusals: faultRefusals };
  }

  const refusals: StartupScriptPinRefusal[] = [];
  const changedKeys: string[] = [];
  const addedKeys: string[] = [];
  const removedKeys: string[] = [];

  for (const key of rendered.keys) {
    const renderedLine = rendered.linesByKey.get(key) as string;
    const liveLine = live.linesByKey.get(key);

    if (liveLine === undefined) {
      // The template carries the line on every node of the role; the substitution only changes text
      // inside values, so the template parses to the same keys as the render.
      const templateLine = template.linesByKey.get(key);
      const carriesPlaceholder = templateLine === undefined || templateLine.includes(PLACEHOLDER_SIGIL);
      if (carriesPlaceholder) {
        refusals.push({ key, reason: "added", side: "render" });
        continue;
      }
      addedKeys.push(key);
      continue;
    }
    if (liveLine === renderedLine) {
      continue;
    }
    if (PIN_BUMP_CHANGEABLE_KEYS.includes(key)) {
      changedKeys.push(key);
      continue;
    }
    refusals.push({ key, reason: "changed", side: "render" });
  }

  for (const key of live.keys) {
    if (!rendered.linesByKey.has(key)) {
      removedKeys.push(key);
    }
  }

  if (refusals.length > 0) {
    return { allowed: false, refusals };
  }
  return { allowed: true, changedKeys, addedKeys, removedKeys };
}

/** One refusal as a phrase for the detail string: names, classes and line numbers only. */
function describeRefusal(refusal: StartupScriptPinRefusal): string {
  let subject = "a line";
  if (refusal.key !== null) {
    subject = refusal.key;
  }
  let where = `in the ${refusal.side} script`;
  if (refusal.line !== undefined) {
    where = `${where} (line ${refusal.line})`;
  }
  if (refusal.reason === "no-readonly-block") {
    return `the ${refusal.side} script has no readonly block in the renderer's form`;
  }
  if (refusal.reason === "no-startup-script") {
    return "the instance has no startup-script to pin";
  }
  if (refusal.reason === "startup-script-url") {
    return "the instance also boots from startup-script-url";
  }
  return `${subject}: ${refusal.reason} ${where}`;
}

// The answer (design §5.3). `outcome` is the discriminant the pin job keys on; never match `detail`.
//   written          — the new script is in place (the write's operation reached DONE).
//   unchanged        — the live script already equals the substituted render; nothing written.
//   refused          — a readonly value would change (or a block cannot be read); nothing written.
//   staleFingerprint — the metadata changed between this op's read and its write; nothing written, and
//                      the op does not retry: the next run reads and compares again.
//   failed           — anything else (token, read, write). `unconfirmed` when the write may be in place.
// `refused`, `staleFingerprint` and `failed` are ok:false, so a pin that did not move never reads as a
// success.
export type GcpInstanceStartupScriptPinResult =
  | {
      ok: true;
      op: "gcp-instance-startup-script-pin";
      instanceName: string;
      outcome: "written";
      /** The metadata fingerprint the comparison read and the write was made under. */
      fingerprintBefore: string;
      /** sha256 hex of the WHOLE script as written (what gcp-instance-get reports once it is in place). */
      valueSha256: string;
      /** The bundle keys whose line changed (a subset of PIN_BUMP_CHANGEABLE_KEYS). */
      changedKeys: string[];
      /** Keys the render added (their template line carried no placeholder). */
      addedKeys: string[];
      /** Keys the render removed. */
      removedKeys: string[];
      placeholdersSubstituted: string[];
      operationName: string;
    }
  | {
      ok: true;
      op: "gcp-instance-startup-script-pin";
      instanceName: string;
      outcome: "unchanged";
      fingerprint: string;
      valueSha256: string;
    }
  | {
      ok: false;
      op: "gcp-instance-startup-script-pin";
      instanceName: string;
      outcome: "refused";
      fingerprint: string;
      refusals: StartupScriptPinRefusal[];
      detail: string;
    }
  | {
      ok: false;
      op: "gcp-instance-startup-script-pin";
      instanceName: string;
      outcome: "staleFingerprint";
      staleFingerprint: true;
      detail: string;
    }
  | {
      ok: false;
      op: "gcp-instance-startup-script-pin";
      instanceName: string;
      outcome: "failed";
      detail: string;
      unconfirmed?: true;
    };

export async function actuateGcpInstanceStartupScriptPin(
  params: GcpInstanceStartupScriptPinParams,
  env: Env,
): Promise<GcpInstanceStartupScriptPinResult> {
  const { project, zone } = params;
  const instanceName = params.name;
  const op = "gcp-instance-startup-script-pin";
  const failure = (detail: string): GcpInstanceStartupScriptPinResult => ({ ok: false, op, instanceName, outcome: "failed", detail });

  // Step 1 — substitute before any token or call, exactly as gcp-instance-set-metadata does.
  const rendered = renderMetadataItems([{ key: STARTUP_SCRIPT_KEY, value: params.startupScript }], env);
  if (!rendered.ok) {
    return failure(rendered.detail);
  }
  const renderedScript = (rendered.renderedItems[0] as { value: string }).value;

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const accessToken = token.accessToken;
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const zonePath = `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}/zones/${encodeURIComponent(zone)}`;
  const instanceUrl = `${zonePath}/instances/${encodeURIComponent(instanceName)}`;
  const what = `instance "${instanceName}"`;

  // Step 2 — one read: the fingerprint the comparison and the write both use.
  const current = await readComputeInstance({ url: instanceUrl, accessToken, what, project });
  if (!current.ok) {
    return failure(current.detail);
  }
  const fingerprint = current.instance.metadata?.fingerprint;
  if (typeof fingerprint !== "string" || fingerprint.length === 0) {
    return failure(`${what} returned no metadata fingerprint — refusing to write metadata without the concurrency guard.`);
  }
  const existingItems = current.instance.metadata?.items ?? [];

  const refuse = (refusals: StartupScriptPinRefusal[]): GcpInstanceStartupScriptPinResult => ({
    ok: false,
    op,
    instanceName,
    outcome: "refused",
    fingerprint,
    refusals,
    detail:
      `refusing to move the boot pin of ${what}: ${refusals.map(describeRefusal).join("; ")} — nothing was written. ` +
      "A change of a readonly value other than the bundle lines goes through the deliberate hand publish.",
  });

  // A boot that also runs startup-script-url would run a script this guard never saw.
  const urlEntry = existingItems.find((entry) => entry.key === STARTUP_SCRIPT_URL_KEY);
  if (urlEntry !== undefined) {
    return refuse([{ key: STARTUP_SCRIPT_URL_KEY, reason: "startup-script-url", side: "live" }]);
  }
  const liveEntry = existingItems.find((entry) => entry.key === STARTUP_SCRIPT_KEY);
  if (liveEntry === undefined || typeof liveEntry.value !== "string" || liveEntry.value.length === 0) {
    return refuse([{ key: STARTUP_SCRIPT_KEY, reason: "no-startup-script", side: "live" }]);
  }
  const liveScript = liveEntry.value;

  const valueSha256 = await utf8Sha256Hex(renderedScript);

  // Step 3 — already in place: nothing to write.
  if (liveScript === renderedScript) {
    return { ok: true, op, instanceName, outcome: "unchanged", fingerprint, valueSha256 };
  }

  // Step 4 — the guard.
  const verdict = compareReadonlyBlocks({ liveScript, renderedScript, templateScript: params.startupScript });
  if (!verdict.allowed) {
    return refuse(verdict.refusals);
  }

  // Step 5 — `startup-script` only; every other key survives verbatim and in place.
  const mergedItems = mergeMetadataItems(existingItems, [{ key: STARTUP_SCRIPT_KEY, value: renderedScript }]);
  const written = await postInstanceMetadata({ zonePath, instanceUrl, accessToken, what, project, fingerprint, items: mergedItems });
  if (!written.ok && written.staleFingerprint === true) {
    return { ok: false, op, instanceName, outcome: "staleFingerprint", staleFingerprint: true, detail: written.detail };
  }
  if (!written.ok) {
    const writeFailure: GcpInstanceStartupScriptPinResult = { ok: false, op, instanceName, outcome: "failed", detail: written.detail };
    if (written.unconfirmed === true) {
      writeFailure.unconfirmed = true;
    }
    return writeFailure;
  }

  return {
    ok: true,
    op,
    instanceName,
    outcome: "written",
    fingerprintBefore: fingerprint,
    valueSha256,
    changedKeys: verdict.changedKeys,
    addedKeys: verdict.addedKeys,
    removedKeys: verdict.removedKeys,
    placeholdersSubstituted: rendered.placeholdersSubstituted,
    operationName: written.operationName,
  };
}
