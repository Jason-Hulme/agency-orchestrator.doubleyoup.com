// hub#476 / planning/58 §6 — the PARAMS of the eleven self-hosted server ops (agency Worker side):
//   SSH ops (§6.2):        host-ssh-check, host-bootstrap, host-repair
//   host-agent ops (§6.3): host-network-ensure, host-vm-create, host-vm-get, host-vm-list, host-vm-delete,
//                          host-vm-restart, host-vm-snapshot, host-vm-set-boot-script
//
// WHY A FILE OF ITS OWN. dispatch-params.ts is shared by many branches at once. These validators sit here so a
// parallel branch that appends to dispatch-params.ts does not conflict with this one (the custom-hostname pattern).
//
// ── TWIN of the app's agency-dispatch-params and the orchestrator's agency-dispatch.ts ──────────────────
// The block between the two markers below is the pinned twin of planning/58 §6.1: app (which refuses to sign what
// this side would reject) and the orchestrator carry it byte for byte, and each repo's suite pins its sha256
// (test/host-ops.test.ts here). A rule changed on one side only fails that side's suite. The header above the block
// may differ between the repos.
//
// WHAT IS NOT IN THE TWIN. The Worker's own pins (SELF_HOSTED_<N>_HOST_KEY, HOST_INSTALLER_ORIGIN,
// HOST_INSTALLER_SHA256S) are read from the agency's Worker configuration in actuate-host.ts, never from a job.

import type { ParamsVerdict } from "./dispatch-params.js";

// ── self-hosted server ops (hub#476): twin block start
/** The eleven op names. They match the orchestrator's and app's twins exactly. */
export const HOST_SSH_OPS = ["host-ssh-check", "host-bootstrap", "host-repair"] as const;
export const HOST_AGENT_OPS = [
  "host-network-ensure",
  "host-vm-create",
  "host-vm-get",
  "host-vm-list",
  "host-vm-delete",
  "host-vm-restart",
  "host-vm-snapshot",
  "host-vm-set-boot-script",
] as const;
export type HostSshOp = (typeof HOST_SSH_OPS)[number];
export type HostAgentOp = (typeof HOST_AGENT_OPS)[number];

/** The VM size names of planning/58 §4.3. */
export const HOST_VM_SIZES = ["dy-s", "dy-m", "dy-l", "dy-xl"] as const;
export type HostVmSize = (typeof HOST_VM_SIZES)[number];
export const HOST_VM_ROLES = ["web", "file", "data", "gateway"] as const;
export type HostVmRole = (typeof HOST_VM_ROLES)[number];
/** The only image a job may name. The host-agent holds its URL and sha256; a job never names an image URL. */
export const HOST_VM_IMAGES = ["debian-12"] as const;
export type HostVmImage = (typeof HOST_VM_IMAGES)[number];
/** The metadata keys the shim serves (planning/58 §5.3). Widening this is a reviewed decision in all three repos. */
export const HOST_BOOT_SCRIPT_KEYS = ["startup-script", "dy-update-hold"] as const;
export type HostBootScriptKey = (typeof HOST_BOOT_SCRIPT_KEYS)[number];

export const HOST_CELL_ID_RE = /^[a-z0-9]{16,40}$/;
export const HOST_DNS_NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
export const HOST_DNS_NAME_MAX_LENGTH = 253;
export const HOST_USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
export const HOST_KEY_FINGERPRINT_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;
export const HOST_LABEL_RE = /^[a-z][a-z0-9-]{0,30}[a-z0-9]$/;
export const HOST_VM_NAME_RE = /^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$/;
export const HOST_NETWORK_NAME_RE = /^dy-cell-[a-z][a-z0-9-]{0,30}[a-z0-9]$/;
export const HOST_SUBNET_RE = /^10\.40\.(0|[1-9][0-9]{0,2})\.0\/24$/;
export const HOST_VM_IP_RE = /^10\.40\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/;
export const HOST_TUNNEL_ID_RE = /^([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
export const HOST_SHA256_RE = /^[a-f0-9]{64}$/;
export const HOST_INSTALLER_URL_MAX_LENGTH = 512;
/** The metadata fingerprint grammar of the GCP pinned twin (GCP_METADATA_FINGERPRINT_RE), reused per §6.3. */
export const HOST_METADATA_FINGERPRINT_RE = /^[A-Za-z0-9+/=_-]{1,64}$/;
export const HOST_SCRIPT_MAX_BYTES = 256 * 1024;
export const HOST_BOOT_SCRIPT_ITEMS_MAX = 8;
export const HOST_SFTP_PORT_MIN = 1024;
export const HOST_KEY_INDEX_MAX = 99;
export const HOST_BOOT_DISK_GB_MIN = 10;
export const HOST_BOOT_DISK_GB_MAX = 500;
export const HOST_DATA_DISK_GB_MIN = 10;
export const HOST_DATA_DISK_GB_MAX = 65536;

/** host-ssh-check: the five connection facts every SSH op carries. */
export interface HostSshTargetParams {
  host: string;
  port: number;
  user: string;
  keyIndex: number;
  hostKeyFingerprint: string;
}
export type HostSshCheckParams = HostSshTargetParams;

/** host-bootstrap and host-repair (the same params, the same installer). */
export interface HostBootstrapParams extends HostSshTargetParams {
  cellId: string;
  label: string;
  subnet: string;
  networkName: string;
  sftpPort: number;
  hostAgentHost: string;
  tunnelId: string;
  mode: "start" | "poll";
  installerUrl: string;
  installerSha256: string;
}

/** Every host-agent op carries these two. */
export interface HostAgentTargetParams {
  cellId: string;
  hostAgentUrl: string;
}
export interface HostNetworkEnsureParams extends HostAgentTargetParams {
  desired: "present" | "absent";
  networkName: string;
  subnet: string;
  sftpPort: number;
}
export interface HostVmCreateParams extends HostAgentTargetParams {
  name: string;
  role: HostVmRole;
  size: HostVmSize;
  ip: string;
  bootDiskGb: number;
  image: HostVmImage;
  dataDiskGb?: number;
  startupScript?: string;
}
export interface HostVmNameParams extends HostAgentTargetParams {
  name: string;
}
export type HostVmGetParams = HostVmNameParams;
export type HostVmListParams = HostAgentTargetParams;
export type HostVmDeleteParams = HostVmNameParams;
export type HostVmRestartParams = HostVmNameParams;
export interface HostVmSnapshotParams extends HostVmNameParams {
  snapshotName: string;
}
export interface HostBootScriptItem {
  key: HostBootScriptKey;
  value: string;
}
export interface HostVmSetBootScriptParams extends HostVmNameParams {
  items: HostBootScriptItem[];
  expectedFingerprint?: string;
}

/** True for a dotted-quad IPv4 literal with every octet 0-255 and no leading zero. */
export function isIpv4Literal(value: string): boolean {
  const octets = value.split(".");
  if (octets.length !== 4) {
    return false;
  }
  for (const octet of octets) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(octet) || Number(octet) > 255) {
      return false;
    }
  }
  return true;
}

/**
 * True for an IPv4 literal the Worker may connect to: not RFC 1918, loopback, link-local, CGNAT, "this network"
 * (0/8) or multicast/reserved (224/3). Only a public address of the agency's own server.
 */
export function isPublicIpv4(value: string): boolean {
  if (!isIpv4Literal(value)) {
    return false;
  }
  const [first, second] = value.split(".").map(Number);
  if (first === 0 || first === 10 || first === 127 || first >= 224) {
    return false;
  }
  if (first === 172 && second >= 16 && second <= 31) {
    return false;
  }
  if (first === 192 && second === 168) {
    return false;
  }
  if (first === 169 && second === 254) {
    return false;
  }
  if (first === 100 && second >= 64 && second <= 127) {
    return false;
  }
  return true;
}

/** True for a lowercase DNS name that is not all-numeric labels (those must pass as a public IPv4 instead). */
export function isHostDnsName(value: unknown): value is string {
  if (typeof value !== "string" || value.length > HOST_DNS_NAME_MAX_LENGTH || !HOST_DNS_NAME_RE.test(value)) {
    return false;
  }
  const allNumeric = value.split(".").every((label) => /^[0-9]+$/.test(label));
  return !allNumeric;
}

/** `host`: a lowercase DNS name or a public IPv4 address. */
export function isSshHost(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  if (isIpv4Literal(value)) {
    return isPublicIpv4(value);
  }
  return isHostDnsName(value);
}

/** `hostAgentUrl`: exactly `https://<lowercase DNS host>`, no path, port, query or user part. */
export function isHostAgentUrl(value: unknown): value is string {
  const scheme = "https://";
  if (typeof value !== "string" || !value.startsWith(scheme)) {
    return false;
  }
  return isHostDnsName(value.slice(scheme.length));
}

/** `installerUrl`: `https://<lowercase DNS host>/<path>`, no query, fragment, quote or space, at most 512 chars. */
export function isInstallerUrl(value: unknown): value is string {
  const scheme = "https://";
  if (typeof value !== "string" || value.length > HOST_INSTALLER_URL_MAX_LENGTH || !value.startsWith(scheme)) {
    return false;
  }
  const rest = value.slice(scheme.length);
  const slashAt = rest.indexOf("/");
  if (slashAt <= 0) {
    return false;
  }
  if (!isHostDnsName(rest.slice(0, slashAt))) {
    return false;
  }
  const path = rest.slice(slashAt);
  return /^\/[A-Za-z0-9._~\/-]+$/.test(path) && !path.includes("..");
}

/** `subnet`: `10.40.N.0/24` with N 0-255. */
export function isHostSubnet(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  const match = HOST_SUBNET_RE.exec(value);
  return match !== null && Number(match[1]) <= 255;
}

/** A VM address inside the 10.40.0.0/16 pool: not the network (.0), the host bridge (.1) or the broadcast (.255). */
export function isHostVmIp(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  const match = HOST_VM_IP_RE.exec(value);
  if (match === null) {
    return false;
  }
  const cellOctet = Number(match[1]);
  const hostOctet = Number(match[2]);
  return cellOctet <= 255 && hostOctet >= 2 && hostOctet <= 254;
}

function isIntegerInRange(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= minimum && value <= maximum;
}

function utf8Length(text: string): number {
  return new TextEncoder().encode(text).length;
}

/** A fresh-object guard: a plain object whose keys are all in `allowed` and include every key in `required`. */
function checkKeys(raw: unknown, required: readonly string[], optional: readonly string[]): { ok: true; object: Record<string, unknown> } | { ok: false; reason: string } {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const object = raw as Record<string, unknown>;
  for (const key of Object.keys(object)) {
    if (!required.includes(key) && !optional.includes(key)) {
      return { ok: false, reason: `unknown param "${key}"` };
    }
  }
  for (const key of required) {
    if (!(key in object)) {
      return { ok: false, reason: `missing param "${key}"` };
    }
  }
  return { ok: true, object };
}

const SSH_TARGET_KEYS = ["host", "port", "user", "keyIndex", "hostKeyFingerprint"] as const;

function sshTargetVerdict(object: Record<string, unknown>): ParamsVerdict<HostSshTargetParams> {
  const { host, port, user, keyIndex, hostKeyFingerprint } = object;
  if (!isSshHost(host)) {
    return { ok: false, reason: "host must be a lowercase DNS name or a public IPv4 address (not private, loopback, link-local or CGNAT)" };
  }
  if (!isIntegerInRange(port, 1, 65535)) {
    return { ok: false, reason: "port must be an integer 1-65535" };
  }
  if (typeof user !== "string" || !HOST_USER_RE.test(user)) {
    return { ok: false, reason: "user must match ^[a-z_][a-z0-9_-]{0,31}$" };
  }
  if (!isIntegerInRange(keyIndex, 1, HOST_KEY_INDEX_MAX)) {
    return { ok: false, reason: `keyIndex must be an integer 1-${HOST_KEY_INDEX_MAX}` };
  }
  if (typeof hostKeyFingerprint !== "string" || !HOST_KEY_FINGERPRINT_RE.test(hostKeyFingerprint)) {
    return { ok: false, reason: "hostKeyFingerprint must be an OpenSSH SHA256 fingerprint, SHA256:<43 base64 chars>" };
  }
  return { ok: true, params: { host, port, user, keyIndex, hostKeyFingerprint } };
}

export function validateHostSshCheckParams(raw: unknown): ParamsVerdict<HostSshCheckParams> {
  const keys = checkKeys(raw, SSH_TARGET_KEYS, []);
  if (!keys.ok) {
    return keys;
  }
  return sshTargetVerdict(keys.object);
}

export function validateHostBootstrapParams(raw: unknown): ParamsVerdict<HostBootstrapParams> {
  const required = [
    ...SSH_TARGET_KEYS,
    "cellId",
    "label",
    "subnet",
    "networkName",
    "sftpPort",
    "hostAgentHost",
    "tunnelId",
    "mode",
    "installerUrl",
    "installerSha256",
  ];
  const keys = checkKeys(raw, required, []);
  if (!keys.ok) {
    return keys;
  }
  const target = sshTargetVerdict(keys.object);
  if (!target.ok) {
    return target;
  }
  const facts = enrolFactsVerdict(keys.object);
  if (!facts.ok) {
    return facts;
  }
  const { mode, installerUrl, installerSha256 } = keys.object;
  if (mode !== "start" && mode !== "poll") {
    return { ok: false, reason: 'mode must be "start" or "poll"' };
  }
  if (!isInstallerUrl(installerUrl)) {
    return { ok: false, reason: "installerUrl must be https://<lowercase host>/<path> with no query, fragment, quote or space (at most 512 chars)" };
  }
  if (typeof installerSha256 !== "string" || !HOST_SHA256_RE.test(installerSha256)) {
    return { ok: false, reason: "installerSha256 must be 64 lowercase hex characters" };
  }
  return { ok: true, params: { ...target.params, ...facts.params, mode, installerUrl, installerSha256 } };
}

/** The cell facts a bootstrap carries; the same set is the manual enrol blob (planning/58 §7.4). */
export interface HostEnrolFacts {
  cellId: string;
  label: string;
  subnet: string;
  networkName: string;
  sftpPort: number;
  hostAgentHost: string;
  tunnelId: string;
}
export const HOST_ENROL_FACT_KEYS = ["cellId", "label", "subnet", "networkName", "sftpPort", "hostAgentHost", "tunnelId"] as const;

/** Validate the seven cell facts. `networkName` must be `dy-cell-<label>`, `hostAgentHost` `cell-<label>-host.<zone>`. */
export function enrolFactsVerdict(object: Record<string, unknown>): ParamsVerdict<HostEnrolFacts> {
  const { cellId, label, subnet, networkName, sftpPort, hostAgentHost, tunnelId } = object;
  if (typeof cellId !== "string" || !HOST_CELL_ID_RE.test(cellId)) {
    return { ok: false, reason: "cellId must match ^[a-z0-9]{16,40}$" };
  }
  if (typeof label !== "string" || !HOST_LABEL_RE.test(label)) {
    return { ok: false, reason: "label must match ^[a-z][a-z0-9-]{0,30}[a-z0-9]$" };
  }
  if (!isHostSubnet(subnet)) {
    return { ok: false, reason: "subnet must be 10.40.N.0/24 with N 0-255" };
  }
  if (networkName !== `dy-cell-${label}`) {
    return { ok: false, reason: "networkName must be exactly dy-cell-<label>" };
  }
  if (!isIntegerInRange(sftpPort, HOST_SFTP_PORT_MIN, 65535)) {
    return { ok: false, reason: `sftpPort must be an integer ${HOST_SFTP_PORT_MIN}-65535` };
  }
  if (!isHostDnsName(hostAgentHost) || !hostAgentHost.startsWith(`cell-${label}-host.`)) {
    return { ok: false, reason: "hostAgentHost must be the lowercase DNS name cell-<label>-host.<zone>" };
  }
  if (typeof tunnelId !== "string" || !HOST_TUNNEL_ID_RE.test(tunnelId)) {
    return { ok: false, reason: "tunnelId must be a Cloudflare tunnel id (32 hex, or a dashed UUID)" };
  }
  return { ok: true, params: { cellId, label, subnet, networkName, sftpPort, hostAgentHost, tunnelId } };
}

const AGENT_TARGET_KEYS = ["cellId", "hostAgentUrl"] as const;

function agentTargetVerdict(object: Record<string, unknown>): ParamsVerdict<HostAgentTargetParams> {
  const { cellId, hostAgentUrl } = object;
  if (typeof cellId !== "string" || !HOST_CELL_ID_RE.test(cellId)) {
    return { ok: false, reason: "cellId must match ^[a-z0-9]{16,40}$" };
  }
  if (!isHostAgentUrl(hostAgentUrl)) {
    return { ok: false, reason: "hostAgentUrl must be exactly https://<lowercase DNS host> (no path, port, query or user part)" };
  }
  return { ok: true, params: { cellId, hostAgentUrl } };
}

function vmNameVerdict(value: unknown, what: string): { ok: true; name: string } | { ok: false; reason: string } {
  if (typeof value !== "string" || !HOST_VM_NAME_RE.test(value)) {
    return { ok: false, reason: `${what} must match ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$` };
  }
  return { ok: true, name: value };
}

export function validateHostNetworkEnsureParams(raw: unknown): ParamsVerdict<HostNetworkEnsureParams> {
  const keys = checkKeys(raw, [...AGENT_TARGET_KEYS, "desired", "networkName", "subnet", "sftpPort"], []);
  if (!keys.ok) {
    return keys;
  }
  const target = agentTargetVerdict(keys.object);
  if (!target.ok) {
    return target;
  }
  const { desired, networkName, subnet, sftpPort } = keys.object;
  if (desired !== "present" && desired !== "absent") {
    return { ok: false, reason: 'desired must be "present" or "absent"' };
  }
  if (typeof networkName !== "string" || !HOST_NETWORK_NAME_RE.test(networkName)) {
    return { ok: false, reason: "networkName must be dy-cell-<label>" };
  }
  if (!isHostSubnet(subnet)) {
    return { ok: false, reason: "subnet must be 10.40.N.0/24 with N 0-255" };
  }
  if (!isIntegerInRange(sftpPort, HOST_SFTP_PORT_MIN, 65535)) {
    return { ok: false, reason: `sftpPort must be an integer ${HOST_SFTP_PORT_MIN}-65535` };
  }
  return { ok: true, params: { ...target.params, desired, networkName, subnet, sftpPort } };
}

export function validateHostVmCreateParams(raw: unknown): ParamsVerdict<HostVmCreateParams> {
  const keys = checkKeys(raw, [...AGENT_TARGET_KEYS, "name", "role", "size", "ip", "bootDiskGb", "image"], ["dataDiskGb", "startupScript"]);
  if (!keys.ok) {
    return keys;
  }
  const target = agentTargetVerdict(keys.object);
  if (!target.ok) {
    return target;
  }
  const { role, size, ip, bootDiskGb, image, dataDiskGb, startupScript } = keys.object;
  const name = vmNameVerdict(keys.object.name, "name");
  if (!name.ok) {
    return name;
  }
  if (typeof role !== "string" || !(HOST_VM_ROLES as readonly string[]).includes(role)) {
    return { ok: false, reason: `role must be one of ${HOST_VM_ROLES.join(", ")}` };
  }
  if (typeof size !== "string" || !(HOST_VM_SIZES as readonly string[]).includes(size)) {
    return { ok: false, reason: `size must be one of ${HOST_VM_SIZES.join(", ")}` };
  }
  if (!isHostVmIp(ip)) {
    return { ok: false, reason: "ip must be an address of the cell subnet 10.40.N.0/24, not .0, .1 or .255" };
  }
  if (!isIntegerInRange(bootDiskGb, HOST_BOOT_DISK_GB_MIN, HOST_BOOT_DISK_GB_MAX)) {
    return { ok: false, reason: `bootDiskGb must be an integer ${HOST_BOOT_DISK_GB_MIN}-${HOST_BOOT_DISK_GB_MAX}` };
  }
  if (typeof image !== "string" || !(HOST_VM_IMAGES as readonly string[]).includes(image)) {
    return { ok: false, reason: `image must be one of ${HOST_VM_IMAGES.join(", ")}` };
  }
  const params: HostVmCreateParams = {
    ...target.params,
    name: name.name,
    role: role as HostVmRole,
    size: size as HostVmSize,
    ip,
    bootDiskGb,
    image: image as HostVmImage,
  };
  if (dataDiskGb !== undefined) {
    if (role !== "file") {
      return { ok: false, reason: "dataDiskGb is allowed only for the file node" };
    }
    if (!isIntegerInRange(dataDiskGb, HOST_DATA_DISK_GB_MIN, HOST_DATA_DISK_GB_MAX)) {
      return { ok: false, reason: `dataDiskGb must be an integer ${HOST_DATA_DISK_GB_MIN}-${HOST_DATA_DISK_GB_MAX}` };
    }
    params.dataDiskGb = dataDiskGb;
  }
  if (startupScript !== undefined) {
    if (typeof startupScript !== "string" || startupScript.length === 0 || utf8Length(startupScript) > HOST_SCRIPT_MAX_BYTES) {
      return { ok: false, reason: `startupScript must be a non-empty string of at most ${HOST_SCRIPT_MAX_BYTES} bytes` };
    }
    params.startupScript = startupScript;
  }
  return { ok: true, params };
}

function validateHostVmNameOnly(raw: unknown): ParamsVerdict<HostVmNameParams> {
  const keys = checkKeys(raw, [...AGENT_TARGET_KEYS, "name"], []);
  if (!keys.ok) {
    return keys;
  }
  const target = agentTargetVerdict(keys.object);
  if (!target.ok) {
    return target;
  }
  const name = vmNameVerdict(keys.object.name, "name");
  if (!name.ok) {
    return name;
  }
  return { ok: true, params: { ...target.params, name: name.name } };
}

export function validateHostVmGetParams(raw: unknown): ParamsVerdict<HostVmGetParams> {
  return validateHostVmNameOnly(raw);
}

export function validateHostVmDeleteParams(raw: unknown): ParamsVerdict<HostVmDeleteParams> {
  return validateHostVmNameOnly(raw);
}

export function validateHostVmRestartParams(raw: unknown): ParamsVerdict<HostVmRestartParams> {
  return validateHostVmNameOnly(raw);
}

export function validateHostVmListParams(raw: unknown): ParamsVerdict<HostVmListParams> {
  const keys = checkKeys(raw, AGENT_TARGET_KEYS, []);
  if (!keys.ok) {
    return keys;
  }
  return agentTargetVerdict(keys.object);
}

export function validateHostVmSnapshotParams(raw: unknown): ParamsVerdict<HostVmSnapshotParams> {
  const keys = checkKeys(raw, [...AGENT_TARGET_KEYS, "name", "snapshotName"], []);
  if (!keys.ok) {
    return keys;
  }
  const target = agentTargetVerdict(keys.object);
  if (!target.ok) {
    return target;
  }
  const name = vmNameVerdict(keys.object.name, "name");
  if (!name.ok) {
    return name;
  }
  const snapshotName = vmNameVerdict(keys.object.snapshotName, "snapshotName");
  if (!snapshotName.ok) {
    return snapshotName;
  }
  return { ok: true, params: { ...target.params, name: name.name, snapshotName: snapshotName.name } };
}

export function validateHostVmSetBootScriptParams(raw: unknown): ParamsVerdict<HostVmSetBootScriptParams> {
  const keys = checkKeys(raw, [...AGENT_TARGET_KEYS, "name", "items"], ["expectedFingerprint"]);
  if (!keys.ok) {
    return keys;
  }
  const target = agentTargetVerdict(keys.object);
  if (!target.ok) {
    return target;
  }
  const name = vmNameVerdict(keys.object.name, "name");
  if (!name.ok) {
    return name;
  }
  const { items, expectedFingerprint } = keys.object;
  if (!Array.isArray(items) || items.length === 0 || items.length > HOST_BOOT_SCRIPT_ITEMS_MAX) {
    return { ok: false, reason: `items must be an array of 1-${HOST_BOOT_SCRIPT_ITEMS_MAX} entries` };
  }
  const cleanItems: HostBootScriptItem[] = [];
  const seenKeys: string[] = [];
  for (const item of items) {
    const itemKeys = checkKeys(item, ["key", "value"], []);
    if (!itemKeys.ok) {
      return { ok: false, reason: `each items entry must be exactly { key, value }: ${itemKeys.reason}` };
    }
    const { key, value } = itemKeys.object;
    if (typeof key !== "string" || !(HOST_BOOT_SCRIPT_KEYS as readonly string[]).includes(key)) {
      return { ok: false, reason: `each items entry's key must be one of ${HOST_BOOT_SCRIPT_KEYS.join(", ")}` };
    }
    if (seenKeys.includes(key)) {
      return { ok: false, reason: `the key "${key}" appears more than once in items` };
    }
    seenKeys.push(key);
    if (typeof value !== "string" || value.length === 0 || utf8Length(value) > HOST_SCRIPT_MAX_BYTES) {
      return { ok: false, reason: `each items entry's value must be a non-empty string of at most ${HOST_SCRIPT_MAX_BYTES} bytes` };
    }
    cleanItems.push({ key: key as HostBootScriptKey, value });
  }
  const params: HostVmSetBootScriptParams = { ...target.params, name: name.name, items: cleanItems };
  if (expectedFingerprint !== undefined) {
    if (typeof expectedFingerprint !== "string" || !HOST_METADATA_FINGERPRINT_RE.test(expectedFingerprint)) {
      return { ok: false, reason: "expectedFingerprint must be a metadata fingerprint (1-64 base64 characters), as host-vm-get reports it" };
    }
    params.expectedFingerprint = expectedFingerprint;
  }
  return { ok: true, params };
}
// ── self-hosted server ops (hub#476): twin block end
