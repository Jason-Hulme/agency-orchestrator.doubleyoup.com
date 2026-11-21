// hub#476 / planning/58 §6.2: a minimal SSH client for the Worker, on `cloudflare:sockets` and Web Crypto only.
//
// WHY OUR OWN CLIENT. The spike of agency-orchestrator#38 tried ssh2 (the maintained Node package) first. Under
// nodejs_compat it only builds with two bundler workarounds (an alias for its native cpu-features module and a
// `__dirname` define), and its pure-JS fallback has no curve25519 key exchange and no working AES-GCM in workerd
// ("No auth tag provided"). It connected only with ecdh-sha2-nistp256 + aes256-ctr. Web Crypto in workerd has every
// primitive the planning/58 profile needs (X25519, Ed25519, AES-GCM, SHA-256), so this file implements exactly that
// profile and nothing else:
//
//   key exchange   curve25519-sha256 (RFC 8731), with OpenSSH strict KEX (kex-strict-c-v00@openssh.com)
//   host key       ssh-ed25519 only, PINNED: the SHA-256 fingerprint must equal the caller's before anything else
//   cipher         aes256-gcm@openssh.com (RFC 5647 as OpenSSH uses it), both directions
//   user auth      publickey with an unencrypted OpenSSH ed25519 private key
//   channel        ONE session channel, ONE exec request, stdin sent then EOF, stdout/stderr/exit status read
//
// There is no re-key, no port forwarding, no agent, no password or keyboard-interactive auth, no compression.
// A server that cannot speak this profile fails the handshake with a clear error.
//
// SECRETS. The private key is parsed into a non-extractable CryptoKey and the PEM text is never logged, returned or
// put in an error. Error messages carry codes and short facts (a fingerprint, an algorithm name), never key bytes.

import { connect } from "cloudflare:sockets";
import {
  SshReader,
  SshWireError,
  SshWriter,
  base64Decode,
  base64Encode,
  bytesEqual,
  concatBytes,
  readUint32,
  sha256Bytes,
  utf8Bytes,
  utf8Text,
} from "./ssh-wire.js";

// ── message numbers (RFC 4250 §4.1) ───────────────────────────────────────────────────────────────
const MSG_DISCONNECT = 1;
const MSG_IGNORE = 2;
const MSG_UNIMPLEMENTED = 3;
const MSG_DEBUG = 4;
const MSG_SERVICE_REQUEST = 5;
const MSG_SERVICE_ACCEPT = 6;
const MSG_EXT_INFO = 7;
const MSG_KEXINIT = 20;
const MSG_NEWKEYS = 21;
const MSG_KEX_ECDH_INIT = 30;
const MSG_KEX_ECDH_REPLY = 31;
const MSG_USERAUTH_REQUEST = 50;
const MSG_USERAUTH_FAILURE = 51;
const MSG_USERAUTH_SUCCESS = 52;
const MSG_USERAUTH_BANNER = 53;
const MSG_GLOBAL_REQUEST = 80;
const MSG_REQUEST_FAILURE = 82;
const MSG_CHANNEL_OPEN = 90;
const MSG_CHANNEL_OPEN_CONFIRMATION = 91;
const MSG_CHANNEL_OPEN_FAILURE = 92;
const MSG_CHANNEL_WINDOW_ADJUST = 93;
const MSG_CHANNEL_DATA = 94;
const MSG_CHANNEL_EXTENDED_DATA = 95;
const MSG_CHANNEL_EOF = 96;
const MSG_CHANNEL_CLOSE = 97;
const MSG_CHANNEL_REQUEST = 98;
const MSG_CHANNEL_SUCCESS = 99;
const MSG_CHANNEL_FAILURE = 100;

// ── the one algorithm profile ─────────────────────────────────────────────────────────────────────
const CLIENT_VERSION = "SSH-2.0-doubleyoup_agency_worker_1";
const KEX_ALGORITHMS = ["curve25519-sha256", "curve25519-sha256@libssh.org"] as const;
const STRICT_KEX_CLIENT_MARKER = "kex-strict-c-v00@openssh.com";
const STRICT_KEX_SERVER_MARKER = "kex-strict-s-v00@openssh.com";
const HOST_KEY_ALGORITHM = "ssh-ed25519";
const CIPHER = "aes256-gcm@openssh.com";
// AES-GCM carries its own integrity, so OpenSSH skips MAC negotiation for it. A name is still sent because the
// KEXINIT format requires a non-empty list.
const MAC_PLACEHOLDER = "hmac-sha2-256";
const COMPRESSION = "none";

const GCM_TAG_LENGTH = 16;
const GCM_BLOCK_SIZE = 16;
const PLAIN_BLOCK_SIZE = 8;
const MAX_PACKET_LENGTH = 256 * 1024;
const MAX_BANNER_BYTES = 16 * 1024;

// Our receive window. The server may send this many channel bytes before we adjust it.
const LOCAL_WINDOW_SIZE = 2 * 1024 * 1024;
const LOCAL_MAX_PACKET = 32 * 1024;
// The most output one exec may return. A fixed command answers in a few KB; this only bounds a runaway.
const MAX_OUTPUT_BYTES = 1024 * 1024;

/** Why an SSH call failed. Each code maps to one failure class of planning/58 §6.2. */
export type SshFailureCode =
  | "unreachable"
  | "timeout"
  | "host-key-mismatch"
  | "auth-failed"
  | "protocol"
  | "exec-refused";

export class SshError extends Error {
  constructor(
    readonly code: SshFailureCode,
    message: string,
  ) {
    super(message);
  }
}

export interface SshExecRequest {
  hostname: string;
  port: number;
  username: string;
  /** The OpenSSH ed25519 private key, already parsed (parseOpenSshEd25519PrivateKey). */
  privateKey: SshPrivateKey;
  /** The pinned host-key fingerprint, `SHA256:<43 base64 chars>`. The handshake stops when the server's differs. */
  hostKeyFingerprint: string;
  /** The remote command. Fixed text from this Worker: never a job value. */
  command: string;
  /** Bytes for the command's stdin. EOF follows them. */
  stdin: Uint8Array;
  /** Milliseconds for the TCP connect. */
  connectTimeoutMs: number;
  /** Milliseconds for the whole call, connect included. */
  totalTimeoutMs: number;
}

export interface SshExecResult {
  /** The exit status, or null when the server reported a signal or no status. */
  exitCode: number | null;
  stdout: Uint8Array;
  stderr: Uint8Array;
}

// ── private key parsing (the PROTOCOL.key format, "openssh-key-v1") ───────────────────────────────

export interface SshPrivateKey {
  /** The ssh-ed25519 public key blob (string "ssh-ed25519", string key). */
  publicKeyBlob: Uint8Array;
  signingKey: CryptoKey;
}

const OPENSSH_KEY_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
const OPENSSH_KEY_END = "-----END OPENSSH PRIVATE KEY-----";
const OPENSSH_KEY_MAGIC = "openssh-key-v1\0";
// The fixed PKCS#8 header of an Ed25519 private key (RFC 8410): a 32-byte seed follows it.
const ED25519_PKCS8_PREFIX = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20);

/**
 * Parse an unencrypted OpenSSH ed25519 private key. The reason on a refusal names the problem, never a byte of the key.
 * The seed is imported as a non-extractable signing key, and the local copies are zeroed.
 */
export async function parseOpenSshEd25519PrivateKey(pemText: string): Promise<{ ok: true; key: SshPrivateKey } | { ok: false; reason: string }> {
  const begin = pemText.indexOf(OPENSSH_KEY_BEGIN);
  const end = pemText.indexOf(OPENSSH_KEY_END);
  if (begin === -1 || end === -1 || end < begin) {
    return { ok: false, reason: "the key is not an OpenSSH private key (no BEGIN/END OPENSSH PRIVATE KEY lines)" };
  }
  const body = pemText.slice(begin + OPENSSH_KEY_BEGIN.length, end).replace(/\s+/g, "");
  const decoded = base64Decode(body);
  if (decoded === null) {
    return { ok: false, reason: "the key body is not base64" };
  }
  try {
    const magic = utf8Bytes(OPENSSH_KEY_MAGIC);
    if (!bytesEqual(decoded.subarray(0, magic.length), magic)) {
      return { ok: false, reason: "the key is not in the openssh-key-v1 format" };
    }
    const reader = new SshReader(decoded.subarray(magic.length));
    const cipherName = reader.text();
    const kdfName = reader.text();
    reader.string();
    if (cipherName !== "none" || kdfName !== "none") {
      return { ok: false, reason: "the key is encrypted with a passphrase; store an unencrypted key (ssh-keygen -p -N '')" };
    }
    const keyCount = reader.uint32();
    if (keyCount !== 1) {
      return { ok: false, reason: "the key file must hold exactly one key" };
    }
    const publicKeyBlob = reader.string();
    const privateSection = new SshReader(reader.string());
    const checkOne = privateSection.uint32();
    const checkTwo = privateSection.uint32();
    if (checkOne !== checkTwo) {
      return { ok: false, reason: "the key's check values differ (a damaged or encrypted key)" };
    }
    const keyType = privateSection.text();
    if (keyType !== HOST_KEY_ALGORITHM) {
      return { ok: false, reason: `the key type is ${keyType.slice(0, 40)}; only ssh-ed25519 keys are supported` };
    }
    const publicKey = privateSection.string();
    const secretAndPublic = privateSection.string();
    if (publicKey.length !== 32 || secretAndPublic.length !== 64) {
      return { ok: false, reason: "the ed25519 key has the wrong length" };
    }
    const expectedBlob = new SshWriter().string(HOST_KEY_ALGORITHM).string(publicKey).toBytes();
    if (!bytesEqual(expectedBlob, publicKeyBlob)) {
      return { ok: false, reason: "the key's public part does not match its private part" };
    }
    const pkcs8 = concatBytes([ED25519_PKCS8_PREFIX, secretAndPublic.subarray(0, 32)]);
    let signingKey: CryptoKey;
    try {
      signingKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
    } finally {
      pkcs8.fill(0);
      decoded.fill(0);
    }
    return { ok: true, key: { publicKeyBlob: expectedBlob, signingKey } };
  } catch (error) {
    if (error instanceof SshWireError) {
      return { ok: false, reason: "the key file is truncated or malformed" };
    }
    throw error;
  }
}

/** The OpenSSH fingerprint of a public key blob: `SHA256:` + unpadded base64 of its SHA-256. */
export async function sshFingerprint(publicKeyBlob: Uint8Array): Promise<string> {
  return `SHA256:${base64Encode(await sha256Bytes(publicKeyBlob), false)}`;
}

// ── deadline helper ───────────────────────────────────────────────────────────────────────────────

class Deadline {
  private readonly endsAtMs: number;

  constructor(totalMs: number) {
    this.endsAtMs = Date.now() + totalMs;
  }

  remainingMs(): number {
    return Math.max(0, this.endsAtMs - Date.now());
  }

  /** Wait for `promise`, but no longer than `limitMs` (default: the rest of the deadline). */
  async race<T>(promise: Promise<T>, what: string, limitMs?: number): Promise<T> {
    let waitMs = this.remainingMs();
    if (limitMs !== undefined && limitMs < waitMs) {
      waitMs = limitMs;
    }
    let timer: ReturnType<typeof setTimeout> | null = null;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new SshError("timeout", `timed out while ${what}`)), waitMs);
    });
    try {
      return await Promise.race([promise, timeout]);
    } finally {
      if (timer !== null) {
        clearTimeout(timer);
      }
    }
  }
}

// ── the byte stream ───────────────────────────────────────────────────────────────────────────────

/** Buffers the socket's readable side so the transport can read exact byte counts. */
class ByteStream {
  private buffered: Uint8Array = new Uint8Array(0);
  private ended = false;

  constructor(
    private readonly reader: ReadableStreamDefaultReader<Uint8Array>,
    private readonly deadline: Deadline,
  ) {}

  private async fill(): Promise<void> {
    if (this.ended) {
      throw new SshError("protocol", "the server closed the connection");
    }
    const chunk = await this.deadline.race(this.reader.read(), "waiting for the server");
    if (chunk.done) {
      this.ended = true;
      throw new SshError("protocol", "the server closed the connection");
    }
    this.buffered = concatBytes([this.buffered, chunk.value]);
  }

  async readExact(count: number): Promise<Uint8Array> {
    while (this.buffered.length < count) {
      await this.fill();
    }
    const head = this.buffered.slice(0, count);
    this.buffered = this.buffered.slice(count);
    return head;
  }

  /** One line ending in LF (CR stripped). Used only for the version exchange. */
  async readLine(maxBytes: number): Promise<string> {
    while (true) {
      const newlineAt = this.buffered.indexOf(0x0a);
      if (newlineAt !== -1) {
        let line = this.buffered.slice(0, newlineAt);
        this.buffered = this.buffered.slice(newlineAt + 1);
        if (line.length > 0 && line[line.length - 1] === 0x0d) {
          line = line.slice(0, line.length - 1);
        }
        return utf8Text(line);
      }
      if (this.buffered.length > maxBytes) {
        throw new SshError("protocol", "the server's version line is too long");
      }
      await this.fill();
    }
  }
}

// ── the transport (binary packet protocol, RFC 4253 §6) ───────────────────────────────────────────

interface GcmDirection {
  key: CryptoKey;
  /** 4-byte fixed field + 8-byte invocation counter; the counter is incremented after every packet. */
  nonce: Uint8Array;
}

function incrementInvocationCounter(nonce: Uint8Array): void {
  for (let index = nonce.length - 1; index >= 4; index--) {
    nonce[index] = (nonce[index] + 1) & 0xff;
    if (nonce[index] !== 0) {
      return;
    }
  }
}

class SshTransport {
  private outbound: GcmDirection | null = null;
  private inbound: GcmDirection | null = null;

  constructor(
    private readonly stream: ByteStream,
    private readonly writer: WritableStreamDefaultWriter<Uint8Array>,
    private readonly deadline: Deadline,
  ) {}

  enableOutboundEncryption(direction: GcmDirection): void {
    this.outbound = direction;
  }

  enableInboundEncryption(direction: GcmDirection): void {
    this.inbound = direction;
  }

  async writeRaw(bytes: Uint8Array): Promise<void> {
    await this.deadline.race(this.writer.write(bytes), "sending to the server");
  }

  async sendPacket(payload: Uint8Array): Promise<void> {
    const blockSize = this.outbound === null ? PLAIN_BLOCK_SIZE : GCM_BLOCK_SIZE;
    // In GCM mode the 4-byte length is not encrypted, so only padding-length + payload + padding must fill whole
    // blocks. In plain mode the length counts too (RFC 4253 §6).
    let coveredLength = 1 + payload.length;
    if (this.outbound === null) {
      coveredLength += 4;
    }
    let paddingLength = blockSize - (coveredLength % blockSize);
    if (paddingLength < 4) {
      paddingLength += blockSize;
    }
    const padding = crypto.getRandomValues(new Uint8Array(paddingLength));
    const body = concatBytes([Uint8Array.of(paddingLength), payload, padding]);
    const lengthField = new SshWriter().uint32(body.length).toBytes();

    if (this.outbound === null) {
      await this.writeRaw(concatBytes([lengthField, body]));
      return;
    }
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: this.outbound.nonce, additionalData: lengthField, tagLength: GCM_TAG_LENGTH * 8 },
        this.outbound.key,
        body,
      ),
    );
    incrementInvocationCounter(this.outbound.nonce);
    await this.writeRaw(concatBytes([lengthField, sealed]));
  }

  async readPacket(): Promise<Uint8Array> {
    const lengthField = await this.stream.readExact(4);
    const packetLength = readUint32(lengthField, 0);
    if (packetLength < 5 || packetLength > MAX_PACKET_LENGTH) {
      throw new SshError("protocol", `the server sent a packet of length ${packetLength}`);
    }
    let body: Uint8Array;
    if (this.inbound === null) {
      body = await this.stream.readExact(packetLength);
    } else {
      if (packetLength % GCM_BLOCK_SIZE !== 0) {
        throw new SshError("protocol", "the server sent a packet that is not a whole number of cipher blocks");
      }
      const sealed = await this.stream.readExact(packetLength + GCM_TAG_LENGTH);
      try {
        body = new Uint8Array(
          await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: this.inbound.nonce, additionalData: lengthField, tagLength: GCM_TAG_LENGTH * 8 },
            this.inbound.key,
            sealed,
          ),
        );
      } catch {
        throw new SshError("protocol", "a packet from the server failed its integrity check");
      }
      incrementInvocationCounter(this.inbound.nonce);
    }
    const paddingLength = body[0];
    if (paddingLength < 4 || paddingLength + 1 > body.length) {
      throw new SshError("protocol", "the server sent a packet with bad padding");
    }
    return body.subarray(1, body.length - paddingLength);
  }
}

// ── the session ───────────────────────────────────────────────────────────────────────────────────

function buildKexInit(): Uint8Array {
  const cookie = crypto.getRandomValues(new Uint8Array(16));
  return new SshWriter()
    .byte(MSG_KEXINIT)
    .raw(cookie)
    .nameList([...KEX_ALGORITHMS, STRICT_KEX_CLIENT_MARKER])
    .nameList([HOST_KEY_ALGORITHM])
    .nameList([CIPHER])
    .nameList([CIPHER])
    .nameList([MAC_PLACEHOLDER])
    .nameList([MAC_PLACEHOLDER])
    .nameList([COMPRESSION])
    .nameList([COMPRESSION])
    .nameList([])
    .nameList([])
    .boolean(false)
    .uint32(0)
    .toBytes();
}

interface ServerKexInit {
  kexAlgorithms: string[];
  hostKeyAlgorithms: string[];
  ciphersClientToServer: string[];
  ciphersServerToClient: string[];
  compressionClientToServer: string[];
  compressionServerToClient: string[];
  firstKexPacketFollows: boolean;
}

function parseServerKexInit(payload: Uint8Array): ServerKexInit {
  const reader = new SshReader(payload);
  reader.byte();
  reader.raw(16);
  const kexAlgorithms = reader.nameList();
  const hostKeyAlgorithms = reader.nameList();
  const ciphersClientToServer = reader.nameList();
  const ciphersServerToClient = reader.nameList();
  reader.nameList();
  reader.nameList();
  const compressionClientToServer = reader.nameList();
  const compressionServerToClient = reader.nameList();
  reader.nameList();
  reader.nameList();
  const firstKexPacketFollows = reader.boolean();
  return {
    kexAlgorithms,
    hostKeyAlgorithms,
    ciphersClientToServer,
    ciphersServerToClient,
    compressionClientToServer,
    compressionServerToClient,
    firstKexPacketFollows,
  };
}

function requireOffered(serverList: string[], wanted: string, what: string): void {
  if (!serverList.includes(wanted)) {
    throw new SshError("protocol", `the server does not offer ${wanted} for ${what} (it offers: ${serverList.join(",").slice(0, 200)})`);
  }
}

/** K_x = HASH(mpint K || H || letter || session_id), cut to `length` bytes (RFC 4253 §7.2; SHA-256 gives 32). */
async function deriveKeyMaterial(sharedSecretMpint: Uint8Array, exchangeHash: Uint8Array, letter: string, sessionId: Uint8Array, length: number): Promise<Uint8Array> {
  const digest = await sha256Bytes(concatBytes([sharedSecretMpint, exchangeHash, utf8Bytes(letter), sessionId]));
  return digest.slice(0, length);
}

async function gcmDirection(keyBytes: Uint8Array, nonceBytes: Uint8Array): Promise<GcmDirection> {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  keyBytes.fill(0);
  return { key, nonce: nonceBytes };
}

/**
 * The key exchange: KEXINIT both ways, curve25519 ECDH, the host-key PIN, the server's signature, NEWKEYS, keys.
 * Returns the session id. Throws SshError("host-key-mismatch") before any credential is sent when the server's
 * key is not the pinned one.
 */
async function negotiateKeys(
  transport: SshTransport,
  clientVersion: string,
  serverVersion: string,
  pinnedFingerprint: string,
): Promise<Uint8Array> {
  const clientKexInit = buildKexInit();
  await transport.sendPacket(clientKexInit);

  const serverKexInit = await transport.readPacket();
  if (serverKexInit[0] !== MSG_KEXINIT) {
    // Strict KEX: the first packet must be KEXINIT. A server that sends something else first is refused.
    throw new SshError("protocol", `expected KEXINIT from the server, got message ${serverKexInit[0]}`);
  }
  const offered = parseServerKexInit(serverKexInit);
  const kexAlgorithm = KEX_ALGORITHMS.find((name) => offered.kexAlgorithms.includes(name));
  if (kexAlgorithm === undefined) {
    throw new SshError("protocol", `the server offers no curve25519-sha256 key exchange (it offers: ${offered.kexAlgorithms.join(",").slice(0, 200)})`);
  }
  const strictKex = offered.kexAlgorithms.includes(STRICT_KEX_SERVER_MARKER);
  requireOffered(offered.hostKeyAlgorithms, HOST_KEY_ALGORITHM, "the host key");
  requireOffered(offered.ciphersClientToServer, CIPHER, "the client-to-server cipher");
  requireOffered(offered.ciphersServerToClient, CIPHER, "the server-to-client cipher");
  requireOffered(offered.compressionClientToServer, COMPRESSION, "compression");
  requireOffered(offered.compressionServerToClient, COMPRESSION, "compression");
  if (offered.firstKexPacketFollows) {
    throw new SshError("protocol", "the server sent a guessed key-exchange packet, which this client does not support");
  }

  const ephemeral = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const clientPublic = new Uint8Array((await crypto.subtle.exportKey("raw", ephemeral.publicKey)) as ArrayBuffer);
  await transport.sendPacket(new SshWriter().byte(MSG_KEX_ECDH_INIT).string(clientPublic).toBytes());

  const reply = await readKexPacket(transport, strictKex);
  if (reply[0] !== MSG_KEX_ECDH_REPLY) {
    throw new SshError("protocol", `expected the key-exchange reply, got message ${reply[0]}`);
  }
  const replyReader = new SshReader(reply.subarray(1));
  const hostKeyBlob = replyReader.string();
  const serverPublic = replyReader.string();
  const signatureBlob = replyReader.string();

  // THE PIN. Checked first, before the signature and long before any credential is sent.
  const presentedFingerprint = await sshFingerprint(hostKeyBlob);
  if (presentedFingerprint !== pinnedFingerprint) {
    throw new SshError(
      "host-key-mismatch",
      `the server presented the ED25519 host key ${presentedFingerprint}, not the pinned ${pinnedFingerprint}; refusing to log in`,
    );
  }
  const hostKeyReader = new SshReader(hostKeyBlob);
  const hostKeyType = hostKeyReader.text();
  const hostPublicKey = hostKeyReader.string();
  if (hostKeyType !== HOST_KEY_ALGORITHM || hostPublicKey.length !== 32) {
    throw new SshError("protocol", "the server's host key is not an ssh-ed25519 key");
  }
  if (serverPublic.length !== 32) {
    throw new SshError("protocol", "the server's curve25519 public value has the wrong length");
  }

  const serverPublicKey = await crypto.subtle.importKey("raw", serverPublic, { name: "X25519" }, false, []);
  const sharedBits = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "X25519", public: serverPublicKey } as unknown as SubtleCryptoDeriveKeyAlgorithm, ephemeral.privateKey, 256),
  );
  if (sharedBits.every((byte) => byte === 0)) {
    throw new SshError("protocol", "the key exchange produced an all-zero secret");
  }
  // RFC 8731 §3.1: the X25519 output bytes are read as an unsigned big-endian integer and encoded as an mpint.
  const sharedSecretMpint = new SshWriter().mpintFromUnsigned(sharedBits).toBytes();
  sharedBits.fill(0);

  const exchangeHash = await sha256Bytes(
    new SshWriter()
      .string(clientVersion)
      .string(serverVersion)
      .string(clientKexInit)
      .string(serverKexInit)
      .string(hostKeyBlob)
      .string(clientPublic)
      .string(serverPublic)
      .raw(sharedSecretMpint)
      .toBytes(),
  );

  const signatureReader = new SshReader(signatureBlob);
  const signatureType = signatureReader.text();
  const signature = signatureReader.string();
  if (signatureType !== HOST_KEY_ALGORITHM || signature.length !== 64) {
    throw new SshError("protocol", "the server's key-exchange signature is not an ssh-ed25519 signature");
  }
  const hostVerifyKey = await crypto.subtle.importKey("raw", hostPublicKey, { name: "Ed25519" }, false, ["verify"]);
  const signatureValid = await crypto.subtle.verify({ name: "Ed25519" }, hostVerifyKey, signature, exchangeHash);
  if (!signatureValid) {
    throw new SshError("host-key-mismatch", "the server's key-exchange signature does not verify with its host key; refusing to log in");
  }

  await transport.sendPacket(Uint8Array.of(MSG_NEWKEYS));
  const newKeys = await readKexPacket(transport, strictKex);
  if (newKeys[0] !== MSG_NEWKEYS) {
    throw new SshError("protocol", `expected NEWKEYS, got message ${newKeys[0]}`);
  }

  const sessionId = exchangeHash;
  const clientNonce = await deriveKeyMaterial(sharedSecretMpint, exchangeHash, "A", sessionId, 12);
  const serverNonce = await deriveKeyMaterial(sharedSecretMpint, exchangeHash, "B", sessionId, 12);
  const clientKey = await deriveKeyMaterial(sharedSecretMpint, exchangeHash, "C", sessionId, 32);
  const serverKey = await deriveKeyMaterial(sharedSecretMpint, exchangeHash, "D", sessionId, 32);
  sharedSecretMpint.fill(0);
  transport.enableOutboundEncryption(await gcmDirection(clientKey, clientNonce));
  transport.enableInboundEncryption(await gcmDirection(serverKey, serverNonce));
  return sessionId;
}

/** A packet during the key exchange. Without strict KEX, IGNORE and DEBUG may appear and are skipped. */
async function readKexPacket(transport: SshTransport, strictKex: boolean): Promise<Uint8Array> {
  while (true) {
    const payload = await transport.readPacket();
    const messageNumber = payload[0];
    if (messageNumber === MSG_DISCONNECT) {
      throw disconnectError(payload);
    }
    if (!strictKex && (messageNumber === MSG_IGNORE || messageNumber === MSG_DEBUG)) {
      continue;
    }
    return payload;
  }
}

function disconnectError(payload: Uint8Array): SshError {
  let description = "";
  try {
    const reader = new SshReader(payload.subarray(1));
    reader.uint32();
    description = reader.text().slice(0, 200);
  } catch {
    description = "";
  }
  return new SshError("protocol", `the server disconnected${description ? `: ${description}` : ""}`);
}

/** A packet after the key exchange, with the transport-level noise (IGNORE, DEBUG, global requests) handled. */
async function readSessionPacket(transport: SshTransport): Promise<Uint8Array> {
  while (true) {
    const payload = await transport.readPacket();
    const messageNumber = payload[0];
    if (messageNumber === MSG_DISCONNECT) {
      throw disconnectError(payload);
    }
    if (messageNumber === MSG_IGNORE || messageNumber === MSG_DEBUG || messageNumber === MSG_UNIMPLEMENTED || messageNumber === MSG_EXT_INFO) {
      continue;
    }
    if (messageNumber === MSG_KEXINIT) {
      throw new SshError("protocol", "the server started a re-key, which this short-lived client does not support");
    }
    if (messageNumber === MSG_GLOBAL_REQUEST) {
      const reader = new SshReader(payload.subarray(1));
      reader.string();
      const wantReply = reader.boolean();
      if (wantReply) {
        await transport.sendPacket(Uint8Array.of(MSG_REQUEST_FAILURE));
      }
      continue;
    }
    return payload;
  }
}

async function authenticate(transport: SshTransport, sessionId: Uint8Array, username: string, privateKey: SshPrivateKey): Promise<void> {
  await transport.sendPacket(new SshWriter().byte(MSG_SERVICE_REQUEST).string("ssh-userauth").toBytes());
  const accept = await readSessionPacket(transport);
  if (accept[0] !== MSG_SERVICE_ACCEPT) {
    throw new SshError("protocol", `expected SERVICE_ACCEPT, got message ${accept[0]}`);
  }

  // RFC 4252 §7: the signature covers the session id and the request up to the key blob.
  const signedData = new SshWriter()
    .string(sessionId)
    .byte(MSG_USERAUTH_REQUEST)
    .string(username)
    .string("ssh-connection")
    .string("publickey")
    .boolean(true)
    .string(HOST_KEY_ALGORITHM)
    .string(privateKey.publicKeyBlob)
    .toBytes();
  const rawSignature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey.signingKey, signedData));
  const signatureBlob = new SshWriter().string(HOST_KEY_ALGORITHM).string(rawSignature).toBytes();
  await transport.sendPacket(
    new SshWriter()
      .byte(MSG_USERAUTH_REQUEST)
      .string(username)
      .string("ssh-connection")
      .string("publickey")
      .boolean(true)
      .string(HOST_KEY_ALGORITHM)
      .string(privateKey.publicKeyBlob)
      .string(signatureBlob)
      .toBytes(),
  );

  while (true) {
    const answer = await readSessionPacket(transport);
    if (answer[0] === MSG_USERAUTH_BANNER) {
      continue;
    }
    if (answer[0] === MSG_USERAUTH_SUCCESS) {
      return;
    }
    if (answer[0] === MSG_USERAUTH_FAILURE) {
      throw new SshError("auth-failed", `the server refused the key for the login "${username}" (is its public key in that login's authorized_keys?)`);
    }
    throw new SshError("protocol", `unexpected message ${answer[0]} during login`);
  }
}

interface RemoteChannel {
  remoteId: number;
  remoteWindow: number;
  remoteMaxPacket: number;
}

async function openSessionChannel(transport: SshTransport): Promise<RemoteChannel> {
  const localId = 0;
  await transport.sendPacket(
    new SshWriter().byte(MSG_CHANNEL_OPEN).string("session").uint32(localId).uint32(LOCAL_WINDOW_SIZE).uint32(LOCAL_MAX_PACKET).toBytes(),
  );
  const answer = await readSessionPacket(transport);
  if (answer[0] === MSG_CHANNEL_OPEN_FAILURE) {
    throw new SshError("exec-refused", "the server refused to open a session channel");
  }
  if (answer[0] !== MSG_CHANNEL_OPEN_CONFIRMATION) {
    throw new SshError("protocol", `expected CHANNEL_OPEN_CONFIRMATION, got message ${answer[0]}`);
  }
  const reader = new SshReader(answer.subarray(1));
  reader.uint32();
  const remoteId = reader.uint32();
  const remoteWindow = reader.uint32();
  const remoteMaxPacket = reader.uint32();
  return { remoteId, remoteWindow, remoteMaxPacket };
}

/** Collected channel output while the exec runs. */
class ChannelOutput {
  stdoutParts: Uint8Array[] = [];
  stderrParts: Uint8Array[] = [];
  totalBytes = 0;
  consumedSinceAdjust = 0;
  exitCode: number | null = null;
  closed = false;
  execAnswered: "pending" | "success" | "failure" = "pending";
}

/** Handle one channel message. Returns true when it changed the remote window (so stdin may continue). */
async function handleChannelMessage(transport: SshTransport, channel: RemoteChannel, output: ChannelOutput, payload: Uint8Array): Promise<void> {
  const messageNumber = payload[0];
  const reader = new SshReader(payload.subarray(1));
  if (messageNumber === MSG_CHANNEL_WINDOW_ADJUST) {
    reader.uint32();
    channel.remoteWindow += reader.uint32();
    return;
  }
  if (messageNumber === MSG_CHANNEL_SUCCESS) {
    output.execAnswered = "success";
    return;
  }
  if (messageNumber === MSG_CHANNEL_FAILURE) {
    output.execAnswered = "failure";
    return;
  }
  if (messageNumber === MSG_CHANNEL_DATA || messageNumber === MSG_CHANNEL_EXTENDED_DATA) {
    reader.uint32();
    let isStderr = false;
    if (messageNumber === MSG_CHANNEL_EXTENDED_DATA) {
      isStderr = reader.uint32() === 1;
    }
    const data = reader.string();
    output.totalBytes += data.length;
    if (output.totalBytes > MAX_OUTPUT_BYTES) {
      throw new SshError("protocol", `the remote command wrote more than ${MAX_OUTPUT_BYTES} bytes of output`);
    }
    if (isStderr) {
      output.stderrParts.push(data.slice());
    } else {
      output.stdoutParts.push(data.slice());
    }
    output.consumedSinceAdjust += data.length;
    if (output.consumedSinceAdjust >= LOCAL_WINDOW_SIZE / 2) {
      await transport.sendPacket(new SshWriter().byte(MSG_CHANNEL_WINDOW_ADJUST).uint32(channel.remoteId).uint32(output.consumedSinceAdjust).toBytes());
      output.consumedSinceAdjust = 0;
    }
    return;
  }
  if (messageNumber === MSG_CHANNEL_REQUEST) {
    reader.uint32();
    const requestType = reader.text();
    const wantReply = reader.boolean();
    if (requestType === "exit-status") {
      output.exitCode = reader.uint32();
    }
    if (wantReply) {
      await transport.sendPacket(new SshWriter().byte(MSG_CHANNEL_FAILURE).uint32(channel.remoteId).toBytes());
    }
    return;
  }
  if (messageNumber === MSG_CHANNEL_EOF) {
    return;
  }
  if (messageNumber === MSG_CHANNEL_CLOSE) {
    output.closed = true;
    return;
  }
  throw new SshError("protocol", `unexpected message ${messageNumber} on the session channel`);
}

async function runExec(transport: SshTransport, command: string, stdin: Uint8Array): Promise<SshExecResult> {
  const channel = await openSessionChannel(transport);
  const output = new ChannelOutput();

  await transport.sendPacket(
    new SshWriter().byte(MSG_CHANNEL_REQUEST).uint32(channel.remoteId).string("exec").boolean(true).string(command).toBytes(),
  );
  while (output.execAnswered === "pending" && !output.closed) {
    await handleChannelMessage(transport, channel, output, await readSessionPacket(transport));
  }
  if (output.execAnswered !== "success") {
    throw new SshError("exec-refused", "the server refused to run the command");
  }

  // Send stdin within the server's window and packet size, then EOF.
  let sent = 0;
  while (sent < stdin.length) {
    if (output.closed) {
      break;
    }
    const allowed = Math.min(channel.remoteWindow, channel.remoteMaxPacket - 64, LOCAL_MAX_PACKET);
    if (allowed <= 0) {
      await handleChannelMessage(transport, channel, output, await readSessionPacket(transport));
      continue;
    }
    const chunk = stdin.subarray(sent, sent + allowed);
    await transport.sendPacket(new SshWriter().byte(MSG_CHANNEL_DATA).uint32(channel.remoteId).string(chunk).toBytes());
    channel.remoteWindow -= chunk.length;
    sent += chunk.length;
  }
  if (!output.closed) {
    await transport.sendPacket(new SshWriter().byte(MSG_CHANNEL_EOF).uint32(channel.remoteId).toBytes());
  }

  while (!output.closed) {
    await handleChannelMessage(transport, channel, output, await readSessionPacket(transport));
  }
  await transport.sendPacket(new SshWriter().byte(MSG_CHANNEL_CLOSE).uint32(channel.remoteId).toBytes());

  return {
    exitCode: output.exitCode,
    stdout: concatBytes(output.stdoutParts),
    stderr: concatBytes(output.stderrParts),
  };
}

/**
 * Connect, pin the host key, log in, run ONE command with `stdin`, and return its output and exit status.
 * Every failure is an SshError with a code; nothing in a message comes from the private key.
 */
export async function sshExec(request: SshExecRequest): Promise<SshExecResult> {
  const deadline = new Deadline(request.totalTimeoutMs);
  let socket: Socket;
  try {
    socket = connect({ hostname: request.hostname, port: request.port });
  } catch (error) {
    throw new SshError("unreachable", `could not open a TCP connection to ${request.hostname}:${request.port} (${describeError(error)})`);
  }
  try {
    try {
      await deadline.race(socket.opened, `connecting to ${request.hostname}:${request.port}`, request.connectTimeoutMs);
    } catch (error) {
      if (error instanceof SshError && error.code === "timeout") {
        throw new SshError("unreachable", `no TCP connection to ${request.hostname}:${request.port} within ${request.connectTimeoutMs} ms`);
      }
      throw new SshError("unreachable", `could not connect to ${request.hostname}:${request.port} (${describeError(error)})`);
    }

    const stream = new ByteStream(socket.readable.getReader(), deadline);
    const writer = socket.writable.getWriter();
    const transport = new SshTransport(stream, writer, deadline);

    await transport.writeRaw(utf8Bytes(`${CLIENT_VERSION}\r\n`));
    const serverVersion = await readServerVersion(stream);
    const sessionId = await negotiateKeys(transport, CLIENT_VERSION, serverVersion, request.hostKeyFingerprint);
    await authenticate(transport, sessionId, request.username, request.privateKey);
    return await runExec(transport, request.command, request.stdin);
  } catch (error) {
    if (error instanceof SshError) {
      throw error;
    }
    if (error instanceof SshWireError) {
      throw new SshError("protocol", `the server sent a malformed message (${error.message})`);
    }
    throw new SshError("protocol", `the SSH session failed (${describeError(error)})`);
  } finally {
    socket.close().catch(() => undefined);
  }
}

/** RFC 4253 §4.2: the server may send other lines before its version line. */
async function readServerVersion(stream: ByteStream): Promise<string> {
  let bytesSeen = 0;
  while (bytesSeen < MAX_BANNER_BYTES) {
    const line = await stream.readLine(MAX_BANNER_BYTES);
    bytesSeen += line.length + 2;
    if (line.startsWith("SSH-")) {
      if (!line.startsWith("SSH-2.0-") && !line.startsWith("SSH-1.99-")) {
        throw new SshError("protocol", `the server speaks an unsupported SSH version (${line.slice(0, 60)})`);
      }
      return line;
    }
  }
  throw new SshError("protocol", "the server sent no SSH version line");
}

function describeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message.slice(0, 200);
  }
  return String(error).slice(0, 200);
}
