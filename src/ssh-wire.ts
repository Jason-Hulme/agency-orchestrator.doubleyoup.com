// hub#476 / planning/58 §6.2: the SSH wire encoding (RFC 4251 §5) that the Worker's SSH client needs.
//
// Only the types the client uses: byte, boolean, uint32, string (length-prefixed bytes), name-list and mpint.
// Plain Uint8Array handling, no Node Buffer, so it runs in workerd without nodejs_compat.

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8Bytes(text: string): Uint8Array {
  return textEncoder.encode(text);
}

export function utf8Text(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const part of parts) {
    totalLength += part.length;
  }
  const joined = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

export function uint32Bytes(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value >>> 0);
  return bytes;
}

export function readUint32(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset);
}

/** Thrown when a peer's message does not parse. The SSH client turns it into a protocol error. */
export class SshWireError extends Error {}

/** Builds one SSH message payload. */
export class SshWriter {
  private readonly parts: Uint8Array[] = [];

  byte(value: number): this {
    this.parts.push(Uint8Array.of(value & 0xff));
    return this;
  }

  boolean(value: boolean): this {
    return this.byte(value ? 1 : 0);
  }

  uint32(value: number): this {
    this.parts.push(uint32Bytes(value));
    return this;
  }

  raw(bytes: Uint8Array): this {
    this.parts.push(bytes);
    return this;
  }

  string(value: Uint8Array | string): this {
    let bytes: Uint8Array;
    if (typeof value === "string") {
      bytes = utf8Bytes(value);
    } else {
      bytes = value;
    }
    this.parts.push(uint32Bytes(bytes.length));
    this.parts.push(bytes);
    return this;
  }

  nameList(names: readonly string[]): this {
    return this.string(names.join(","));
  }

  /** An mpint from unsigned big-endian bytes (RFC 4251 §5): no leading zero byte, and a 0x00 when the top bit is set. */
  mpintFromUnsigned(unsignedBigEndian: Uint8Array): this {
    return this.raw(encodeMpint(unsignedBigEndian));
  }

  toBytes(): Uint8Array {
    return concatBytes(this.parts);
  }
}

/** The full mpint encoding (length prefix included) of an unsigned big-endian integer. */
export function encodeMpint(unsignedBigEndian: Uint8Array): Uint8Array {
  let start = 0;
  while (start < unsignedBigEndian.length && unsignedBigEndian[start] === 0) {
    start++;
  }
  const magnitude = unsignedBigEndian.subarray(start);
  if (magnitude.length === 0) {
    return uint32Bytes(0);
  }
  const needsSignByte = (magnitude[0] & 0x80) !== 0;
  if (needsSignByte) {
    return concatBytes([uint32Bytes(magnitude.length + 1), Uint8Array.of(0), magnitude]);
  }
  return concatBytes([uint32Bytes(magnitude.length), magnitude]);
}

/** Reads one SSH message payload. Every read is bounds-checked and throws SshWireError past the end. */
export class SshReader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  private need(count: number): void {
    if (this.offset + count > this.bytes.length) {
      throw new SshWireError("message ended early");
    }
  }

  byte(): number {
    this.need(1);
    const value = this.bytes[this.offset];
    this.offset += 1;
    return value;
  }

  boolean(): boolean {
    return this.byte() !== 0;
  }

  uint32(): number {
    this.need(4);
    const value = readUint32(this.bytes, this.offset);
    this.offset += 4;
    return value;
  }

  raw(count: number): Uint8Array {
    this.need(count);
    const value = this.bytes.subarray(this.offset, this.offset + count);
    this.offset += count;
    return value;
  }

  string(): Uint8Array {
    const length = this.uint32();
    return this.raw(length);
  }

  text(): string {
    return utf8Text(this.string());
  }

  nameList(): string[] {
    const text = this.text();
    if (text === "") {
      return [];
    }
    return text.split(",");
  }

  remaining(): number {
    return this.bytes.length - this.offset;
  }
}

/** Standard base64 of bytes. `pad` false drops the trailing "=" (the OpenSSH fingerprint form). */
export function base64Encode(bytes: Uint8Array, pad: boolean): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const encoded = btoa(binary);
  if (pad) {
    return encoded;
  }
  return encoded.replace(/=+$/, "");
}

/** Standard base64 to bytes, or null when the text is not base64. */
export function base64Decode(text: string): Uint8Array | null {
  let binary: string;
  try {
    binary = atob(text);
  } catch {
    return null;
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function hexEncode(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

export async function sha256Bytes(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
