import { deflateRaw, inflateRaw } from 'pako';

/**
 * Browser-only text and transport encoding helpers. These intentionally use
 * Web Platform APIs rather than Node's Buffer module.
 */

export type RawDeflate = (input: Uint8Array) => Uint8Array | Promise<Uint8Array>;
export type RawInflate = (input: Uint8Array) => Uint8Array | Promise<Uint8Array>;
export type TimestampUnit = 'auto' | 'seconds' | 'milliseconds';

export interface JwtDecodeResult {
  header: string;
  payload: string;
  headerValue: unknown;
  payloadValue: unknown;
  verified: false;
  verificationMessage: 'Not verified; decoding only.';
}

export interface UnixTimestamp {
  milliseconds: number;
  seconds: number;
  iso: string;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function assertString(value: string, name: string): void {
  if (typeof value !== 'string') {
    throw new TypeError(`${name} must be a string.`);
  }
}

function bytesToBinary(bytes: Uint8Array): string {
  const parts: string[] = [];
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    parts.push(String.fromCharCode(...bytes.subarray(offset, offset + chunkSize)));
  }
  return parts.join('');
}

function binaryToBytes(binary: string): Uint8Array {
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function base64EncodeBytes(bytes: Uint8Array): string {
  return btoa(bytesToBinary(bytes));
}

function base64DecodeBytes(value: string): Uint8Array {
  assertString(value, 'Base64 value');
  const normalized = value.replace(/\s/g, '');
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(normalized)) {
    throw new Error('Invalid Base64 input.');
  }
  return binaryToBytes(atob(normalized));
}

function hexFromBytes(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Encodes UTF-8 text as standard Base64. */
export function base64Encode(value: string): string {
  assertString(value, 'Text');
  return base64EncodeBytes(textEncoder.encode(value));
}

/** Decodes standard Base64 as UTF-8 text. */
export function base64Decode(value: string): string {
  return textDecoder.decode(base64DecodeBytes(value));
}

/** Encodes UTF-8 text as unpadded RFC 4648 Base64URL. */
export function base64UrlEncode(value: string): string {
  return base64Encode(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodes padded or unpadded RFC 4648 Base64URL as UTF-8 text. */
export function base64UrlDecode(value: string): string {
  assertString(value, 'Base64URL value');
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    throw new Error('Invalid Base64URL input.');
  }
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  return base64Decode(value.replace(/-/g, '+').replace(/_/g, '/') + padding);
}

export function urlEncode(value: string): string {
  assertString(value, 'URL value');
  return encodeURIComponent(value);
}

export function urlDecode(value: string): string {
  assertString(value, 'URL value');
  return decodeURIComponent(value);
}

/**
 * Computes an MD5 digest in lowercase hexadecimal. MD5 is retained for
 * interoperability only and must not be used for security decisions.
 */
export function md5Hex(value: string): string {
  assertString(value, 'Text');
  const input = textEncoder.encode(value);
  const paddedLength = Math.ceil((input.length + 9) / 64) * 64;
  const bytes = new Uint8Array(paddedLength);
  bytes.set(input);
  bytes[input.length] = 0x80;

  const length = BigInt(input.length) * 8n;
  for (let index = 0; index < 8; index += 1) {
    bytes[paddedLength - 8 + index] = Number((length >> BigInt(index * 8)) & 0xffn);
  }

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  const shifts = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const constants = Array.from(
    { length: 64 },
    (_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 0x100000000) | 0
  );

  for (let offset = 0; offset < bytes.length; offset += 64) {
    const words = new Int32Array(16);
    for (let index = 0; index < 16; index += 1) {
      const start = offset + index * 4;
      words[index] =
        bytes[start] |
        (bytes[start + 1] << 8) |
        (bytes[start + 2] << 16) |
        (bytes[start + 3] << 24);
    }

    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;
    for (let index = 0; index < 64; index += 1) {
      let f: number;
      let g: number;
      if (index < 16) {
        f = (b & c) | (~b & d);
        g = index;
      } else if (index < 32) {
        f = (d & b) | (~d & c);
        g = (5 * index + 1) % 16;
      } else if (index < 48) {
        f = b ^ c ^ d;
        g = (3 * index + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * index) % 16;
      }
      const nextD = d;
      d = c;
      c = b;
      const sum = (a + f + constants[index] + words[g]) | 0;
      b = (b + ((sum << shifts[index]) | (sum >>> (32 - shifts[index])))) | 0;
      a = nextD;
    }
    a0 = (a0 + a) | 0;
    b0 = (b0 + b) | 0;
    c0 = (c0 + c) | 0;
    d0 = (d0 + d) | 0;
  }

  const digest = new Uint8Array(16);
  [a0, b0, c0, d0].forEach((word, wordIndex) => {
    for (let byteIndex = 0; byteIndex < 4; byteIndex += 1) {
      digest[wordIndex * 4 + byteIndex] = word >>> (byteIndex * 8);
    }
  });
  return hexFromBytes(digest);
}

/** Computes a lowercase SHA-256 hexadecimal digest using WebCrypto. */
export async function sha256Hex(value: string): Promise<string> {
  assertString(value, 'Text');
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto SubtleCrypto is unavailable in this browser.');
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', textEncoder.encode(value));
  return hexFromBytes(new Uint8Array(digest));
}

export function prettyJson(value: string): string {
  assertString(value, 'JSON');
  return JSON.stringify(JSON.parse(value), null, 2);
}

/** Encodes UTF-8 text as RFC 2045 quoted-printable with CRLF line endings. */
export function quotedPrintableEncode(value: string): string {
  assertString(value, 'Text');
  const bytes = textEncoder.encode(value.replace(/\r\n?|\n/g, '\n'));
  const lines: number[][] = [[]];
  for (const byte of bytes) {
    if (byte === 0x0a) {
      lines.push([]);
    } else {
      lines[lines.length - 1].push(byte);
    }
  }

  return lines
    .map((line) => {
      const tokens = line.map((byte, index) => {
        const atEnd = index === line.length - 1;
        if ((byte === 0x20 || byte === 0x09) && !atEnd) return String.fromCharCode(byte);
        if (byte >= 33 && byte <= 60) return String.fromCharCode(byte);
        if (byte >= 62 && byte <= 126) return String.fromCharCode(byte);
        return `=${byte.toString(16).toUpperCase().padStart(2, '0')}`;
      });
      let output = '';
      let width = 0;
      for (const token of tokens) {
        if (width + token.length > 75) {
          output += '=\r\n';
          width = 0;
        }
        output += token;
        width += token.length;
      }
      return output;
    })
    .join('\r\n');
}

/** Decodes RFC 2045 quoted-printable text as UTF-8. */
export function quotedPrintableDecode(value: string): string {
  assertString(value, 'Quoted-printable value');
  const compact = value.replace(/=\r?\n/g, '');
  const bytes: number[] = [];
  for (let index = 0; index < compact.length; index += 1) {
    if (compact[index] === '=') {
      const hex = compact.slice(index + 1, index + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
        throw new Error('Invalid quoted-printable escape.');
      }
      bytes.push(Number.parseInt(hex, 16));
      index += 2;
    } else {
      bytes.push(compact.charCodeAt(index));
    }
  }
  return textDecoder.decode(new Uint8Array(bytes));
}

/** Produces a complete, ASCII UUEncode message using UTF-8 input bytes. */
export function uuEncode(value: string, filename = 'data'): string {
  assertString(value, 'Text');
  if (!/^[\x20-\x7e]+$/.test(filename)) {
    throw new Error('UUEncode filename must contain printable ASCII characters.');
  }
  const bytes = textEncoder.encode(value);
  const lines = [`begin 644 ${filename}`];
  for (let offset = 0; offset < bytes.length; offset += 45) {
    const chunk = bytes.subarray(offset, offset + 45);
    let line = String.fromCharCode((chunk.length & 0x3f) + 32);
    for (let index = 0; index < chunk.length; index += 3) {
      const a = chunk[index];
      const b = chunk[index + 1] ?? 0;
      const c = chunk[index + 2] ?? 0;
      line += String.fromCharCode(((a >> 2) & 0x3f) + 32);
      line += String.fromCharCode((((a << 4) | (b >> 4)) & 0x3f) + 32);
      line += String.fromCharCode((((b << 2) | (c >> 6)) & 0x3f) + 32);
      line += String.fromCharCode((c & 0x3f) + 32);
    }
    lines.push(line);
  }
  lines.push('`', 'end');
  return lines.join('\n');
}

/** Decodes a complete UUEncode message (or its body) as UTF-8 text. */
export function uuDecode(value: string): string {
  assertString(value, 'UUEncode value');
  const sourceLines = value.replace(/\r\n?/g, '\n').split('\n');
  const beginIndex = sourceLines.findIndex((line) => /^begin [0-7]{3} .+$/.test(line));
  const lines = beginIndex >= 0 ? sourceLines.slice(beginIndex + 1) : sourceLines;
  const bytes: number[] = [];
  let sawTerminator = false;
  for (const line of lines) {
    if (line === 'end') {
      sawTerminator = true;
      break;
    }
    if (!line) continue;
    const length = (line.charCodeAt(0) - 32) & 0x3f;
    if (length === 0) continue;
    if (line.length < 1 + Math.ceil(length / 3) * 4) {
      throw new Error('Truncated UUEncode line.');
    }
    const decoded: number[] = [];
    for (let index = 1; index < line.length; index += 4) {
      const chars = [line[index], line[index + 1], line[index + 2], line[index + 3]];
      if (
        chars.some(
          (char) => char === undefined || char.charCodeAt(0) < 32 || char.charCodeAt(0) > 96
        )
      ) {
        throw new Error('Invalid UUEncode character.');
      }
      const [a, b, c, d] = chars.map((char) => (char.charCodeAt(0) - 32) & 0x3f);
      decoded.push((a << 2) | (b >> 4), (b << 4) | (c >> 2), (c << 6) | d);
    }
    bytes.push(...decoded.slice(0, length));
  }
  if (beginIndex >= 0 && !sawTerminator) {
    throw new Error('UUEncode message is missing its end line.');
  }
  return textDecoder.decode(new Uint8Array(bytes));
}

/** Decodes hexadecimal UTF-16 code units, including separators and 0x prefixes. */
export function utf16HexDecode(value: string): string {
  assertString(value, 'UTF-16 hexadecimal value');
  const withoutPrefixes = value.trim().replace(/0x/gi, '');
  if (!withoutPrefixes || /[^0-9a-fA-F\s,;:_|/-]/.test(withoutPrefixes)) {
    throw new Error('Invalid UTF-16 hexadecimal input.');
  }
  const groups = withoutPrefixes.split(/[\s,;:_|/-]+/).filter(Boolean);
  const units: number[] = [];
  for (const group of groups) {
    if (group.length % 4 !== 0) {
      throw new Error('UTF-16 hexadecimal code units must contain four hex digits.');
    }
    for (let index = 0; index < group.length; index += 4) {
      units.push(Number.parseInt(group.slice(index, index + 4), 16));
    }
  }
  return String.fromCharCode(...units);
}

/** Decodes hexadecimal bytes to UTF-8 text; whitespace, separators, and 0x are accepted. */
export function hexDecode(value: string): string {
  assertString(value, 'Hexadecimal value');
  const normalized = value.replace(/0x/gi, '').replace(/[\s,;:_|/-]/g, '');
  if (!normalized || normalized.length % 2 !== 0 || /[^0-9a-fA-F]/.test(normalized)) {
    throw new Error('Invalid hexadecimal input.');
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return textDecoder.decode(bytes);
}

export function decodeJwt(value: string): JwtDecodeResult {
  assertString(value, 'JWT');
  const parts = value.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1]) {
    throw new Error('A JWT must contain non-empty header and payload segments.');
  }
  const headerValue = JSON.parse(base64UrlDecode(parts[0]));
  const payloadValue = JSON.parse(base64UrlDecode(parts[1]));
  return {
    header: JSON.stringify(headerValue, null, 2),
    payload: JSON.stringify(payloadValue, null, 2),
    headerValue,
    payloadValue,
    verified: false,
    verificationMessage: 'Not verified; decoding only.',
  };
}

function timestampMilliseconds(value: number, unit: TimestampUnit): number {
  if (!Number.isFinite(value)) throw new Error('Timestamp must be a finite number.');
  const resolvedUnit =
    unit === 'auto' ? (Math.abs(value) >= 100_000_000_000 ? 'milliseconds' : 'seconds') : unit;
  const milliseconds = resolvedUnit === 'seconds' ? value * 1000 : value;
  if (!Number.isFinite(milliseconds) || Number.isNaN(new Date(milliseconds).getTime())) {
    throw new Error('Timestamp is outside the supported Date range.');
  }
  return milliseconds;
}

/** Converts a seconds or milliseconds Unix timestamp to a UTC ISO string. */
export function unixTimestampToIso(value: number, unit: TimestampUnit = 'auto'): string {
  return new Date(timestampMilliseconds(value, unit)).toISOString();
}

/** Converts an ISO date string to both seconds and milliseconds Unix timestamps. */
export function isoToUnixTimestamp(value: string): UnixTimestamp {
  assertString(value, 'ISO date');
  const milliseconds = new Date(value).getTime();
  if (Number.isNaN(milliseconds)) throw new Error('Invalid ISO date.');
  return { milliseconds, seconds: milliseconds / 1000, iso: new Date(milliseconds).toISOString() };
}

/** Converts either a Unix timestamp or an ISO date string to all timestamp representations. */
export function convertUnixTimestamp(
  value: number | string,
  unit: TimestampUnit = 'auto'
): UnixTimestamp {
  if (typeof value === 'number') {
    const milliseconds = timestampMilliseconds(value, unit);
    return {
      milliseconds,
      seconds: milliseconds / 1000,
      iso: new Date(milliseconds).toISOString(),
    };
  }
  if (/^[+-]?\d+(?:\.\d+)?$/.test(value.trim())) {
    return convertUnixTimestamp(Number(value), unit);
  }
  return isoToUnixTimestamp(value);
}

export const samlRedirectBindingSupport = {
  supported: true,
  reason: 'SAML Redirect binding uses raw DEFLATE, Base64, and URL encoding.',
} as const;

/**
 * Applies SAML Redirect transport encoding with a caller-supplied raw DEFLATE
 * implementation. Native browser compression cannot safely replace raw DEFLATE.
 */
export async function samlRedirectEncode(
  xml: string,
  rawDeflate: RawDeflate = deflateRaw
): Promise<string> {
  assertString(xml, 'SAML XML');
  const compressed = await rawDeflate(textEncoder.encode(xml));
  return urlEncode(base64EncodeBytes(compressed));
}

/** Reverses SAML Redirect transport encoding with a caller-supplied raw inflater. */
export async function samlRedirectDecode(
  value: string,
  rawInflate: RawInflate = inflateRaw
): Promise<string> {
  assertString(value, 'SAML Redirect value');
  const compressed = base64DecodeBytes(urlDecode(value));
  return textDecoder.decode(await rawInflate(compressed));
}
