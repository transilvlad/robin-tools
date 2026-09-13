import { describe, expect, it } from 'vitest';
import {
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  convertUnixTimestamp,
  decodeJwt,
  hexDecode,
  isoToUnixTimestamp,
  md5Hex,
  prettyJson,
  quotedPrintableDecode,
  quotedPrintableEncode,
  samlRedirectBindingSupport,
  samlRedirectDecode,
  samlRedirectEncode,
  sha256Hex,
  unixTimestampToIso,
  urlDecode,
  urlEncode,
  utf16HexDecode,
  uuDecode,
  uuEncode,
} from './encoding';

describe('browser encoding utilities', () => {
  it('encodes and decodes Base64 UTF-8 canonical vectors', () => {
    expect(base64Encode('Hello')).toBe('SGVsbG8=');
    expect(base64Decode('Y2hlY2s6IOKckw==')).toBe('check: \u2713');
    expect(base64Encode('\u2713')).toBe('4pyT');
  });

  it('encodes and decodes unpadded Base64URL', () => {
    expect(base64UrlEncode('Hello?')).toBe('SGVsbG8_');
    expect(base64UrlDecode('SGVsbG8_')).toBe('Hello?');
  });

  it('URL encodes reserved characters', () => {
    expect(urlEncode('a b&c/')).toBe('a%20b%26c%2F');
    expect(urlDecode('a%20b%26c%2F')).toBe('a b&c/');
  });

  it('hashes standard MD5 and SHA-256 vectors', async () => {
    expect(md5Hex('abc')).toBe('900150983cd24fb0d6963f7d28e17f72');
    await expect(sha256Hex('abc')).resolves.toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });

  it('pretty prints JSON', () => {
    expect(prettyJson('{"a":[1,true]}')).toBe('{\n  "a": [\n    1,\n    true\n  ]\n}');
  });

  it('encodes and decodes quoted-printable', () => {
    expect(quotedPrintableEncode("J'aime = \u2713")).toBe("J'aime =3D =E2=9C=93");
    expect(quotedPrintableDecode('J=27aime =3D =E2=9C=93')).toBe("J'aime = \u2713");
    expect(quotedPrintableDecode('a=\r\nb')).toBe('ab');
  });

  it('round trips complete UUEncode messages', () => {
    const encoded = uuEncode('Cat', 'cat.txt');
    expect(encoded).toBe('begin 644 cat.txt\n#0V%T\n`\nend');
    expect(uuDecode(encoded)).toBe('Cat');
  });

  it('decodes UTF-16 code units and hexadecimal bytes', () => {
    expect(utf16HexDecode('0x0048, 0069 0021')).toBe('Hi!');
    expect(utf16HexDecode('D83D-DE00')).toBe('\ud83d\ude00');
    expect(hexDecode('0x48 65:6c-6c_6f')).toBe('Hello');
  });

  it('decodes JWT JSON without claiming verification', () => {
    const jwt = decodeJwt(
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature'
    );
    expect(jwt.header).toContain('"alg": "HS256"');
    expect(jwt.payload).toContain('"name": "John Doe"');
    expect(jwt.verified).toBe(false);
    expect(jwt.verificationMessage).toBe('Not verified; decoding only.');
  });

  it('converts seconds, milliseconds, and ISO dates', () => {
    expect(unixTimestampToIso(0, 'seconds')).toBe('1970-01-01T00:00:00.000Z');
    expect(unixTimestampToIso(1_700_000_000_000, 'milliseconds')).toBe('2023-11-14T22:13:20.000Z');
    expect(isoToUnixTimestamp('1970-01-01T00:00:01.000Z')).toMatchObject({
      seconds: 1,
      milliseconds: 1000,
    });
    expect(convertUnixTimestamp('1970-01-01T00:00:01.000Z')).toMatchObject({ seconds: 1 });
  });

  it('round trips SAML Redirect binding', async () => {
    expect(samlRedirectBindingSupport.supported).toBe(true);
    const encoded = await samlRedirectEncode('<AuthnRequest/>');
    await expect(samlRedirectDecode(encoded)).resolves.toBe('<AuthnRequest/>');
  });
});
