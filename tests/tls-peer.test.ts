import { describe, it, expect } from 'vitest';
import { buildClientHello } from '@/lib/tls-peer/client-hello';
import {
  parseServerHello,
  parseCertificateMessage,
  alertName,
  cipherSuiteName,
  tlsVersionName,
} from '@/lib/tls-peer/records';

describe('ClientHello builder', () => {
  it('produces a TLS record wrapping a handshake with SNI', () => {
    const rand = new Uint8Array(32);
    for (let i = 0; i < 32; i++) rand[i] = i;
    const out = buildClientHello('example.com', rand);
    // Record header: type=22, version=0x0301, length
    expect(out[0]).toBe(0x16);
    expect(out[1]).toBe(0x03);
    expect(out[2]).toBe(0x01);
    const recordLen = (out[3]! << 8) | out[4]!;
    expect(recordLen).toBe(out.length - 5);
    // Handshake header: type=0x01 (ClientHello)
    expect(out[5]).toBe(0x01);
    // ClientHello legacy_version right after the 3-byte length
    expect(out[9]).toBe(0x03);
    expect(out[10]).toBe(0x03);
    // Client random = bytes 11..43 should match our seed
    for (let i = 0; i < 32; i++) expect(out[11 + i]).toBe(i);

    // Find the SNI bytes somewhere in the payload.
    const ascii = new TextDecoder().decode(out);
    expect(ascii).toContain('example.com');
  });

  it('rejects oversized SNI', () => {
    const bad = 'a'.repeat(300);
    expect(() => buildClientHello(bad)).toThrow();
  });
});

describe('ServerHello parser', () => {
  it('decodes version, cipher, and supported_versions extension', () => {
    // Build a minimal synthetic ServerHello body:
    const legacyVersion = [0x03, 0x03];
    const random = new Array(32).fill(0xaa);
    const sessionId = [0x00]; // empty
    const cipher = [0xc0, 0x2f];
    const compression = [0x00];
    // supported_versions ext declaring TLS 1.3
    const svExt = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
    const extLen = [0x00, svExt.length];
    const body = new Uint8Array([
      ...legacyVersion,
      ...random,
      ...sessionId,
      ...cipher,
      ...compression,
      ...extLen,
      ...svExt,
    ]);
    const sh = parseServerHello(body);
    expect(sh).not.toBeNull();
    expect(sh!.legacyVersion).toBe(0x0303);
    expect(sh!.negotiatedVersion).toBe(0x0304);
    expect(sh!.cipherSuite).toBe(0xc02f);
    expect(sh!.extensions.has(0x002b)).toBe(true);
  });

  it('returns null on truncated ServerHello', () => {
    expect(parseServerHello(new Uint8Array(10))).toBeNull();
  });
});

describe('Certificate message parser', () => {
  it('splits a multi-cert chain correctly', () => {
    const cert1 = new Uint8Array(5).fill(0x11);
    const cert2 = new Uint8Array(7).fill(0x22);
    const entry = (c: Uint8Array) => [0x00, 0x00, c.length, ...Array.from(c)];
    const listBytes = [...entry(cert1), ...entry(cert2)];
    const listLenBytes = [
      (listBytes.length >> 16) & 0xff,
      (listBytes.length >> 8) & 0xff,
      listBytes.length & 0xff,
    ];
    const body = new Uint8Array([...listLenBytes, ...listBytes]);
    const parsed = parseCertificateMessage(body);
    expect(parsed).not.toBeNull();
    expect(parsed!.length).toBe(2);
    expect(parsed![0]!.length).toBe(5);
    expect(parsed![1]!.length).toBe(7);
    expect(parsed![0]![0]).toBe(0x11);
    expect(parsed![1]![0]).toBe(0x22);
  });

  it('returns null on truncated body', () => {
    expect(parseCertificateMessage(new Uint8Array(2))).toBeNull();
  });
});

describe('friendly name helpers', () => {
  it('names known alerts, ciphers, versions', () => {
    expect(alertName(70)).toBe('protocol_version');
    expect(alertName(40)).toBe('handshake_failure');
    expect(alertName(0)).toBe('close_notify');
    expect(alertName(255)).toBe('alert_255');
    expect(cipherSuiteName(0xc02f)).toContain('AES_128_GCM');
    expect(cipherSuiteName(0xffff)).toBe('0xffff');
    expect(tlsVersionName(0x0303)).toBe('TLS 1.2');
    expect(tlsVersionName(0x0304)).toBe('TLS 1.3');
  });
});
