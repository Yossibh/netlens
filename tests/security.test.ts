import { describe, it, expect } from 'vitest';
import { validateInput, validateHost, validateFetchUrl, MAX_INPUT_LENGTH } from '../src/lib/security';

describe('validateInput - size and shape', () => {
  it('rejects empty', () => {
    expect(validateInput('').ok).toBe(false);
    expect(validateInput('   ').ok).toBe(false);
  });

  it('rejects over-long input', () => {
    const long = 'a'.repeat(MAX_INPUT_LENGTH + 1);
    expect(validateInput(long).ok).toBe(false);
  });

  it('accepts a normal domain', () => {
    expect(validateInput('github.com').ok).toBe(true);
    expect(validateInput('https://github.com/path').ok).toBe(true);
  });

  it('accepts a public IP', () => {
    expect(validateInput('1.1.1.1').ok).toBe(true);
  });

  it('rejects non-http schemes', () => {
    expect(validateInput('file:///etc/passwd').ok).toBe(false);
    expect(validateInput('javascript:alert(1)').ok).toBe(false);
    expect(validateInput('gopher://evil.example').ok).toBe(false);
    expect(validateInput('ftp://example.com').ok).toBe(false);
  });
});

describe('validateHost - private / special-use IPv4', () => {
  const blocked = [
    '127.0.0.1',
    '127.7.7.7',
    '10.0.0.1',
    '10.255.255.255',
    '172.16.5.5',
    '172.31.0.1',
    '192.168.1.1',
    '169.254.169.254', // AWS/GCP/Azure metadata
    '100.64.0.1',      // CGNAT
    '0.0.0.0',
    '224.0.0.1',       // multicast
    '255.255.255.255',
    '192.0.2.1',       // TEST-NET
  ];
  for (const ip of blocked) {
    it(`blocks ${ip}`, () => {
      expect(validateHost(ip).ok).toBe(false);
    });
  }

  const allowed = ['1.1.1.1', '8.8.8.8', '52.1.2.3', '151.101.1.1', '185.199.108.153'];
  for (const ip of allowed) {
    it(`allows ${ip}`, () => {
      expect(validateHost(ip).ok).toBe(true);
    });
  }
});

describe('validateHost - IPv6', () => {
  it('blocks ::1', () => { expect(validateHost('::1').ok).toBe(false); });
  it('blocks link-local fe80::', () => { expect(validateHost('fe80::1').ok).toBe(false); });
  it('blocks ULA fc00::', () => { expect(validateHost('fc00::1').ok).toBe(false); });
  it('blocks 2001:db8:: doc range', () => { expect(validateHost('2001:db8::1').ok).toBe(false); });
  it('blocks v4-mapped loopback', () => { expect(validateHost('::ffff:127.0.0.1').ok).toBe(false); });
  it('allows a public v6', () => { expect(validateHost('2606:4700:4700::1111').ok).toBe(true); });
});

describe('validateHost - hostnames', () => {
  const blocked = ['localhost', 'LOCALHOST', 'some.internal', 'printer.lan', 'svc.local', 'app.corp'];
  for (const h of blocked) {
    it(`blocks ${h}`, () => { expect(validateHost(h).ok).toBe(false); });
  }
  it('allows normal public domains', () => {
    expect(validateHost('github.com').ok).toBe(true);
    expect(validateHost('www.microsoft.com').ok).toBe(true);
  });
});

describe('validateFetchUrl', () => {
  it('blocks metadata URL even via URL', () => {
    expect(validateFetchUrl('http://169.254.169.254/latest/meta-data/').ok).toBe(false);
  });

  it('blocks file scheme', () => {
    expect(validateFetchUrl('file:///etc/passwd').ok).toBe(false);
  });

  it('allows real https', () => {
    expect(validateFetchUrl('https://github.com/').ok).toBe(true);
  });
});
