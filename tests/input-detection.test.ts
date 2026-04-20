import { describe, it, expect } from 'vitest';
import { detectInput, toProbeUrl } from '../src/lib/input-detection';

describe('detectInput', () => {
  it('detects IPv4', () => {
    const r = detectInput('1.1.1.1');
    expect(r.type).toBe('ip');
    expect(r.ip).toBe('1.1.1.1');
    expect(r.ipVersion).toBe('v4');
  });

  it('detects IPv6 (compressed)', () => {
    const r = detectInput('2606:4700:4700::1111');
    expect(r.type).toBe('ip');
    expect(r.ipVersion).toBe('v6');
  });

  it('detects bare domain (lowercases)', () => {
    const r = detectInput('Example.COM');
    expect(r.type).toBe('domain');
    expect(r.domain).toBe('example.com');
  });

  it('detects URL with path', () => {
    const r = detectInput('https://www.github.com/foo/bar?x=1');
    expect(r.type).toBe('url');
    expect(r.host).toBe('www.github.com');
    expect(r.domain).toBe('www.github.com');
    expect(r.url).toContain('github.com');
  });

  it('detects http URL with IP host', () => {
    const r = detectInput('http://1.1.1.1/path');
    expect(r.type).toBe('url');
    expect(r.ip).toBe('1.1.1.1');
    expect(r.domain).toBeUndefined();
  });

  it('rejects unsupported protocols', () => {
    expect(() => detectInput('ftp://example.com/')).toThrow(/Unsupported protocol/);
  });

  it('rejects empty / garbage', () => {
    expect(() => detectInput('   ')).toThrow();
    expect(() => detectInput('not a domain!!')).toThrow(/Unable to detect/);
  });

  it('accepts host:port form as domain', () => {
    const r = detectInput('example.com:8443');
    expect(r.type).toBe('domain');
    expect(r.domain).toBe('example.com');
  });

  it('toProbeUrl synthesizes https for domains', () => {
    const r = detectInput('example.com');
    expect(toProbeUrl(r)).toBe('https://example.com');
  });

  it('toProbeUrl returns original URL when URL given', () => {
    const r = detectInput('https://a.b/c');
    expect(toProbeUrl(r)).toBe('https://a.b/c');
  });

  it('toProbeUrl handles IPv6 with brackets', () => {
    const r = detectInput('2606:4700:4700::1111');
    expect(toProbeUrl(r)).toBe('https://[2606:4700:4700::1111]');
  });
});
