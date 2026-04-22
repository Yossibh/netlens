import { describe, it, expect } from 'vitest';
import { parseCsp, parseSetCookie } from '../src/lib/signals';

describe('signals.parseCsp', () => {
  it('splits directives and sorts sources', () => {
    const out = parseCsp("default-src 'self'; script-src 'unsafe-inline' 'self' https://cdn.x");
    expect(out.directives['default-src']).toEqual(["'self'"]);
    expect(out.directives['script-src']).toEqual([
      "'self'",
      "'unsafe-inline'",
      'https://cdn.x',
    ]);
  });

  it('merges duplicate directives', () => {
    const out = parseCsp("script-src 'self'; script-src https://cdn.x");
    expect(out.directives['script-src']).toEqual(["'self'", 'https://cdn.x']);
  });

  it('lowercases directive names', () => {
    const out = parseCsp("Default-SRC 'self'");
    expect(Object.keys(out.directives)).toEqual(['default-src']);
  });

  it('retains raw text', () => {
    const src = "default-src 'self'";
    expect(parseCsp(src).raw).toBe(src);
  });
});

describe('signals.parseSetCookie', () => {
  it('extracts name, sameSite, secure, httpOnly', () => {
    const out = parseSetCookie([
      'sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600',
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      name: 'sid',
      sameSite: 'Lax',
      secure: true,
      httpOnly: true,
      path: '/',
      maxAge: 3600,
    });
  });

  it('handles missing attributes as falsy', () => {
    const out = parseSetCookie(['plain=value']);
    expect(out[0]).toMatchObject({ name: 'plain', secure: false, httpOnly: false, hasExpires: false });
    expect(out[0]!.sameSite).toBeUndefined();
  });

  it('sorts cookies by name for stable diff', () => {
    const out = parseSetCookie(['z=1', 'a=1', 'm=1']);
    expect(out.map((c) => c.name)).toEqual(['a', 'm', 'z']);
  });

  it('preserves domain and expires flag', () => {
    const out = parseSetCookie(['s=1; Domain=.example.com; Expires=Wed, 01 Jan 2025 00:00:00 GMT']);
    expect(out[0]!.domain).toBe('.example.com');
    expect(out[0]!.hasExpires).toBe(true);
  });

  it('ignores malformed lines without dropping valid ones', () => {
    const out = parseSetCookie(['', 'novalue', 'good=1']);
    expect(out.map((c) => c.name)).toEqual(['good']);
  });
});
