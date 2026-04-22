import { describe, it, expect } from 'vitest';
import { diffSnapshots } from '../src/lib/diff';

describe('diffSnapshots', () => {
  it('returns equal=true for identical objects', () => {
    const a = { headers: { hsts: 'max-age=1' }, csp: null } as const;
    const b = JSON.parse(JSON.stringify(a));
    const r = diffSnapshots(a as never, b);
    expect(r.equal).toBe(true);
    expect(r.changes).toHaveLength(0);
  });

  it('detects added and removed primitive fields', () => {
    const a = { a: 1 };
    const b = { a: 1, b: 2 };
    const r = diffSnapshots(a as never, b as never);
    expect(r.equal).toBe(false);
    expect(r.changes).toEqual([{ path: 'b', before: undefined, after: 2, kind: 'added' }]);
  });

  it('detects changed primitives with before+after', () => {
    const a = { x: 'old' };
    const b = { x: 'new' };
    const r = diffSnapshots(a as never, b as never);
    expect(r.changes).toEqual([{ path: 'x', before: 'old', after: 'new', kind: 'changed' }]);
  });

  it('treats scalar arrays as sets (order-insensitive)', () => {
    const a = { hosts: ['a.com', 'b.com'] };
    const b = { hosts: ['b.com', 'a.com'] };
    expect(diffSnapshots(a as never, b as never).equal).toBe(true);
  });

  it('reports additions and removals in scalar arrays', () => {
    const a = { hosts: ['a.com', 'b.com'] };
    const b = { hosts: ['a.com', 'c.com'] };
    const r = diffSnapshots(a as never, b as never);
    const kinds = r.changes.map((c) => c.kind).sort();
    expect(kinds).toEqual(['added', 'removed']);
    const paths = new Set(r.changes.map((c) => c.path));
    expect(paths).toEqual(new Set(['hosts']));
  });

  it('aligns object arrays by "name" key so reorder is not noise', () => {
    const a = { cookies: [{ name: 'a', secure: true }, { name: 'b', secure: false }] };
    const b = { cookies: [{ name: 'b', secure: false }, { name: 'a', secure: true }] };
    expect(diffSnapshots(a as never, b as never).equal).toBe(true);
  });

  it('reports changed cookie attributes on the right path', () => {
    const a = { cookies: [{ name: 'sess', sameSite: 'Lax', secure: true }] };
    const b = { cookies: [{ name: 'sess', sameSite: 'None', secure: true }] };
    const r = diffSnapshots(a as never, b as never);
    expect(r.changes).toHaveLength(1);
    const c = r.changes[0]!;
    expect(c.kind).toBe('changed');
    expect(c.path).toBe('cookies.name=sess.sameSite');
    expect(c.before).toBe('Lax');
    expect(c.after).toBe('None');
  });

  it('reports added/removed cookies', () => {
    const a = { cookies: [{ name: 'a' }] };
    const b = { cookies: [{ name: 'a' }, { name: 'b' }] };
    const r = diffSnapshots(a as never, b as never);
    expect(r.changes).toEqual([{
      path: 'cookies.name=b', before: undefined, after: { name: 'b' }, kind: 'added',
    }]);
  });

  it('recurses into nested objects', () => {
    const a = { csp: { directives: { 'script-src': ['self'] } } };
    const b = { csp: { directives: { 'script-src': ['self', 'cdn.x'] } } };
    const r = diffSnapshots(a as never, b as never);
    expect(r.changes).toEqual([{
      path: 'csp.directives.script-src', before: undefined, after: 'cdn.x', kind: 'added',
    }]);
  });

  it('handles null vs missing correctly', () => {
    const a = { csp: null };
    const b = { csp: { directives: {} } };
    const r = diffSnapshots(a as never, b as never);
    expect(r.changes).toHaveLength(1);
    expect(r.changes[0]!.kind).toBe('changed');
  });
});
