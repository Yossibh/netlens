import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { probeExposure, PROBE_LIST } from '../src/lib/exposure';

// Minimal fake fetch we can prime with a status-per-path map.
function installFakeFetch(statusByPath: Record<string, number>): () => void {
  const orig = globalThis.fetch;
  globalThis.fetch = vi.fn(async (url: string | URL | Request, _init?: RequestInit) => {
    const u = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
    const parsed = new URL(u);
    const path = parsed.pathname;
    const status = statusByPath[path];
    if (status === undefined) {
      // Simulate network failure by throwing.
      throw new Error('ECONNRESET');
    }
    return new Response('x', {
      status,
      headers: { 'content-type': 'text/html', 'content-length': '1' },
    });
  }) as unknown as typeof globalThis.fetch;
  return () => { globalThis.fetch = orig; };
}

describe('probeExposure', () => {
  let restore: () => void = () => {};
  afterEach(() => restore());
  beforeEach(() => { restore = () => {}; });

  it('probes every path in the curated list', async () => {
    const allFound: Record<string, number> = {};
    for (const p of PROBE_LIST) allFound[p.path] = 404;
    restore = installFakeFetch(allFound);
    const m = await probeExposure('https://example.com/');
    expect(m.probes.length).toBe(PROBE_LIST.length);
    expect(m.summary.total).toBe(PROBE_LIST.length);
    expect(m.summary.notFound).toBe(PROBE_LIST.length);
    expect(m.summary.reachable).toBe(0);
  });

  it('categorises 200/401/404/error correctly', async () => {
    restore = installFakeFetch({
      '/openapi.json': 200,
      '/admin': 401,
      '/graphql': 200,
      '/.env': 403,
      '/health': 200,
      // everything else throws → error
    });
    const m = await probeExposure('https://example.com/');
    expect(m.summary.reachable).toBeGreaterThanOrEqual(3);
    expect(m.summary.authRequired).toBeGreaterThanOrEqual(2);
    const gq = m.probes.find((p) => p.path === '/graphql');
    expect(gq?.note).toBe('graphql-reachable');
  });

  it('sorts probes by path for stable diffs', async () => {
    restore = installFakeFetch(Object.fromEntries(PROBE_LIST.map((p) => [p.path, 404])));
    const m = await probeExposure('https://example.com/');
    for (let i = 1; i < m.probes.length; i++) {
      expect(m.probes[i].path >= m.probes[i - 1].path).toBe(true);
    }
  });

  it('returns an empty matrix if the base URL is not parseable', async () => {
    const m = await probeExposure('not-a-url');
    expect(m.probes).toEqual([]);
    expect(m.summary.total).toBe(0);
  });

  it('treats network errors as status=null, not a crash', async () => {
    // Throw for every URL.
    restore = installFakeFetch({});
    const m = await probeExposure('https://example.com/');
    expect(m.probes.every((p) => p.status === null)).toBe(true);
    expect(m.summary.error).toBe(PROBE_LIST.length);
  });
});
