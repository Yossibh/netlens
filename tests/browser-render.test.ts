import { describe, it, expect, vi, beforeEach } from 'vitest';
import { captureBrowserRender } from '../src/lib/browser-render';

// Build a fake puppeteer that simulates a page load and drives the event
// handlers registered by the module under test. This lets us assert shape,
// truncation, sorting, and third-party host categorisation without a real
// browser binding.

interface FakeEvents {
  console?: Array<{ type: string; text: string }>;
  pageerror?: string[];
  requests?: string[];
  responseUrl?: string;
  timing?: { dcl?: number; load?: number; fcp?: number; lcp?: number };
  throwOnLaunch?: boolean;
  throwOnGoto?: string;
}

function makeFake(ev: FakeEvents) {
  const pageHandlers: Record<string, ((...args: unknown[]) => void)[]> = {};
  const page = {
    on(event: string, handler: (...args: unknown[]) => void) {
      (pageHandlers[event] ||= []).push(handler);
    },
    async goto(_url: string) {
      if (ev.throwOnGoto) throw new Error(ev.throwOnGoto);
      // Drive the listeners synchronously-ish.
      for (const c of ev.console || []) {
        for (const h of pageHandlers['console'] || []) h({ type: () => c.type, text: () => c.text });
      }
      for (const msg of ev.pageerror || []) {
        for (const h of pageHandlers['pageerror'] || []) h(new Error(msg));
      }
      for (const url of ev.requests || []) {
        for (const h of pageHandlers['request'] || []) h({ url: () => url });
      }
      return { url: () => ev.responseUrl || _url };
    },
    async evaluate(_fn: unknown) {
      return ev.timing || {};
    },
  };
  return {
    launch: async () => {
      if (ev.throwOnLaunch) throw new Error('launch failed');
      return { newPage: async () => page, close: async () => {} };
    },
  };
}

vi.mock('@cloudflare/puppeteer', async () => {
  return { default: {} };
});

// Re-import the module under test after mock is installed. Because the module
// imports puppeteer at the top, we rewire via a per-test dynamic import using
// vi.doMock.
async function loadWithFake(fake: ReturnType<typeof makeFake>) {
  vi.resetModules();
  vi.doMock('@cloudflare/puppeteer', () => ({ default: fake }));
  const mod = await import('../src/lib/browser-render');
  return mod;
}

describe('browser-render', () => {
  beforeEach(() => { vi.resetModules(); });

  it('returns an unavailable envelope when no binding is passed', async () => {
    const mod = await loadWithFake(makeFake({}));
    const r = await mod.captureBrowserRender('https://example.com/', null);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/unavailable/);
  });

  it('rejects blocked URLs via the SSRF guard', async () => {
    const mod = await loadWithFake(makeFake({}));
    const r = await mod.captureBrowserRender('http://127.0.0.1/', { fake: true });
    expect(r.ok).toBe(false);
  });

  it('captures console errors and truncates long messages', async () => {
    const long = 'x'.repeat(500);
    const fake = makeFake({
      console: [
        { type: 'error', text: long },
        { type: 'error', text: 'boom' },
        { type: 'log', text: 'ignored' },
      ],
      requests: ['https://example.com/', 'https://cdn.other.com/a.js'],
      responseUrl: 'https://example.com/',
      timing: { dcl: 120.7, load: 330.2, fcp: 90, lcp: 150 },
    });
    const mod = await loadWithFake(fake);
    const r = await mod.captureBrowserRender('https://example.com/', { fake: true });
    expect(r.ok).toBe(true);
    expect(r.consoleErrors.count).toBe(2);
    expect(r.consoleErrors.samples.every((s) => s.length <= 120)).toBe(true);
    expect(r.timing?.domContentLoaded).toBe(121);
    expect(r.timing?.load).toBe(330);
    expect(r.timing?.firstContentfulPaint).toBe(90);
    expect(r.timing?.largestContentfulPaint).toBe(150);
  });

  it('separates first-party from third-party hosts and sorts', async () => {
    const fake = makeFake({
      requests: [
        'https://example.com/',
        'https://example.com/assets/x.js',
        'https://z.example.net/a',
        'https://a.example.net/a',
        'https://cdn.segment.io/v1/p',
      ],
      responseUrl: 'https://example.com/',
    });
    const mod = await loadWithFake(fake);
    const r = await mod.captureBrowserRender('https://example.com/', { fake: true });
    expect(r.ok).toBe(true);
    expect(r.network.total).toBe(5);
    expect(r.network.firstParty).toBe(2);
    expect(r.network.thirdParty).toBe(3);
    expect(r.network.thirdPartyHosts).toEqual(['a.example.net', 'cdn.segment.io', 'z.example.net']);
  });

  it('returns ok=false with the error message on navigation failure', async () => {
    const fake = makeFake({ throwOnGoto: 'net::ERR_TIMED_OUT' });
    const mod = await loadWithFake(fake);
    const r = await mod.captureBrowserRender('https://example.com/', { fake: true });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/ERR_TIMED_OUT/);
  });
});
// silence unused import warning
void captureBrowserRender;
