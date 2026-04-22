// Tier D3 — browser-rendered diagnostic signals.
//
// Spins up headless Chromium via the BROWSER binding, loads the target, and
// captures what the browser actually observes (console errors, network fan-out,
// navigation timing, LCP). These signals are *structurally* impossible to get
// from a raw fetch — they're the differentiator vs. an AI coding agent that
// can `curl` locally.
//
// Cost model: Workers Free gives 10 browser-minutes / day and 3 concurrent
// sessions. A render here averages ~4-6s wall time, so ~100-150/day budget.
// We gate this behind an owner-triggered opt-in (`?browser=1`) plus a 22h
// per-target cooldown enforced in KV so users can't accidentally burn the cap.
//
// Stability: console messages and network orders are inherently flaky across
// renders. We shape the output for diff-friendliness:
//   - Messages are truncated to 120 chars, de-duped, sorted.
//   - Third-party hosts are sorted.
//   - Timing numbers are stored as integers (ms), not floats.
// A two-render sanity test against a stable site should produce either an
// equal diff or a very small one.
//
// Safety: we honour the same SSRF guard as the raw fetch path (validateFetchUrl).

import puppeteer, { type Browser } from '@cloudflare/puppeteer';
import { validateFetchUrl } from './security';

export interface BrowserRender {
  v: 1;
  ok: boolean;
  error?: string;
  finalUrl?: string;
  // Wall-clock ms from navigationStart, rounded to int. Missing entries are
  // omitted rather than zeroed so "unavailable" doesn't look like "instant".
  timing?: {
    domContentLoaded?: number;
    load?: number;
    firstContentfulPaint?: number;
    largestContentfulPaint?: number;
  };
  // Console messages with level=error. Stable-shaped for diffing.
  consoleErrors: {
    count: number;
    samples: string[]; // up to 5 unique prefixes, sorted, ≤120 chars each
  };
  unhandledRejections: {
    count: number;
    samples: string[]; // up to 3 unique prefixes, sorted
  };
  network: {
    total: number;
    firstParty: number;
    thirdParty: number;
    thirdPartyHosts: string[]; // sorted, unique
  };
}

const NAV_TIMEOUT_MS = 15_000;
const MAX_CONSOLE_SAMPLES = 5;
const MAX_REJECTION_SAMPLES = 3;
const MAX_MSG_LEN = 120;

function truncate(s: string, n = MAX_MSG_LEN): string {
  return s.length > n ? s.slice(0, n) : s;
}

function uniqSort(xs: string[]): string[] {
  return Array.from(new Set(xs)).sort();
}

function failEnvelope(error: string): BrowserRender {
  return {
    v: 1,
    ok: false,
    error,
    consoleErrors: { count: 0, samples: [] },
    unhandledRejections: { count: 0, samples: [] },
    network: { total: 0, firstParty: 0, thirdParty: 0, thirdPartyHosts: [] },
  };
}

export async function captureBrowserRender(
  input: string,
  browser: unknown,
): Promise<BrowserRender> {
  if (!browser) return failEnvelope('browser binding unavailable');

  const guard = validateFetchUrl(input);
  if (!guard.ok) return failEnvelope(guard.reason || 'blocked target');

  let originHost: string;
  try { originHost = new URL(input).host; }
  catch { return failEnvelope('invalid url'); }

  let b: Browser | null = null;
  const errors: string[] = [];
  const rejections: string[] = [];
  const requestHosts: string[] = [];
  let total = 0;

  try {
    b = await puppeteer.launch(browser as never);
    const page = await b.newPage();

    page.on('console', (msg: unknown) => {
      const m = msg as { type?: () => string; text?: () => string };
      try {
        if (m.type && m.type() === 'error') {
          const text = m.text ? m.text() : '';
          if (text) errors.push(truncate(text));
        }
      } catch { /* ignore */ }
    });
    page.on('pageerror', (err: unknown) => {
      const e = err as Error;
      rejections.push(truncate(e?.message || String(err)));
    });
    page.on('request', (req: unknown) => {
      const r = req as { url?: () => string };
      try {
        const u = r.url ? r.url() : '';
        if (!u) return;
        total += 1;
        const host = new URL(u).host;
        if (host !== originHost) requestHosts.push(host);
      } catch { /* ignore */ }
    });

    const response = await page.goto(input, { waitUntil: 'load', timeout: NAV_TIMEOUT_MS });
    const finalUrl = response?.url?.() || input;

    // Navigation timing. Use the spec'd PerformanceObserver so we get modern
    // values (FCP, LCP) when the page supports them.
    type PageTiming = { dcl?: number; load?: number; fcp?: number; lcp?: number };
    let timing: PageTiming = {};
    try {
      timing = (await page.evaluate(() => {
        const t = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
        const paints = performance.getEntriesByType('paint') as PerformanceEntry[];
        const fcp = paints.find((p) => p.name === 'first-contentful-paint')?.startTime;
        // Best-effort LCP grab; requires observer to be set up before the event
        // ideally — on a completed load we just take the largest entry if the
        // browser has surfaced it.
        let lcp: number | undefined;
        try {
          const lcpEntries = performance.getEntriesByType('largest-contentful-paint') as PerformanceEntry[];
          if (lcpEntries && lcpEntries.length > 0) lcp = lcpEntries[lcpEntries.length - 1].startTime;
        } catch { /* some engines don't index LCP via getEntriesByType */ }
        return {
          dcl: t?.domContentLoadedEventEnd,
          load: t?.loadEventEnd,
          fcp,
          lcp,
        };
      })) as PageTiming;
    } catch { /* timing collection failed; leave empty */ }

    const thirdPartyHosts = uniqSort(requestHosts);
    const firstParty = total - requestHosts.length;

    const result: BrowserRender = {
      v: 1,
      ok: true,
      finalUrl,
      timing: {},
      consoleErrors: {
        count: errors.length,
        samples: uniqSort(errors).slice(0, MAX_CONSOLE_SAMPLES),
      },
      unhandledRejections: {
        count: rejections.length,
        samples: uniqSort(rejections).slice(0, MAX_REJECTION_SAMPLES),
      },
      network: {
        total,
        firstParty,
        thirdParty: requestHosts.length,
        thirdPartyHosts,
      },
    };
    if (typeof timing.dcl === 'number' && Number.isFinite(timing.dcl)) result.timing!.domContentLoaded = Math.round(timing.dcl);
    if (typeof timing.load === 'number' && Number.isFinite(timing.load)) result.timing!.load = Math.round(timing.load);
    if (typeof timing.fcp === 'number' && Number.isFinite(timing.fcp)) result.timing!.firstContentfulPaint = Math.round(timing.fcp);
    if (typeof timing.lcp === 'number' && Number.isFinite(timing.lcp)) result.timing!.largestContentfulPaint = Math.round(timing.lcp);
    return result;
  } catch (err) {
    return failEnvelope(err instanceof Error ? err.message : 'render failed');
  } finally {
    try { await b?.close(); } catch { /* ignore */ }
  }
}
