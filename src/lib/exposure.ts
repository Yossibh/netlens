// Tier D2 signal — endpoint-exposure matrix.
//
// Probes a curated list of sensitive or informational paths and records the
// HTTP status + gist (content-type + approximate size) for each. The diff of
// this matrix across snapshots is one of the highest-signal checks netrecon
// can do — a `/admin` that flips from 404 to 200 between deploys, a `/.env`
// that suddenly resolves, a `/graphql` that starts accepting introspection:
// these are the kinds of regressions that cost companies real money and that
// a local AI coding agent cannot spot because it lacks the temporal dimension.
//
// Design constraints:
//  - Subrequest-frugal. Cloudflare Workers free-tier cap is 50 subrequests per
//    invocation. captureSignals() already spends ~5 on redirects + well-known.
//    This module targets ≤20 probes so we keep budget for the future.
//  - Short timeouts. Each probe has a 4s budget; we'd rather miss one than
//    hang the whole snapshot.
//  - HEAD first, GET only if HEAD is disallowed. HEAD is cheap and most WAFs
//    allow it; if the server 405s, we fall back to a small ranged GET.
//  - No request bodies, no auth headers, no cookies. We probe as an anon.
//  - Origin-restricted. Every probe target must share origin with the final
//    URL of the snapshot — we do NOT want to accidentally probe a third party.
//
// The list of paths below is curated from common misconfiguration reports,
// the OWASP "sensitive data exposure" categories, and typical api-docs /
// admin-panel defaults. It is deliberately small: the value is in DIFFS of
// the matrix over time, not in a giant wordlist scan (which would look like
// an attack and get rate-limited). Users who want deep scanning should run a
// proper scanner; netrecon's job is change detection.

import { validateFetchUrl } from './security';

const PROBE_TIMEOUT_MS = 4000;
const USER_AGENT = 'netrecon/0.1 (+https://netrecon.pages.dev; change-detection)';

export interface ExposureProbe {
  path: string;
  status: number | null; // null = network/error
  ok: boolean; // status in 200..399
  contentType?: string;
  size?: number;
  category: 'api-docs' | 'graphql' | 'admin' | 'source-leak' | 'health' | 'meta';
  note?: string; // e.g. "graphql-introspection"
}

export interface ExposureMatrix {
  probes: ExposureProbe[];
  summary: {
    total: number;
    reachable: number; // status in 200..399
    authRequired: number; // 401/403
    notFound: number; // 404
    error: number; // network fail
  };
}

export const PROBE_LIST: Array<{ path: string; category: ExposureProbe['category'] }> = [
  // --- api-docs / openapi / swagger ---
  { path: '/openapi.json', category: 'api-docs' },
  { path: '/openapi.yaml', category: 'api-docs' },
  { path: '/swagger.json', category: 'api-docs' },
  { path: '/swagger-ui/', category: 'api-docs' },
  { path: '/api-docs', category: 'api-docs' },
  { path: '/docs', category: 'api-docs' },
  { path: '/redoc', category: 'api-docs' },
  // --- graphql ---
  { path: '/graphql', category: 'graphql' },
  { path: '/api/graphql', category: 'graphql' },
  // --- admin / console ---
  { path: '/admin', category: 'admin' },
  { path: '/admin/', category: 'admin' },
  { path: '/wp-admin/', category: 'admin' },
  // --- classic source-leaks ---
  { path: '/.git/HEAD', category: 'source-leak' },
  { path: '/.env', category: 'source-leak' },
  { path: '/.DS_Store', category: 'source-leak' },
  // --- health / telemetry (info, not vuln) ---
  { path: '/health', category: 'health' },
  { path: '/status', category: 'health' },
  { path: '/metrics', category: 'health' },
  // --- meta ---
  { path: '/humans.txt', category: 'meta' },
];

function summarize(probes: ExposureProbe[]): ExposureMatrix['summary'] {
  let reachable = 0, authRequired = 0, notFound = 0, error = 0;
  for (const p of probes) {
    if (p.status === null) error += 1;
    else if (p.status >= 200 && p.status < 400) reachable += 1;
    else if (p.status === 401 || p.status === 403) authRequired += 1;
    else if (p.status === 404) notFound += 1;
  }
  return { total: probes.length, reachable, authRequired, notFound, error };
}

async function probeOne(origin: string, path: string): Promise<Partial<ExposureProbe>> {
  const url = origin + path;
  const guard = validateFetchUrl(url);
  if (!guard.ok) return { status: null };

  // Try HEAD first; fall back to GET on 405/501 (some servers disable HEAD).
  for (const method of ['HEAD', 'GET'] as const) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), PROBE_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method,
        redirect: 'manual',
        signal: ctrl.signal,
        headers: { 'user-agent': USER_AGENT, accept: '*/*' },
      });
      clearTimeout(timer);
      // If HEAD is rejected with "method not allowed", retry with GET.
      if (method === 'HEAD' && (res.status === 405 || res.status === 501)) continue;
      const ct = res.headers.get('content-type') || undefined;
      const lenRaw = res.headers.get('content-length');
      const len = lenRaw ? parseInt(lenRaw, 10) : undefined;
      return {
        status: res.status,
        contentType: ct ? ct.split(';')[0].trim().toLowerCase() : undefined,
        size: Number.isFinite(len) ? len : undefined,
      };
    } catch {
      clearTimeout(timer);
      // Keep trying GET if HEAD was the only failure so far.
      if (method === 'HEAD') continue;
      return { status: null };
    }
  }
  return { status: null };
}

export async function probeExposure(finalUrl: string): Promise<ExposureMatrix> {
  let origin: string;
  try {
    origin = new URL(finalUrl).origin;
  } catch {
    return { probes: [], summary: { total: 0, reachable: 0, authRequired: 0, notFound: 0, error: 0 } };
  }

  // Probe in parallel but cap the fan-out to keep egress peaks polite.
  const BATCH = 6;
  const probes: ExposureProbe[] = [];
  for (let i = 0; i < PROBE_LIST.length; i += BATCH) {
    const slice = PROBE_LIST.slice(i, i + BATCH);
    const batchResults = await Promise.all(
      slice.map(async (p) => {
        const r = await probeOne(origin, p.path);
        const probe: ExposureProbe = {
          path: p.path,
          category: p.category,
          status: r.status ?? null,
          ok: r.status != null && r.status >= 200 && r.status < 400,
          contentType: r.contentType,
          size: r.size,
        };
        // Special case: a GraphQL endpoint that responds 200 to a GET without
        // a query often means introspection is open. We don't actively probe
        // (that's scanning), but we record the hint so the narrator can flag
        // it.
        if (probe.category === 'graphql' && probe.ok) probe.note = 'graphql-reachable';
        return probe;
      }),
    );
    probes.push(...batchResults);
  }
  // Stable order for stable diffs — sort by path.
  probes.sort((a, b) => a.path.localeCompare(b.path));
  return { probes, summary: summarize(probes) };
}
