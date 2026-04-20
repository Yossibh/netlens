import type { HttpModuleResult, HttpRedirect } from '@/types';

const MAX_REDIRECTS = 8;
const FETCH_TIMEOUT_MS = 8000;

// Cloudflare Workers' outbound fetch() injects its own headers on the response
// (the subrequest round-trips through CF's edge). These are NOT origin headers.
// We strip them so CDN inference, findings, and raw JSON reflect the real origin.
// 'server: cloudflare' is also injected in some paths; we drop it only when
// cf-ray is present (signal that the response passed through our own runtime).
const CF_INJECTED_HEADERS = new Set([
  'cf-ray',
  'cf-cache-status',
  'cf-request-id',
  'cf-connecting-ip',
  'cf-visitor',
  'cf-ipcountry',
  'cf-ew-via',
]);

function headersToObject(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((v, k) => { out[k.toLowerCase()] = v; });
  const cfRayPresent = 'cf-ray' in out;
  for (const k of CF_INJECTED_HEADERS) delete out[k];
  if (cfRayPresent && out['server']?.toLowerCase() === 'cloudflare') {
    delete out['server'];
  }
  return out;
}

function pickSecurity(h: Record<string, string>): HttpModuleResult['securityHeaders'] {
  return {
    hsts: h['strict-transport-security'],
    csp: h['content-security-policy'],
    xContentTypeOptions: h['x-content-type-options'],
    xFrameOptions: h['x-frame-options'],
    referrerPolicy: h['referrer-policy'],
    permissionsPolicy: h['permissions-policy'],
  };
}

function pickCors(h: Record<string, string>): HttpModuleResult['corsHeaders'] {
  return {
    accessControlAllowOrigin: h['access-control-allow-origin'],
    accessControlAllowCredentials: h['access-control-allow-credentials'],
  };
}

function pickCache(h: Record<string, string>): HttpModuleResult['cacheHeaders'] {
  return {
    cacheControl: h['cache-control'],
    age: h['age'],
    etag: h['etag'],
    expires: h['expires'],
  };
}

export async function inspectHttp(startUrl: string): Promise<HttpModuleResult> {
  const redirects: HttpRedirect[] = [];
  const startedAt = Date.now();
  let current = startUrl;
  let lastResponse: Response | undefined;
  const seen = new Set<string>();

  try {
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      if (seen.has(current)) {
        return {
          ok: false,
          error: `Redirect loop detected at ${current}`,
          redirects,
          headers: lastResponse ? headersToObject(lastResponse.headers) : {},
          securityHeaders: {},
          corsHeaders: {},
          cacheHeaders: {},
        };
      }
      seen.add(current);

      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
      let res: Response;
      try {
        res = await fetch(current, {
          method: 'GET',
          redirect: 'manual',
          signal: ctrl.signal,
          headers: { 'user-agent': 'netlens/0.1 (+https://netlens.pages.dev)' },
        });
      } finally {
        clearTimeout(timer);
      }
      lastResponse = res;

      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        const loc = res.headers.get('location')!;
        let next: string;
        try {
          next = new URL(loc, current).toString();
        } catch {
          return {
            ok: false,
            error: `Invalid redirect Location header: ${loc}`,
            redirects,
            headers: headersToObject(res.headers),
            securityHeaders: pickSecurity(headersToObject(res.headers)),
            corsHeaders: pickCors(headersToObject(res.headers)),
            cacheHeaders: pickCache(headersToObject(res.headers)),
          };
        }
        redirects.push({ from: current, to: next, status: res.status });
        current = next;
        continue;
      }

      const h = headersToObject(res.headers);
      return {
        ok: true,
        finalUrl: current,
        status: res.status,
        redirects,
        headers: h,
        securityHeaders: pickSecurity(h),
        corsHeaders: pickCors(h),
        cacheHeaders: pickCache(h),
        server: h['server'],
        timingMs: Date.now() - startedAt,
      };
    }

    return {
      ok: false,
      error: `Too many redirects (>${MAX_REDIRECTS})`,
      redirects,
      headers: lastResponse ? headersToObject(lastResponse.headers) : {},
      securityHeaders: {},
      corsHeaders: {},
      cacheHeaders: {},
    };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      redirects,
      headers: {},
      securityHeaders: {},
      corsHeaders: {},
      cacheHeaders: {},
    };
  }
}
