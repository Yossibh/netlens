// Per-IP rate limiter for /api/* using the Cloudflare Cache API as a
// cross-invocation counter.
//
// Why the Cache API and not KV or a Durable Object?
// - Cache API is available on free Pages without any binding.
// - Counters are per-colo, not global. That's perfectly acceptable here: a
//   flooding attacker typically lands on a small number of colos, and edge-
//   local limits still cap blast radius. The worst case (distributed low-rate
//   attack spreading across colos) is exactly what Cloudflare's DDoS layer
//   already handles upstream.
// - No extra cost, no extra moving parts.
//
// Policy (per client IP, per path family):
//   POST/GET /api/analyze   10 req / 60s
//   POST     /api/compare   10 req / 60s
//   GET      /api/whoami    60 req / 60s
//   GET      /api/health    unlimited (used by our own status chip)
//   GET      /api/tools     unlimited (static metadata)

interface Policy {
  limit: number;
  windowSec: number;
}

function policyFor(path: string): Policy | null {
  if (path.startsWith('/api/analyze')) return { limit: 10, windowSec: 60 };
  if (path.startsWith('/api/compare')) return { limit: 10, windowSec: 60 };
  if (path.startsWith('/api/mcp'))     return { limit: 20, windowSec: 60 };
  if (path.startsWith('/api/whoami'))  return { limit: 60, windowSec: 60 };
  return null;
}

function clientIp(request: Request): string {
  return (
    request.headers.get('cf-connecting-ip') ||
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    'unknown'
  );
}

// Build a cache key unique to the (ip, path-family, window-bucket) triple.
// Using a time bucket means the counter naturally expires; we don't have to
// clean up stale entries.
function bucketKey(ip: string, family: string, windowSec: number): Request {
  const bucket = Math.floor(Date.now() / 1000 / windowSec);
  // The URL is internal - it's only used as a cache key, never fetched.
  const url = `https://ratelimit.internal/${encodeURIComponent(ip)}/${family}/${bucket}`;
  return new Request(url, { method: 'GET' });
}

function pathFamily(path: string): string {
  if (path.startsWith('/api/analyze')) return 'analyze';
  if (path.startsWith('/api/compare')) return 'compare';
  if (path.startsWith('/api/mcp'))     return 'mcp';
  if (path.startsWith('/api/whoami'))  return 'whoami';
  return 'other';
}

export const onRequest: PagesFunction = async (ctx) => {
  const url = new URL(ctx.request.url);
  const policy = policyFor(url.pathname);
  if (!policy) return ctx.next();

  // Never rate-limit CORS preflights - they're cheap and harmless.
  if (ctx.request.method === 'OPTIONS') return ctx.next();

  const ip = clientIp(ctx.request);
  const family = pathFamily(url.pathname);
  const cache = (caches as unknown as { default: Cache }).default;
  const key = bucketKey(ip, family, policy.windowSec);

  let count = 0;
  const hit = await cache.match(key);
  if (hit) {
    const prev = parseInt(hit.headers.get('x-rl-count') || '0', 10);
    count = Number.isFinite(prev) ? prev : 0;
  }
  count += 1;

  // Persist the updated counter. We set a TTL slightly longer than the window
  // so late-arriving requests in the same bucket still see the counter.
  const storeResp = new Response('', {
    headers: {
      'x-rl-count': String(count),
      'cache-control': `public, max-age=${policy.windowSec + 5}`,
    },
  });
  // waitUntil so we don't block the hot path on the cache write.
  ctx.waitUntil(cache.put(key, storeResp));

  const remaining = Math.max(policy.limit - count, 0);
  const resetSec = policy.windowSec - (Math.floor(Date.now() / 1000) % policy.windowSec);

  if (count > policy.limit) {
    return new Response(
      JSON.stringify({
        error: 'Rate limit exceeded. Please slow down.',
        limit: policy.limit,
        windowSec: policy.windowSec,
        retryAfterSec: resetSec,
      }, null, 2),
      {
        status: 429,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'retry-after': String(resetSec),
          'x-ratelimit-limit': String(policy.limit),
          'x-ratelimit-remaining': '0',
          'x-ratelimit-reset': String(resetSec),
          'access-control-allow-origin': '*',
        },
      },
    );
  }

  const response = await ctx.next();
  // Annotate successful responses with the usual rate-limit headers.
  const clone = new Response(response.body, response);
  clone.headers.set('x-ratelimit-limit', String(policy.limit));
  clone.headers.set('x-ratelimit-remaining', String(remaining));
  clone.headers.set('x-ratelimit-reset', String(resetSec));
  return clone;
};
