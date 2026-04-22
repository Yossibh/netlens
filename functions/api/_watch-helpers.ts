// Shared helpers for the /api/targets/* and /api/diff endpoints.

import type { KvBinding } from '../../src/lib/watch-store';

export interface WatchEnv {
  NETRECON_KV?: KvBinding;
}

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
  'access-control-allow-headers': 'content-type',
} as const;

export function json(body: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...CORS,
      ...extraHeaders,
    },
  });
}

export function preflight(): Response {
  return new Response(null, { status: 204, headers: CORS });
}

const UID_COOKIE = 'netrecon_uid';

function readCookie(req: Request, name: string): string | null {
  const raw = req.headers.get('cookie') ?? '';
  for (const part of raw.split(/;\s*/)) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq) === name) return part.slice(eq + 1);
  }
  return null;
}

export interface UidResolution {
  uid: string;
  setCookieHeader?: string;
}

// Resolve the anonymous owner id. If the client has no cookie, mint one and
// return a Set-Cookie header that must be attached to the response.
export function resolveUid(req: Request): UidResolution {
  const existing = readCookie(req, UID_COOKIE);
  if (existing && /^[a-zA-Z0-9_-]{12,64}$/.test(existing)) return { uid: existing };
  const uid = `u_${crypto.randomUUID().replace(/-/g, '').slice(0, 20)}`;
  // 1 year, same-site lax so cookie survives redirects from our own domain.
  const setCookieHeader = `${UID_COOKIE}=${uid}; Max-Age=31536000; Path=/; SameSite=Lax; Secure; HttpOnly`;
  return { uid, setCookieHeader };
}

export function withSetCookie(res: Response, setCookieHeader?: string): Response {
  if (!setCookieHeader) return res;
  const h = new Headers(res.headers);
  h.append('set-cookie', setCookieHeader);
  return new Response(res.body, { status: res.status, headers: h });
}

export function requireKv(env: WatchEnv): KvBinding | Response {
  if (!env.NETRECON_KV) {
    return json({ error: 'Target registry is not configured on this deployment (missing NETRECON_KV binding).' }, 503);
  }
  return env.NETRECON_KV;
}
