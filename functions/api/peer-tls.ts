// GET /api/peer-tls?host=<hostname>[&port=443]
//
// Opens a raw TCP connection to the target, performs enough of a TLS 1.2
// handshake to capture the peer's Certificate chain, and returns extracted
// cert metadata + negotiated version/cipher.
//
// Prototype status: see docs/phase4-live-tls.md.

import { inspectPeerTls } from '../../src/lib/tls-peer';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-netrecon-endpoint': 'peer-tls',
    },
  });
}

export const onRequestGet: PagesFunction = async ({ request }) => {
  const url = new URL(request.url);
  const host = (url.searchParams.get('host') || '').trim();
  const portRaw = url.searchParams.get('port');
  if (!host) return json({ error: 'Missing required query param: host' }, 400);
  let port = 443;
  if (portRaw) {
    const p = parseInt(portRaw, 10);
    if (Number.isNaN(p) || p < 1 || p > 65535) return json({ error: 'Invalid port' }, 400);
    port = p;
  }
  try {
    const result = await inspectPeerTls(host, port);
    return json(result, result.ok ? 200 : 200); // always 200, status is in body.ok
  } catch (err: any) {
    return json({ error: err?.message ?? String(err) }, 500);
  }
};
