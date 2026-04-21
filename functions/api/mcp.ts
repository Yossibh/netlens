// Streamable HTTP MCP transport for netrecon.
//
// Spec compliance highlights:
//   - POST  accepts a JSON-RPC 2.0 request, responds with JSON-RPC 2.0.
//   - POST of a notification (no id) returns HTTP 202 Accepted with no body.
//   - GET   returns 405 (we don't offer server-initiated SSE streams).
//   - OPTIONS (CORS preflight) is always allowed; we do not rate-limit it.
//   - Origin is validated to defeat DNS-rebinding attacks from browsers.
//   - We do NOT issue or accept Mcp-Session-Id (stateless server).

import { handleMcp, type JsonRpcRequest } from '../../src/lib/mcp';

type Env = { SHODAN_API_KEY?: string };

// Browser origins allowed to call us. A missing Origin header (curl, Node,
// native MCP clients) is ALSO allowed - those aren't DNS-rebinding surfaces.
const ALLOWED_ORIGIN_SUFFIXES = [
  'netrecon.pages.dev',
  'pages.dev', // allow preview builds like <hash>.netrecon.pages.dev
];
const ALLOWED_LOCALHOSTS = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

function originAllowed(origin: string | null): { ok: boolean; echo: string } {
  if (!origin) return { ok: true, echo: '*' };
  if (ALLOWED_LOCALHOSTS.test(origin)) return { ok: true, echo: origin };
  try {
    const u = new URL(origin);
    for (const suf of ALLOWED_ORIGIN_SUFFIXES) {
      if (u.hostname === suf || u.hostname.endsWith('.' + suf)) {
        return { ok: true, echo: origin };
      }
    }
  } catch {
    // fall through
  }
  return { ok: false, echo: '' };
}

function corsHeaders(origin: string): HeadersInit {
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-methods': 'POST, GET, OPTIONS',
    'access-control-allow-headers': 'content-type, mcp-protocol-version',
    'access-control-max-age': '86400',
    vary: 'Origin',
  };
}

function json(body: unknown, status: number, origin: string): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...corsHeaders(origin),
    },
  });
}

export const onRequestOptions: PagesFunction<Env> = async ({ request }) => {
  const origin = request.headers.get('origin');
  const check = originAllowed(origin);
  if (!check.ok) return new Response(null, { status: 403 });
  return new Response(null, { status: 204, headers: corsHeaders(check.echo) });
};

export const onRequestGet: PagesFunction<Env> = async ({ request }) => {
  const origin = request.headers.get('origin');
  const check = originAllowed(origin);
  if (!check.ok) return new Response(null, { status: 403 });
  // MCP spec allows GET for SSE; we don't expose server-initiated notifications.
  return json({ error: 'GET not supported on this MCP transport (stateless server).' }, 405, check.echo);
};

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const origin = request.headers.get('origin');
  const check = originAllowed(origin);
  if (!check.ok) return new Response(null, { status: 403 });

  let msg: JsonRpcRequest;
  try {
    msg = (await request.json()) as JsonRpcRequest;
  } catch {
    return json(
      { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } },
      400,
      check.echo,
    );
  }

  const response = await handleMcp(msg, { shodanApiKey: env.SHODAN_API_KEY });

  // Notification: no response per JSON-RPC 2.0, HTTP 202 per MCP spec.
  if (response === null) {
    return new Response(null, { status: 202, headers: corsHeaders(check.echo) });
  }

  return json(response, 200, check.echo);
};
