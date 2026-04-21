import { buildReport, type LiveTlsMode } from '../../src/lib/report-builder';
import { validateInput } from '../../src/lib/security';

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...CORS_HEADERS },
  });
}

type Env = { SHODAN_API_KEY?: string; BROWSER?: unknown };

function parseLiveMode(v: string | null | undefined): LiveTlsMode | undefined {
  if (v == null) return undefined;
  const s = String(v).toLowerCase();
  if (s === 'off' || s === 'fast' || s === 'full') return s;
  return undefined;
}

export const onRequestOptions: PagesFunction<Env> = async () =>
  new Response(null, { status: 204, headers: CORS_HEADERS });

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  const url = new URL(request.url);
  const input = url.searchParams.get('input');
  if (!input) return json({ error: 'Missing required query parameter: input' }, 400);
  const livetlsMode = parseLiveMode(url.searchParams.get('live'));
  return runAndRespond(input, env, livetlsMode);
};

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  let body: { input?: string; live?: string } = {};
  try {
    body = (await request.json()) as { input?: string; live?: string };
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }
  if (!body.input) return json({ error: 'Body must include "input"' }, 400);
  return runAndRespond(body.input, env, parseLiveMode(body.live));
};

async function runAndRespond(input: string, env: Env, livetlsMode?: LiveTlsMode): Promise<Response> {
  const v = validateInput(input);
  if (!v.ok) return json({ error: v.reason }, 400);
  try {
    const report = await buildReport(input, {
      shodanApiKey: env.SHODAN_API_KEY,
      browserBinding: env.BROWSER,
      livetlsMode,
    });
    return json(report);
  } catch (err) {
    return json({ error: err instanceof Error ? err.message : String(err) }, 400);
  }
}
