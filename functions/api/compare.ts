import { buildComparison } from '../../src/lib/report-builder';

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...CORS_HEADERS },
  });
}

export const onRequestOptions: PagesFunction = async () =>
  new Response(null, { status: 204, headers: CORS_HEADERS });

export const onRequestPost: PagesFunction = async ({ request }) => {
  let body: { a?: string; b?: string } = {};
  try {
    body = (await request.json()) as { a?: string; b?: string };
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }
  if (!body.a || !body.b) return json({ error: 'Body must include "a" and "b"' }, 400);
  try {
    const report = await buildComparison(body.a, body.b);
    return json(report);
  } catch (err) {
    return json({ error: err instanceof Error ? err.message : String(err) }, 400);
  }
};
