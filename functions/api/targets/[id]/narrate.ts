// POST /api/targets/:id/narrate?a=<snapId>&b=<snapId>
//
// Runs the two named snapshots through the diff engine, then through the
// AI narrator. Separated from GET /diff so that the (potentially slow,
// neuron-burning) AI call is opt-in — the diff endpoint stays fast and free.

import { getTarget, getSnapshot } from '../../../../src/lib/watch-store';
import { diffSnapshots } from '../../../../src/lib/diff';
import { narrateDiff } from '../../../../src/lib/ai-narrator';
import {
  json,
  preflight,
  resolveUid,
  withSetCookie,
  requireKv,
  type WatchEnv,
} from '../../_watch-helpers';

export const onRequestOptions: PagesFunction<WatchEnv> = async () => preflight();

export const onRequestPost: PagesFunction<WatchEnv> = async ({ request, env, params }) => {
  const kv = requireKv(env);
  if (kv instanceof Response) return kv;
  if (!env.AI) {
    return json(
      { error: 'AI narrator is not configured on this deployment (missing AI binding).' },
      503,
    );
  }
  const id = String(params.id || '');
  if (!id) return json({ error: 'Missing target id' }, 400);

  const { uid, setCookieHeader } = resolveUid(request);
  const target = await getTarget(kv, uid, id);
  if (!target) return withSetCookie(json({ error: 'Target not found' }, 404), setCookieHeader);

  const url = new URL(request.url);
  const a = url.searchParams.get('a');
  const b = url.searchParams.get('b');
  if (!a || !b) {
    return withSetCookie(
      json({ error: 'Provide both ?a= and ?b= snapshot ids.' }, 400),
      setCookieHeader,
    );
  }

  const [snapA, snapB] = await Promise.all([
    getSnapshot(kv, target.id, a),
    getSnapshot(kv, target.id, b),
  ]);
  if (!snapA) return withSetCookie(json({ error: `Snapshot ${a} not found` }, 404), setCookieHeader);
  if (!snapB) return withSetCookie(json({ error: `Snapshot ${b} not found` }, 404), setCookieHeader);

  const stripMeta = (s: typeof snapA): Record<string, unknown> => {
    const { v: _v, capturedAt: _ts, input: _in, ...rest } = s;
    return rest as unknown as Record<string, unknown>;
  };
  const diff = diffSnapshots(
    stripMeta(snapA) as unknown as Parameters<typeof diffSnapshots>[0],
    stripMeta(snapB) as unknown as Parameters<typeof diffSnapshots>[1],
  );

  try {
    const narration = await narrateDiff(
      env.AI,
      target.input,
      { id: a, capturedAt: snapA.capturedAt },
      { id: b, capturedAt: snapB.capturedAt },
      diff,
    );
    return withSetCookie(
      json({
        target: { id: target.id, input: target.input },
        a: { id: a, capturedAt: snapA.capturedAt },
        b: { id: b, capturedAt: snapB.capturedAt },
        diff,
        narration,
      }),
      setCookieHeader,
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'AI narration failed';
    return withSetCookie(json({ error: 'AI narration failed', detail: msg }, 502), setCookieHeader);
  }
};
