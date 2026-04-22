import { getTarget, getSnapshot } from '../../../../src/lib/watch-store';
import { diffSnapshots } from '../../../../src/lib/diff';
import {
  json,
  preflight,
  resolveUid,
  withSetCookie,
  requireKv,
  type WatchEnv,
} from '../../_watch-helpers';

export const onRequestOptions: PagesFunction<WatchEnv> = async () => preflight();

// GET /api/targets/:id/diff?a=<snapId>&b=<snapId>
export const onRequestGet: PagesFunction<WatchEnv> = async ({ request, env, params }) => {
  const kv = requireKv(env);
  if (kv instanceof Response) return kv;
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

  // Strip metadata fields that always differ (timestamps, schema version, input
  // URL) before diffing so the change list only contains externally-observable
  // state changes.
  const stripMeta = (s: typeof snapA): Record<string, unknown> => {
    const { v: _v, capturedAt: _ts, input: _in, ...rest } = s;
    return rest as unknown as Record<string, unknown>;
  };
  const result = diffSnapshots(
    stripMeta(snapA) as unknown as Parameters<typeof diffSnapshots>[0],
    stripMeta(snapB) as unknown as Parameters<typeof diffSnapshots>[1],
  );
  return withSetCookie(
    json({
      target: { id: target.id, input: target.input },
      a: { id: a, capturedAt: snapA.capturedAt },
      b: { id: b, capturedAt: snapB.capturedAt },
      ...result,
    }),
    setCookieHeader,
  );
};
