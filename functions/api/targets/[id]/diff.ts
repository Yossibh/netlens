import { getTargetPublic, getSnapshot } from '../../../../src/lib/watch-store';
import { diffSnapshots } from '../../../../src/lib/diff';
import {
  json,
  preflight,
  requireKv,
  type WatchEnv,
} from '../../_watch-helpers';

export const onRequestOptions: PagesFunction<WatchEnv> = async () => preflight();

// GET /api/targets/:id/diff?a=<snapId>&b=<snapId>
// Public read — powers the /d/<id> permalink.
export const onRequestGet: PagesFunction<WatchEnv> = async ({ request, env, params }) => {
  const kv = requireKv(env);
  if (kv instanceof Response) return kv;
  const id = String(params.id || '');
  if (!id) return json({ error: 'Missing target id' }, 400);
  const target = await getTargetPublic(kv, id);
  if (!target) return json({ error: 'Target not found' }, 404);

  const url = new URL(request.url);
  const a = url.searchParams.get('a');
  const b = url.searchParams.get('b');
  if (!a || !b) return json({ error: 'Provide both ?a= and ?b= snapshot ids.' }, 400);

  const [snapA, snapB] = await Promise.all([
    getSnapshot(kv, target.id, a),
    getSnapshot(kv, target.id, b),
  ]);
  if (!snapA) return json({ error: `Snapshot ${a} not found` }, 404);
  if (!snapB) return json({ error: `Snapshot ${b} not found` }, 404);

  const stripMeta = (s: typeof snapA): Record<string, unknown> => {
    const { v: _v, capturedAt: _ts, input: _in, ...rest } = s;
    return rest as unknown as Record<string, unknown>;
  };
  const result = diffSnapshots(
    stripMeta(snapA) as unknown as Parameters<typeof diffSnapshots>[0],
    stripMeta(snapB) as unknown as Parameters<typeof diffSnapshots>[1],
  );
  return json({
    target: { id: target.id, input: target.input },
    a: { id: a, capturedAt: snapA.capturedAt },
    b: { id: b, capturedAt: snapB.capturedAt },
    ...result,
  });
};
