import { captureSignals } from '../../../../src/lib/signals';
import {
  getTarget,
  putSnapshot,
  listSnapshotHeaders,
} from '../../../../src/lib/watch-store';
import {
  json,
  preflight,
  resolveUid,
  withSetCookie,
  requireKv,
  type WatchEnv,
} from '../../_watch-helpers';

export const onRequestOptions: PagesFunction<WatchEnv> = async () => preflight();

export const onRequestGet: PagesFunction<WatchEnv> = async ({ request, env, params }) => {
  const kv = requireKv(env);
  if (kv instanceof Response) return kv;
  const id = String(params.id || '');
  if (!id) return json({ error: 'Missing target id' }, 400);
  const { uid, setCookieHeader } = resolveUid(request);
  const target = await getTarget(kv, uid, id);
  if (!target) return withSetCookie(json({ error: 'Target not found' }, 404), setCookieHeader);
  const snapshots = await listSnapshotHeaders(kv, target.id);
  return withSetCookie(json({ targetId: target.id, snapshots }), setCookieHeader);
};

export const onRequestPost: PagesFunction<WatchEnv> = async ({ request, env, params }) => {
  const kv = requireKv(env);
  if (kv instanceof Response) return kv;
  const id = String(params.id || '');
  if (!id) return json({ error: 'Missing target id' }, 400);
  const { uid, setCookieHeader } = resolveUid(request);
  const target = await getTarget(kv, uid, id);
  if (!target) return withSetCookie(json({ error: 'Target not found' }, 404), setCookieHeader);

  try {
    const snap = await captureSignals(target.input);
    const header = await putSnapshot(kv, target, snap);
    return withSetCookie(json({ snapshot: header, data: snap }, 201), setCookieHeader);
  } catch (err) {
    return withSetCookie(
      json({ error: err instanceof Error ? err.message : 'Snapshot failed' }, 500),
      setCookieHeader,
    );
  }
};
