import { getTargetPublic, deleteTarget } from '../../../../src/lib/watch-store';
import {
  json,
  preflight,
  resolveUid,
  withSetCookie,
  requireKv,
  type WatchEnv,
} from '../../_watch-helpers';

export const onRequestOptions: PagesFunction<WatchEnv> = async () => preflight();

// Public read: anyone with a target id can see its metadata (input, created,
// last-snapshot time, optional note). This enables shareable permalinks
// (/t/<id>) without exposing the owner's uid to the caller.
export const onRequestGet: PagesFunction<WatchEnv> = async ({ env, params }) => {
  const kv = requireKv(env);
  if (kv instanceof Response) return kv;
  const id = String(params.id || '');
  if (!id) return json({ error: 'Missing target id' }, 400);
  const target = await getTargetPublic(kv, id);
  if (!target) return json({ error: 'Target not found' }, 404);
  // Don't leak the owner uid; everything else is safe to expose.
  const { ownerUid: _owner, ...publicView } = target;
  return json({ target: publicView });
};

export const onRequestDelete: PagesFunction<WatchEnv> = async ({ request, env, params }) => {
  const kv = requireKv(env);
  if (kv instanceof Response) return kv;
  const id = String(params.id || '');
  if (!id) return json({ error: 'Missing target id' }, 400);
  const { uid, setCookieHeader } = resolveUid(request);
  const removed = await deleteTarget(kv, uid, id);
  if (!removed) return withSetCookie(json({ error: 'Target not found' }, 404), setCookieHeader);
  return withSetCookie(json({ ok: true }), setCookieHeader);
};
