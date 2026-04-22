import { validateInput } from '../../../src/lib/security';
import { detectInput } from '../../../src/lib/input-detection';
import {
  createTarget,
  listTargets,
} from '../../../src/lib/watch-store';
import {
  json,
  preflight,
  resolveUid,
  withSetCookie,
  requireKv,
  type WatchEnv,
} from '../_watch-helpers';

export const onRequestOptions: PagesFunction<WatchEnv> = async () => preflight();

export const onRequestGet: PagesFunction<WatchEnv> = async ({ request, env }) => {
  const kv = requireKv(env);
  if (kv instanceof Response) return kv;
  const { uid, setCookieHeader } = resolveUid(request);
  const targets = await listTargets(kv, uid);
  return withSetCookie(json({ uid, targets }), setCookieHeader);
};

export const onRequestPost: PagesFunction<WatchEnv> = async ({ request, env }) => {
  const kv = requireKv(env);
  if (kv instanceof Response) return kv;

  let body: { input?: string; note?: string };
  try {
    body = (await request.json()) as { input?: string; note?: string };
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }
  const raw = (body.input ?? '').trim();
  if (!raw) return json({ error: 'Body must include "input"' }, 400);

  const v = validateInput(raw);
  if (!v.ok) return json({ error: v.reason || 'Invalid input' }, 400);

  let normalisedInput: string;
  try {
    const detected = detectInput(raw);
    if (detected.type !== 'url' && detected.type !== 'domain') {
      return json({ error: 'Only URL / domain targets are supported in this release.' }, 400);
    }
    normalisedInput = detected.type === 'domain' ? `https://${detected.domain}/` : detected.url!;
  } catch (err) {
    return json({ error: err instanceof Error ? err.message : 'Invalid input' }, 400);
  }

  const { uid, setCookieHeader } = resolveUid(request);
  try {
    const target = await createTarget(kv, uid, normalisedInput, body.note);
    return withSetCookie(json({ target }, 201), setCookieHeader);
  } catch (err) {
    return json({ error: err instanceof Error ? err.message : 'Could not create target' }, 400);
  }
};
