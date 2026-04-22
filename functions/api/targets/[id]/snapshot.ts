import { captureSignals } from '../../../../src/lib/signals';
import {
  getTarget,
  getTargetPublic,
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

// Public read of snapshot history. Permalinks /t/<id> depend on this.
export const onRequestGet: PagesFunction<WatchEnv> = async ({ env, params }) => {
  const kv = requireKv(env);
  if (kv instanceof Response) return kv;
  const id = String(params.id || '');
  if (!id) return json({ error: 'Missing target id' }, 400);
  const target = await getTargetPublic(kv, id);
  if (!target) return json({ error: 'Target not found' }, 404);
  const snapshots = await listSnapshotHeaders(kv, target.id);
  return json({ targetId: target.id, snapshots });
};

// Owner-only: capture a fresh snapshot. Write path costs an outbound fetch
// (or five), so we gate on ownership. If `?browser=1` is present, also run
// a headless-Chromium render via the BROWSER binding — cost-metered, so
// enforce a 22h per-target cooldown to protect the 10-browser-minute/day cap.
export const onRequestPost: PagesFunction<WatchEnv> = async ({ request, env, params }) => {
  const kv = requireKv(env);
  if (kv instanceof Response) return kv;
  const id = String(params.id || '');
  if (!id) return json({ error: 'Missing target id' }, 400);
  const { uid, setCookieHeader } = resolveUid(request);
  const target = await getTarget(kv, uid, id);
  if (!target) return withSetCookie(json({ error: 'Target not found' }, 404), setCookieHeader);

  const url = new URL(request.url);
  const wantBrowser = url.searchParams.get('browser') === '1';

  let browserBinding: unknown | undefined;
  if (wantBrowser) {
    if (!env.BROWSER) {
      return withSetCookie(
        json({ error: 'Browser rendering is not configured on this deployment.' }, 503),
        setCookieHeader,
      );
    }
    const cooldownKey = `browser-last:${id}`;
    const last = (await kv.get(cooldownKey, { type: 'text' })) as string | null;
    const COOLDOWN_SECONDS = 22 * 60 * 60;
    if (last) {
      const lastMs = Date.parse(last);
      if (Number.isFinite(lastMs)) {
        const elapsed = Date.now() - lastMs;
        if (elapsed < COOLDOWN_SECONDS * 1000) {
          const retryAfter = Math.ceil((COOLDOWN_SECONDS * 1000 - elapsed) / 1000);
          return withSetCookie(
            json({ error: 'Browser render cooldown active.', retryAfter }, 429),
            setCookieHeader,
          );
        }
      }
    }
    browserBinding = env.BROWSER;
    await kv.put(cooldownKey, new Date().toISOString(), { expirationTtl: COOLDOWN_SECONDS + 60 });
  }

  try {
    const snap = await captureSignals(target.input, browserBinding ? { browser: browserBinding } : {});
    const header = await putSnapshot(kv, target, snap);
    return withSetCookie(json({ snapshot: header, data: snap }, 201), setCookieHeader);
  } catch (err) {
    return withSetCookie(
      json({ error: err instanceof Error ? err.message : 'Snapshot failed' }, 500),
      setCookieHeader,
    );
  }
};
