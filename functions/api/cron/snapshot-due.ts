// POST /api/cron/snapshot-due
//
// Called by a GitHub Actions scheduled workflow to drive automatic snapshot
// refresh. The Cloudflare Pages runtime does NOT support Cron Triggers (those
// are a Workers-only feature), so we use GH Actions' free cron surface and
// call back in here. Authenticated by a shared secret header.
//
// Behaviour:
//  - Iterates the public target index.
//  - For each target whose last snapshot is older than DUE_AFTER_MS (or has
//    no snapshot at all), captures a new one.
//  - Hard-caps the batch size per invocation so we stay under Cloudflare's
//    free-tier subrequest budget (~50 per invocation; each snapshot costs
//    5–25 subrequests depending on redirects and exposure probes).
//  - Always returns a JSON report so the GH Actions run log is useful.

import { captureSignals } from '../../../src/lib/signals';
import {
  listAllTargetIds,
  getTargetPublic,
  putSnapshot,
  type TargetRecord,
} from '../../../src/lib/watch-store';
import { json, preflight, requireKv, type WatchEnv } from '../_watch-helpers';

interface CronEnv extends WatchEnv {
  NETRECON_CRON_SECRET?: string;
}

// Refresh a target if its last snapshot is older than this (or if it has
// never been snapshotted). 5h 30m so a 6-hour cron catches everything without
// flapping around the exact boundary.
const DUE_AFTER_MS = 5.5 * 60 * 60 * 1000;

// Cap per invocation. Each captureSignals() call itself does ~5 subrequests
// (redirects + 3 well-known + exposure probes batched). The exposure probes
// are sent in batches of 6 but each is a separate subrequest — count roughly
// 25 per snapshot. To stay safely below the 50-per-invocation free-tier cap
// we do just ONE snapshot per invocation and rely on GH Actions' frequent
// runs to cover the registry. Raise later if we verify budget headroom.
const MAX_PER_INVOCATION = 1;

export const onRequestOptions: PagesFunction<CronEnv> = async () => preflight();

export const onRequestPost: PagesFunction<CronEnv> = async ({ request, env }) => {
  const secret = env.NETRECON_CRON_SECRET;
  if (!secret) {
    return json({ error: 'Cron not configured (missing NETRECON_CRON_SECRET).' }, 503);
  }
  const header = request.headers.get('x-netrecon-cron');
  if (!header || header !== secret) {
    return json({ error: 'Unauthorized' }, 401);
  }

  const kv = requireKv(env);
  if (kv instanceof Response) return kv;

  const started = Date.now();
  const ids = await listAllTargetIds(kv, 500);
  const records = (
    await Promise.all(ids.map((id) => getTargetPublic(kv, id)))
  ).filter((r): r is TargetRecord => !!r);

  const now = Date.now();
  const due = records.filter((t) => {
    if (!t.lastSnapshotAt) return true;
    const last = Date.parse(t.lastSnapshotAt);
    return !Number.isFinite(last) || now - last >= DUE_AFTER_MS;
  });

  // Pick the oldest-stale first so we don't starve anything.
  due.sort((a, b) => {
    const la = a.lastSnapshotAt ? Date.parse(a.lastSnapshotAt) : 0;
    const lb = b.lastSnapshotAt ? Date.parse(b.lastSnapshotAt) : 0;
    return la - lb;
  });

  const batch = due.slice(0, MAX_PER_INVOCATION);
  const results: Array<{ targetId: string; input: string; ok: boolean; snapshotId?: string; error?: string; ms: number }> = [];

  for (const t of batch) {
    const t0 = Date.now();
    try {
      const snap = await captureSignals(t.input);
      const header = await putSnapshot(kv, t, snap);
      results.push({
        targetId: t.id,
        input: t.input,
        ok: !snap.error,
        snapshotId: header.id,
        error: snap.error,
        ms: Date.now() - t0,
      });
    } catch (err) {
      results.push({
        targetId: t.id,
        input: t.input,
        ok: false,
        error: err instanceof Error ? err.message : 'capture failed',
        ms: Date.now() - t0,
      });
    }
  }

  return json({
    ok: true,
    totalRegistered: records.length,
    dueForSnapshot: due.length,
    processed: results.length,
    remaining: Math.max(due.length - results.length, 0),
    durationMs: Date.now() - started,
    results,
  });
};
