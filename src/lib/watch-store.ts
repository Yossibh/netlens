// Target registry + snapshot store backed by Cloudflare KV.
//
// Single-user-per-device mode: ownership is keyed by an anonymous UUID kept in
// the `netrecon_uid` cookie. There is no login. If the user clears cookies,
// they lose access to their saved targets (not their data — which is still in
// KV under the old uid — just their handle to it). Good enough for a passion
// project. A future /auth/github flow can upgrade an anon uid to a real owner.
//
// KV keys:
//   target:<uid>:<targetId>           -> TargetRecord (point read for list+detail via prefix)
//   target-input:<uid>:<hash(input)>  -> <targetId>   (dedupe: one target per owner per input)
//   snapshot:<targetId>:<reversed-ts> -> Snapshot    (reversed-ts so list() returns newest first)

import type { Snapshot } from './signals';

export interface TargetRecord {
  id: string;
  ownerUid: string;
  kind: 'url';
  input: string;
  createdAt: string;
  lastSnapshotAt?: string;
  lastSnapshotId?: string;
  note?: string;
}

export interface KvBinding {
  get(key: string, opts?: { type?: 'text' | 'json' }): Promise<string | null | unknown>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
  list(opts: { prefix?: string; limit?: number; cursor?: string }): Promise<{
    keys: Array<{ name: string; expiration?: number; metadata?: unknown }>;
    list_complete?: boolean;
    cursor?: string;
  }>;
}

const TARGET_PREFIX = 'target:';
const INPUT_PREFIX = 'target-input:';
const SNAPSHOT_PREFIX = 'snapshot:';
const MAX_SNAPSHOTS_PER_LIST = 50;
const MAX_TARGETS_PER_UID = 25;
// ~2^63-1 in base-10 width. Reversing a millisecond-precision timestamp lets KV
// list() return newest-first without extra index metadata.
const REV_TS_BASE = 9_999_999_999_999;

function targetKey(uid: string, id: string): string { return `${TARGET_PREFIX}${uid}:${id}`; }
function inputKey(uid: string, inputHash: string): string { return `${INPUT_PREFIX}${uid}:${inputHash}`; }
function snapshotKey(targetId: string, reversedTs: string): string { return `${SNAPSHOT_PREFIX}${targetId}:${reversedTs}`; }

function reverseTs(ts: number): string {
  return String(REV_TS_BASE - ts).padStart(13, '0');
}

function randomId(prefix: string): string {
  // crypto.randomUUID is available in Workers.
  return `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
}

async function hashInput(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input.trim().toLowerCase());
  const digest = await crypto.subtle.digest('SHA-256', buf);
  const bytes = new Uint8Array(digest).slice(0, 12); // 96-bit is plenty for per-uid dedupe
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

export async function createTarget(kv: KvBinding, uid: string, input: string, note?: string): Promise<TargetRecord> {
  const inputHash = await hashInput(input);
  const existingId = await kv.get(inputKey(uid, inputHash), { type: 'text' });
  if (typeof existingId === 'string') {
    const existing = (await kv.get(targetKey(uid, existingId), { type: 'json' })) as TargetRecord | null;
    if (existing) return existing;
  }

  // Lightweight cap so an abusive caller can't fill KV for a uid.
  const existing = await kv.list({ prefix: `${TARGET_PREFIX}${uid}:`, limit: MAX_TARGETS_PER_UID + 1 });
  if (existing.keys.length >= MAX_TARGETS_PER_UID) {
    throw new Error(`Target limit reached (${MAX_TARGETS_PER_UID} per user).`);
  }

  const id = randomId('t');
  const record: TargetRecord = {
    id,
    ownerUid: uid,
    kind: 'url',
    input,
    createdAt: new Date().toISOString(),
    note,
  };
  await kv.put(targetKey(uid, id), JSON.stringify(record));
  await kv.put(inputKey(uid, inputHash), id);
  return record;
}

export async function listTargets(kv: KvBinding, uid: string): Promise<TargetRecord[]> {
  const page = await kv.list({ prefix: `${TARGET_PREFIX}${uid}:`, limit: MAX_TARGETS_PER_UID });
  const out: TargetRecord[] = [];
  // KV list returns keys only; fetch values in parallel.
  const records = await Promise.all(
    page.keys.map((k) => kv.get(k.name, { type: 'json' }) as Promise<TargetRecord | null>),
  );
  for (const r of records) if (r) out.push(r);
  out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  return out;
}

export async function getTarget(kv: KvBinding, uid: string, id: string): Promise<TargetRecord | null> {
  return ((await kv.get(targetKey(uid, id), { type: 'json' })) as TargetRecord | null);
}

export async function deleteTarget(kv: KvBinding, uid: string, id: string): Promise<boolean> {
  const existing = await getTarget(kv, uid, id);
  if (!existing) return false;
  const inputHash = await hashInput(existing.input);
  await Promise.all([
    kv.delete(targetKey(uid, id)),
    kv.delete(inputKey(uid, inputHash)),
  ]);
  // Snapshots are orphaned by design — they may still be referenced by /d/<id>
  // permalinks. They TTL via the snapshot-level TTL or via a future janitor.
  return true;
}

export interface SnapshotHeader {
  id: string;
  targetId: string;
  capturedAt: string;
  ok: boolean;
  status: number | null;
}

export async function putSnapshot(
  kv: KvBinding,
  target: TargetRecord,
  snap: Snapshot,
  ttlSeconds?: number,
): Promise<SnapshotHeader> {
  const ts = Date.parse(snap.capturedAt);
  const rev = reverseTs(Number.isFinite(ts) ? ts : Date.now());
  const id = `s_${rev}_${crypto.randomUUID().replace(/-/g, '').slice(0, 6)}`;
  const key = snapshotKey(target.id, id);
  await kv.put(key, JSON.stringify(snap), ttlSeconds ? { expirationTtl: ttlSeconds } : undefined);

  // Update the target's last-snapshot pointer.
  const updated: TargetRecord = {
    ...target,
    lastSnapshotAt: snap.capturedAt,
    lastSnapshotId: id,
  };
  await kv.put(targetKey(target.ownerUid, target.id), JSON.stringify(updated));

  return {
    id,
    targetId: target.id,
    capturedAt: snap.capturedAt,
    ok: !snap.error,
    status: snap.final?.status ?? null,
  };
}

export async function listSnapshotHeaders(kv: KvBinding, targetId: string, limit = MAX_SNAPSHOTS_PER_LIST): Promise<SnapshotHeader[]> {
  const page = await kv.list({ prefix: `${SNAPSHOT_PREFIX}${targetId}:`, limit });
  const out: SnapshotHeader[] = [];
  const bodies = await Promise.all(
    page.keys.map(async (k) => ({ key: k.name, snap: (await kv.get(k.name, { type: 'json' })) as Snapshot | null })),
  );
  for (const { key, snap } of bodies) {
    if (!snap) continue;
    const id = key.split(':').slice(2).join(':');
    out.push({
      id,
      targetId,
      capturedAt: snap.capturedAt,
      ok: !snap.error,
      status: snap.final?.status ?? null,
    });
  }
  return out;
}

export async function getSnapshot(kv: KvBinding, targetId: string, snapshotId: string): Promise<Snapshot | null> {
  return ((await kv.get(snapshotKey(targetId, snapshotId), { type: 'json' })) as Snapshot | null);
}
