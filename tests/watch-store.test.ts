import { describe, it, expect } from 'vitest';
import {
  createTarget,
  getTarget,
  getTargetPublic,
  listAllTargetIds,
  deleteTarget,
  putSnapshot,
  DEFAULT_SNAPSHOT_TTL_SECONDS,
  type KvBinding,
} from '../src/lib/watch-store';
import type { Snapshot } from '../src/lib/signals';

// Minimal in-memory KV mock compatible with the KvBinding interface. Records
// `expirationTtl` alongside values so we can assert TTLs were passed correctly.
function mockKv() {
  const store = new Map<string, string>();
  const ttls = new Map<string, number | undefined>();
  const kv: KvBinding = {
    async get(key, opts) {
      const v = store.get(key);
      if (v === undefined) return null;
      if (opts?.type === 'json') {
        try { return JSON.parse(v); } catch { return null; }
      }
      return v;
    },
    async put(key, value, opts) { store.set(key, value); ttls.set(key, opts?.expirationTtl); },
    async delete(key) { store.delete(key); ttls.delete(key); },
    async list({ prefix = '', limit = 1000 }) {
      const keys = [];
      for (const k of store.keys()) {
        if (k.startsWith(prefix)) keys.push({ name: k });
        if (keys.length >= limit) break;
      }
      return { keys, list_complete: true };
    },
  };
  return { kv, store, ttls };
}

function fakeSnapshot(whenIso = new Date().toISOString()): Snapshot {
  return {
    v: 1,
    input: 'https://example.com/',
    capturedAt: whenIso,
    final: { url: 'https://example.com/', status: 200 },
    redirects: [],
    headers: {},
    tls: null,
    wellKnown: {},
    exposure: null,
  } as unknown as Snapshot;
}

describe('watch-store public index', () => {
  it('creates a public pointer when a target is created', async () => {
    const { kv } = mockKv();
    const t = await createTarget(kv, 'uid-a', 'https://example.com/');
    const pub = await getTargetPublic(kv, t.id);
    expect(pub).not.toBeNull();
    expect(pub!.id).toBe(t.id);
    expect(pub!.ownerUid).toBe('uid-a');
  });

  it('lets a non-owner read via getTargetPublic but not via getTarget', async () => {
    const { kv } = mockKv();
    const t = await createTarget(kv, 'uid-a', 'https://example.com/');
    expect(await getTargetPublic(kv, t.id)).not.toBeNull();
    expect(await getTarget(kv, 'uid-other', t.id)).toBeNull();
    expect(await getTarget(kv, 'uid-a', t.id)).not.toBeNull();
  });

  it('listAllTargetIds returns every registered target across owners', async () => {
    const { kv } = mockKv();
    const ta = await createTarget(kv, 'uid-a', 'https://a.example.com/');
    const tb = await createTarget(kv, 'uid-b', 'https://b.example.com/');
    const tc = await createTarget(kv, 'uid-c', 'https://c.example.com/');
    const ids = await listAllTargetIds(kv);
    expect(ids.sort()).toEqual([ta.id, tb.id, tc.id].sort());
  });

  it('delete removes the public pointer so the target is no longer listable', async () => {
    const { kv } = mockKv();
    const t = await createTarget(kv, 'uid-a', 'https://example.com/');
    expect(await listAllTargetIds(kv)).toContain(t.id);
    await deleteTarget(kv, 'uid-a', t.id);
    expect(await listAllTargetIds(kv)).not.toContain(t.id);
    expect(await getTargetPublic(kv, t.id)).toBeNull();
  });

  it('getTargetPublic returns null for an unknown id', async () => {
    const { kv } = mockKv();
    expect(await getTargetPublic(kv, 't_doesnotexist')).toBeNull();
  });
});

describe('watch-store snapshot lifecycle', () => {
  it('snapshots are stored with the 90-day default TTL', async () => {
    const { kv, ttls } = mockKv();
    const t = await createTarget(kv, 'uid-a', 'https://example.com/');
    await putSnapshot(kv, t, fakeSnapshot());
    const snapTtls = [...ttls.entries()].filter(([k]) => k.startsWith('snapshot:'));
    expect(snapTtls.length).toBe(1);
    expect(snapTtls[0][1]).toBe(DEFAULT_SNAPSHOT_TTL_SECONDS);
  });

  it('putSnapshot with ttlSeconds=null stores without expiration', async () => {
    const { kv, ttls } = mockKv();
    const t = await createTarget(kv, 'uid-a', 'https://example.com/');
    await putSnapshot(kv, t, fakeSnapshot(), null);
    const snapTtls = [...ttls.entries()].filter(([k]) => k.startsWith('snapshot:'));
    expect(snapTtls[0][1]).toBeUndefined();
  });

  it('deleteTarget cascades and removes every snapshot body for the target', async () => {
    const { kv, store } = mockKv();
    const t = await createTarget(kv, 'uid-a', 'https://example.com/');
    // Three snapshots spaced by a second so reverse-ts ids differ.
    await putSnapshot(kv, t, fakeSnapshot('2026-04-22T10:00:00.000Z'));
    await putSnapshot(kv, t, fakeSnapshot('2026-04-22T10:00:01.000Z'));
    await putSnapshot(kv, t, fakeSnapshot('2026-04-22T10:00:02.000Z'));
    const before = [...store.keys()].filter((k) => k.startsWith(`snapshot:${t.id}:`));
    expect(before.length).toBe(3);
    await deleteTarget(kv, 'uid-a', t.id);
    const after = [...store.keys()].filter((k) => k.startsWith(`snapshot:${t.id}:`));
    expect(after.length).toBe(0);
  });

  it('deleteTarget leaves snapshots for other targets untouched', async () => {
    const { kv, store } = mockKv();
    const ta = await createTarget(kv, 'uid-a', 'https://a.example.com/');
    const tb = await createTarget(kv, 'uid-a', 'https://b.example.com/');
    await putSnapshot(kv, ta, fakeSnapshot('2026-04-22T10:00:00.000Z'));
    await putSnapshot(kv, tb, fakeSnapshot('2026-04-22T10:00:00.000Z'));
    await deleteTarget(kv, 'uid-a', ta.id);
    const bSnaps = [...store.keys()].filter((k) => k.startsWith(`snapshot:${tb.id}:`));
    expect(bSnaps.length).toBe(1);
  });
});
