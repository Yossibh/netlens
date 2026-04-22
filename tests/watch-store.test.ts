import { describe, it, expect } from 'vitest';
import {
  createTarget,
  getTarget,
  getTargetPublic,
  listAllTargetIds,
  deleteTarget,
  type KvBinding,
} from '../src/lib/watch-store';

// Minimal in-memory KV mock compatible with the KvBinding interface.
function mockKv(): KvBinding {
  const store = new Map<string, string>();
  return {
    async get(key, opts) {
      const v = store.get(key);
      if (v === undefined) return null;
      if (opts?.type === 'json') {
        try { return JSON.parse(v); } catch { return null; }
      }
      return v;
    },
    async put(key, value) { store.set(key, value); },
    async delete(key) { store.delete(key); },
    async list({ prefix = '', limit = 1000 }) {
      const keys = [];
      for (const k of store.keys()) {
        if (k.startsWith(prefix)) keys.push({ name: k });
        if (keys.length >= limit) break;
      }
      return { keys, list_complete: true };
    },
  };
}

describe('watch-store public index', () => {
  it('creates a public pointer when a target is created', async () => {
    const kv = mockKv();
    const t = await createTarget(kv, 'uid-a', 'https://example.com/');
    const pub = await getTargetPublic(kv, t.id);
    expect(pub).not.toBeNull();
    expect(pub!.id).toBe(t.id);
    expect(pub!.ownerUid).toBe('uid-a');
  });

  it('lets a non-owner read via getTargetPublic but not via getTarget', async () => {
    const kv = mockKv();
    const t = await createTarget(kv, 'uid-a', 'https://example.com/');
    expect(await getTargetPublic(kv, t.id)).not.toBeNull();
    expect(await getTarget(kv, 'uid-other', t.id)).toBeNull();
    expect(await getTarget(kv, 'uid-a', t.id)).not.toBeNull();
  });

  it('listAllTargetIds returns every registered target across owners', async () => {
    const kv = mockKv();
    const ta = await createTarget(kv, 'uid-a', 'https://a.example.com/');
    const tb = await createTarget(kv, 'uid-b', 'https://b.example.com/');
    const tc = await createTarget(kv, 'uid-c', 'https://c.example.com/');
    const ids = await listAllTargetIds(kv);
    expect(ids.sort()).toEqual([ta.id, tb.id, tc.id].sort());
  });

  it('delete removes the public pointer so the target is no longer listable', async () => {
    const kv = mockKv();
    const t = await createTarget(kv, 'uid-a', 'https://example.com/');
    expect(await listAllTargetIds(kv)).toContain(t.id);
    await deleteTarget(kv, 'uid-a', t.id);
    expect(await listAllTargetIds(kv)).not.toContain(t.id);
    expect(await getTargetPublic(kv, t.id)).toBeNull();
  });

  it('getTargetPublic returns null for an unknown id', async () => {
    const kv = mockKv();
    expect(await getTargetPublic(kv, 't_doesnotexist')).toBeNull();
  });
});
