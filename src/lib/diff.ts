// Stable, recursive diff for JSON-serialisable values.
//
// Output is deliberately simple:
//   - `added`:   paths present only in `b`
//   - `removed`: paths present only in `a`
//   - `changed`: paths present in both but with different values
// Arrays are treated as ordered sets for scalar lists; for object arrays with
// stable "name" keys we align by name so re-ordered cookies/scripts don't
// produce noise. The diff engine is schema-agnostic — the snapshot shape is
// encoded entirely in the data, not here.

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [k: string]: JsonValue };

export interface DiffChange {
  path: string;
  before: JsonValue | undefined;
  after: JsonValue | undefined;
  kind: 'added' | 'removed' | 'changed';
}

export interface DiffResult {
  equal: boolean;
  changes: DiffChange[];
}

const SCALAR_KEY_FIELDS = ['name', 'from'];

function isObject(v: unknown): v is Record<string, JsonValue> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function deepEqual(a: JsonValue, b: JsonValue): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (!deepEqual(a[i]!, b[i]!)) return false;
    return true;
  }
  if (isObject(a) && isObject(b)) {
    const ak = Object.keys(a).sort();
    const bk = Object.keys(b).sort();
    if (ak.length !== bk.length) return false;
    for (let i = 0; i < ak.length; i++) if (ak[i] !== bk[i]) return false;
    for (const k of ak) if (!deepEqual(a[k]!, b[k]!)) return false;
    return true;
  }
  return false;
}

function joinPath(parent: string, key: string | number): string {
  if (parent === '') return String(key);
  return `${parent}.${String(key)}`;
}

function keyForObject(obj: Record<string, JsonValue>): string | null {
  for (const f of SCALAR_KEY_FIELDS) {
    if (typeof obj[f] === 'string') return `${f}=${obj[f]}`;
  }
  return null;
}

function diffArray(a: JsonValue[], b: JsonValue[], path: string, out: DiffChange[]): void {
  const aAllScalar = a.every((x) => x === null || typeof x !== 'object');
  const bAllScalar = b.every((x) => x === null || typeof x !== 'object');

  if (aAllScalar && bAllScalar) {
    const aSet = new Set(a.map((x) => JSON.stringify(x)));
    const bSet = new Set(b.map((x) => JSON.stringify(x)));
    for (const v of bSet) if (!aSet.has(v)) out.push({ path, before: undefined, after: JSON.parse(v), kind: 'added' });
    for (const v of aSet) if (!bSet.has(v)) out.push({ path, before: JSON.parse(v), after: undefined, kind: 'removed' });
    return;
  }

  // Object-array alignment by a stable key field if present.
  const aKeyed = new Map<string, Record<string, JsonValue>>();
  const bKeyed = new Map<string, Record<string, JsonValue>>();
  let keyed = true;
  for (const item of a) {
    if (!isObject(item)) { keyed = false; break; }
    const k = keyForObject(item);
    if (!k) { keyed = false; break; }
    aKeyed.set(k, item);
  }
  if (keyed) for (const item of b) {
    if (!isObject(item)) { keyed = false; break; }
    const k = keyForObject(item);
    if (!k) { keyed = false; break; }
    bKeyed.set(k, item);
  }

  if (keyed) {
    const allKeys = new Set<string>([...aKeyed.keys(), ...bKeyed.keys()]);
    for (const k of Array.from(allKeys).sort()) {
      const av = aKeyed.get(k);
      const bv = bKeyed.get(k);
      const childPath = joinPath(path, k);
      if (!av) out.push({ path: childPath, before: undefined, after: bv as JsonValue, kind: 'added' });
      else if (!bv) out.push({ path: childPath, before: av as JsonValue, after: undefined, kind: 'removed' });
      else diffValue(av as JsonValue, bv as JsonValue, childPath, out);
    }
    return;
  }

  // Fallback: positional.
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i++) {
    const av = a[i];
    const bv = b[i];
    const childPath = joinPath(path, i);
    if (av === undefined) out.push({ path: childPath, before: undefined, after: bv as JsonValue, kind: 'added' });
    else if (bv === undefined) out.push({ path: childPath, before: av as JsonValue, after: undefined, kind: 'removed' });
    else diffValue(av, bv, childPath, out);
  }
}

function diffValue(a: JsonValue, b: JsonValue, path: string, out: DiffChange[]): void {
  if (deepEqual(a, b)) return;
  if (Array.isArray(a) && Array.isArray(b)) return diffArray(a, b, path, out);
  if (isObject(a) && isObject(b)) {
    const ak = new Set(Object.keys(a));
    const bk = new Set(Object.keys(b));
    const allKeys = Array.from(new Set<string>([...ak, ...bk])).sort();
    for (const k of allKeys) {
      const childPath = joinPath(path, k);
      if (!ak.has(k)) out.push({ path: childPath, before: undefined, after: b[k] as JsonValue, kind: 'added' });
      else if (!bk.has(k)) out.push({ path: childPath, before: a[k] as JsonValue, after: undefined, kind: 'removed' });
      else diffValue(a[k] as JsonValue, b[k] as JsonValue, childPath, out);
    }
    return;
  }
  out.push({ path, before: a, after: b, kind: 'changed' });
}

export function diffSnapshots(a: JsonValue, b: JsonValue): DiffResult {
  const out: DiffChange[] = [];
  diffValue(a, b, '', out);
  return { equal: out.length === 0, changes: out };
}
