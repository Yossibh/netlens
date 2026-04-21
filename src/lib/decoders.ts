// Pure, dependency-free client-side decoders. Designed to run in the browser
// so that inputs (potentially sensitive tokens) never leave the user's device.
// Keep this file free of Node/Web-only imports; it must be runnable from both
// Astro SSR (for tests) and the browser.

export type DecodeKind =
  | 'jwt'
  | 'base64'
  | 'base64url'
  | 'url'
  | 'hex'
  | 'json'
  | 'uuid'
  | 'ulid'
  | 'timestamp';

export interface DecodeResult {
  kind: DecodeKind;
  ok: boolean;
  /** Short, neutral label (e.g. "JWT"). */
  label: string;
  /** The decoded string payload, if applicable. */
  output?: string;
  /** Structured details for complex formats (JWT header/payload, timestamp parts, etc.). */
  details?: Record<string, unknown>;
  /** Human-readable warnings or caveats. */
  notes?: string[];
  /** Error message, if ok=false. */
  error?: string;
}

// ---------- shared helpers ----------

function b64ToBytes(input: string): Uint8Array {
  // Accept both standard and url-safe alphabets; tolerate missing padding.
  const clean = input.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  const pad = clean.length % 4 === 0 ? clean : clean + '='.repeat(4 - (clean.length % 4));
  // atob is available in browsers and Workers.
  const bin = typeof atob === 'function' ? atob(pad) : Buffer.from(pad, 'base64').toString('binary');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToUtf8(bytes: Uint8Array): string {
  if (typeof TextDecoder !== 'undefined') {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }
  return Buffer.from(bytes).toString('utf-8');
}

function isPrintableAscii(s: string, threshold = 0.9): boolean {
  if (!s.length) return false;
  let printable = 0;
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) printable++;
  }
  return printable / s.length >= threshold;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

// ---------- detection ----------

const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
const HEX_RE = /^[0-9a-fA-F]+$/;
const B64_RE = /^[A-Za-z0-9+/=\s]+$/;
const B64URL_RE = /^[A-Za-z0-9_\-]+={0,2}$/;
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const URL_ENC_RE = /%[0-9a-fA-F]{2}/;

export function detectKinds(raw: string): DecodeKind[] {
  const s = raw.trim();
  if (!s) return [];
  const kinds: DecodeKind[] = [];
  if (JWT_RE.test(s)) kinds.push('jwt');
  if (UUID_RE.test(s)) kinds.push('uuid');
  if (ULID_RE.test(s) && !/^\d+$/.test(s)) kinds.push('ulid');
  if (/^-?\d{9,13}(\.\d+)?$/.test(s)) kinds.push('timestamp');
  try {
    const t = s.trim();
    if ((t.startsWith('{') && t.endsWith('}')) || (t.startsWith('[') && t.endsWith(']'))) {
      JSON.parse(t);
      kinds.push('json');
    }
  } catch { /* not json */ }
  if (URL_ENC_RE.test(s)) kinds.push('url');
  if (HEX_RE.test(s) && s.length % 2 === 0 && s.length >= 8) kinds.push('hex');
  if (B64URL_RE.test(s) && !JWT_RE.test(s) && s.length >= 8) kinds.push('base64url');
  if (B64_RE.test(s) && s.replace(/\s+/g, '').length % 4 === 0 && s.length >= 8) kinds.push('base64');
  // Deduplicate preserving order
  return Array.from(new Set(kinds));
}

// ---------- decoders ----------

export function decodeJwt(raw: string): DecodeResult {
  const s = raw.trim();
  if (!JWT_RE.test(s)) {
    return { kind: 'jwt', ok: false, label: 'JWT', error: 'Does not look like a JWT (expected three base64url parts separated by dots).' };
  }
  const [h, p, sig] = s.split('.');
  try {
    const headerJson = bytesToUtf8(b64ToBytes(h));
    const payloadJson = bytesToUtf8(b64ToBytes(p));
    const header = JSON.parse(headerJson);
    const payload = JSON.parse(payloadJson);
    const notes: string[] = [];
    notes.push('Signature is NOT verified here - netrecon only decodes, does not validate.');
    const nowSec = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number') {
      const diff = payload.exp - nowSec;
      if (diff < 0) notes.push(`Token expired ${formatDuration(-diff)} ago (exp=${payload.exp}).`);
      else notes.push(`Token expires in ${formatDuration(diff)} (exp=${payload.exp}).`);
    }
    if (typeof payload.nbf === 'number' && payload.nbf > nowSec) {
      notes.push(`Token not valid until ${new Date(payload.nbf * 1000).toISOString()} (nbf).`);
    }
    if (typeof payload.iat === 'number') {
      notes.push(`Issued ${formatDuration(nowSec - payload.iat)} ago (iat=${payload.iat}).`);
    }
    if (header.alg === 'none') notes.push('alg=none - this token claims no signature. Never accept this server-side.');
    return {
      kind: 'jwt',
      ok: true,
      label: 'JWT',
      output: JSON.stringify({ header, payload }, null, 2),
      details: { header, payload, signatureB64Url: sig, signatureBytes: sig ? sig.length : 0 },
      notes,
    };
  } catch (e) {
    return { kind: 'jwt', ok: false, label: 'JWT', error: (e as Error).message };
  }
}

export function decodeBase64(raw: string, urlSafe = false): DecodeResult {
  const s = raw.trim();
  const re = urlSafe ? B64URL_RE : B64_RE;
  if (!re.test(s)) {
    return { kind: urlSafe ? 'base64url' : 'base64', ok: false, label: urlSafe ? 'base64url' : 'base64', error: 'Input contains characters outside the base64 alphabet.' };
  }
  try {
    const bytes = b64ToBytes(s);
    const text = bytesToUtf8(bytes);
    const printable = isPrintableAscii(text);
    const notes: string[] = [];
    if (!printable) notes.push('Decoded bytes are not printable text - showing hex dump instead.');
    return {
      kind: urlSafe ? 'base64url' : 'base64',
      ok: true,
      label: urlSafe ? 'base64url' : 'base64',
      output: printable ? text : bytesToHex(bytes),
      details: { byteLength: bytes.length, printable },
      notes,
    };
  } catch (e) {
    return { kind: urlSafe ? 'base64url' : 'base64', ok: false, label: urlSafe ? 'base64url' : 'base64', error: (e as Error).message };
  }
}

export function decodeUrl(raw: string): DecodeResult {
  try {
    const output = decodeURIComponent(raw);
    return { kind: 'url', ok: true, label: 'URL-encoded', output };
  } catch (e) {
    return { kind: 'url', ok: false, label: 'URL-encoded', error: (e as Error).message };
  }
}

export function decodeHex(raw: string): DecodeResult {
  const s = raw.trim().replace(/\s+/g, '');
  if (!HEX_RE.test(s) || s.length % 2 !== 0) {
    return { kind: 'hex', ok: false, label: 'hex', error: 'Expected even-length hexadecimal string.' };
  }
  const bytes = new Uint8Array(s.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(s.substr(i * 2, 2), 16);
  const text = bytesToUtf8(bytes);
  const printable = isPrintableAscii(text);
  return {
    kind: 'hex',
    ok: true,
    label: 'hex',
    output: printable ? text : bytes.join(' '),
    details: { byteLength: bytes.length, printable },
    notes: printable ? [] : ['Decoded bytes are not printable - showing decimal byte values.'],
  };
}

export function decodeJson(raw: string): DecodeResult {
  try {
    const parsed = JSON.parse(raw);
    return { kind: 'json', ok: true, label: 'JSON', output: JSON.stringify(parsed, null, 2), details: { type: Array.isArray(parsed) ? 'array' : typeof parsed } };
  } catch (e) {
    return { kind: 'json', ok: false, label: 'JSON', error: (e as Error).message };
  }
}

export function decodeUuid(raw: string): DecodeResult {
  const s = raw.trim();
  if (!UUID_RE.test(s)) return { kind: 'uuid', ok: false, label: 'UUID', error: 'Not a UUID.' };
  const versionNibble = s[14];
  const variantNibble = s[19];
  const version = parseInt(versionNibble, 16);
  const variantBits = parseInt(variantNibble, 16) >> 2;
  let variant = 'unknown';
  if (variantBits < 0b10) variant = 'NCS (legacy)';
  else if (variantBits < 0b110) variant = 'RFC 4122';
  else if (variantBits < 0b111) variant = 'Microsoft (legacy)';
  const details: Record<string, unknown> = { version, variant };
  // v1 has an embedded timestamp
  if (version === 1) {
    const hex = s.replace(/-/g, '');
    const timeLow = hex.substring(0, 8);
    const timeMid = hex.substring(8, 12);
    const timeHi = hex.substring(13, 16);
    const ticks = BigInt('0x' + timeHi + timeMid + timeLow);
    const unixMs = Number((ticks - 122192928000000000n) / 10000n);
    details.timestamp = new Date(unixMs).toISOString();
  }
  return { kind: 'uuid', ok: true, label: `UUID v${version}`, output: s.toLowerCase(), details };
}

// Crockford base32 alphabet used by ULID
const ULID_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function decodeUlid(raw: string): DecodeResult {
  const s = raw.trim().toUpperCase();
  if (!ULID_RE.test(s)) return { kind: 'ulid', ok: false, label: 'ULID', error: 'Not a ULID.' };
  const timePart = s.substring(0, 10);
  let ms = 0n;
  for (const ch of timePart) {
    const idx = ULID_ALPHABET.indexOf(ch);
    if (idx < 0) return { kind: 'ulid', ok: false, label: 'ULID', error: 'Invalid character for ULID.' };
    ms = ms * 32n + BigInt(idx);
  }
  const unixMs = Number(ms);
  return {
    kind: 'ulid',
    ok: true,
    label: 'ULID',
    output: s,
    details: { timestampMs: unixMs, timestamp: new Date(unixMs).toISOString(), random: s.substring(10) },
  };
}

export function decodeTimestamp(raw: string): DecodeResult {
  const s = raw.trim();
  if (!/^-?\d{9,13}(\.\d+)?$/.test(s)) return { kind: 'timestamp', ok: false, label: 'timestamp', error: 'Not a Unix timestamp.' };
  const n = Number(s);
  const ms = s.length <= 10 ? n * 1000 : n;
  const d = new Date(ms);
  if (isNaN(d.getTime())) return { kind: 'timestamp', ok: false, label: 'timestamp', error: 'Out of range.' };
  const now = Date.now();
  const diffSec = Math.floor((ms - now) / 1000);
  const rel = diffSec < 0 ? `${formatDuration(-diffSec)} ago` : `in ${formatDuration(diffSec)}`;
  return {
    kind: 'timestamp',
    ok: true,
    label: s.length <= 10 ? 'Unix timestamp (seconds)' : 'Unix timestamp (milliseconds)',
    output: d.toISOString(),
    details: { iso: d.toISOString(), utc: d.toUTCString(), relative: rel, localString: d.toString() },
  };
}

function formatDuration(sec: number): string {
  const s = Math.abs(sec);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  if (s < 86400 * 30) return `${Math.floor(s / 86400)}d`;
  if (s < 86400 * 365) return `${Math.floor(s / 86400 / 30)}mo`;
  return `${Math.floor(s / 86400 / 365)}y`;
}

export function decodeAuto(raw: string): DecodeResult[] {
  const kinds = detectKinds(raw);
  const out: DecodeResult[] = [];
  for (const k of kinds) {
    const r = decodeByKind(raw, k);
    if (r.ok) out.push(r);
  }
  return out;
}

export function decodeByKind(raw: string, kind: DecodeKind): DecodeResult {
  switch (kind) {
    case 'jwt': return decodeJwt(raw);
    case 'base64': return decodeBase64(raw, false);
    case 'base64url': return decodeBase64(raw, true);
    case 'url': return decodeUrl(raw);
    case 'hex': return decodeHex(raw);
    case 'json': return decodeJson(raw);
    case 'uuid': return decodeUuid(raw);
    case 'ulid': return decodeUlid(raw);
    case 'timestamp': return decodeTimestamp(raw);
  }
}
