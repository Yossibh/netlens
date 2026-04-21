// Defense-in-depth input validation for public API endpoints.
// Prevents the most obvious abuse vectors:
//   - oversized inputs (worker CPU-time abuse)
//   - SSRF-style targets (private IPs, loopback, link-local, cloud metadata IPs)
//   - non-http(s) schemes
//
// NOTE: Cloudflare Workers fetch() does NOT route to the worker's local network
// (there is no "inside" network to attack), so classic SSRF-against-the-tool is
// not exploitable the same way as on a traditional VM. The value of these
// guards is:
//   1. We refuse to be an attribution-laundering proxy targeting someone's
//      publicly-routed "private" range (some orgs advertise RFC1918 internally
//      via VPN and expose them via attacker-controlled DNS).
//   2. We refuse to probe cloud metadata IPs (169.254.169.254) that, while
//      unreachable from the Workers runtime, still look hostile if logged by
//      upstream observers.
//   3. We produce useful, deterministic 400 responses instead of unpredictable
//      upstream errors.

export const MAX_INPUT_LENGTH = 2048;

export interface ValidateResult {
  ok: boolean;
  reason?: string;
}

/** Thrown by tool-registry validators when an input is rejected. */
export class SecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecurityError';
  }
}

// RFC1918 and friends - IPv4
function isPrivateOrSpecialV4(ip: string): boolean {
  const parts = ip.split('.').map((n) => parseInt(n, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts as [number, number, number, number];
  if (a === 0) return true;                                    // 0.0.0.0/8
  if (a === 10) return true;                                   // RFC1918
  if (a === 127) return true;                                  // loopback
  if (a === 169 && b === 254) return true;                     // link-local / AWS+Azure+GCP metadata
  if (a === 172 && b >= 16 && b <= 31) return true;            // RFC1918
  if (a === 192 && b === 168) return true;                     // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true;           // CGNAT RFC6598
  if (a === 192 && b === 0 && parts[2] === 0) return true;     // 192.0.0.0/24 IETF
  if (a === 192 && b === 0 && parts[2] === 2) return true;     // TEST-NET-1
  if (a === 198 && parts[2] === 51 && parts[3] === 100) return true; // TEST-NET-2
  if (a === 203 && parts[2] === 0 && parts[3] === 113) return true;  // TEST-NET-3
  if (a === 198 && b >= 18 && b <= 19) return true;            // benchmark
  if (a >= 224 && a <= 239) return true;                       // multicast
  if (a >= 240) return true;                                   // reserved / 255.255.255.255
  return false;
}

// IPv6 private / special-use - cheap string checks.
function isPrivateOrSpecialV6(ip: string): boolean {
  const s = ip.toLowerCase();
  if (s === '::' || s === '::1') return true;                  // unspecified / loopback
  if (s.startsWith('fe80:') || /^fe[89ab]/.test(s)) return true; // link-local fe80::/10
  if (/^f[cd]/.test(s)) return true;                           // fc00::/7 ULA
  if (s.startsWith('ff')) return true;                         // multicast
  if (s.startsWith('2001:db8')) return true;                   // documentation
  if (s.startsWith('::ffff:')) {                               // v4-mapped
    const v4 = s.substring(7);
    if (/^\d+\.\d+\.\d+\.\d+$/.test(v4)) return isPrivateOrSpecialV4(v4);
  }
  return false;
}

const IPV4_STRICT = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
// Allows embedded IPv4 (e.g. ::ffff:127.0.0.1)
const IPV6_LOOSE = /^[0-9a-fA-F:.]+$/;
// Sanity check: legitimate hostnames / IPs don't contain spaces or reserved URL chars.
const HOSTNAME_CHARS = /^[a-zA-Z0-9._:\[\]-]+$/;

// Hostnames we never probe even if they resolve publicly.
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'broadcasthost',
]);

// Suffixes we refuse (internal-by-convention and RFC6762 mDNS).
const BLOCKED_SUFFIXES = ['.local', '.internal', '.localhost', '.lan', '.home', '.corp', '.intranet'];

/** Returns { ok: true } if safe to probe. Otherwise { ok: false, reason }. */
export function validateHost(host: string): ValidateResult {
  if (!host) return { ok: false, reason: 'Empty host.' };
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!HOSTNAME_CHARS.test(h)) return { ok: false, reason: `Invalid host: ${host}` };
  if (BLOCKED_HOSTNAMES.has(h)) return { ok: false, reason: `Refusing to probe reserved hostname: ${h}` };
  for (const suf of BLOCKED_SUFFIXES) {
    if (h === suf.slice(1) || h.endsWith(suf)) {
      return { ok: false, reason: `Refusing to probe reserved TLD/suffix: ${suf}` };
    }
  }
  if (IPV4_STRICT.test(h)) {
    if (isPrivateOrSpecialV4(h)) return { ok: false, reason: `Refusing to probe private/special-use address: ${h}` };
  } else if (h.includes(':') && IPV6_LOOSE.test(h)) {
    if (isPrivateOrSpecialV6(h)) return { ok: false, reason: `Refusing to probe private/special-use address: ${h}` };
  } else if (h.includes(':')) {
    // Contains a colon but isn't a valid IPv6 candidate (e.g. javascript:alert(1)).
    return { ok: false, reason: `Invalid host: ${host}` };
  }
  return { ok: true };
}

/** Validates the raw input string and, when URL-shaped, its host. */
export function validateInput(raw: string): ValidateResult {
  if (typeof raw !== 'string') return { ok: false, reason: 'Input must be a string.' };
  const trimmed = raw.trim();
  if (!trimmed) return { ok: false, reason: 'Empty input.' };
  if (trimmed.length > MAX_INPUT_LENGTH) {
    return { ok: false, reason: `Input exceeds ${MAX_INPUT_LENGTH}-character limit.` };
  }
  // If it looks URL-shaped, parse and validate the host. We allow only http(s).
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    let u: URL;
    try { u = new URL(trimmed); } catch {
      return { ok: false, reason: 'Invalid URL.' };
    }
    if (!['http:', 'https:'].includes(u.protocol)) {
      return { ok: false, reason: `Unsupported scheme: ${u.protocol}` };
    }
    const host = u.hostname.replace(/^\[|\]$/g, '');
    return validateHost(host);
  }
  // Bare IP or domain.
  return validateHost(trimmed);
}

/** Call from the HTTP provider immediately before fetch() - defense in depth. */
export function validateFetchUrl(urlStr: string): ValidateResult {
  let u: URL;
  try { u = new URL(urlStr); } catch { return { ok: false, reason: 'Invalid URL.' }; }
  if (!['http:', 'https:'].includes(u.protocol)) {
    return { ok: false, reason: `Unsupported scheme: ${u.protocol}` };
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  return validateHost(host);
}
