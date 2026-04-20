import type { NormalizedInput } from '@/types';

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
// Permissive IPv6 detection: must contain at least one colon, only hex/colons,
// and either use "::" compression or have 8 groups. Strict RFC 4291 parsing is
// unnecessary for routing input to the right modules - the DNS/HTTP layers will
// reject truly malformed addresses.
function isIpv6(s: string): boolean {
  if (!/^[0-9a-fA-F:]+$/.test(s)) return false;
  if (!s.includes(':')) return false;
  const doubleColons = (s.match(/::/g) ?? []).length;
  if (doubleColons > 1) return false;
  const groups = s.split(':');
  if (doubleColons === 1) {
    // With "::" compression, total groups can be 3..8 after split (empty entries allowed).
    return groups.length >= 3 && groups.length <= 8 && groups.every((g) => g === '' || /^[0-9a-fA-F]{1,4}$/.test(g));
  }
  return groups.length === 8 && groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g));
}
const DOMAIN_RE = /^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$/;

export function detectInput(raw: string): NormalizedInput {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('Empty input');

  // URL (explicit scheme)
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    let u: URL;
    try {
      u = new URL(trimmed);
    } catch {
      throw new Error(`Invalid URL: ${trimmed}`);
    }
    if (!['http:', 'https:'].includes(u.protocol)) {
      throw new Error(`Unsupported protocol: ${u.protocol}`);
    }
    const host = u.hostname.replace(/^\[|\]$/g, '');
    const isIP = IPV4_RE.test(host) || isIpv6(host);
    return {
      raw: trimmed,
      type: 'url',
      url: u.toString(),
      host,
      domain: isIP ? undefined : host.toLowerCase(),
      ip: isIP ? host : undefined,
      ipVersion: IPV4_RE.test(host) ? 'v4' : isIpv6(host) ? 'v6' : undefined,
    };
  }

  // IPv4
  if (IPV4_RE.test(trimmed)) {
    return { raw: trimmed, type: 'ip', ip: trimmed, ipVersion: 'v4' };
  }

  // IPv6
  if (isIpv6(trimmed)) {
    return { raw: trimmed, type: 'ip', ip: trimmed.toLowerCase(), ipVersion: 'v6' };
  }

  // Bare host:port → domain + implicit URL
  const hostPortMatch = /^([^\s/:]+)(?::(\d+))?$/.exec(trimmed);
  if (hostPortMatch && hostPortMatch[1] && DOMAIN_RE.test(hostPortMatch[1])) {
    const domain = hostPortMatch[1].toLowerCase();
    return { raw: trimmed, type: 'domain', domain, host: domain };
  }

  // Domain
  if (DOMAIN_RE.test(trimmed)) {
    const domain = trimmed.toLowerCase();
    return { raw: trimmed, type: 'domain', domain, host: domain };
  }

  throw new Error(`Unable to detect input type for: ${trimmed}`);
}

export function toProbeUrl(input: NormalizedInput): string | undefined {
  if (input.url) return input.url;
  if (input.type === 'domain' && input.domain) return `https://${input.domain}`;
  if (input.type === 'ip' && input.ip) {
    return input.ipVersion === 'v6' ? `https://[${input.ip}]` : `https://${input.ip}`;
  }
  return undefined;
}
