import type { TlsModuleResult } from '@/types';

// LIMITATION: Cloudflare Workers outbound fetch() does not expose the peer
// certificate. We cannot perform a live TLS handshake inspection from the edge.
// For MVP we use crt.sh Certificate Transparency logs as a best-effort source
// for recent issuance and expiry of the *latest* leaf cert for the domain.
//
// TODO: Swap in a live probe when an origin-side probe worker or a provider
// like ssl-labs / tls.com is wired up. Keep this function signature stable.
//
// crt.sh JSON endpoint: https://crt.sh/?q=<domain>&output=json
// It returns one entry per CT log entry (potentially many duplicates).

interface CrtShEntry {
  issuer_name: string;
  common_name?: string;
  name_value: string;
  not_before: string;
  not_after: string;
  entry_timestamp?: string;
  id?: number;
}

export async function inspectTls(domain: string): Promise<TlsModuleResult> {
  const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&exclude=expired`;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    let res: Response;
    try {
      res = await fetch(url, { signal: ctrl.signal, headers: { accept: 'application/json' } });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) {
      return { ok: true, source: 'unavailable', skipped: true, skipReason: `crt.sh HTTP ${res.status}` };
    }
    const text = await res.text();
    if (!text.trim()) {
      return { ok: true, source: 'crt.sh', recentCount: 0 };
    }
    let entries: CrtShEntry[];
    try {
      entries = JSON.parse(text);
    } catch {
      return { ok: true, source: 'unavailable', skipped: true, skipReason: 'crt.sh returned non-JSON' };
    }
    if (!entries.length) return { ok: true, source: 'crt.sh', recentCount: 0 };

    entries.sort((a, b) => new Date(b.not_before).getTime() - new Date(a.not_before).getTime());
    const latest = entries[0]!;
    const notAfter = new Date(latest.not_after);
    const daysUntilExpiry = Math.floor((notAfter.getTime() - Date.now()) / 86_400_000);
    const sans = Array.from(new Set((latest.name_value || '').split('\n').map((s) => s.trim()).filter(Boolean)));

    return {
      ok: true,
      source: 'crt.sh',
      recentCount: entries.length,
      latestCertificate: {
        issuer: latest.issuer_name,
        notBefore: latest.not_before,
        notAfter: latest.not_after,
        daysUntilExpiry,
        commonName: latest.common_name,
        sans,
      },
    };
  } catch (err) {
    return {
      ok: true,
      source: 'unavailable',
      skipped: true,
      skipReason: err instanceof Error ? err.message : String(err),
    };
  }
}
