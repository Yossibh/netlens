import type { DnsModuleResult, DnsRecord } from '@/types';

const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'CAA', 'SOA'] as const;
type RecType = (typeof TYPES)[number];

interface DohAnswer {
  name: string;
  type: number;
  TTL?: number;
  data: string;
}
interface DohResponse {
  Status: number;
  AD?: boolean;
  Answer?: DohAnswer[];
  Authority?: DohAnswer[];
}

const TYPE_NUM_TO_NAME: Record<number, string> = {
  1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT', 2: 'NS', 257: 'CAA', 6: 'SOA',
};

export async function queryDoH(name: string, type: RecType, signal?: AbortSignal): Promise<DohResponse> {
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}&do=1`;
  const res = await fetch(url, {
    headers: { accept: 'application/dns-json' },
    signal,
  });
  if (!res.ok) throw new Error(`DoH ${type} ${name} -> HTTP ${res.status}`);
  return (await res.json()) as DohResponse;
}

function toRecord(a: DohAnswer): DnsRecord {
  return {
    name: a.name.replace(/\.$/, ''),
    type: TYPE_NUM_TO_NAME[a.type] ?? String(a.type),
    ttl: a.TTL,
    data: a.data,
  };
}

export async function resolveAll(domain: string, signal?: AbortSignal): Promise<DnsModuleResult> {
  const records: DnsModuleResult['records'] = {
    A: [], AAAA: [], CNAME: [], MX: [], TXT: [], NS: [], CAA: [], SOA: [],
  };
  let dnssec: boolean | undefined;

  const results = await Promise.allSettled(
    TYPES.map((t) => queryDoH(domain, t, signal))
  );

  for (let i = 0; i < TYPES.length; i++) {
    const t = TYPES[i]!;
    const r = results[i];
    if (!r || r.status !== 'fulfilled') continue;
    const resp = r.value;
    if (resp.AD !== undefined) dnssec = dnssec || resp.AD;
    for (const ans of resp.Answer ?? []) {
      const name = TYPE_NUM_TO_NAME[ans.type];
      if (name && name in records) {
        records[name as RecType].push(toRecord(ans));
      }
    }
  }

  return {
    ok: true,
    records,
    hasIPv6: records.AAAA.length > 0,
    hasCAA: records.CAA.length > 0,
    dnssec,
  };
}

// Lookup a specific TXT name (e.g. _dmarc.example.com) and return raw strings.
export async function resolveTxt(name: string, signal?: AbortSignal): Promise<string[]> {
  try {
    const resp = await queryDoH(name, 'TXT', signal);
    return (resp.Answer ?? [])
      .filter((a) => TYPE_NUM_TO_NAME[a.type] === 'TXT')
      .map((a) => a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
  } catch {
    return [];
  }
}

// Team Cymru ASN lookup over DoH: reversed-ip.origin.asn.cymru.com TXT
// Example: 1.1.1.1 -> 1.1.1.1.origin.asn.cymru.com -> "13335 | 1.1.1.0/24 | US | arin | 2011-08-11"
export async function lookupAsn(
  ip: string,
  signal?: AbortSignal
): Promise<{ asn?: number; prefix?: string; cc?: string; registry?: string; raw?: string } | undefined> {
  if (!ip.includes('.')) return undefined; // IPv6 ASN lookup uses origin6.asn.cymru.com with nibble format; skip for MVP.
  const reversed = ip.split('.').reverse().join('.');
  const txt = await resolveTxt(`${reversed}.origin.asn.cymru.com`, signal);
  if (!txt.length) return undefined;
  const raw = txt[0]!;
  const parts = raw.split('|').map((s) => s.trim());
  const asnNum = parts[0] ? Number(parts[0].split(' ')[0]) : undefined;
  return {
    asn: Number.isFinite(asnNum) ? asnNum : undefined,
    prefix: parts[1],
    cc: parts[2],
    registry: parts[3],
    raw,
  };
}

export async function asnOwner(asn: number, signal?: AbortSignal): Promise<string | undefined> {
  const txt = await resolveTxt(`AS${asn}.asn.cymru.com`, signal);
  if (!txt.length) return undefined;
  // "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
  const parts = txt[0]!.split('|').map((s) => s.trim());
  return parts[4];
}
