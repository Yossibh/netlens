import type { ShodanModuleResult } from '@/types';

// Shodan integration. Requires a paid API key bound as SHODAN_API_KEY.
//
// Endpoints used:
// - GET /shodan/host/{ip}?key=...          per-IP posture (ports, banners, vulns, tags)
// - GET /dns/domain/{domain}?key=...       subdomains + DNS records seen by Shodan
//
// Both are paid endpoints. A free Shodan account cannot call /shodan/host/{ip};
// it returns HTTP 401. We fail cleanly when the key is missing or the call is
// unauthorized, rather than pretending we have no data.
//
// Docs: https://developer.shodan.io/api

interface ShodanHostResponse {
  ip_str?: string;
  org?: string;
  isp?: string;
  asn?: string;
  os?: string | null;
  hostnames?: string[];
  domains?: string[];
  tags?: string[];
  ports?: number[];
  vulns?: string[];
  country_code?: string;
  city?: string;
  region_code?: string;
  last_update?: string;
  data?: Array<{
    port?: number;
    transport?: string;
    product?: string;
    version?: string;
    cpe?: string[];
    timestamp?: string;
    hostnames?: string[];
    ssl?: {
      cert?: { subject?: Record<string, string>; issuer?: Record<string, string>; expires?: string; issued?: string };
      versions?: string[];
    };
  }>;
}

interface ShodanDomainResponse {
  domain?: string;
  subdomains?: string[];
  tags?: string[];
  data?: Array<{ subdomain?: string; type?: string; value?: string; ports?: number[]; last_seen?: string }>;
}

interface ShodanCountResponse {
  total?: number;
  facets?: Record<string, Array<{ value: string | number; count: number }>>;
}

async function fetchWithTimeout(url: string, ms: number): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { signal: ctrl.signal, headers: { accept: 'application/json' } });
  } finally {
    clearTimeout(timer);
  }
}

export async function shodanHost(ip: string, apiKey: string): Promise<ShodanModuleResult> {
  try {
    const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`;
    const res = await fetchWithTimeout(url, 10_000);
    if (res.status === 404) {
      return { ok: true, kind: 'host', ip, skipped: true, skipReason: 'No exposure data recorded for this IP.' };
    }
    if (res.status === 401 || res.status === 403) {
      return { ok: true, kind: 'host', ip, skipped: true, skipReason: 'Exposure intel credentials rejected.' };
    }
    if (!res.ok) {
      return { ok: true, kind: 'host', ip, skipped: true, skipReason: `Exposure intel backend returned HTTP ${res.status}` };
    }
    const body = (await res.json()) as ShodanHostResponse;
    const services = (body.data ?? []).map((s) => ({
      port: s.port,
      transport: s.transport,
      product: s.product,
      version: s.version,
      cpe: s.cpe ?? [],
      hostnames: s.hostnames ?? [],
      timestamp: s.timestamp,
      ssl: s.ssl?.cert
        ? {
            subjectCn: s.ssl.cert.subject?.CN,
            issuerCn: s.ssl.cert.issuer?.CN,
            notBefore: s.ssl.cert.issued,
            notAfter: s.ssl.cert.expires,
            versions: s.ssl.versions ?? [],
          }
        : undefined,
    }));
    return {
      ok: true,
      kind: 'host',
      ip,
      hostnames: body.hostnames ?? [],
      domains: body.domains ?? [],
      org: body.org,
      isp: body.isp,
      asn: body.asn,
      os: body.os ?? undefined,
      tags: body.tags ?? [],
      ports: body.ports ?? [],
      vulns: body.vulns ?? [],
      lastUpdate: body.last_update,
      services,
    };
  } catch (e) {
    return {
      ok: true,
      kind: 'host',
      ip,
      skipped: true,
      skipReason: e instanceof Error ? `Exposure intel error: ${e.message}` : 'Exposure intel error',
    };
  }
}

async function shodanCount(query: string, apiKey: string): Promise<ShodanCountResponse | null> {
  // /shodan/host/count is free of query credits and returns total + facets.
  // We request compact facets so the response is small.
  const facets = 'port:10,org:10,product:10,country:10,vuln:10,ssl.version:5';
  const url = `https://api.shodan.io/shodan/host/count?query=${encodeURIComponent(query)}&facets=${encodeURIComponent(facets)}&key=${encodeURIComponent(apiKey)}`;
  try {
    const res = await fetchWithTimeout(url, 10_000);
    if (!res.ok) return null;
    return (await res.json()) as ShodanCountResponse;
  } catch {
    return null;
  }
}

export async function shodanDomain(domain: string, apiKey: string): Promise<ShodanModuleResult> {
  try {
    const url = `https://api.shodan.io/dns/domain/${encodeURIComponent(domain)}?key=${encodeURIComponent(apiKey)}`;
    // Fire the dns/domain call and host/count in parallel. The latter mirrors
    // the "what the internet looks like for this name" view: how many banners
    // mention the hostname, broken down by port, org, product, country, CVE.
    const [domainRes, hostnameCount, sslCount] = await Promise.all([
      fetchWithTimeout(url, 10_000),
      shodanCount(`hostname:${domain}`, apiKey),
      shodanCount(`ssl.cert.subject.cn:${domain}`, apiKey),
    ]);
    if (domainRes.status === 404) {
      return { ok: true, kind: 'domain', domain, skipped: true, skipReason: 'No subdomain records for this domain in our corpus.' };
    }
    if (domainRes.status === 401 || domainRes.status === 403) {
      return { ok: true, kind: 'domain', domain, skipped: true, skipReason: 'Exposure intel credentials rejected.' };
    }
    if (!domainRes.ok) {
      return { ok: true, kind: 'domain', domain, skipped: true, skipReason: `Exposure intel backend returned HTTP ${domainRes.status}` };
    }
    const body = (await domainRes.json()) as ShodanDomainResponse;
    return {
      ok: true,
      kind: 'domain',
      domain,
      subdomains: body.subdomains ?? [],
      tags: body.tags ?? [],
      records: (body.data ?? []).map((r) => ({
        subdomain: r.subdomain,
        type: r.type,
        value: r.value,
        ports: r.ports ?? [],
        lastSeen: r.last_seen,
      })),
      exposure: {
        hostnameMatches: hostnameCount?.total,
        certMatches: sslCount?.total,
        facets: {
          port: hostnameCount?.facets?.port ?? [],
          org: hostnameCount?.facets?.org ?? [],
          product: hostnameCount?.facets?.product ?? [],
          country: hostnameCount?.facets?.country ?? [],
          vuln: hostnameCount?.facets?.vuln ?? [],
          sslVersion: hostnameCount?.facets?.['ssl.version'] ?? [],
        },
      },
    };
  } catch (e) {
    return {
      ok: true,
      kind: 'domain',
      domain,
      skipped: true,
      skipReason: e instanceof Error ? `Exposure intel error: ${e.message}` : 'Exposure intel error',
    };
  }
}
