import type { DnsModuleResult, HttpModuleResult, InferenceModuleResult } from '@/types';
import { lookupAsn, asnOwner } from './dns';

interface CdnSignature {
  name: string;
  headerMatchers: Array<{ header: string; pattern: RegExp }>;
  asnIds?: number[];
}

// ASN ids for common CDNs (not exhaustive - extend over time).
const CDN_SIGNATURES: CdnSignature[] = [
  {
    name: 'Cloudflare',
    headerMatchers: [
      { header: 'server', pattern: /cloudflare/i },
      { header: 'cf-ray', pattern: /./ },
    ],
    asnIds: [13335],
  },
  {
    name: 'Fastly',
    headerMatchers: [
      { header: 'x-served-by', pattern: /cache-/i },
      { header: 'x-fastly-request-id', pattern: /./ },
      { header: 'server', pattern: /fastly/i },
    ],
    asnIds: [54113],
  },
  {
    name: 'Akamai',
    headerMatchers: [
      { header: 'server', pattern: /AkamaiGHost|AkamaiNetStorage/i },
      { header: 'x-akamai-transformed', pattern: /./ },
    ],
    asnIds: [20940, 16625, 21342],
  },
  {
    name: 'AWS CloudFront',
    headerMatchers: [
      { header: 'server', pattern: /CloudFront/i },
      { header: 'x-amz-cf-id', pattern: /./ },
    ],
    asnIds: [16509, 14618],
  },
  {
    name: 'Vercel',
    headerMatchers: [
      { header: 'server', pattern: /Vercel/i },
      { header: 'x-vercel-id', pattern: /./ },
    ],
  },
  {
    name: 'Netlify',
    headerMatchers: [{ header: 'server', pattern: /Netlify/i }],
  },
  {
    name: 'GitHub Pages',
    headerMatchers: [{ header: 'server', pattern: /GitHub\.com/i }],
  },
];

export async function inferInfrastructure(
  dns: DnsModuleResult | undefined,
  http: HttpModuleResult | undefined
): Promise<InferenceModuleResult> {
  const evidence: string[] = [];
  const proxyHints: string[] = [];
  let cdnName: string | undefined;

  const headers = http?.headers ?? {};
  if (headers['via']) proxyHints.push(`via: ${headers['via']}`);
  if (headers['x-cache']) proxyHints.push(`x-cache: ${headers['x-cache']}`);
  if (headers['x-forwarded-for']) proxyHints.push('x-forwarded-for present in response');

  for (const sig of CDN_SIGNATURES) {
    for (const m of sig.headerMatchers) {
      const val = headers[m.header];
      if (val && m.pattern.test(val)) {
        cdnName = sig.name;
        evidence.push(`Header ${m.header}: ${val} matches ${sig.name}`);
        break;
      }
    }
    if (cdnName === sig.name) break;
  }

  // ASN lookup for first A record
  let asnInfo: InferenceModuleResult['asn'];
  const firstA = dns?.records.A[0]?.data;
  if (firstA) {
    try {
      const asn = await lookupAsn(firstA);
      if (asn?.asn) {
        const owner = await asnOwner(asn.asn).catch(() => undefined);
        asnInfo = { ip: firstA, asn: asn.asn, owner, cc: asn.cc, registry: asn.registry };
        evidence.push(`A ${firstA} -> AS${asn.asn}${owner ? ` (${owner})` : ''}`);
        // Infer CDN from ASN if not already
        if (!cdnName) {
          for (const sig of CDN_SIGNATURES) {
            if (sig.asnIds?.includes(asn.asn)) {
              cdnName = sig.name;
              evidence.push(`ASN ${asn.asn} belongs to ${sig.name}`);
              break;
            }
          }
        }
      }
    } catch {
      /* ignore */
    }
  }

  // Origin-exposure correlation:
  // If HTTP headers claim a CDN but the A record ASN does NOT match that CDN,
  // the origin may be directly exposed.
  let originExposureRisk: InferenceModuleResult['originExposureRisk'];
  if (cdnName && asnInfo?.asn) {
    const sig = CDN_SIGNATURES.find((s) => s.name === cdnName);
    if (sig?.asnIds?.length && !sig.asnIds.includes(asnInfo.asn)) {
      originExposureRisk = {
        risk: 'medium',
        reason: `${cdnName} signals in headers but A record (AS${asnInfo.asn}${asnInfo.owner ? ` ${asnInfo.owner}` : ''}) is not in ${cdnName}'s ASN set. Origin may be directly reachable.`,
      };
    } else {
      originExposureRisk = { risk: 'low', reason: `A record ASN matches ${cdnName}.` };
    }
  } else if (cdnName && !asnInfo) {
    originExposureRisk = { risk: 'none', reason: 'CDN detected via headers; ASN lookup unavailable for correlation.' };
  }

  return {
    ok: true,
    cdn: cdnName ? { detected: true, name: cdnName, evidence } : { detected: false, evidence },
    proxyHints,
    asn: asnInfo,
    originExposureRisk,
  };
}
