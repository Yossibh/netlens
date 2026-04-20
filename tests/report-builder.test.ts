import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Integration test for buildReport using a mocked global.fetch so we don't hit the network.
// Exercises the full pipeline: DNS -> HTTP -> Email -> TLS -> Inference -> Findings.

import { buildReport } from '../src/lib/report-builder';

function dnsJson(answer: Array<{ name: string; type: number; TTL?: number; data: string }>) {
  return new Response(JSON.stringify({ Status: 0, AD: true, Answer: answer }), {
    status: 200,
    headers: { 'content-type': 'application/dns-json' },
  });
}

describe('buildReport (integration, fetch mocked)', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input instanceof URL ? input.toString() : input.url);

      // DoH
      if (url.startsWith('https://cloudflare-dns.com/dns-query')) {
        const u = new URL(url);
        const name = u.searchParams.get('name') || '';
        const type = u.searchParams.get('type') || '';
        if (name === 'example.test' && type === 'A') {
          return dnsJson([{ name: 'example.test.', type: 1, TTL: 300, data: '93.184.216.34' }]);
        }
        if (name === 'example.test' && type === 'AAAA') {
          return dnsJson([{ name: 'example.test.', type: 28, TTL: 300, data: '2606:2800:220:1:248:1893:25c8:1946' }]);
        }
        if (name === 'example.test' && type === 'MX') {
          return dnsJson([{ name: 'example.test.', type: 15, TTL: 300, data: '10 mail.example.test.' }]);
        }
        if (name === 'example.test' && type === 'TXT') {
          return dnsJson([{ name: 'example.test.', type: 16, TTL: 300, data: '"v=spf1 -all"' }]);
        }
        if (name === '_dmarc.example.test' && type === 'TXT') {
          return dnsJson([{ name: '_dmarc.example.test.', type: 16, TTL: 300, data: '"v=DMARC1; p=reject;"' }]);
        }
        // Default: empty answer
        return dnsJson([]);
      }

      // crt.sh
      if (url.startsWith('https://crt.sh/')) {
        const future = new Date(Date.now() + 90 * 86_400_000).toISOString();
        return new Response(JSON.stringify([
          { issuer_name: 'C=US, O=Let\'s Encrypt, CN=R3', common_name: 'example.test', name_value: 'example.test\nwww.example.test', not_before: '2026-01-01T00:00:00', not_after: future },
        ]), { status: 200, headers: { 'content-type': 'application/json' } });
      }

      // HTTP probe of the domain
      if (url === 'https://example.test' || url === 'https://example.test/') {
        return new Response('ok', {
          status: 200,
          headers: {
            server: 'cloudflare',
            'cf-ray': 'abc123-EWR',
            'strict-transport-security': 'max-age=31536000',
          },
        });
      }

      return new Response('not mocked: ' + url, { status: 500 });
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('produces a correlated report for a domain', async () => {
    const report = await buildReport('example.test');
    expect(report.input.type).toBe('domain');
    expect(report.modules.dns?.ok).toBe(true);
    expect(report.modules.dns?.records.A[0]?.data).toBe('93.184.216.34');
    expect(report.modules.http?.ok).toBe(true);
    expect(report.modules.http?.status).toBe(200);
    expect(report.modules.inference?.cdn?.detected).toBe(true);
    expect(report.modules.inference?.cdn?.name).toBe('Cloudflare');
    expect(report.modules.email?.dmarc?.policy).toBe('reject');
    expect(report.modules.tls?.latestCertificate?.daysUntilExpiry).toBeGreaterThan(60);
    expect(report.summary.highlights.length).toBeGreaterThan(0);
    expect(report.generatedCommands.length).toBeGreaterThan(0);
    // No fake findings that don't apply
    expect(report.findings.find((f) => f.id === 'dns.no-address-records')).toBeUndefined();
    expect(report.findings.find((f) => f.id === 'http.no-hsts')).toBeUndefined();
  });

  it('rejects garbage input', async () => {
    await expect(buildReport('$$$')).rejects.toThrow();
  });
});
