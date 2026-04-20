import { describe, it, expect } from 'vitest';
import { runFindings, riskLevel } from '../src/lib/findings-engine';
import type { AnalyzeModules, NormalizedInput } from '../src/types';

const domainInput: NormalizedInput = { raw: 'example.com', type: 'domain', domain: 'example.com', host: 'example.com' };

function emptyDns(): NonNullable<AnalyzeModules['dns']> {
  return {
    ok: true,
    records: { A: [], AAAA: [], CNAME: [], MX: [], TXT: [], NS: [], CAA: [], SOA: [] },
    hasIPv6: false,
    hasCAA: false,
  };
}

describe('findings-engine', () => {
  it('emits "no address records" when A/AAAA/CNAME all empty', () => {
    const dns = emptyDns();
    const findings = runFindings({ input: domainInput, modules: { dns } });
    expect(findings.some((f) => f.id === 'dns.no-address-records')).toBe(true);
  });

  it('emits missing IPv6 when only A present', () => {
    const dns = emptyDns();
    dns.records.A.push({ name: 'example.com', type: 'A', data: '93.184.216.34' });
    const findings = runFindings({ input: domainInput, modules: { dns } });
    expect(findings.some((f) => f.id === 'dns.missing-ipv6')).toBe(true);
    expect(findings.some((f) => f.id === 'dns.no-address-records')).toBe(false);
  });

  it('emits missing-caa when hasCAA=false', () => {
    const dns = emptyDns();
    dns.records.A.push({ name: 'x', type: 'A', data: '1.2.3.4' });
    dns.records.AAAA.push({ name: 'x', type: 'AAAA', data: '::1' });
    dns.hasIPv6 = true;
    const findings = runFindings({ input: domainInput, modules: { dns } });
    expect(findings.some((f) => f.id === 'dns.missing-caa')).toBe(true);
  });

  it('email: missing SPF+DMARC when MX present', () => {
    const findings = runFindings({
      input: domainInput,
      modules: {
        email: { ok: true, mxPresent: true, spf: { present: false }, dmarc: { present: false } },
      },
    });
    expect(findings.some((f) => f.id === 'email.no-spf')).toBe(true);
    expect(findings.some((f) => f.id === 'email.no-dmarc')).toBe(true);
  });

  it('email: dmarc p=none emits low finding', () => {
    const findings = runFindings({
      input: domainInput,
      modules: {
        email: {
          ok: true,
          mxPresent: true,
          spf: { present: true, raw: 'v=spf1 -all', qualifier: '-' },
          dmarc: { present: true, raw: 'v=DMARC1; p=none;', policy: 'none' },
        },
      },
    });
    expect(findings.some((f) => f.id === 'email.dmarc-p-none')).toBe(true);
  });

  it('http: emits no-hsts when security headers missing', () => {
    const findings = runFindings({
      input: domainInput,
      modules: {
        http: {
          ok: true,
          finalUrl: 'https://example.com/',
          status: 200,
          redirects: [],
          headers: {},
          securityHeaders: {},
          corsHeaders: {},
          cacheHeaders: {},
        },
      },
    });
    expect(findings.some((f) => f.id === 'http.no-hsts')).toBe(true);
  });

  it('http: emits cors wildcard with credentials (high)', () => {
    const findings = runFindings({
      input: domainInput,
      modules: {
        http: {
          ok: true,
          finalUrl: 'https://example.com/',
          status: 200,
          redirects: [],
          headers: {},
          securityHeaders: { hsts: 'max-age=1' },
          corsHeaders: { accessControlAllowOrigin: '*', accessControlAllowCredentials: 'true' },
          cacheHeaders: {},
        },
      },
    });
    expect(findings.some((f) => f.id === 'http.cors-wildcard-with-credentials' && f.severity === 'high')).toBe(true);
  });

  it('inference: origin exposure produces a finding', () => {
    const findings = runFindings({
      input: domainInput,
      modules: {
        inference: {
          ok: true,
          proxyHints: [],
          cdn: { detected: true, name: 'Cloudflare', evidence: ['cf-ray: xxx'] },
          asn: { ip: '1.2.3.4', asn: 99999, owner: 'SomeoneElse' },
          originExposureRisk: { risk: 'medium', reason: 'ASN mismatch' },
        },
      },
    });
    expect(findings.some((f) => f.id === 'inference.origin-possibly-exposed')).toBe(true);
  });

  it('tls: certificate expiring soon', () => {
    const in10days = new Date(Date.now() + 10 * 86_400_000).toISOString();
    const findings = runFindings({
      input: domainInput,
      modules: {
        tls: {
          ok: true,
          source: 'crt.sh',
          latestCertificate: { issuer: 'X', notBefore: '2020', notAfter: in10days, daysUntilExpiry: 10, sans: [] },
        },
      },
    });
    expect(findings.some((f) => f.id === 'tls.certificate-expiring-soon')).toBe(true);
  });

  it('riskLevel prioritizes high over medium over low', () => {
    expect(riskLevel([{ id: 'a', severity: 'low', title: '', explanation: '', evidence: [], nextSteps: [], suggestedCommands: [] }])).toBe('low');
    expect(riskLevel([
      { id: 'a', severity: 'low', title: '', explanation: '', evidence: [], nextSteps: [], suggestedCommands: [] },
      { id: 'b', severity: 'medium', title: '', explanation: '', evidence: [], nextSteps: [], suggestedCommands: [] },
    ])).toBe('medium');
    expect(riskLevel([
      { id: 'a', severity: 'medium', title: '', explanation: '', evidence: [], nextSteps: [], suggestedCommands: [] },
      { id: 'b', severity: 'high', title: '', explanation: '', evidence: [], nextSteps: [], suggestedCommands: [] },
    ])).toBe('high');
  });
});
