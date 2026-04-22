// Tier D1 signal extraction for change-detection.
//
// Captures the externally-observable surface of a URL that actually moves on
// every deploy (headers, CSP, cookies, redirect chain, HTML meta/OG/canonical,
// third-party hosts, preload hints, robots.txt, sitemap.xml, security.txt).
//
// Design goals:
//  - Stable JSON: two captures of an unchanged site must produce byte-identical
//    serialisation (sorted keys, sorted arrays, normalised cookie attrs).
//  - Compact: target ~10 KB per snapshot so KV storage and diff UI stay fast.
//  - Diff-friendly: no free-form text where structured data will do.

import { validateFetchUrl } from './security';

const MAX_REDIRECTS = 8;
const FETCH_TIMEOUT_MS = 8000;
const MAX_HTML_BYTES = 512 * 1024; // 512 KB of HTML is plenty for meta extraction
const USER_AGENT = 'netrecon/0.1 (+https://netrecon.pages.dev; change-detection)';

export const SIGNALS_VERSION = 1 as const;

export interface Snapshot {
  v: typeof SIGNALS_VERSION;
  input: string;
  capturedAt: string; // ISO
  final: { url: string; status: number } | null;
  error?: string;
  redirectChain: Array<{ from: string; to: string; status: number }>;
  headers: Record<string, string>; // security/CORS/cache-only subset, lowercased, sorted
  csp: { raw: string; directives: Record<string, string[]> } | null;
  setCookie: Array<{
    name: string;
    sameSite?: string;
    secure: boolean;
    httpOnly: boolean;
    path?: string;
    domain?: string;
    maxAge?: number;
    hasExpires: boolean;
  }>;
  html: {
    title?: string;
    canonical?: string;
    robotsMeta?: string;
    og: Record<string, string>;
    thirdPartyHosts: string[];
    preloadHosts: string[];
    scriptSrcs: string[];
    externalStyleHosts: string[];
    sriCoverage: { total: number; withIntegrity: number };
    mixedContent: string[];
  } | null;
  wellKnown: {
    robotsTxt: { present: boolean; size: number; hash?: string; firstLines?: string[] };
    sitemapXml: { present: boolean; urlCount: number; firstUrls: string[] };
    securityTxt: { present: boolean; size: number; hash?: string };
  };
}

// The only headers we persist in a snapshot. Response headers are wildly
// verbose (cookies, ETags, Dates, CDN-injected noise) and mostly irrelevant to
// change detection. This allowlist keeps the diff signal high.
const TRACKED_HEADERS = new Set([
  'strict-transport-security',
  'content-security-policy',
  'content-security-policy-report-only',
  'x-content-type-options',
  'x-frame-options',
  'x-xss-protection',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'access-control-allow-methods',
  'access-control-allow-headers',
  'access-control-expose-headers',
  'cache-control',
  'expires',
  'vary',
  'content-type',
  'content-encoding',
  'server',
  'x-powered-by',
  'via',
  'alt-svc',
  'report-to',
  'reporting-endpoints',
  'nel',
]);

function sortObjectKeys<T>(obj: Record<string, T>): Record<string, T> {
  const out: Record<string, T> = {};
  for (const k of Object.keys(obj).sort()) out[k] = obj[k]!;
  return out;
}

function uniqueSorted(xs: string[]): string[] {
  return Array.from(new Set(xs)).sort();
}

export function parseCsp(raw: string): { raw: string; directives: Record<string, string[]> } {
  const directives: Record<string, string[]> = {};
  for (const chunk of raw.split(';')) {
    const parts = chunk.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) continue;
    const name = parts[0]!.toLowerCase();
    const values = parts.slice(1).sort();
    // Merge duplicates (some servers emit the same directive twice).
    directives[name] = uniqueSorted([...(directives[name] ?? []), ...values]);
  }
  return { raw, directives: sortObjectKeys(directives) };
}

export function parseSetCookie(lines: string[]): Snapshot['setCookie'] {
  const out: Snapshot['setCookie'] = [];
  for (const line of lines) {
    const [nameValue, ...attrParts] = line.split(';').map((s) => s.trim());
    if (!nameValue) continue;
    const eq = nameValue.indexOf('=');
    if (eq < 0) continue;
    const name = nameValue.slice(0, eq);
    if (!name) continue;
    const attrs: Record<string, string | true> = {};
    for (const p of attrParts) {
      const e = p.indexOf('=');
      if (e < 0) attrs[p.toLowerCase()] = true;
      else attrs[p.slice(0, e).toLowerCase()] = p.slice(e + 1);
    }
    const maxAgeRaw = attrs['max-age'];
    const maxAge = typeof maxAgeRaw === 'string' ? Number(maxAgeRaw) : undefined;
    out.push({
      name,
      sameSite: typeof attrs['samesite'] === 'string' ? (attrs['samesite'] as string) : undefined,
      secure: attrs['secure'] === true,
      httpOnly: attrs['httponly'] === true,
      path: typeof attrs['path'] === 'string' ? (attrs['path'] as string) : undefined,
      domain: typeof attrs['domain'] === 'string' ? (attrs['domain'] as string) : undefined,
      maxAge: Number.isFinite(maxAge) ? (maxAge as number) : undefined,
      hasExpires: 'expires' in attrs,
    });
  }
  out.sort((a, b) => a.name.localeCompare(b.name));
  return out;
}

// Grab the raw Set-Cookie lines. The Fetch API spec exposes them via
// `headers.getSetCookie()` in modern runtimes (Workers included). Fall back to
// a manual scan for older runtimes used in tests.
function extractSetCookieLines(h: Headers): string[] {
  const anyH = h as unknown as { getSetCookie?: () => string[] };
  if (typeof anyH.getSetCookie === 'function') return anyH.getSetCookie();
  const lines: string[] = [];
  h.forEach((v, k) => {
    if (k.toLowerCase() === 'set-cookie') lines.push(v);
  });
  return lines;
}

// Cheap HTML scraping via regex. We don't need DOM correctness; we need
// deterministic, stable extraction of a handful of tags (<title>, <meta>,
// <link>, <script src>). Regex keeps the bundle tiny and the capture fast.
function extractHtml(html: string, baseUrl: string): Snapshot['html'] {
  const lower = html.toLowerCase();
  const base = new URL(baseUrl);

  const pickAttr = (tag: string, attr: string): string | undefined => {
    const re = new RegExp(`<${tag}\\b[^>]*?\\b${attr}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i');
    const m = html.match(re);
    return m ? (m[2] ?? m[3] ?? m[4]) : undefined;
  };

  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch?.[1]?.trim().slice(0, 200);

  let canonical: string | undefined;
  const canonRe = /<link\b[^>]*\brel\s*=\s*("canonical"|'canonical'|canonical)[^>]*>/gi;
  const canonMatch = html.match(canonRe);
  if (canonMatch && canonMatch[0]) {
    const href = canonMatch[0].match(/\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i);
    if (href) canonical = href[2] ?? href[3] ?? href[4];
  }

  let robotsMeta: string | undefined;
  const robotsRe = /<meta\b[^>]*\bname\s*=\s*("robots"|'robots'|robots)[^>]*>/gi;
  const robotsMatch = html.match(robotsRe);
  if (robotsMatch && robotsMatch[0]) {
    const content = robotsMatch[0].match(/\bcontent\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i);
    if (content) robotsMeta = (content[2] ?? content[3] ?? content[4])?.toLowerCase();
  }

  const og: Record<string, string> = {};
  const ogRe = /<meta\b[^>]*\bproperty\s*=\s*("(og:[^"]+)"|'(og:[^']+)')[^>]*>/gi;
  for (const m of html.matchAll(ogRe)) {
    const prop = m[2] ?? m[3];
    if (!prop) continue;
    const content = m[0].match(/\bcontent\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const val = content?.[2] ?? content?.[3] ?? content?.[4];
    if (val && !(prop in og)) og[prop] = val.slice(0, 300);
  }

  const hostsFromAttr = (tag: string, attr: string): string[] => {
    const re = new RegExp(`<${tag}\\b[^>]*?\\b${attr}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'gi');
    const hosts: string[] = [];
    for (const m of html.matchAll(re)) {
      const url = m[2] ?? m[3] ?? m[4];
      if (!url) continue;
      try {
        const u = new URL(url, base);
        if (u.protocol === 'http:' || u.protocol === 'https:') hosts.push(u.host);
      } catch { /* ignore malformed URLs */ }
    }
    return hosts;
  };

  const scriptUrls: string[] = [];
  const scriptAttrs: Array<{ src: string; integrity?: string; crossorigin?: string }> = [];
  const scriptRe = /<script\b[^>]*\bsrc\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/gi;
  for (const m of html.matchAll(scriptRe)) {
    const src = m[2] ?? m[3] ?? m[4];
    if (!src) continue;
    try {
      const u = new URL(src, base);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
      scriptUrls.push(u.toString());
      const integrityMatch = m[0].match(/\bintegrity\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i);
      scriptAttrs.push({
        src: u.toString(),
        integrity: integrityMatch?.[2] ?? integrityMatch?.[3] ?? integrityMatch?.[4],
      });
    } catch { /* ignore */ }
  }

  const linkStyleRe = /<link\b[^>]*\brel\s*=\s*("stylesheet"|'stylesheet'|stylesheet)[^>]*>/gi;
  const styleAttrs: Array<{ href: string; integrity?: string }> = [];
  const externalStyleHosts: string[] = [];
  for (const m of html.matchAll(linkStyleRe)) {
    const href = m[0].match(/\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const u = href?.[2] ?? href?.[3] ?? href?.[4];
    if (!u) continue;
    try {
      const abs = new URL(u, base);
      if (abs.protocol !== 'http:' && abs.protocol !== 'https:') continue;
      if (abs.host !== base.host) externalStyleHosts.push(abs.host);
      const integrityMatch = m[0].match(/\bintegrity\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i);
      styleAttrs.push({
        href: abs.toString(),
        integrity: integrityMatch?.[2] ?? integrityMatch?.[3] ?? integrityMatch?.[4],
      });
    } catch { /* ignore */ }
  }

  const preloadRe = /<link\b[^>]*\brel\s*=\s*("(?:preload|preconnect|dns-prefetch|modulepreload)"|'(?:preload|preconnect|dns-prefetch|modulepreload)')[^>]*>/gi;
  const preloadHosts: string[] = [];
  for (const m of html.matchAll(preloadRe)) {
    const href = m[0].match(/\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const u = href?.[2] ?? href?.[3] ?? href?.[4];
    if (!u) continue;
    try {
      const abs = new URL(u, base);
      if (abs.protocol === 'http:' || abs.protocol === 'https:') preloadHosts.push(abs.host);
    } catch { /* ignore */ }
  }

  // Third-party = any host from scripts/styles/images/iframes that isn't us.
  const otherHosts = [
    ...hostsFromAttr('script', 'src'),
    ...hostsFromAttr('iframe', 'src'),
    ...hostsFromAttr('img', 'src'),
    ...hostsFromAttr('link', 'href'),
    ...hostsFromAttr('source', 'src'),
  ];
  const thirdPartyHosts = uniqueSorted(otherHosts.filter((h) => h !== base.host));

  // Mixed content: only meaningful if we loaded over HTTPS.
  const mixedContent: string[] = [];
  if (base.protocol === 'https:') {
    const httpRefRe = /\b(?:src|href)\s*=\s*("(http:\/\/[^"]+)"|'(http:\/\/[^']+)'|(http:\/\/[^\s>]+))/gi;
    for (const m of html.matchAll(httpRefRe)) {
      const u = m[2] ?? m[3] ?? m[4];
      if (u) mixedContent.push(u.slice(0, 200));
    }
  }

  const allSubresources = [...scriptAttrs, ...styleAttrs];
  const external = allSubresources.filter((r) => {
    try { return new URL('src' in r ? r.src : r.href, base).host !== base.host; } catch { return false; }
  });
  const withIntegrity = external.filter((r) => !!r.integrity).length;

  // Basic sanity: we only claim an HTML payload if we actually matched *something*.
  const anyContent = title || canonical || robotsMeta || Object.keys(og).length > 0 ||
    scriptUrls.length > 0 || thirdPartyHosts.length > 0;
  if (!anyContent && !lower.includes('<html') && !lower.includes('<!doctype')) return null;

  return {
    title,
    canonical,
    robotsMeta,
    og: sortObjectKeys(og),
    thirdPartyHosts,
    preloadHosts: uniqueSorted(preloadHosts),
    scriptSrcs: uniqueSorted(scriptUrls),
    externalStyleHosts: uniqueSorted(externalStyleHosts),
    sriCoverage: { total: external.length, withIntegrity },
    mixedContent: uniqueSorted(mixedContent),
  };
}

async function sha256Hex(text: string): Promise<string> {
  const buf = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', buf);
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

async function fetchWellKnown(origin: string, path: string, cap = 64 * 1024): Promise<{
  present: boolean;
  size: number;
  body?: string;
}> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    const url = origin + path;
    const guard = validateFetchUrl(url);
    if (!guard.ok) return { present: false, size: 0 };
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: 'follow',
      headers: { 'user-agent': USER_AGENT },
    });
    clearTimeout(timer);
    if (!res.ok) return { present: false, size: 0 };
    const text = await res.text();
    const body = text.length > cap ? text.slice(0, cap) : text;
    return { present: true, size: text.length, body };
  } catch {
    return { present: false, size: 0 };
  }
}

function parseSitemap(xml: string): { urlCount: number; firstUrls: string[] } {
  const locs: string[] = [];
  const re = /<loc>([^<]+)<\/loc>/gi;
  for (const m of xml.matchAll(re)) {
    if (m[1]) locs.push(m[1].trim());
    if (locs.length >= 1000) break;
  }
  return { urlCount: locs.length, firstUrls: locs.slice(0, 10).sort() };
}

export async function captureSignals(input: string): Promise<Snapshot> {
  const capturedAt = new Date().toISOString();
  const redirectChain: Snapshot['redirectChain'] = [];
  let headers: Record<string, string> = {};
  let csp: Snapshot['csp'] = null;
  let setCookie: Snapshot['setCookie'] = [];
  let html: Snapshot['html'] = null;
  let finalStatus = 0;
  let finalUrl = input;

  const failEnvelope = (error: string): Snapshot => ({
    v: SIGNALS_VERSION,
    input,
    capturedAt,
    final: null,
    error,
    redirectChain,
    headers: {},
    csp: null,
    setCookie: [],
    html: null,
    wellKnown: {
      robotsTxt: { present: false, size: 0 },
      sitemapXml: { present: false, urlCount: 0, firstUrls: [] },
      securityTxt: { present: false, size: 0 },
    },
  });

  let startUrl: URL;
  try {
    startUrl = new URL(input);
  } catch {
    return failEnvelope(`Invalid URL: ${input}`);
  }
  if (startUrl.protocol !== 'http:' && startUrl.protocol !== 'https:') {
    return failEnvelope(`Unsupported scheme: ${startUrl.protocol}`);
  }

  // Follow redirects manually so we can record every hop.
  let current = startUrl.toString();
  const seen = new Set<string>();
  let bodyText = '';
  try {
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      if (seen.has(current)) return failEnvelope(`Redirect loop at ${current}`);
      seen.add(current);
      const guard = validateFetchUrl(current);
      if (!guard.ok) return failEnvelope(guard.reason || 'Blocked target.');

      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
      const res = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal: ctrl.signal,
        headers: { 'user-agent': USER_AGENT },
      });
      clearTimeout(timer);

      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        const loc = res.headers.get('location')!;
        let next: string;
        try { next = new URL(loc, current).toString(); }
        catch { return failEnvelope(`Invalid redirect Location: ${loc}`); }
        redirectChain.push({ from: current, to: next, status: res.status });
        current = next;
        continue;
      }

      finalUrl = current;
      finalStatus = res.status;

      const rawHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        const lower = k.toLowerCase();
        if (TRACKED_HEADERS.has(lower)) rawHeaders[lower] = v;
      });
      headers = sortObjectKeys(rawHeaders);

      const cspRaw = rawHeaders['content-security-policy'] ?? rawHeaders['content-security-policy-report-only'];
      if (cspRaw) csp = parseCsp(cspRaw);

      setCookie = parseSetCookie(extractSetCookieLines(res.headers));

      const ctype = (rawHeaders['content-type'] ?? '').toLowerCase();
      if (ctype.includes('html') || ctype === '') {
        try {
          const buf = new Uint8Array(await res.arrayBuffer());
          const slice = buf.subarray(0, Math.min(buf.byteLength, MAX_HTML_BYTES));
          bodyText = new TextDecoder('utf-8', { fatal: false }).decode(slice);
          html = extractHtml(bodyText, finalUrl);
        } catch { /* body read failed; leave html null */ }
      }
      break;
    }
  } catch (err) {
    return failEnvelope(err instanceof Error ? err.message : String(err));
  }

  const origin = new URL(finalUrl).origin;
  const [robots, sitemap, sectxt] = await Promise.all([
    fetchWellKnown(origin, '/robots.txt'),
    fetchWellKnown(origin, '/sitemap.xml', 256 * 1024),
    fetchWellKnown(origin, '/.well-known/security.txt'),
  ]);

  const robotsTxt: Snapshot['wellKnown']['robotsTxt'] = { present: robots.present, size: robots.size };
  if (robots.present && robots.body) {
    robotsTxt.hash = await sha256Hex(robots.body);
    robotsTxt.firstLines = robots.body.split(/\r?\n/).slice(0, 8);
  }
  const sitemapXml: Snapshot['wellKnown']['sitemapXml'] = { present: sitemap.present, urlCount: 0, firstUrls: [] };
  if (sitemap.present && sitemap.body) {
    const parsed = parseSitemap(sitemap.body);
    sitemapXml.urlCount = parsed.urlCount;
    sitemapXml.firstUrls = parsed.firstUrls;
  }
  const securityTxt: Snapshot['wellKnown']['securityTxt'] = { present: sectxt.present, size: sectxt.size };
  if (sectxt.present && sectxt.body) securityTxt.hash = await sha256Hex(sectxt.body);

  return {
    v: SIGNALS_VERSION,
    input,
    capturedAt,
    final: { url: finalUrl, status: finalStatus },
    redirectChain,
    headers,
    csp,
    setCookie,
    html,
    wellKnown: { robotsTxt, sitemapXml, securityTxt },
  };
}
