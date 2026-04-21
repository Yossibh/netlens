import { z } from 'zod';
import { resolveAll, resolveTxt } from './providers/dns';
import { inspectHttp } from './providers/http';
import { analyzeEmail } from './providers/email';
import { inspectTls } from './providers/tls';
import { inferInfrastructure } from './providers/inference';
import { detectInput } from './input-detection';
import { buildReport, buildComparison } from './report-builder';
import { validateInput, validateHost, validateFetchUrl, SecurityError } from './security';

// A tool is a named callable with a Zod schema for inputs. Every diagnostic
// module exposes one. In Phase 2 this registry is mounted as an MCP server
// (see docs/mcp-plan.md) by iterating TOOLS and wiring each to tools/call.
//
// This is the single source of truth for "what netrecon can do" - UI, HTTP API,
// and MCP will all go through this registry.
//
// SECURITY: every tool.run() validates its own inputs via src/lib/security.ts
// before doing any network I/O. The HTTP API handlers (/api/analyze,
// /api/compare) also pre-validate for nicer 400 responses, but the tool-level
// check is what protects MCP callers.

export interface ToolContext {
  /** Optional Shodan API key for enriched host/domain intel. */
  shodanApiKey?: string;
}

export interface Tool<I, O> {
  name: string;
  description: string;
  inputSchema: z.ZodType<I>;
  run(input: I, ctx?: ToolContext): Promise<O>;
}

function tool<I, O>(t: Tool<I, O>): Tool<I, O> {
  return t;
}

function requireHost(host: string): void {
  const v = validateHost(host);
  if (!v.ok) throw new SecurityError(v.reason ?? 'Host validation failed.');
}

function requireInput(input: string): void {
  const v = validateInput(input);
  if (!v.ok) throw new SecurityError(v.reason ?? 'Input validation failed.');
}

function requireFetchUrl(url: string): void {
  const v = validateFetchUrl(url);
  if (!v.ok) throw new SecurityError(v.reason ?? 'URL validation failed.');
}

export const analyzeInput = tool({
  name: 'analyze_input',
  description: 'Auto-detect input type (domain, IP, or URL) and return a normalized object.',
  inputSchema: z.object({ input: z.string().min(1) }),
  run: async ({ input }) => {
    requireInput(input);
    return detectInput(input);
  },
});

export const resolveDns = tool({
  name: 'resolve_dns',
  description: 'Resolve A/AAAA/CNAME/MX/TXT/NS/CAA/SOA for a domain over DoH.',
  inputSchema: z.object({ domain: z.string().min(1) }),
  run: async ({ domain }) => {
    requireHost(domain);
    return resolveAll(domain);
  },
});

export const lookupTxt = tool({
  name: 'lookup_txt',
  description: 'Fetch TXT records at a specific name (useful for _dmarc, _mta-sts, DKIM selectors).',
  inputSchema: z.object({ name: z.string().min(1) }),
  run: async ({ name }) => {
    requireHost(name);
    return resolveTxt(name);
  },
});

export const inspectHttpTool = tool({
  name: 'inspect_http',
  description: 'Fetch a URL and return status, redirect chain, and categorized response headers.',
  inputSchema: z.object({ url: z.string().url() }),
  run: async ({ url }) => {
    requireFetchUrl(url);
    return inspectHttp(url);
  },
});

export const checkEmailSecurity = tool({
  name: 'check_email_security',
  description: 'Check SPF, DMARC, MTA-STS, BIMI, MX, and probe common DKIM selectors for a domain.',
  inputSchema: z.object({
    domain: z.string().min(1),
    dkimSelectors: z.array(z.string()).optional(),
  }),
  run: async ({ domain, dkimSelectors }) => {
    requireHost(domain);
    return analyzeEmail(domain, dkimSelectors);
  },
});

export const inspectTlsTool = tool({
  name: 'inspect_tls',
  description: 'Retrieve recent TLS certificate metadata from crt.sh (CT logs). Not a live peer handshake.',
  inputSchema: z.object({ domain: z.string().min(1) }),
  run: async ({ domain }) => {
    requireHost(domain);
    return inspectTls(domain);
  },
});

export const inferInfra = tool({
  name: 'infer_infrastructure',
  description: 'Correlate DNS + HTTP headers to infer CDN/proxy and detect possible origin exposure.',
  inputSchema: z.object({ domain: z.string().min(1) }),
  run: async ({ domain }) => {
    requireHost(domain);
    const [dns, http] = await Promise.all([
      resolveAll(domain),
      inspectHttp(`https://${domain}`),
    ]);
    return inferInfrastructure(dns, http);
  },
});

export const analyze = tool({
  name: 'analyze',
  description: 'Run the full netrecon analysis pipeline for an input and return a correlated report.',
  inputSchema: z.object({ input: z.string().min(1) }),
  run: async ({ input }, ctx) => {
    requireInput(input);
    return buildReport(input, { shodanApiKey: ctx?.shodanApiKey });
  },
});

export const compareTargets = tool({
  name: 'compare_targets',
  description: 'Produce correlated reports for two inputs and diff their DNS, HTTP, CDN, and email posture.',
  inputSchema: z.object({ a: z.string().min(1), b: z.string().min(1) }),
  run: async ({ a, b }, ctx) => {
    requireInput(a);
    requireInput(b);
    return buildComparison(a, b, { shodanApiKey: ctx?.shodanApiKey });
  },
});

export const TOOLS = [
  analyzeInput,
  resolveDns,
  lookupTxt,
  inspectHttpTool,
  checkEmailSecurity,
  inspectTlsTool,
  inferInfra,
  analyze,
  compareTargets,
] as const;

export function getTool(name: string): Tool<unknown, unknown> | undefined {
  return TOOLS.find((t) => t.name === name) as Tool<unknown, unknown> | undefined;
}
