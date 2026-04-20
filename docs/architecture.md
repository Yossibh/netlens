# Architecture

## Goals

- **Static-first** UI deployable to Cloudflare Pages.
- **API-first** backend so UI, CLI, and a future MCP server share one implementation.
- **Pure** findings engine (no I/O), trivially unit-testable.
- **Provider interface** for every diagnostic module, so sources can be swapped.

## High-level flow

```
     ┌──────────────┐
     │ browser / UI │
     └──────┬───────┘
            │ fetch /api/analyze?input=…
            ▼
┌──────────────────────────────────────┐
│ functions/api/analyze.ts (Pages Fn)  │
└──────┬───────────────────────────────┘
       │ calls buildReport(raw)
       ▼
┌──────────────────────────────────────┐
│ src/lib/report-builder.ts            │
│  1. detectInput                      │
│  2. run provider modules in parallel │
│  3. runFindings (pure)               │
│  4. generateCommands (pure)          │
│  5. compose AnalyzeReport            │
└──────┬───────────────────────────────┘
       │
       ▼
┌───────────── providers ──────────────┐
│ dns   → Cloudflare DoH JSON          │
│ http  → Worker fetch (manual redirects)│
│ email → DoH TXT (SPF/DMARC/MTA-STS)  │
│ tls   → crt.sh (CT logs, best-effort)│
│ infer → correlates DNS + HTTP + ASN  │
└──────────────────────────────────────┘
```

## Key modules

### `src/lib/input-detection.ts`
Pure normalization: `string → NormalizedInput` with `type ∈ {domain, ip, url}`. Also computes a synthetic probe URL for HTTP checks.

### `src/lib/providers/*`
Each provider returns a typed `ModuleResult` with an `ok` flag and optional `skipped`/`skipReason`. No shared I/O state; all providers are stateless.

### `src/lib/findings-engine.ts`
Pure function: `({input, modules}) → Finding[]`. Rules are organized by module (`dnsRules`, `emailRules`, `httpRules`, `tlsRules`, `inferenceRules`) and combined. Each rule is small and individually testable.

The **correlation rules** deliberately cross module boundaries - that is the product's reason to exist.

### `src/lib/report-builder.ts`
Orchestrator. Owns parallelism, timeouts (per provider), risk aggregation, and highlight generation.

### `src/lib/tools.ts`
Registry of named tools with Zod input schemas. This is the abstraction that maps 1:1 to MCP tools in Phase 2 (see `mcp-plan.md`).

### `functions/api/*`
Thin adapters over `buildReport` / `buildComparison` / `TOOLS`. Add CORS, JSON serialization, and validation. **No business logic lives in functions.**

## Frontend

Astro with `output: 'static'`. The homepage ships one short inline script that calls `/api/analyze` and renders tabs. No framework, no client state library - the report is a pure render of JSON.

## Typing

- Strict TypeScript project-wide (`strict: true`, `noUncheckedIndexedAccess: true`).
- Zod schemas only where runtime input validation is needed (tool inputs, API bodies). Internal types are TS-only to keep bundle size tiny.

## Testing

- Vitest for unit tests (input detection, findings engine, commands).
- Integration test for `buildReport` with a mocked `globalThis.fetch` that simulates DoH and crt.sh responses.
- No Astro component tests in the MVP (UI is thin and deterministic).

## Why Cloudflare Pages + Functions

- Free tier, edge-close to users.
- `fetch()` in Workers makes DoH and crt.sh trivial.
- Pages Functions are filesystem-routed (`functions/api/foo.ts` → `/api/foo`), no extra config.
- Static HTML + edge fns matches the "API-first, static-first" goal with no SSR complexity.
