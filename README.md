# netlens

**Correlated network diagnostics for engineers. See through the network.**

netlens takes a domain, IP, or URL and returns a *correlated* report: DNS, HTTP, TLS (via CT logs), email posture, and CDN/ASN inference - combined into findings with severity, evidence, next steps, and reproducible commands. Everything the UI shows is also available as JSON at `/api/analyze`.

Built by [Yossi Ben Hagai](https://www.linkedin.com/in/yossibenhagai/).

## What it is not

- Not a commodity "dig in a browser" tool.
- Not a paid-API aggregator.
- Not a marketing funnel.

## What it is

- A static-first Astro site deployable to Cloudflare Pages in under a minute.
- Pages Functions at the edge for the analyze / compare / tools endpoints.
- A tool registry (`src/lib/tools.ts`) that is the single source of truth for capabilities and the foundation for a future MCP server.

## Product features

- **Unified input.** Auto-detects domain, IP, or URL.
- **Findings engine.** Rules correlate signals across modules (e.g. *CDN headers present but A record ASN mismatches the CDN* → origin may be exposed).
- **Reproducible commands.** Every finding ships with the exact `dig` / `curl` / `openssl` line that verifies it.
- **Compare mode.** Diff two environments across DNS, HTTP, CDN, and email posture.
- **Machine-readable.** `GET /api/analyze?input=…` returns the full structured report.
- **MCP-ready.** Tool registry designed to be mirrored 1:1 as MCP tools. See `docs/mcp-plan.md`.

## Local setup

```bash
npm install
npm run dev          # Astro dev server for the UI (no Pages Functions)
npm run build        # static build -> ./dist
npm run preview      # wrangler pages dev ./dist  (UI + functions locally)
npm test             # vitest
```

Requirements: Node 18.17+ and npm. Wrangler is installed as a dev dependency.

## Deployment (Cloudflare Pages)

```bash
npm run build
npm run deploy       # wrangler pages deploy ./dist
```

Or connect the repo in the Cloudflare dashboard with:
- Build command: `npm run build`
- Build output directory: `dist`
- `functions/` is auto-detected as Pages Functions.

No environment variables are required for the MVP.

## API

| Endpoint                     | Method       | Description                                   |
| ---                          | ---          | ---                                           |
| `/api/analyze?input=…`       | GET          | Full report                                   |
| `/api/analyze`               | POST `{input}` | Full report                                 |
| `/api/compare`               | POST `{a,b}` | Side-by-side diff                             |
| `/api/tools`                 | GET          | Tool manifest (what the backend can do)       |
| `/api/health`                | GET          | Liveness                                      |

## Architecture

See `docs/architecture.md`.

## Limitations

See `docs/limitations.md`. In short: no ping/traceroute/port scan (not possible from a Workers runtime), and TLS inspection uses Certificate Transparency logs rather than a live peer handshake. Both are disclosed honestly in-product.

## Roadmap

See `docs/roadmap.md`.

## License

MIT © Yossi Ben Hagai.
