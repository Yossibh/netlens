# Roadmap

## Phase 1 - MVP (this release)
- Unified input, auto-detection.
- DNS, HTTP, email-posture, TLS-via-CT, infrastructure inference modules.
- Findings engine with cross-module correlation rules.
- Reproducible command generation.
- `/api/analyze`, `/api/compare`, `/api/tools`, `/api/health`.
- Compare UI, blog scaffold, about page.
- Deploys to Cloudflare Pages free tier with zero env vars.

## Phase 2 - MCP server
- Second deployable (`mcp-server/`) that mirrors `TOOLS` as MCP tools.
- Both stdio (for local agents) and Streamable HTTP (for remote agents) transports.
- Same code paths as the HTTP API.

## Phase 3 - CI / CD integrations
- GitHub Action: run netlens on every PR to a `sites.txt` file; post a summary comment.
- CLI (`npx netlens analyze <input>`) that hits the hosted `/api/analyze`.
- Webhook: subscribe to a domain; alert when DMARC weakens, cert expiry drops below threshold, or CDN fronting disappears.
- Saved "diagnostic recipes": named bundles of checks for specific incident classes.

## Phase 4 - Live peer inspection
- Add an origin-side probe (small worker in a non-CF PoP, or a Cloudflare-run TCP egress path) to perform true TLS peer handshake and capture the live chain.
- Swap the `tls` provider without changing the public shape of `TlsModuleResult`.

## Phase 5 - Historical diffs
- Optional authenticated persistence (Cloudflare D1 / KV).
- Track a target's reports over time; surface regressions ("HSTS disappeared last Tuesday").

## Explicit non-goals
- No becoming uptime monitoring ("is it down?") - plenty of tools do that.
- No bulk scanning / ranking / leaderboards.
- No ads, no email-gated reports.
