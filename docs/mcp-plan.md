# MCP plan

netrecon is built with MCP (Model Context Protocol) as a first-class target -
not an afterthought. **Phase 2 (MCP server) is shipped** as of the `mcp-server`
commit. The deployed endpoint is live at:

```
https://netrecon.pages.dev/api/mcp
```

## What's live

- `functions/api/mcp.ts` - Streamable HTTP transport (POST JSON-RPC 2.0)
- `src/lib/mcp.ts` - pure, transport-agnostic handler
- `src/lib/zod-to-json-schema.ts` - minimal Zod→JSON Schema converter
- Same `TOOLS` registry drives the UI, `/api/analyze`, `/api/compare`, `/api/tools`
  and MCP - zero duplicated business logic.
- Rate-limited (20 req/min/IP) via the existing Pages Functions middleware.
- Origin-validated (DNS rebinding defense per spec).
- Stateless: no session IDs issued or tracked.

## Supported methods

| Method                    | Purpose                                                     |
| ---                       | ---                                                         |
| `initialize`              | Protocol version negotiation + capability advertisement     |
| `notifications/initialized` | Client readiness (accepted silently, HTTP 202)            |
| `ping`                    | Liveness                                                    |
| `tools/list`              | Return all 9 netrecon tools with JSON Schema inputs         |
| `tools/call`              | Dispatch to `Tool.run()` in `src/lib/tools.ts`              |

Not implemented (and not planned for this server): `resources/*`, `prompts/*`,
`sampling/*`, `logging/*`, `roots/*`, server-initiated notifications.

## Protocol versions

We respond to the requested version if it's one of `2025-06-18`, `2025-03-26`,
or `2024-11-05`; otherwise we reply with `2025-06-18` and the client can
decide. Unsupported version is **not** a hard error - the spec says the client
can still try.

## Error discipline

| Situation                                   | Response                  |
| ---                                         | ---                       |
| Malformed JSON body                         | JSON-RPC `-32700`         |
| JSON-RPC request missing `method`           | JSON-RPC `-32600`         |
| Unknown method                              | JSON-RPC `-32601`         |
| Unknown tool name in `tools/call`           | JSON-RPC `-32602`         |
| Zod parse failure on tool arguments         | JSON-RPC `-32602` with `data.issues` |
| Tool throws `SecurityError`                 | `result.isError = true`, text "Security validation failed: ..." |
| Tool throws other `Error`                   | `result.isError = true`   |

## Output shape

Every `tools/call` success returns:

```json
{
  "content": [
    { "type": "text", "text": "<compact-JSON-of-the-result>" }
  ],
  "structuredContent": <the-result>,
  "isError": false
}
```

Text is **compact** JSON (no indentation) - `analyze` reports can exceed 100KB
and pretty-printing would ~4x the payload. Agents that can read structured
content should prefer `structuredContent`; agents that only read text get the
same data in `content[0].text`.

## Tool-boundary validation

Every `Tool.run()` self-validates its inputs via `src/lib/security.ts` before
doing network I/O:

| Tool                    | Validator             |
| ---                     | ---                   |
| `analyze_input`         | `validateInput`       |
| `analyze`               | `validateInput`       |
| `compare_targets`       | `validateInput` (both a+b) |
| `resolve_dns`           | `validateHost`        |
| `lookup_txt`            | `validateHost`        |
| `inspect_http`          | `validateFetchUrl`    |
| `check_email_security`  | `validateHost`        |
| `inspect_tls`           | `validateHost`        |
| `infer_infrastructure`  | `validateHost`        |

This means an MCP client calling `resolve_dns {"domain":"169.254.169.254"}`
gets `isError: true "Security validation failed: ..."` - same protection as
the HTTP API layer provides for `/api/analyze`.

## Why no SDK?

`@modelcontextprotocol/sdk` is ~500KB, depends on Node streams, and has
historically had Cloudflare Workers compatibility rough edges. The protocol
itself is ~200 lines of JSON-RPC when you only need a stateless tool server,
so hand-rolling it keeps the bundle small and removes a fragile dep.

The handler (`src/lib/mcp.ts`) is transport-agnostic. If we ever add stdio
for local agent use, the same module drives it through a 30-line Node
wrapper.

## Curl smoke test

```bash
# tools/list
curl -s https://netrecon.pages.dev/api/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq

# tools/call analyze github.com
curl -s https://netrecon.pages.dev/api/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"analyze_input","arguments":{"input":"github.com"}}}' | jq
```
