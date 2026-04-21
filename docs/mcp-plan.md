# MCP plan

netrecon is built with MCP (Model Context Protocol) as a first-class target - not an afterthought.

## Current state (Phase 1)

- Every capability is a registered **Tool** in `src/lib/tools.ts` with:
  - a stable name,
  - a human-readable description,
  - a Zod input schema,
  - a pure `run(input)` implementation.
- `GET /api/tools` returns a manifest of all tools, which is a proto-MCP `tools/list`.

## Mapping to MCP (Phase 2)

The MCP server will be a thin adapter with no duplicated logic. Each netrecon tool becomes an MCP tool verbatim:

| netrecon tool           | MCP tool name         | Notes                                      |
| ---                    | ---                   | ---                                        |
| `analyze_input`        | `analyze_input`       | Auto-detect + normalize                    |
| `resolve_dns`          | `resolve_dns`         | Full DoH record set                        |
| `lookup_txt`           | `lookup_txt`          | Targeted TXT (e.g. `_dmarc.*`)             |
| `inspect_http`         | `inspect_http`        | Redirect chain + categorized headers       |
| `check_email_security` | `check_email_security`| SPF / DMARC / MTA-STS / BIMI / DKIM probe  |
| `inspect_tls`          | `inspect_tls`         | CT log metadata (see limitations)          |
| `infer_infrastructure` | `infer_infrastructure`| CDN + ASN correlation                      |
| `analyze`              | `analyze`             | Full report                                |
| `compare_targets`      | `compare_targets`     | Diff two targets                           |

## Implementation sketch

Phase 2 adds a second deployable:

```
mcp-server/
├── package.json
├── src/index.ts        # MCP transport bootstrap (stdio or streamable HTTP)
└── src/bridge.ts       # imports TOOLS from ../netrecon/src/lib/tools and maps them
```

`bridge.ts` iterates `TOOLS`:

```ts
server.setRequestHandler(ListToolsRequestSchema, () => ({
  tools: TOOLS.map((t) => ({ name: t.name, description: t.description, inputSchema: toJsonSchema(t.inputSchema) })),
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const t = getTool(req.params.name);
  const parsed = t.inputSchema.parse(req.params.arguments);
  const result = await t.run(parsed);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});
```

Because `run` is plain async TypeScript, the MCP server can be **either**:
- a Node process (for stdio transport - local agent use), or
- a second Cloudflare Worker (for Streamable HTTP MCP - remote agent use).

The same `TOOLS` array drives both.

## Why this is not done in Phase 1

- MCP clients are not the primary user of an unauthenticated public diagnostic tool yet.
- A stable tool registry + public JSON API is the correct precursor. Phase 2 adds zero new business logic.
- Keeping the MVP as just "Pages + Functions" maximizes the free-tier deployment simplicity for launch.
