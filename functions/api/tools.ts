import { TOOLS } from '../../src/lib/tools';

// Self-describing manifest for the tool registry.
// This is what the future MCP server (see docs/mcp-plan.md) will mirror as
// tools/list. For now it is a JSON endpoint that lets agents / CLIs discover
// the available capabilities without scraping HTML.

export const onRequest: PagesFunction = async () => {
  const manifest = {
    service: 'netrecon',
    version: '0.1.0',
    tools: TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
    })),
  };
  return new Response(JSON.stringify(manifest, null, 2), {
    headers: {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
    },
  });
};
