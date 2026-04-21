import { describe, expect, it } from 'vitest';
import { handleMcp, SERVER_NAME, JsonRpcErrorCodes } from '../src/lib/mcp';
import { toJsonSchema } from '../src/lib/zod-to-json-schema';
import { z } from 'zod';

describe('zod-to-json-schema', () => {
  it('converts z.object with required + optional fields', () => {
    const s = z.object({
      a: z.string().min(1),
      b: z.array(z.string()).optional(),
    });
    const j = toJsonSchema(s);
    expect(j.type).toBe('object');
    expect(j.properties?.a).toEqual({ type: 'string', minLength: 1 });
    expect(j.properties?.b).toEqual({ type: 'array', items: { type: 'string' } });
    expect(j.required).toEqual(['a']);
  });

  it('marks z.string().url() as format:uri', () => {
    const j = toJsonSchema(z.object({ u: z.string().url() }));
    expect(j.properties?.u).toEqual({ type: 'string', format: 'uri' });
  });

  it('preserves additionalProperties:false on objects', () => {
    const j = toJsonSchema(z.object({ x: z.string() }));
    expect(j.additionalProperties).toBe(false);
  });
});

describe('MCP: initialize', () => {
  it('echoes a supported protocol version back to the client', async () => {
    const res = await handleMcp({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '0' } },
    });
    expect(res).not.toBeNull();
    expect(res).toMatchObject({ id: 1, result: { protocolVersion: '2024-11-05' } });
  });

  it('falls back to latest version when client asks for something unsupported', async () => {
    const res = await handleMcp({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '1999-01-01' },
    });
    const result = (res as { result: { protocolVersion: string } }).result;
    expect(result.protocolVersion).toBe('2025-06-18');
  });

  it('advertises tools capability and correct serverInfo', async () => {
    const res = await handleMcp({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    const r = (res as { result: { capabilities: { tools: unknown }; serverInfo: { name: string } } }).result;
    expect(r.capabilities.tools).toBeDefined();
    expect(r.serverInfo.name).toBe(SERVER_NAME);
  });
});

describe('MCP: tools/list', () => {
  it('returns all 9 netrecon tools with name/description/inputSchema', async () => {
    const res = await handleMcp({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const r = (res as { result: { tools: Array<{ name: string; description: string; inputSchema: { type: string } }> } }).result;
    expect(r.tools).toHaveLength(9);
    for (const t of r.tools) {
      expect(t.name).toBeTruthy();
      expect(t.description).toBeTruthy();
      expect(t.inputSchema.type).toBe('object');
    }
    const names = r.tools.map((t) => t.name);
    expect(names).toContain('analyze');
    expect(names).toContain('analyze_input');
    expect(names).toContain('compare_targets');
  });
});

describe('MCP: tools/call - analyze_input (no network)', () => {
  it('happy path returns structuredContent + compact text', async () => {
    const res = await handleMcp({
      jsonrpc: '2.0', id: 3, method: 'tools/call',
      params: { name: 'analyze_input', arguments: { input: 'github.com' } },
    });
    const r = (res as { result: { isError: boolean; content: Array<{ text: string }>; structuredContent: { type: string } } }).result;
    expect(r.isError).toBe(false);
    expect(r.structuredContent.type).toBe('domain');
    // Compact JSON (no 2-space indent).
    expect(r.content[0].text).not.toContain('  "');
  });

  it('invalid args -> JSON-RPC -32602 with issues detail', async () => {
    const res = await handleMcp({
      jsonrpc: '2.0', id: 4, method: 'tools/call',
      params: { name: 'analyze_input', arguments: { input: '' } }, // min(1) violation
    });
    const r = res as { error: { code: number; data: { issues: unknown[] } } };
    expect(r.error.code).toBe(JsonRpcErrorCodes.InvalidParams);
    expect(Array.isArray(r.error.data.issues)).toBe(true);
  });

  it('unknown tool -> JSON-RPC -32602', async () => {
    const res = await handleMcp({
      jsonrpc: '2.0', id: 5, method: 'tools/call',
      params: { name: 'nope', arguments: {} },
    });
    const r = res as { error: { code: number; message: string } };
    expect(r.error.code).toBe(JsonRpcErrorCodes.InvalidParams);
    expect(r.error.message).toMatch(/Unknown tool/);
  });

  it('SecurityError from tool -> isError:true (not JSON-RPC error)', async () => {
    const res = await handleMcp({
      jsonrpc: '2.0', id: 6, method: 'tools/call',
      params: { name: 'resolve_dns', arguments: { domain: '127.0.0.1' } },
    });
    const r = (res as { result: { isError: boolean; content: Array<{ text: string }> } }).result;
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/Security validation failed/);
  });
});

describe('MCP: dispatch', () => {
  it('unknown method -> JSON-RPC -32601', async () => {
    const res = await handleMcp({ jsonrpc: '2.0', id: 7, method: 'resources/list' });
    const r = res as { error: { code: number } };
    expect(r.error.code).toBe(JsonRpcErrorCodes.MethodNotFound);
  });

  it('ping returns empty result', async () => {
    const res = await handleMcp({ jsonrpc: '2.0', id: 8, method: 'ping' });
    expect((res as { result: unknown }).result).toEqual({});
  });

  it('notification (no id) returns null', async () => {
    const res = await handleMcp({ jsonrpc: '2.0', method: 'notifications/initialized' });
    expect(res).toBeNull();
  });

  it('malformed message (missing method) -> -32600', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const res = await handleMcp({ jsonrpc: '2.0', id: 9 } as any);
    const r = res as { error: { code: number } };
    expect(r.error.code).toBe(JsonRpcErrorCodes.InvalidRequest);
  });
});
