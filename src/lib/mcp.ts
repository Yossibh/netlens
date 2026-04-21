// Pure MCP (Model Context Protocol) JSON-RPC 2.0 handler, transport-agnostic.
//
// Handles the subset of MCP that a stateless, tool-only server needs:
//   - initialize            (version negotiation + capability advertisement)
//   - initialized            (client notification, no response)
//   - ping                   (liveness)
//   - tools/list             (enumerate the registry)
//   - tools/call             (dispatch to a registered tool.run())
//
// Intentionally NOT implemented: resources/*, prompts/*, logging/*, sampling/*,
// roots/*, server-initiated notifications. We don't use those.
//
// Error discipline (matches spec and rubber-duck review):
//   - Parse / malformed JSON                  => -32700 "Parse error"
//   - Unknown method                          => -32601 "Method not found"
//   - Zod parse failure on tools/call args    => -32602 "Invalid params"
//   - Unknown tool name                       => -32602 "Invalid params"
//   - Unsupported protocol version            => -32602 "Invalid params"
//   - Tool throws SecurityError / other       => result.isError=true (business error)
//   - JSON-RPC request missing "method"       => -32600 "Invalid Request"

import { z } from 'zod';
import { TOOLS, getTool, type ToolContext } from './tools';
import { toJsonSchema } from './zod-to-json-schema';
import { SecurityError } from './security';

export const SERVER_NAME = 'netrecon';
export const SERVER_VERSION = '0.1.0';

// Protocol versions we understand. If a client asks for one of these we echo
// it back (per MCP spec version-negotiation). Otherwise we reply with our
// latest and the client can decide whether to proceed.
const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const LATEST_PROTOCOL_VERSION = '2025-06-18';

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: unknown;
}

export interface JsonRpcSuccess {
  jsonrpc: '2.0';
  id: string | number | null;
  result: unknown;
}

export interface JsonRpcErrorResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  error: { code: number; message: string; data?: unknown };
}

export type JsonRpcResponse = JsonRpcSuccess | JsonRpcErrorResponse;

export const JsonRpcErrorCodes = {
  ParseError: -32700,
  InvalidRequest: -32600,
  MethodNotFound: -32601,
  InvalidParams: -32602,
  InternalError: -32603,
} as const;

export function rpcError(
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcErrorResponse {
  const err: JsonRpcErrorResponse['error'] = { code, message };
  if (data !== undefined) err.data = data;
  return { jsonrpc: '2.0', id, error: err };
}

export function rpcOk(id: string | number | null, result: unknown): JsonRpcSuccess {
  return { jsonrpc: '2.0', id, result };
}

/** True if the message is a JSON-RPC notification (no id). */
export function isNotification(msg: JsonRpcRequest): boolean {
  return msg.id === undefined;
}

/**
 * Handle one JSON-RPC message. Returns the response, or `null` for
 * notifications (which must not be answered per JSON-RPC 2.0).
 */
export async function handleMcp(
  msg: JsonRpcRequest,
  ctx?: ToolContext,
): Promise<JsonRpcResponse | null> {
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return rpcError(msg?.id ?? null, JsonRpcErrorCodes.InvalidRequest, 'Invalid Request');
  }

  // Notifications: accept silently and return null.
  if (isNotification(msg)) {
    // Nothing to do - we don't maintain session state.
    return null;
  }

  const id = msg.id ?? null;
  const params = (msg.params ?? {}) as Record<string, unknown>;

  try {
    switch (msg.method) {
      case 'initialize':
        return rpcOk(id, handleInitialize(params));

      case 'ping':
        return rpcOk(id, {});

      case 'tools/list':
        return rpcOk(id, { tools: listTools() });

      case 'tools/call':
        return await handleCallTool(id, params, ctx);

      default:
        return rpcError(id, JsonRpcErrorCodes.MethodNotFound, `Method not found: ${msg.method}`);
    }
  } catch (err) {
    return rpcError(
      id,
      JsonRpcErrorCodes.InternalError,
      err instanceof Error ? err.message : 'Internal error',
    );
  }
}

function handleInitialize(params: Record<string, unknown>): unknown {
  const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : null;
  const agreedVersion =
    requested && SUPPORTED_PROTOCOL_VERSIONS.includes(requested)
      ? requested
      : LATEST_PROTOCOL_VERSION;

  return {
    protocolVersion: agreedVersion,
    capabilities: {
      tools: { listChanged: false },
    },
    serverInfo: {
      name: SERVER_NAME,
      version: SERVER_VERSION,
    },
    instructions:
      'netrecon exposes correlated network diagnostics (DNS, HTTP, TLS, email posture, CDN/ASN inference). ' +
      'Start with tools/list. For ad-hoc investigations, call analyze with a domain, IP, or URL and read the ' +
      'summary.findings + summary.nextCommands fields before drilling into raw sub-reports.',
  };
}

function listTools() {
  return TOOLS.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: toJsonSchema(t.inputSchema),
  }));
}

async function handleCallTool(
  id: string | number | null,
  params: Record<string, unknown>,
  ctx?: ToolContext,
): Promise<JsonRpcResponse> {
  const name = typeof params.name === 'string' ? params.name : null;
  if (!name) {
    return rpcError(id, JsonRpcErrorCodes.InvalidParams, 'Missing tool name');
  }

  const t = getTool(name);
  if (!t) {
    return rpcError(id, JsonRpcErrorCodes.InvalidParams, `Unknown tool: ${name}`);
  }

  // Parse arguments with the tool's Zod schema. Schema failure is a JSON-RPC
  // protocol error, not a tool-level error (per MCP spec + rubber-duck review).
  let parsed: unknown;
  try {
    parsed = t.inputSchema.parse(params.arguments ?? {});
  } catch (err) {
    if (err instanceof z.ZodError) {
      return rpcError(
        id,
        JsonRpcErrorCodes.InvalidParams,
        'Invalid arguments',
        { issues: err.issues },
      );
    }
    return rpcError(
      id,
      JsonRpcErrorCodes.InvalidParams,
      err instanceof Error ? err.message : 'Invalid arguments',
    );
  }

  // Tool execution. Errors from run() are tool-level (SecurityError, upstream
  // API failures, etc.) and should be reported via CallToolResult.isError=true
  // so agents can reason about them instead of treating them as protocol bugs.
  try {
    const result = await t.run(parsed as never, ctx);
    return rpcOk(id, {
      content: [
        // Compact JSON, NOT pretty-printed. Large reports (100KB+) should not
        // be inflated 4x by indentation.
        { type: 'text', text: JSON.stringify(result) },
      ],
      structuredContent: result,
      isError: false,
    });
  } catch (err) {
    const message =
      err instanceof SecurityError
        ? `Security validation failed: ${err.message}`
        : err instanceof Error
          ? err.message
          : String(err);
    return rpcOk(id, {
      content: [{ type: 'text', text: message }],
      isError: true,
    });
  }
}

export const _internals = { SUPPORTED_PROTOCOL_VERSIONS, LATEST_PROTOCOL_VERSION };
