// Test-only stub for the Workers `cloudflare:sockets` runtime module.
// Importing the real module under Node blows up with "Failed to load url".
// We never actually call `connect()` in unit tests — integration tests of
// the peer-TLS fast path run on Cloudflare Pages. This stub exists so the
// module graph loads under vitest.
export function connect(..._args: unknown[]): unknown {
  throw new Error('cloudflare:sockets.connect() is not available in the Node test runner');
}
