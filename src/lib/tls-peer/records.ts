// TLS record layer + handshake message reassembly.
//
// The wire has three nesting levels:
//   [ TLSPlaintext record | ... ]   (record layer: type, version, length, payload)
//   The payload of a record may contain one OR MORE handshake messages, or
//   a partial handshake message. A single handshake message may also span
//   MULTIPLE records.
//   [ Handshake message | ... ]     (handshake layer: type, length-24, body)
//
// We keep reading records into a single "handshake stream buffer" and slice
// off complete handshake messages as they're fully available. We stop when we
// see the Certificate message (handshake type 11), or a fatal Alert (21),
// or we hit limits.

export interface TlsRecord {
  contentType: number;   // 22=handshake, 21=alert, 20=ChangeCipherSpec, 23=application_data
  version: number;       // 16-bit, e.g. 0x0303
  payload: Uint8Array;
}

export interface HandshakeMessage {
  type: number;          // 2=ServerHello, 11=Certificate, 14=ServerHelloDone, ...
  body: Uint8Array;
}

export interface AlertRecord {
  level: number;         // 1=warning, 2=fatal
  description: number;   // see alertName()
}

const MAX_BYTES = 64 * 1024;       // total bytes we'll consume from the peer
const MAX_HS_MESSAGE = 48 * 1024;  // single handshake message cap (cert chains are usually <20KB)

/** Concatenate a list of Uint8Arrays efficiently. */
function concat(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

/**
 * Pull bytes from a ReadableStream reader until we've observed either:
 *   - a handshake Certificate message (returned via `certificate`), OR
 *   - a fatal alert (returned via `alert`), OR
 *   - the stream ended / total limit / timeout.
 *
 * `serverHello` is captured as soon as the ServerHello handshake message is
 * fully available. The caller handles both.
 */
export interface ReadResult {
  serverHello?: HandshakeMessage;
  certificate?: HandshakeMessage;
  alert?: AlertRecord;
  bytesRead: number;
  endedEarly: boolean;     // stream closed before we saw Certificate
}

export async function readServerFlight(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<ReadResult> {
  const recordBuf: Uint8Array[] = [];
  let recordBufLen = 0;
  let hsStream = new Uint8Array(0); // accumulates handshake bytes across records
  const result: ReadResult = { bytesRead: 0, endedEarly: false };

  const pushChunk = (u: Uint8Array) => {
    recordBuf.push(u);
    recordBufLen += u.length;
    result.bytesRead += u.length;
  };

  const consumeRecord = (): TlsRecord | 'short' | 'invalid' => {
    if (recordBufLen < 5) return 'short';
    const head = recordBuf.length === 1 ? recordBuf[0]! : concat(recordBuf);
    if (recordBuf.length > 1) { recordBuf.length = 0; recordBuf.push(head); }
    const contentType = head[0]!;
    const version = (head[1]! << 8) | head[2]!;
    const length = (head[3]! << 8) | head[4]!;
    if (length > 17 * 1024) return 'invalid'; // RFC caps TLSPlaintext at 2^14 + small
    if (head.length < 5 + length) return 'short';
    const payload = head.slice(5, 5 + length);
    const rest = head.slice(5 + length);
    recordBuf.length = 0;
    if (rest.length > 0) recordBuf.push(rest);
    recordBufLen = rest.length;
    return { contentType, version, payload };
  };

  while (result.bytesRead < MAX_BYTES) {
    // Try to consume as many complete records as we have already buffered.
    let rec = consumeRecord();
    while (rec !== 'short') {
      if (rec === 'invalid') {
        return result;
      }
      if (rec.contentType === 21 /* alert */) {
        if (rec.payload.length >= 2) {
          result.alert = { level: rec.payload[0]!, description: rec.payload[1]! };
        }
        return result;
      }
      if (rec.contentType === 22 /* handshake */) {
        const combined = new Uint8Array(hsStream.length + rec.payload.length);
        combined.set(hsStream, 0);
        combined.set(rec.payload, hsStream.length);
        hsStream = combined;

        // Peel off complete handshake messages.
        for (;;) {
          if (hsStream.length < 4) break;
          const hsType = hsStream[0]!;
          const hsLen = (hsStream[1]! << 16) | (hsStream[2]! << 8) | hsStream[3]!;
          if (hsLen > MAX_HS_MESSAGE) return result;
          if (hsStream.length < 4 + hsLen) break;
          const body = hsStream.slice(4, 4 + hsLen);
          hsStream = hsStream.slice(4 + hsLen);

          if (hsType === 2 /* ServerHello */ && !result.serverHello) {
            result.serverHello = { type: hsType, body };
          } else if (hsType === 11 /* Certificate */) {
            result.certificate = { type: hsType, body };
            return result;
          }
          // Other handshake types (Certificate, ServerKeyExchange, etc.) after
          // Certificate we don't care about; we return as soon as we have it.
        }
      }
      // Other content types (ChangeCipherSpec 20, application_data 23) are
      // post-handshake or unexpected here; ignore and keep reading.
      rec = consumeRecord();
    }

    // Need more bytes from the socket.
    const { value, done } = await reader.read();
    if (done) { result.endedEarly = true; return result; }
    if (value && value.length > 0) pushChunk(value);
  }

  return result;
}

/** Parse ServerHello body: version, cipher suite id, negotiated extensions. */
export interface ParsedServerHello {
  legacyVersion: number;      // e.g. 0x0303 for TLS 1.2
  negotiatedVersion: number;  // legacy_version unless supported_versions ext says otherwise
  cipherSuite: number;
  extensions: Map<number, Uint8Array>;
}

export function parseServerHello(body: Uint8Array): ParsedServerHello | null {
  if (body.length < 38) return null;
  let o = 0;
  const legacyVersion = (body[o]! << 8) | body[o + 1]!; o += 2;
  o += 32; // random
  const sessionIdLen = body[o]!; o += 1;
  if (o + sessionIdLen > body.length) return null;
  o += sessionIdLen;
  if (o + 2 > body.length) return null;
  const cipherSuite = (body[o]! << 8) | body[o + 1]!; o += 2;
  if (o + 1 > body.length) return null;
  o += 1; // compression_method
  const extensions = new Map<number, Uint8Array>();
  let negotiatedVersion = legacyVersion;
  if (o + 2 <= body.length) {
    const extLen = (body[o]! << 8) | body[o + 1]!; o += 2;
    if (o + extLen > body.length) return null;
    const end = o + extLen;
    while (o + 4 <= end) {
      const type = (body[o]! << 8) | body[o + 1]!; o += 2;
      const len = (body[o]! << 8) | body[o + 1]!; o += 2;
      if (o + len > end) return null;
      const data = body.slice(o, o + len);
      extensions.set(type, data);
      o += len;
      if (type === 0x002b /* supported_versions */ && data.length >= 2) {
        negotiatedVersion = (data[0]! << 8) | data[1]!;
      }
    }
  }
  return { legacyVersion, negotiatedVersion, cipherSuite, extensions };
}

/**
 * Parse the Certificate handshake message body into a list of DER cert blobs.
 *   struct { opaque certificate_list<0..2^24-1>; } Certificate;
 *   where each entry is   opaque cert_data<1..2^24-1>
 */
export function parseCertificateMessage(body: Uint8Array): Uint8Array[] | null {
  if (body.length < 3) return null;
  const listLen = (body[0]! << 16) | (body[1]! << 8) | body[2]!;
  if (3 + listLen > body.length) return null;
  const certs: Uint8Array[] = [];
  let o = 3;
  const end = 3 + listLen;
  while (o + 3 <= end) {
    const cLen = (body[o]! << 16) | (body[o + 1]! << 8) | body[o + 2]!;
    o += 3;
    if (o + cLen > end) return null;
    if (certs.length >= 16) return certs; // chain sanity cap
    certs.push(body.slice(o, o + cLen));
    o += cLen;
  }
  return certs;
}

/** RFC 5246/8446 alert descriptions we care about for reporting. */
export function alertName(desc: number): string {
  const map: Record<number, string> = {
    0: 'close_notify',
    10: 'unexpected_message',
    20: 'bad_record_mac',
    40: 'handshake_failure',
    42: 'bad_certificate',
    43: 'unsupported_certificate',
    44: 'certificate_revoked',
    45: 'certificate_expired',
    46: 'certificate_unknown',
    47: 'illegal_parameter',
    48: 'unknown_ca',
    49: 'access_denied',
    50: 'decode_error',
    51: 'decrypt_error',
    70: 'protocol_version',
    71: 'insufficient_security',
    80: 'internal_error',
    86: 'inappropriate_fallback',
    90: 'user_canceled',
    109: 'missing_extension',
    112: 'unrecognized_name',
    113: 'bad_certificate_status_response',
    120: 'no_application_protocol',
  };
  return map[desc] ?? `alert_${desc}`;
}

/** Friendly name for a handful of widely-seen cipher suites. */
export function cipherSuiteName(id: number): string {
  const map: Record<number, string> = {
    0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  };
  return map[id] ?? `0x${id.toString(16).padStart(4, '0')}`;
}

/** Friendly name for the negotiated version field. */
export function tlsVersionName(v: number): string {
  switch (v) {
    case 0x0301: return 'TLS 1.0';
    case 0x0302: return 'TLS 1.1';
    case 0x0303: return 'TLS 1.2';
    case 0x0304: return 'TLS 1.3';
    default:     return `0x${v.toString(16).padStart(4, '0')}`;
  }
}
