// Live peer TLS inspection.
//
// What this does:
//   1. Open a raw TCP socket to host:port (default 443) via Cloudflare's
//      `connect()` API.
//   2. Write a hand-crafted TLS 1.2 ClientHello with SNI.
//   3. Read the server's handshake flight.
//   4. Parse ServerHello (negotiated version + cipher) and Certificate (DER chain).
//   5. Close the socket (we never complete the handshake - no crypto needed).
//   6. Extract human-friendly fields from each cert via pkijs.
//
// Why bother: our CT-logs-based TLS module only knows what certs *were issued*
// for a hostname. This module knows what cert is *actually being served right
// now*, which is what every operator really wants when debugging TLS issues.
//
// Limitations called out in the response:
//   - TLS 1.3-only servers reject our TLS 1.2 hello with `protocol_version`.
//     We report that clearly; we can't inspect 1.3-only peers without full
//     handshake crypto.
//   - Clients sending servers that require client-cert auth before sending
//     Certificate won't work (very rare in the public web).
//   - No ALPN, no OCSP stapling parsing yet (future work).

import { connect } from 'cloudflare:sockets';
import { validateHost } from '../security';
import { buildClientHello } from './client-hello';
import {
  readServerFlight,
  parseServerHello,
  parseCertificateMessage,
  alertName,
  cipherSuiteName,
  tlsVersionName,
} from './records';
import { extractCertFields, matchesHostname, type ExtractedCert } from './cert';

export interface PeerTlsResult {
  ok: boolean;
  host: string;
  port: number;
  negotiatedVersion?: string;      // e.g. "TLS 1.2"
  cipherSuite?: string;            // e.g. "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  certs?: ExtractedCert[];         // leaf first, then chain
  hostnameMatch?: boolean;         // leaf cert matches requested SNI?
  error?: string;                  // plain-english failure reason
  alert?: { level: number; description: string };
  durationMs: number;
  bytesRead?: number;
  notes: string[];                 // caveats we want operators to see
}

const HANDSHAKE_TIMEOUT_MS = 5000;

/** Race a promise against a timer; losing side is never awaited. */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, rej) => setTimeout(() => rej(new Error(`timeout after ${ms}ms: ${label}`)), ms)),
  ]);
}

export async function inspectPeerTls(host: string, port = 443): Promise<PeerTlsResult> {
  const started = Date.now();
  const notes: string[] = [];
  const result: PeerTlsResult = { ok: false, host, port, durationMs: 0, notes };

  // Gate 1: SSRF / hostname sanity (same rules as the rest of the app).
  const v = validateHost(host);
  if (!v.ok) {
    result.error = v.reason;
    result.durationMs = Date.now() - started;
    return result;
  }

  // SNI requires an ASCII hostname, not an IP. (Workers' connect() will still
  // work for IPs, but real-world servers cert-mux by SNI, and an IP in the
  // SNI extension is a protocol violation.)
  const looksLikeIp = /^(\d{1,3}(\.\d{1,3}){3}|\[?[0-9a-fA-F:]+\]?)$/.test(host);
  if (looksLikeIp) {
    result.error = 'Live peer TLS requires a hostname (SNI). IP-only inputs cannot set SNI.';
    result.durationMs = Date.now() - started;
    return result;
  }

  // Gate 2: connect + handshake capture. We set secureTransport:"off" so the
  // runtime does NOT attempt its own TLS handshake - we're doing it ourselves.
  let socket: any;
  try {
    socket = connect({ hostname: host, port }, { secureTransport: 'off', allowHalfOpen: false });
  } catch (err: any) {
    result.error = `Connect failed: ${err?.message ?? String(err)}`;
    result.durationMs = Date.now() - started;
    return result;
  }

  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();

  let writerReleased = false;
  let readerReleased = false;
  const releaseAndClose = async () => {
    try { if (!writerReleased) { writer.releaseLock(); writerReleased = true; } } catch {}
    try { if (!readerReleased) { await reader.cancel().catch(() => {}); reader.releaseLock(); readerReleased = true; } } catch {}
    try { await socket.close().catch(() => {}); } catch {}
  };

  try {
    const hello = buildClientHello(host);
    await withTimeout(writer.write(hello), HANDSHAKE_TIMEOUT_MS, 'write ClientHello');
    // Done writing - release the writer eagerly so the TCP half-close doesn't
    // confuse the peer if it waits for EOF.
    try { writer.releaseLock(); writerReleased = true; } catch {}

    const flight = await withTimeout(readServerFlight(reader), HANDSHAKE_TIMEOUT_MS, 'read handshake');
    result.bytesRead = flight.bytesRead;

    if (flight.alert) {
      const name = alertName(flight.alert.description);
      result.alert = { level: flight.alert.level, description: name };
      if (name === 'protocol_version') {
        result.error = 'Peer rejected TLS 1.2 with protocol_version alert. This is typically a TLS 1.3-only server; our prototype cannot inspect 1.3-encrypted certs.';
        notes.push('TLS 1.3-only servers encrypt the Certificate under handshake traffic secrets; live inspection of those would require a full TLS 1.3 implementation.');
      } else if (name === 'handshake_failure' || name === 'insufficient_security') {
        result.error = `Peer rejected our ClientHello with ${name}. Likely no shared cipher suite or sig algorithm.`;
      } else if (name === 'unrecognized_name') {
        result.error = `Peer does not have a certificate for SNI "${host}" (alert: ${name}).`;
      } else {
        result.error = `Peer sent fatal alert: ${name}`;
      }
      return result;
    }

    if (!flight.serverHello) {
      result.error = flight.endedEarly
        ? 'Peer closed connection before sending ServerHello.'
        : 'Did not receive ServerHello within handshake budget.';
      return result;
    }

    const sh = parseServerHello(flight.serverHello.body);
    if (!sh) { result.error = 'Malformed ServerHello.'; return result; }
    result.negotiatedVersion = tlsVersionName(sh.negotiatedVersion);
    result.cipherSuite = cipherSuiteName(sh.cipherSuite);

    if (sh.negotiatedVersion === 0x0304) {
      // Server accepted our hello but negotiated 1.3 via supported_versions.
      // Certificate message here is encrypted and we can't decode it.
      result.error = 'Peer negotiated TLS 1.3 despite our 1.2-only hello; Certificate is encrypted. Prototype cannot inspect.';
      notes.push('This is unusual: normally omitting `supported_versions` pins to 1.2. Some edge stacks still pick 1.3.');
      return result;
    }

    if (!flight.certificate) {
      result.error = flight.endedEarly
        ? 'Peer closed connection before sending Certificate.'
        : 'No Certificate message observed before handshake budget elapsed.';
      return result;
    }

    const derChain = parseCertificateMessage(flight.certificate.body);
    if (!derChain || derChain.length === 0) {
      result.error = 'Empty or malformed Certificate message.';
      return result;
    }

    const extracted: ExtractedCert[] = [];
    for (let i = 0; i < derChain.length; i++) {
      try {
        // eslint-disable-next-line no-await-in-loop
        extracted.push(await extractCertFields(derChain[i]!));
      } catch (err: any) {
        notes.push(`Cert #${i} parse error: ${err?.message ?? String(err)}`);
      }
    }
    if (extracted.length === 0) {
      result.error = 'All peer certs failed to parse.';
      return result;
    }
    result.certs = extracted;
    result.hostnameMatch = matchesHostname(extracted[0]!, host);
    result.ok = true;

    if (extracted[0]!.expired) notes.push('Leaf certificate is expired as of this check.');
    if (extracted[0]!.daysUntilExpiry >= 0 && extracted[0]!.daysUntilExpiry < 14) {
      notes.push(`Leaf certificate expires in ${extracted[0]!.daysUntilExpiry} day(s).`);
    }
    if (!result.hostnameMatch) notes.push('Leaf certificate SANs do not match the requested hostname.');

    return result;
  } catch (err: any) {
    result.error = err?.message ?? String(err);
    return result;
  } finally {
    await releaseAndClose();
    result.durationMs = Date.now() - started;
  }
}
