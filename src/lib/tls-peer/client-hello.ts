// Hand-crafted TLS 1.2 ClientHello byte builder.
//
// Why 1.2 specifically: in TLS 1.2 the server's Certificate handshake message
// is sent in cleartext, so we can read the peer cert off the wire without
// completing the handshake or doing any crypto. In TLS 1.3 the Certificate
// is encrypted under handshake traffic secrets, which we can't derive without
// implementing full key-share crypto.
//
// To force TLS 1.2 on a modern server we deliberately do NOT send the
// `supported_versions` extension (RFC 8446 §4.2.1). Without it, servers
// that support 1.2 will respect the `legacy_version` field (0x0303) and
// negotiate 1.2. A 1.3-only server will reject with a `protocol_version`
// alert, which we detect downstream.
//
// We still send the extensions a normal client would send, because many
// real-world servers refuse hellos that look "too minimal":
//   - server_name (SNI)
//   - signature_algorithms
//   - supported_groups (a.k.a. elliptic_curves)
//   - ec_point_formats

function be16(n: number): number[] { return [(n >> 8) & 0xff, n & 0xff]; }
function be24(n: number): number[] { return [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]; }

function lenPrefix16(payload: number[]): number[] { return [...be16(payload.length), ...payload]; }
function lenPrefix8(payload: number[]): number[] { return [payload.length, ...payload]; }

const CIPHER_SUITES: number[] = [
  0xc02f, 0xc030, 0xc02b, 0xc02c,  // ECDHE-*-AES-GCM
  0xcca8, 0xcca9,                  // ECDHE-*-CHACHA20
  0xc013, 0xc014,                  // ECDHE-RSA-AES-CBC
  0x009c, 0x009d,                  // RSA-AES-GCM (fallback)
  0x002f, 0x0035,                  // RSA-AES-CBC  (legacy fallback)
];

function sniExtension(host: string): number[] {
  const name = Array.from(new TextEncoder().encode(host));
  const serverName = [0x00, ...lenPrefix16(name)];
  const list = lenPrefix16(serverName);
  return [...be16(0x0000), ...lenPrefix16(list)];
}

function signatureAlgorithmsExtension(): number[] {
  const algs: number[] = [
    0x04, 0x03, 0x05, 0x03,                 // ecdsa_secp256r1_sha256, secp384_sha384
    0x08, 0x04, 0x08, 0x05, 0x08, 0x06,     // rsa_pss_rsae_sha{256,384,512}
    0x04, 0x01, 0x05, 0x01, 0x06, 0x01,     // rsa_pkcs1_sha{256,384,512}
    0x02, 0x01,                             // rsa_pkcs1_sha1 (legacy)
  ];
  return [...be16(0x000d), ...lenPrefix16(lenPrefix16(algs))];
}

function supportedGroupsExtension(): number[] {
  const groups: number[] = [
    ...be16(0x001d), // x25519
    ...be16(0x0017), // secp256r1
    ...be16(0x0018), // secp384r1
    ...be16(0x0019), // secp521r1
  ];
  return [...be16(0x000a), ...lenPrefix16(lenPrefix16(groups))];
}

function ecPointFormatsExtension(): number[] {
  return [...be16(0x000b), ...lenPrefix16(lenPrefix8([0x00]))];
}

/**
 * Build a TLS 1.2 ClientHello for the given SNI hostname.
 * Returns the full TLSPlaintext record (content_type=handshake).
 */
export function buildClientHello(sniHost: string, random?: Uint8Array): Uint8Array {
  if (!sniHost || sniHost.length > 255) throw new Error('Invalid SNI hostname');

  const clientRandom: number[] = [];
  if (random && random.length === 32) {
    clientRandom.push(...random);
  } else {
    const r = new Uint8Array(32);
    crypto.getRandomValues(r);
    clientRandom.push(...r);
  }

  const suites: number[] = [];
  for (const s of CIPHER_SUITES) suites.push(...be16(s));

  const extensions = [
    ...sniExtension(sniHost),
    ...signatureAlgorithmsExtension(),
    ...supportedGroupsExtension(),
    ...ecPointFormatsExtension(),
  ];

  const body: number[] = [
    0x03, 0x03,               // legacy_version = TLS 1.2
    ...clientRandom,
    ...lenPrefix8([]),        // empty session_id
    ...lenPrefix16(suites),
    ...lenPrefix8([0x00]),    // compression: null
    ...lenPrefix16(extensions),
  ];

  const handshake = [0x01, ...be24(body.length), ...body]; // type=ClientHello
  const record = [
    0x16,                     // content_type: handshake
    0x03, 0x01,               // legacy_record_version: TLS 1.0 (compat)
    ...be16(handshake.length),
    ...handshake,
  ];

  return new Uint8Array(record);
}
