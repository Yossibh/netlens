# Phase 4 — Live peer TLS inspection (prototype)

## Status
**Integrated into `/api/analyze`** as `modules.livetls`. Runs in parallel with
the existing HTTP/email probes. Default mode is `fast` (raw TCP only).
`?live=full` opts into the Browser Rendering fallback for CF-fronted / TLS 1.3-
only targets. A UI checkbox exposes this toggle.

The standalone `/api/peer-tls` endpoint is still available for direct use.

## What it does
Two code paths, chosen automatically:

1. **Fast path — raw TCP via Workers `connect()`**
   Opens a raw TCP connection to `host:443`, performs enough of a TLS 1.2
   handshake to capture the peer's `Certificate` message, parses the DER chain
   with [`pkijs`](https://github.com/PeculiarVentures/PKI.js), and returns
   extracted cert fields plus negotiated version and cipher suite. It **never
   completes the handshake** — no crypto, no Finished, no app data. Just enough
   to read what the server sent. ~200-600ms per target.

2. **Fallback — Cloudflare Browser Rendering**
   For targets the fast path cannot reach (Cloudflare-fronted hosts, TLS 1.3-
   only servers that encrypt the Certificate record), we launch a headless
   Chromium via the `BROWSER` binding, navigate to `https://host/`, and ask
   Chrome for the peer cert via the CDP `Network.getCertificate` command plus
   `response.securityDetails()`. ~3-5s per target. Free plan: 10 browser-
   minutes/day, 3 concurrent.

### Fallback trigger matrix
| Fast-path outcome | Action |
|---|---|
| Success | return fast-path result (`source: "raw-tcp"`) |
| `alert.description === "protocol_version"` (TLS 1.3-only) | fall back to browser |
| Error contains `"Stream was cancelled"` (CF-internal block) | fall back to browser |
| Error contains `"Peer negotiated TLS 1.3"` | fall back to browser |
| Any other error | return the fast-path error, no fallback |

### Known browser-path limitations
Browser Rendering gives us a less direct view of the peer cert than raw TCP
does. We mitigate by combining three CDP signals and patching empty fields
from whichever source has them:

1. **Primary DER source — `Security.visibleSecurityStateChanged` event**
   Subscribed to *before* `page.goto`; we then wait up to 2s after
   `domcontentloaded` for it to fire. Carries `certificateSecurityState.certificate`
   (base64 DER chain) plus structured `subjectName`, `issuer`, `validFrom`,
   `validTo`, `protocol`, `cipher`, `keyExchange`.
2. **Secondary DER source — `Network.getCertificate({origin})`**
   Tried against the final redirected origin first, then the originally
   requested origin. Historically returns empty `tableNames` for CF-proxied
   hosts, which is why we moved to the Security event as primary.
3. **Tertiary signal — Puppeteer `response.securityDetails()`**
   Used for `protocol` / `issuer` / `validFrom` when CDP Security didn't
   surface them. Often empty for CF-edge responses.

After extraction, we patch any empty leaf-cert fields (`issuer`, `subject`,
`sans`) from whichever structured CDP source had a value. A manual ASN.1 walk
also runs as a last-resort fallback in `rdnToDn` when pkijs returns
`typesAndValues=[]` despite `valueBeforeDecode` still holding raw bytes.

**What the browser path reliably returns on CF-fronted targets today:**
`subject`, `sans`, `notBefore`, `notAfter`, `negotiatedVersion`,
`hostnameMatch`, `expired`, `daysUntilExpiry`, `fingerprintSha256`,
`serialNumber`, `signatureAlgorithm`, `publicKeyAlgorithm`.

**Known remaining gap — issuer on Cloudflare-fronted targets:**
For hosts like `cloudflare.com` / `www.cloudflare.com`, the DER returned via
`Security.visibleSecurityStateChanged` has fingerprints that do *not* match
the cert seen by standard clients (e.g. Python `ssl.getpeercert`). Chrome
under the Browser Rendering binding appears to see a different cert whose
issuer `RelativeDistinguishedNames.typesAndValues` decodes as an empty
SEQUENCE. The high-level CDP `issuer` string is also empty in that path, so
we have no authoritative source for the issuer and surface a clear note to
users. Users needing authoritative issuer data should use the fast path
(which works for all non-CF-fronted targets including github.com, google.com,
badssl variants, etc).

Browser path is also gated by CF Browser Rendering quotas (10 browser-minutes/day
free plan); a 429-style error from the binding is surfaced as a clean error
message, not a crash.

## Why bother
Our existing TLS module uses Certificate Transparency logs. CT tells us what
certs *were issued* for a hostname. It does **not** tell us what cert is
*actually being served right now* — which is what operators actually care
about when debugging TLS. Examples:
- CT shows a shiny new LE cert issued yesterday; peer still serves the old
  DigiCert cert from 2023 because the deployment didn't roll.
- Server is serving an expired cert (CT won't flag this).
- Server is serving the default CDN cert instead of the customer cert.
- Wrong chain ordering / missing intermediate.

## How it works
1. **Raw TCP via `cloudflare:sockets`** — `connect(..., { secureTransport: 'off' })`.
   The Workers runtime does NOT attempt its own TLS handshake.
2. **Hand-crafted TLS 1.2 ClientHello** with SNI, `signature_algorithms`,
   `supported_groups`, `ec_point_formats`. We deliberately omit the
   `supported_versions` extension so servers fall back to TLS 1.2. That's
   critical: in TLS 1.3 the Certificate message is encrypted under handshake
   traffic secrets and cannot be read without implementing the full handshake.
3. **Record + handshake reassembly**. TLS records and handshake messages can
   fragment independently; we buffer both layers correctly. Cap at 64KB total.
4. **Parse ServerHello + Certificate + Alert**. If the server sends a fatal
   alert, we map it to a plain-english description (e.g. `protocol_version`
   means "this is probably a TLS 1.3-only server we can't inspect").
5. **Extract cert fields via pkijs** — subject CN, issuer CN, notBefore,
   notAfter, SANs, signature algorithm, public-key algorithm, serial,
   SHA-256 fingerprint. Plus derived fields: `expired`, `daysUntilExpiry`,
   `selfSigned`.
6. **Hostname match** — check SANs against the requested SNI, honouring
   single-label wildcards.
7. **Close socket aggressively** in `finally`.

## Endpoint
```
GET /api/peer-tls?host=<hostname>[&port=443]
```
Rate-limited: 10/min/IP (shared family with analyze/compare).

Returns a `PeerTlsResult` JSON body — never a non-200 unless there was an
internal error. Check `body.ok`, `body.error`, `body.alert`, and
`body.notes[]` for operator-facing context.

## Security posture
- **SSRF guard**: same `validateHost()` the rest of the app uses. Blocks
  RFC1918, loopback, link-local (metadata), CGNAT, reserved TLDs.
- **Cloudflare's own guard**: `connect()` also refuses CF-owned IPs, so
  `cloudflare.com` returns `"Stream was cancelled."` — which is actually the
  desired outcome (we can't turn this tool into a Cloudflare-internal probe).
- **Parser resource caps**: 64KB total read budget, 48KB/handshake-message,
  16 certs max, 5s handshake timeout. `pkijs`/`asn1js` own the ASN.1 nesting
  risk and are battle-tested on the web.
- **IP-only inputs rejected**: a literal IP in the SNI extension is a protocol
  violation, and most servers would send `unrecognized_name` — we fail early
  with a clear message instead.
- **No crypto means no key material to leak**: we never derive a master secret.

## Verified live
Against `https://netrecon.pages.dev/api/peer-tls`:
| Host                    | Result                                                          |
|-------------------------|-----------------------------------------------------------------|
| github.com              | TLS 1.2, ECDHE-ECDSA-AES128-GCM, 3-cert chain, hostnameMatch=true |
| google.com              | TLS 1.2, wildcard `*.google.com`, hostnameMatch=true            |
| expired.badssl.com      | `expired: true`, note "Leaf certificate is expired"             |
| wrong.host.badssl.com   | hostnameMatch=false, note about SAN mismatch                    |
| 1.1.1.1                 | rejected early: "requires a hostname (SNI)"                     |
| cloudflare.com          | `connect()` refused by CF: "Stream was cancelled."              |

## Known limitations
1. **TLS 1.3-only servers** are unreadable. We detect `protocol_version`
   alerts and report clearly. Doing TLS 1.3 properly would require full
   handshake crypto (ECDHE + HKDF + AEAD) — a much bigger lift.
2. **Servers that demand client auth** before sending `Certificate` won't
   work. Very rare on the public web.
3. **No ALPN/OCSP/SCT parsing yet**. The ServerHello `extensions` map is
   captured but not surfaced.
4. **IPv4 only in SANs from pkijs** is fine; IPv6 SANs are decoded too
   but not exhaustively tested.
5. **Per-colo isolation of rate limits** — same quirk as the rest of the API.

## Next steps (if we go further)
- ✅ Integrate into `/api/analyze` as `modules.livetls` — done. CT-vs-peer
  drift rules ship as findings (`ct-drift-peer-expired` high,
  `ct-peer-notafter-differs` info).
- Surface negotiated ALPN (parse `application_layer_protocol_negotiation` ext).
- Capture SCT list from the Certificate Transparency extension and correlate
  with our CT-log lookups.
- Add "cert chain validity" check: walk the chain and verify each cert's
  issuer matches the next cert's subject (structural only; no sig check).
- Try the TLS 1.3 path via a second socket that only offers 1.3 — capture
  ServerHello (version, cipher, group) even though Certificate is encrypted.
- **Investigate issuer gap on Cloudflare-fronted targets** via Browser
  Rendering. Candidate experiments: compare Security event DER vs a forced
  `Network.getCertificate` on a non-redirected origin; check if the gap is
  specific to CF's headless-Chrome TLS path or also affects other large
  CF-fronted sites.
