# Limitations

netrecon is hosted on Cloudflare Workers / Pages Functions. That runtime is a superb fit for HTTPS-based diagnostics at the edge, but it intentionally does not expose several primitives that engineers might expect from a traditional netdiag box.

## Not available in the MVP

### `ping` / ICMP
Workers cannot open ICMP sockets. There is no workaround in the runtime. A hosted ping would require a separate control-plane (e.g. a tiny VM pool) which is out of scope for a free-tier MVP.

### `traceroute`
Same reason as `ping` - raw socket access is not available.

### Arbitrary TCP/UDP port scans
Workers `fetch()` is limited to HTTPS (and a small allowlist of schemes). There is no generic `net.Socket` API. The Cloudflare `connect()` Sockets API is available but restricted to outbound TCP on a limited set of ports; we have chosen not to wire it up in the MVP to keep the tool aligned with its explicit "HTTP-layer diagnostics" scope.

### Live TLS peer handshake
The Workers `fetch()` implementation does the TLS handshake for us and does **not** expose peer certificate details to the calling code. This means we cannot reliably return:
- the actual certificate chain as presented by the origin,
- the negotiated TLS version and cipher,
- the OCSP staple.

**What we do instead:** `src/lib/providers/tls.ts` queries [crt.sh](https://crt.sh) Certificate Transparency logs for the most recent leaf certificate issued for the domain, and reports issuer / validity / SANs from that record. This is *different* from a live peer handshake - it captures what CAs have logged, not what the origin is currently serving - and the UI labels it accordingly. A `// TODO` in that file marks the place to swap in a live probe when Phase 4 adds one.

### `whois` (registrar-level)
Classic `whois` uses TCP/43. Workers cannot reach it. RDAP (`https://rdap.org/domain/<d>`) is usable over HTTPS and may be added in a future phase, but it is not included in the MVP to avoid rate-limit surprises.

## Available but deliberately scoped

- **ASN lookups** use Team Cymru's DNS-based whois (`origin.asn.cymru.com`) via DoH. This works for IPv4 today; IPv6 ASN lookup via `origin6.asn.cymru.com` uses a different name format and is not wired up.
- **DKIM selector probe** cannot enumerate unknown selectors - by design, there is no way to "list" selectors for a domain. We probe a short built-in list (`default`, `google`, `selector1`, `selector2`, `k1`, `mail`). The user can pass custom selectors via the tool API.

## Why we disclose this

Every diagnostic tool has limits. Most sites pretend they don't. If a tool silently returns "no certificate found" when it just can't see one, the engineer will waste minutes (or hours) chasing a ghost. netrecon is built to tell the truth about what it does and doesn't know.
