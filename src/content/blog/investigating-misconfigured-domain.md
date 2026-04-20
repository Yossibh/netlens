---
title: "How to investigate a misconfigured domain"
description: "A short, opinionated playbook for the first 5 minutes of a 'the site is acting weird' incident."
pubDate: 2026-04-10
author: "Yossi Ben Hagai"
tags: ["sre", "dns", "http", "debugging"]
---

You get a message: *"our checkout page is 502-ing for some users."* Here is the order I work through the problem in, and how netlens compresses most of it into one request.

## 1. Normalize the input

Is the user reporting a domain, a URL, or a specific host? Ambiguity here wastes ten minutes. Treat the reporter's string as the canonical input and route from there.

## 2. DNS before anything

```
dig A   checkout.example.com +short
dig AAAA checkout.example.com +short
dig CNAME checkout.example.com +short
dig NS   checkout.example.com +short
dig CAA  checkout.example.com +short
```

What you're checking:
- **Does it resolve at all?** (Empty A/AAAA/CNAME → stop, this is a DNS problem.)
- **IPv6 parity.** If a subset of users is affected, IPv6 misconfiguration is a frequent cause.
- **Chain of CNAMEs.** A CNAME that points into a SaaS vendor who failed a deploy is common.
- **CAA.** Usually irrelevant during an incident, but missing CAA is a cheap win for the post-mortem.

## 3. Resolve the HTTP reality

```
curl -sSI -L https://checkout.example.com
curl -sS -o /dev/null -w "%{http_code} %{url_effective} (%{time_total}s)\n" -L https://checkout.example.com
```

You want three things: the **final URL**, the **redirect chain**, and the **server / CDN signal** headers (`cf-ray`, `x-amz-cf-id`, `server: cloudflare`, etc.).

If the final URL is not what you expected, stop. You have a routing or canonicalization bug, not a server bug.

## 4. Correlate DNS with the HTTP claim

This is the highest-signal step and the one most engineers skip. If the response headers claim Cloudflare but the A record is on your origin ASN (not AS13335), the CDN is not actually in the path - and you're debugging the wrong box.

```
# reversed-ip.origin.asn.cymru.com TXT
dig TXT 1.1.1.1.origin.asn.cymru.com +short
```

## 5. TLS, only if relevant

Only pull the cert if the browser is complaining or the failure correlates with a renewal window. Otherwise it's noise.

```
openssl s_client -connect checkout.example.com:443 -servername checkout.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -dates -issuer -subject -ext subjectAltName
```

## 6. Email posture - in the post-mortem, not during the incident

SPF/DMARC rarely cause "site down" incidents. But if the incident is *"customers stopped receiving password resets"*, it's the first place to look.

## What netlens does differently

All six steps above, in parallel, in under a second, with correlated findings instead of six tool outputs. That is the entire thesis.
