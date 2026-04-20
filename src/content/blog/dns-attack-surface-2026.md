---
title: "DNS is still the attack surface everyone forgets"
description: "Subdomain takeovers, dangling CNAMEs, NS hijacks, and DMARC spoofing are not exotic. They are this quarter's incident. Here is what to actually check."
pubDate: 2026-04-05
author: "Yossi Ben Hagai"
tags: ["security", "dns"]
---

Security reviews love to argue about WAF rules and JWT algorithms. Meanwhile the breach starts with a `CNAME` that has pointed at a decommissioned S3 bucket for 14 months.

DNS sits outside most organizations' threat models because it feels like plumbing. It is not plumbing. It is an unauthenticated, cacheable, globally replicated identity system that decides where your users' traffic goes.

## The four realistic threats

### 1. Subdomain takeover via dangling CNAMEs

Pattern: `marketing.example.com` `CNAME` to `example.azureedge.net`. Someone deleted the Azure endpoint last year. The `CNAME` was never cleaned up. An attacker registers that Azure endpoint name and now serves content from your subdomain - with your cookies, your DMARC alignment, and your users' trust.

Detection is cheap:

```
dig CNAME marketing.example.com +short
# then for each target:
dig A <target> +short        # NXDOMAIN or SERVFAIL is the red flag
```

A quarterly scan of your DNS zones against a list of takeover-prone SaaS providers is the single highest-ROI security hygiene task most orgs skip.

### 2. DMARC spoofing

If your domain has `MX` records but no DMARC policy (or `p=none`), attackers can send mail that aligns with SPF but is not yours. Password reset emails are the high-value target.

```
dig TXT _dmarc.example.com +short
```

No record, or `p=none` without a monitoring pipeline, is a gift to phishing campaigns. Moving to `p=quarantine` is a two-line change once you have validated your legitimate senders.

### 3. NS hijack

Rare, catastrophic. If an attacker compromises your registrar account or your DNS provider's control plane, they own everything downstream - email, TLS issuance via HTTP-01, the lot. Defenses:

- Registrar lock enabled.
- MFA on registrar and DNS provider, with hardware keys for privileged accounts.
- DNSSEC where your zone can support it. The AD bit on a DoH response is a cheap pulse check.
- CAA records pinning your CAs, so a hijacker cannot trivially issue a certificate.

```
dig CAA example.com +short
```

Empty output here is a finding, not a non-event.

### 4. IP/ASN drift

Your `A` record claims to be on your CDN. Six months ago someone flattened the apex to the raw origin IP "just for a test". Now the origin is directly reachable, the WAF is bypassed, and nobody noticed because the CDN still sits in front of `www`.

```
dig A example.com +short
# For each IP, check the ASN:
dig TXT 1.2.3.4.origin.asn.cymru.com +short
```

If the ASN is not your CDN's ASN, the "edge protection" you are paying for is not in the path.

## What you should run, on a schedule

Pick a cadence - quarterly minimum - and automate all four checks. Treat any drift as a security finding, not an ops ticket. The class of attacker who exploits these does not need zero-days; they need your cleanup to be late.

netlens runs these checks and correlates the signals into findings in one pass. It is not a substitute for an actual posture program. It is the first ten minutes of one.
