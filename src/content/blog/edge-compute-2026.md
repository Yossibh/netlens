---
title: "Where the edge actually lives in 2026"
description: "Cloudflare Workers, Fastly Compute, Vercel Edge, Deno Deploy, Lambda@Edge. They are not interchangeable. Here is what each one lets you measure, and what each one hides."
pubDate: 2026-03-10
author: "Yossi Ben Hagai"
tags: ["sre", "networking", "edge"]
---

Edge compute shipped, then atomized. Today "the edge" is five platforms with genuinely different runtime models. Picking between them is a network decision, an observability decision, and a cost decision - in that order, usually ignored in reverse.

## The five platforms, compared by what matters

| | Cloudflare Workers | Fastly Compute | Vercel Edge | Deno Deploy | Lambda@Edge |
| --- | --- | --- | --- | --- | --- |
| Runtime | V8 isolate | Wasm (Lucet) | V8 isolate | V8 isolate | Node container |
| Cold start | ~0ms | ~0ms | ~0ms | ~0ms | 100ms+ |
| PoPs (approx) | 300+ | 100+ | depends on CDN | 35+ | CloudFront (400+) |
| Raw TCP (`connect()`) | Limited | No | No | No | No |
| WebSockets | Yes | No | Limited | Yes | No |
| Durable state | Durable Objects, D1, KV | KV | KV (via vendor) | KV | None at edge |

None of these are interchangeable drop-ins. The runtime model drives everything else.

## What the edge lets you measure

All five platforms expose a per-request geolocation of the PoP (or client) that served the request. Cloudflare's `cf` object is the richest, with ASN, country, TLS version, and HTTP protocol all readily available. Fastly exposes similar via VCL/Compute bindings. Vercel Edge and Deno Deploy expose a more limited subset.

What this means in practice: from an edge function you can trivially answer "what is the distribution of requests by country, client HTTP version, and TLS version?" without standing up any telemetry infrastructure beyond a structured log.

## What the edge hides

### Outbound connection detail

Edge `fetch()` does the TLS handshake for you and returns a response object. You do not see the peer certificate chain, the negotiated cipher, or the OCSP staple. For a site that is itself behind the edge, this is fine. For a site that is doing **diagnostics** against third parties, it is a hard limit. netlens hits this limit; we document it in `limitations.md` and use Certificate Transparency logs as a proxy.

### Origin network path

When your edge function calls your origin, you do not control the path. The platform's private backbone is better than the public internet on average, but it is opaque. You cannot `traceroute` it. If you need to debug "edge talks to origin slowly from South America but fine from Europe", you are relying on platform-provided metrics, which vary wildly in quality.

### Failure modes you cannot reach from outside

Isolate CPU limits, Wasm memory limits, and request body size limits are all enforced at the runtime boundary. You will see a `1102` (Cloudflare) or similar only in the platform's dashboard, not in an edge log you control. Set up platform-side error streaming (Cloudflare Logpush, Fastly Real-Time Log Streaming) on day one or you will fly blind.

## Choosing

The honest heuristic:

- **Raw HTTP transformation / routing:** Cloudflare Workers or Fastly Compute. Both are excellent. Fastly's Wasm model gives you stronger isolation and more predictable performance; Workers is faster to develop against because of V8 and the adjacent stack (KV, D1, R2, Queues, Durable Objects).
- **Next.js front-end on the edge:** Vercel, because the integration depth is unmatched. Not for general-purpose compute.
- **TypeScript-first backend without build tooling:** Deno Deploy.
- **You are already all-in on AWS:** Lambda@Edge, unhappily. Expect cold starts and worse dev ergonomics.

## The meta-point

"The edge" is a network architecture choice, not a generic compute tier. Deploy code there because the problem is latency-sensitive, region-aware, or benefits from massive fan-out - not because a blog post said edge is the future. The runtime restrictions are real and they will bite you if you assumed it is "just Node, closer".

netlens runs on Cloudflare Workers for a specific reason: DNS-over-HTTPS, crt.sh, and target HTTP fetches are all HTTPS calls, which is exactly where the Workers model shines. If any of those needed a raw TCP socket, the deployment target would be different.
