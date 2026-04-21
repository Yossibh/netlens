---
title: "Why raw lookup tools are not enough for SRE workflows"
description: "Commodity DNS/IP lookup sites optimize for the wrong problem. Here is what engineers actually need from a diagnostics tool."
pubDate: 2026-04-18
author: "Yossi Ben Hagai"
tags: ["sre", "tooling", "diagnostics"]
---

Open any "DNS lookup" site. You paste a domain. You get a table of A records. You get another table of MX records. You get an ad. You close the tab.

This is useless for on-call work. It solves the *display* problem and ignores the *interpretation* problem.

## What real SRE diagnostic work looks like

A production incident is never "what is the A record of example.com?" It's always a correlated question:

- *Why does this domain behave differently from its sibling?*
- *Why is latency high from one region but not another?*
- *Is the CDN actually in the path, or just claimed in headers?*
- *Why are some emails landing in spam after last week's DNS change?*

None of these questions are answerable by a tool that prints a list of records. Answering them requires combining signals across DNS, HTTP, TLS, routing, and email posture - and then explaining what the combination means.

## The correlation gap

Consider two real situations:

1. `server: cloudflare` + `cf-ray` header present, but A record on AWS ASN.
2. SPF passes, DKIM passes, but DMARC is at `p=none`.

Situation 1 is almost certainly an exposed origin. Situation 2 is almost certainly a spoofing risk. A raw lookup tool prints the inputs and stops. An engineer has to recognize the pattern. That cognitive step is where tools should be helping - not where they should be handing off.

## What a useful tool looks like

- **It names the finding.** "Origin may be directly reachable" beats "here's a header dump".
- **It cites evidence.** Every claim links to the exact record or header that justifies it.
- **It gives you next steps.** Severity is useless without a suggested action.
- **It gives you commands.** Because the tool will be wrong sometimes, and you need to reproduce its work without re-typing.
- **It returns JSON.** Because in six months you'll want an agent or a CI job to consume the same report.
- **It is honest about limits.** TLS live peer inspection is not possible from a Workers edge - say so, don't fake it.

netrecon is an attempt to be that tool. It's deliberately not another commodity lookup site. If you want one of those, there are fifty. If you want correlated diagnostics you can pipe into your agent, start here.
