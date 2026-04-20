---
title: "SLOs that survive contact with reality"
description: "Most SLO dashboards lie because they measure the wrong thing. The fix is cheaper than you think, and it is not another vendor."
pubDate: 2026-03-28
author: "Yossi Ben Hagai"
tags: ["sre"]
---

I have never seen an org whose SLO dashboard accurately reflected user experience in its first year. The dashboards lie for predictable reasons, and the fixes are boring and structural.

## Why the dashboard lies

### It aggregates too aggressively

"99.95% availability this month" hides a six-hour outage that only hit one region. Averaging globally is almost always a mistake. Report per-region, per-user-segment, per-tier. If the payments tier is 99.2% and marketing is 99.99%, one number for both is worse than no number.

### It measures the wrong endpoint

The health check returns 200 because the process is up. The cart endpoint returns 500 because the Redis it depends on is down. The dashboard is green. The users are gone.

SLIs should be defined on user-critical paths. "Can a returning user sign in and add an item to cart in under 2 seconds?" is an SLI. "Is `/health` returning 200?" is not.

### Synthetic blinds you to the middle of the distribution

Synthetic probes tell you the best-case path works. They tell you nothing about the 8% of users on a mobile network in a region your CDN serves from a distant PoP. Real user metrics (RUM) complement synthetic; they do not replace it.

### The error budget is not connected to the on-call calendar

If burning the budget does not change anyone's behavior, it is decoration. An error budget without a freeze-on-burn rule, or a retro gate, or *something* that creates a cost to burning it, is just a graph. The point of the budget is to be a constraint.

## What actually works

### 1. Define SLIs per user journey, not per service

Each critical journey (sign-in, purchase, search) gets 2 to 4 SLIs: latency, availability, correctness. Ownership is *the journey*, across services. Any team that touches the journey shares the number.

### 2. Burn rate alerts, not threshold alerts

Alert when the budget is burning faster than sustainable, not when a threshold is crossed. Multi-window, multi-burn-rate alerts (a common pattern now) are strictly better than "if error rate > 1% for 5 minutes" because they combine fast incidents and slow decay into one policy.

### 3. Make the budget cost something

When the month's budget is half gone, non-trivial releases pause. When it is fully gone, only security-critical releases go out. Either the org will scream and you will learn which SLOs were wrong, or it will adjust and you will ship less breakage. Both outcomes are good.

### 4. Review SLOs quarterly with the same rigor as financial numbers

SLIs decay. A journey that was critical a year ago may be legacy. A new journey may be invisible in your telemetry. If you do not review, your dashboard drifts from reality linearly.

## The non-glamorous conclusion

SLOs are an operational discipline, not a tooling purchase. Most orgs I have worked with do not need a new observability vendor. They need to accept that their current dashboard is aspirational, and spend two focused weeks defining three journeys, two SLIs each, with burn-rate alerts and a freeze rule.

That is the whole playbook. The rest is execution.
