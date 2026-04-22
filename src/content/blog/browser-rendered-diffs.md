---
title: "What you see vs. what the browser does: adding real-render diffs"
description: "Raw fetches tell you what a server sent. A headless browser tells you what actually ran. Here is why netrecon's change-detection needed both — and the rate-limit trick that makes it work on a free tier."
pubDate: 2026-04-23
author: "Yossi Ben Hagai"
tags: ["sre", "performance", "browser", "netrecon"]
---

For six weeks netrecon's change-detection ran on raw fetches only: follow redirects, pull headers, parse HTML, probe a set of well-known paths. Fast, cheap, subrequest-budget-friendly. It catches a lot — CSP changes, cookie-attribute regressions, new third-party hosts in `<script>` tags.

And it missed entire classes of regression that matter.

## The things you can only see by actually rendering

Three examples I hit in the last week:

1. **A site shipped a bundle that threw an unhandled `ReferenceError` on load.** Raw fetch: clean 200, unchanged headers, unchanged HTML. Real render: console error count went from 0 to 3. If you only watch the response, the site looks healthy. If you watch the browser, it's visibly broken.

2. **A new analytics tag loaded a third-party host I'd never seen in the HTML.** It got injected client-side by Google Tag Manager after page load. The raw HTML had `<script src="https://www.googletagmanager.com/..">` which I was tracking. The *actual* fan-out — 7 more hostnames fetched at runtime — only showed up in the browser's network panel.

3. **LCP regressed from 1.4s to 3.1s.** No header change, no payload change, same number of scripts. A CSS media query was switching on a very large image below the fold. The only way to catch this was to render and observe the LCP entry.

You cannot approximate any of these with `curl`. They are genuinely new signal.

## The cost problem

The reason I didn't ship this on day one: headless Chromium is the most expensive thing in the Workers ecosystem. On the Workers free tier, Browser Rendering gives you **10 browser-minutes per day and 3 concurrent sessions**. A real render averages 4–6 seconds of wall time, so the daily cap is about 100–150 renders.

For a tool that captures snapshots on a cron every 6 hours across multiple targets, that math doesn't close. If every target got a browser snapshot every 6 hours, even 10 targets would eat the cap.

## The fix: make it opt-in and cool down aggressively

The browser render is:

- **Never run by cron.** The 6-hourly scheduled job captures the raw signals only. That keeps the scheduled path within the 50-subrequest-per-invocation cap and uses zero browser minutes.
- **Opt-in per request.** The user clicks a dedicated "take snapshot + browser render" button. The API route accepts `?browser=1`; absent, it doesn't touch Chromium.
- **Per-target 22-hour cooldown.** When a browser render fires, we write `browser-last:<targetId>` to KV with a 22h TTL. Subsequent browser-render requests within the window get a 429 with `retryAfter`. This caps any one target at ~1 render/day and leaves the 10-minute budget mostly untouched.
- **Fail-soft.** If the browser binding is missing (local dev, budget exhausted upstream), the render step returns an `ok: false` envelope with an `error` field. The rest of the snapshot still captures normally; diffs against prior renders just show the failure for that field.

The effect: the expensive signal is available where it's worth the cost (one click, diagnostic) and absent where it isn't (automated drift tracking).

## Shaping the output for diffs

Real-render output is inherently flaky. Two renders of the same site a minute apart will produce different console-error orderings, sometimes different third-party host timings, sometimes one fewer request because an ad didn't load.

To keep the diff useful rather than noisy I normalise hard:

- **Console errors** are truncated to 120 chars (error messages from minified code are usually just the first line; the long tail is stack frames we don't want in a diff), de-duped, sorted, and capped to 5 samples. We *also* keep the raw count, so you get signal on "went from 0 to 4" without churning on which 4.
- **Third-party hosts** are deduped and sorted alphabetically. The *set* is what matters; the order they loaded in is not.
- **Timing numbers** are rounded to integer ms. Nobody diffs on 121.7 vs 121.3.
- **Unhandled rejections** are captured separately from console errors (different root causes: one is caught-and-logged, the other is escaped).

The result is a payload where "this render looked like the previous one" is byte-identical JSON, not approximately-equal.

## What the diff actually looks like

From a real render of a demo target I broke on purpose:

```json
{
  "browser": {
    "consoleErrors": {
      "count": { "before": 0, "after": 3 },
      "samples": {
        "added": [
          "Uncaught ReferenceError: segment is not defined",
          "Failed to load resource: net::ERR_BLOCKED_BY_CLIENT",
          "[Violation] Forced reflow while executing JavaScript"
        ]
      }
    },
    "network": {
      "thirdPartyHosts": {
        "added": ["cdn.segment.io", "api.segment.io"]
      }
    },
    "timing": {
      "largestContentfulPaint": { "before": 1420, "after": 3180 }
    }
  }
}
```

Three things jump out immediately without reading code: someone wired up Segment, the analytics call is being blocked by (some) clients, and the LCP nearly tripled. That is the value: each field is already a sentence a human can act on.

## Why the AI narrator gets along with this

The [diff narrator I shipped last week](/blog/writing-a-diagnostic-llm-that-doesnt-lie) only sees the delta — not the before/after snapshots. Adding the browser signals didn't change the narrator at all; it just gave the LLM more citation paths to work with. A typical narration on the diff above now looks like:

> **Segment analytics was added to the site.** Three console errors appeared — the `segment is not defined` error suggests the script loaded but its global isn't available at the point it's being called. Also: `cdn.segment.io` and `api.segment.io` are new third-party hosts, and LCP regressed from 1.4s to 3.2s. The LCP regression may be directly caused by the analytics load; worth checking the render-blocking attribute.

Citations: `browser.consoleErrors.samples`, `browser.network.thirdPartyHosts`, `browser.timing.largestContentfulPaint`. All real paths in the diff object. No hallucinations, because the citation whitelist only accepts paths the diff actually contains.

## TL;DR

- Raw fetches miss client-side-only regressions — new runtime hosts, console errors, LCP drift.
- A headless browser catches all of them but is expensive on any free tier.
- Keep cron cheap (raw only). Gate the browser behind an explicit button and a per-target cooldown.
- Shape the output for diff stability: truncate, dedupe, sort, round.
- Feed it into the existing AI-narrator — no prompt changes needed, citations just get richer.

Try it on a target you own at [/watch](https://netrecon.pages.dev/watch) — there's a "take snapshot + browser render" button next to the normal one.
