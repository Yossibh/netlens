---
title: "Writing a diagnostic LLM that doesn't lie"
description: "How netrecon keeps an LLM-narrated diff grounded: schema-bound outputs, no snapshots in the prompt, and citation whitelisting that silently drops hallucinated field names."
pubDate: 2026-04-22
author: "Yossi Ben Hagai"
tags: ["ai", "sre", "security", "netrecon"]
---

netrecon's "explain with AI" button takes the diff between two snapshots of a target and asks a model to narrate it: what changed, how alarming it looks, what to check next. The moment you ship a feature like that you inherit the entire LLM-hallucination problem.

This post is about the small set of techniques I used to keep it trustworthy — none of them new, all of them underrated when you put them together.

## The failure mode we're avoiding

A naive implementation is:

1. Fetch snapshot A and snapshot B from KV.
2. Shove both snapshots into the prompt.
3. Ask the model: "Explain the change."

This fails in three predictable ways:

- The model invents fields that don't exist ("I notice you changed your `x-frame-options` policy" — you didn't, it wasn't in either snapshot).
- The model describes the data you showed it rather than the *delta*, so every narration is bloated and most of it is irrelevant.
- The model's severity estimate is free-form prose; downstream code can't do anything with "seems mildly concerning".

Each of those is fixable independently. The combination produces a diagnostic surface that's actually useful.

## Technique 1 — only send the delta

The first rule is that the model never sees the snapshots. It sees the *diff*.

netrecon's diff engine emits a canonical change list:

```json
{
  "equal": false,
  "changes": [
    {
      "path": "headers.strict-transport-security",
      "kind": "removed",
      "before": "max-age=63072000",
      "after": null
    },
    {
      "path": "setCookie[session].secure",
      "kind": "changed",
      "before": true,
      "after": false
    }
  ]
}
```

That's the entire input to the model. No raw HTTP headers, no HTML, no redirect chain. If a field didn't change, the model doesn't know it exists — which means the model can't confidently narrate about it.

This single change does two things. It shrinks the prompt by an order of magnitude (and therefore the cost), and it collapses the hallucination surface to the set of paths actually in the diff.

## Technique 2 — schema-bound output

Workers AI (and every mainstream inference API) now supports structured output via JSON Schema. We bind the model to emit exactly this:

```ts
const NARRATION_SCHEMA = {
  type: 'object',
  required: ['summary', 'severity', 'likely_causes',
             'suggested_checks', 'confidence', 'citations'],
  properties: {
    summary:           { type: 'string', maxLength: 400 },
    severity:          { type: 'string', enum:
                         ['info','notice','warning','critical'] },
    likely_causes:     { type: 'array', maxItems: 5,
                         items: { type: 'string', maxLength: 200 } },
    suggested_checks:  { type: 'array', maxItems: 5,
                         items: { type: 'string', maxLength: 200 } },
    confidence:        { type: 'string', enum: ['low','medium','high'] },
    citations: {
      type: 'array', maxItems: 20,
      items: {
        type: 'object',
        required: ['path','why'],
        properties: {
          path: { type: 'string', maxLength: 200 },
          why:  { type: 'string', maxLength: 200 }
        }
      }
    }
  }
};
```

The enums are the important part. `severity` is not "is this bad?" in a freeform sentence — it's one of four values the UI knows how to render. That's what lets the product have a coloured severity pill and a sorted list of narrations instead of a wall of prose.

Schema binding is cheap and every production-grade inference API supports it in 2026. The only reason people skip it is that the toy version of their feature worked without it.

## Technique 3 — citation whitelisting

This is the lever that turns "mostly accurate" into "I actually trust this".

The schema requires every narration to include `citations`, where each citation has a `path` pointing at a change in the diff the model was shown. After the model returns, we validate *every citation's path against the diff we actually sent*:

```ts
const validPaths = new Set(citableChanges.map(c => c.path));
const citations = [];
for (const c of rawCitations) {
  if (!validPaths.has(c.path)) continue;   // silent drop
  citations.push({ path: c.path, why: c.why });
}
```

If the model emitted a citation pointing at `headers.invented-header` that wasn't in the diff, the citation disappears. We don't error; we just drop it. Over time, this means:

- Hallucinated claims end up without citations. Low-citation narrations look conspicuous in the UI.
- The model rapidly learns (within a single session; no retraining) that off-list claims don't help it — because we only surface cited findings in a way that matters.
- Reviewers can't be tricked by a plausible-sounding sentence if there's no link back to real evidence.

The system prompt is explicit about the contract:

> Every claim you make must be supported by a citation pointing at a `change.path` from the list.

That contract is enforced server-side. The model is told the rule, the schema enforces the shape, and we verify the content.

## Technique 4 — categorised severity, not free-form adjectives

The prompt doesn't ask for "a severity rating". It gives the model a rubric:

```
critical = missing security header, CSP weakened, cookie lost Secure/
           HttpOnly, mixed content, third-party takeover candidate.
warning  = CSP tightened wrong, preload removed, SRI coverage dropped,
           new third-party host, redirect chain changed shape.
notice   = cache policy changed, server banner changed, sitemap shifted.
info     = cosmetic (title, OG tags, ordering) with no security impact.
```

A rubric is cheap to add and almost eliminates the "what does warning mean here?" noise. It also makes the feature predictable: two consecutive runs against the same diff produce the same severity more than 95% of the time. (Temperature 0.2 helps, but the rubric is doing most of the work.)

## What it looks like in practice

When netrecon narrated a diff of `github.com`'s security.txt hash change, the model came back with:

```json
{
  "summary": "Security.txt hash changed",
  "severity": "notice",
  "likely_causes": [
    "Update to security contact information",
    "Change in security policy"
  ],
  "suggested_checks": [
    "Verify security contact information",
    "Review security policy updates"
  ],
  "confidence": "high",
  "citations": [
    {
      "path": "wellKnown.securityTxt.hash",
      "why": "Hash value changed from … to …"
    }
  ]
}
```

Severity is `notice` (correct — a content change, not a security regression). The single citation points at a real path in the diff. There's no hallucinated field. If the model had invented a sentence about HSTS, the citation whitelist would have silently dropped it and the UI would surface the narration with fewer backing claims, which is itself a signal to a human reviewer.

## The cost of all this

Writing this layer is maybe 200 lines of TypeScript. A handful of unit tests cover the citation whitelist, the enum fallback, the prompt-size truncation and the empty-diff short-circuit. The model call itself is on the Workers AI free tier — small llama with JSON mode, temperature 0.2, max_tokens 800, ~1–2 seconds of wall clock per diff.

What you buy for that cost is a diagnostic feature that doesn't embarrass you when a principal engineer kicks the tires. That's the whole game for applied AI in operations tooling in 2026: ship a feature that doesn't melt under a skeptic.

## Why this matters beyond netrecon

Every "applied AI" feature in ops tooling has the same failure profile. A local coding agent can wire up an LLM call in ten minutes, and that's precisely why the version that ships to production should be the version with schema binding, citation whitelisting, rubrics, and delta-only inputs. The moat isn't "we called an LLM"; the moat is "we called it with enough scaffolding that you can stake a page on it".

If you want to play with the thing, it's live at [netrecon.pages.dev/watch](https://netrecon.pages.dev/watch). Add a target, take two snapshots a few minutes apart, and click **explain with AI**.
