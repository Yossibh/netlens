---
title: "Applied AI for infra teams: patterns that actually work"
description: "LLMs are good at narrow, read-only, well-evaluated tool calls. They are bad at long autonomous loops in production. Here is the shape of the systems that actually hold up."
pubDate: 2026-04-15
author: "Yossi Ben Hagai"
tags: ["ai", "sre"]
---

Most "AI for ops" demos collapse the moment they meet a real incident. The pattern that survives is boringly specific: **narrow, read-only tools; short horizons; evals you wrote before the agent existed.**

## What keeps failing

The failure modes are depressingly consistent:

- **Runaway loops.** Agent retries a flaky tool 40 times because "success" was defined as "no exception".
- **Hallucinated arguments.** Model passes `--force` or `--region=prod` because those tokens appeared in a similar documentation snippet.
- **Context drift.** At step 9 of a 12-step plan, the model has forgotten what step 1 decided.
- **Confident nonsense summaries.** The summary reads "healthy" because three out of five checks returned 200, even though the two failures were the ones that mattered.

None of these are fixed by a better prompt. They are structural.

## Patterns that hold up

### 1. Tools are narrow, typed, read-only by default

Every tool I ship for agent use has a Zod schema and a single verb. `inspect_http`. `resolve_dns`. `check_email_security`. Not `debug_website`. The model can chain them; it cannot invent them.

Write is a separate, auth-gated tier. Even then, the write tools should be idempotent and scoped: `acknowledge_alert(alert_id)` is fine; `run_runbook(any_runbook)` is not.

### 2. Evals before agents

If you cannot write 20 test cases with expected outputs before you build the agent, you do not have a problem definition - you have a vibe. Build the eval harness first. Every change to the prompt or the toolset runs it.

This sounds obvious. Almost nobody does it.

### 3. Short horizons, explicit plans

Long autonomous loops are where context rot lives. Force the agent to produce a plan in 3 to 7 steps, and re-plan after every step where the observation surprised it. An agent that replans is dramatically more robust than one that barrels through.

### 4. Cost-aware routing

Not every question needs your most expensive model. Classify the input; route trivial cases to a cheap model, escalate only on ambiguity. This is a 10x cost reduction in practice and people keep refusing to do it because it's "not elegant".

### 5. The summary is a separate call with its own contract

Never let the model both act *and* summarize in the same turn. Do the work with a tool-calling model. Summarize with a separate call whose prompt explicitly lists the failure modes to watch for ("if any check failed, say so plainly in the first sentence").

## Where netlens fits

The reason every netlens diagnostic module is a registered tool with a typed input schema is exactly this: when the MCP server ships, an agent can call `analyze`, `compare_targets`, or `check_email_security` directly. Each tool is read-only, each has an explicit contract, each returns machine-readable findings. The agent gets to reason over the *findings*, not over scraped HTML.

That is not a small choice. It is the difference between an agent that actually helps on call and one that generates plausible-sounding paragraphs while production burns.
