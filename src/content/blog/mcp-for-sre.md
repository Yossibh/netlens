---
title: "MCP for SRE: giving agents real tools, safely"
description: "Model Context Protocol is the right primitive for on-call agents. It is also a footgun if you expose write tools without thinking. Here is a safer default."
pubDate: 2026-03-20
author: "Yossi Ben Hagai"
tags: ["ai", "sre", "security"]
---

An agent without tools is a chatbot. A chatbot reading your runbooks is not an SRE. The only version of "AI on call" that works is one where the agent can actually query the systems it is reasoning about. MCP (Model Context Protocol) is the cleanest primitive for that today.

It is also extremely easy to deploy badly.

## The minimum safe default

Three rules, in order:

1. **Every tool is read-only unless explicitly justified.**
2. **Every tool has a typed input schema.**
3. **Write tools require idempotency, scoping, and an audit trail.**

That is not "best practice hand-waving". Those three rules cut the realistic failure modes by roughly an order of magnitude, and they cost you almost nothing.

## What the tools should look like

Narrow verbs. Typed. Observable.

Good:
- `resolve_dns(domain)`
- `inspect_http(url)`
- `check_email_security(domain)`
- `fetch_recent_errors(service, window)` (read)
- `acknowledge_alert(alert_id)` (write, but scoped and idempotent)

Bad:
- `debug_website(anything)`
- `run_arbitrary_command(cmd)`
- `fix_the_problem()`

The big verbs feel tempting because they map to how humans describe the work. They are a trap. The model will chain them incorrectly, and because they are high-level, every mistake is high-impact.

## Idempotency is the load-bearing property

The worst agent outages I have heard about all share a shape: the agent did something, did not see the effect it expected within N seconds, and did it again. Five times. In parallel.

If the action is idempotent (`acknowledge_alert(42)` is a no-op the second time), that's a hiccup. If it is not (`scale_up_service("api", +5)` called six times is +30), that's an incident.

Either design your write tools to be idempotent, or wrap them in a server-side de-dup layer keyed by `(tool, args_hash, caller_session)`. There is no third option.

## Scoping

The scope of a tool is not "the tool's permission"; it is the smallest unit the tool can affect. `deploy(environment)` where `environment in {staging, prod}` is poorly scoped - one flag flip causes a prod deploy. `deploy_staging()` and `deploy_prod()` as separate tools, each with their own auth, is a better split because the auth surface maps to the blast radius.

Same principle for netrecon: every diagnostic is scoped to a single target. There is no `scan_the_internet()`.

## Observability

Every MCP call should produce a structured log line with the tool name, inputs, caller identity, duration, and outcome. If you cannot answer "what did the agent do in the last hour?" in one Kusto/Grafana/whatever query, your MCP deployment is not yet production-ready.

## Where this is heading

The next year is going to be full of "we gave the agent access to our prod APIs" postmortems. The teams that avoid them are the ones treating MCP tools with the same discipline they already apply to cross-service RPCs: schemas, idempotency, scoping, auditing, rate limits.

netrecon's Phase 2 (an MCP server mirroring the tool registry) is written with exactly these constraints. Every tool is a pure, read-only function over public data. That is the only reason it can be exposed to agents at all.
