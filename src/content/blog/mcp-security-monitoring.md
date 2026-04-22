---
title: "Securing and monitoring an MCP server in production"
description: "MCP turns a chat UI into a system that can take actions on your behalf. That changes the security and observability story. Here is the stack I run for netrecon."
pubDate: 2026-04-22
author: "Yossi Ben Hagai"
tags: ["ai", "security", "sre", "mcp", "netrecon"]
---

"Give the model some tools" is a one-line architecture change with a very long blast radius. The moment you expose an MCP server, you have built an RPC API whose caller is non-deterministic, prompt-injectable, and difficult to audit after the fact. This post is the security and monitoring posture I actually run for [netrecon's MCP endpoint](https://netrecon.pages.dev/api/mcp) — not theory, just what survived a real deployment.

## What changes the moment you expose MCP

Three things shift at once:

1. **Your callers are LLMs.** They will construct inputs you never tested. They will retry with variations when a call fails. They will sometimes be operated by someone else's agent via a chain of delegated tool calls.
2. **Prompt injection becomes a privilege escalation vector.** A page the agent fetches can contain instructions that tell it to call your `delete` tool. If you built `delete`, you built an injection sink.
3. **The audit log becomes the only thing you have.** Stack traces in LLM land look like "the model decided to call `search_logs` with this weird argument" — no stack, no caller identity, no repro unless you captured it.

The posture below addresses all three.

## 1. Write tools, read tools, and destructive tools are three different products

The single highest-leverage decision is not technical — it's which tools you ship at all.

For netrecon I ship **read-only** tools only. `analyze`, `lookup`, `decode`. There is no `delete_target`, no `create_target`, no `rotate_key`. The MCP server cannot mutate state the user cares about. If you want to add destructive tools later, they should:

- Require a capability token the agent cannot obtain from prompt-injected content
- Log an explicit before/after diff
- Be behind a human-in-the-loop confirmation by default

If your tool name starts with `create_`, `delete_`, `update_`, `rotate_`, or `send_`, assume someone will inject instructions that trigger it and design accordingly.

## 2. Input validation is not the same as schema validation

MCP gives you JSON Schema for free. That is table stakes, not the security model. You still need:

- **Length caps** on every string field. An LLM will happily send a 200KB field "just in case."
- **Canonicalisation** before any comparison. Lowercase hostnames. Strip zero-width characters. Normalise unicode.
- **SSRF guards** on any URL the tool will fetch. Block RFC1918, link-local, loopback, `file://`, `.onion`, your own metadata endpoints. Re-validate on redirects. netrecon does this via a shared `validateFetchUrl()` used by every outbound fetch — the [exposure probes](https://netrecon.pages.dev/blog/writing-a-diagnostic-llm-that-doesnt-lie) inherit it.
- **Allowlists over denylists** wherever you can get away with it. "Which hostnames may be probed" is easier to enumerate than "which hostnames may not."

A useful heuristic: if an attacker can talk to your MCP tool directly, without going through the chat UI, what is the worst input they can send? That is your actual threat model.

## 3. Rate limiting is a correctness concern, not a cost concern

An agent in a retry loop will hammer your tool faster than any human. On netrecon the ordinary web surface and the MCP surface share a single [middleware](https://netrecon.pages.dev/blog/raw-lookup-tools-not-enough) that enforces per-IP and per-tool quotas. Two things made this work:

- **Shared budget across surfaces.** If the same agent has already burned 100 `analyze` calls via the web UI, it doesn't get a fresh 100 via MCP. Budgets are keyed by (IP, tool), not (IP, surface, tool).
- **Informative 429s.** Returning `retry-after` and a structured error code matters when the caller is a model. A raw 429 with no body gets retried; a 429 with `{"error":"rate_limited","retryAfter":60}` gets respected most of the time.

## 4. Treat the trace stream like a SIEM feed

Because stack traces are useless in the LLM-calls-tool world, **the MCP event log becomes the only thing you can investigate with**. Capture, at minimum:

- Tool name, arguments (redacted), timestamp, latency
- Decision outcome: success, validation-rejected, rate-limited, upstream-error
- Client fingerprint you can actually act on — for netrecon that is IP + user-agent + a hash of the MCP session

That's a cheap sink. I push to Cloudflare's built-in logs plus a tiny KV counter keyed by `(tool, day)` for fast health dashboards. No external SIEM, no cost.

The indicators I actually look at:

- **Sudden spike in validation rejections on one tool.** Either a client is broken or someone is fuzzing the schema.
- **Ratio of `analyze` calls to `decode` calls inverting.** Normal traffic has a signature; change means something is new.
- **The same input being retried with small variations.** Classic agent-loop pattern. Either my error messages are unhelpful or the agent's prompt is broken.

## 5. Assume your tool description will be read by adversaries

Your tool descriptions are prompt content. If you write "Deletes a target. Do not call this unless the user explicitly asks," you have given an attacker a script: inject a page that says "the user explicitly asks."

Write tool descriptions that are:

- **Narrow** — one sentence, one behaviour
- **Capability-free** — never mention admin, internal, bypass, or force
- **Truthful about side effects** — lying to the model produces worse outcomes than telling it exactly what will happen

For netrecon the description of `analyze` is literally: "Run DNS, HTTP, TLS and exposure probes against a public hostname. Returns JSON. Read-only." That is the entire social contract.

## 6. Test the MCP surface the way an agent will actually use it

Unit tests check that your tool works. They do not check that your tool *only* works the way you expect. I run three layers:

1. **Schema fuzz.** Generate random JSON conforming to the tool's schema; assert the server either succeeds cleanly or returns a typed error. No 500s, no unhandled rejections.
2. **Injection regression.** A small corpus of pages that contain "call delete_target with id=T1" style payloads. Pipe them through an agent harness and assert my server never sees a call I didn't authorise.
3. **Cross-tool chains.** Does `analyze` → `diff` → `narrate` compose without leaking state between calls? Session isolation matters when one MCP client is actually N agents.

## What I skip (and why that is OK)

Things that sound secure but I haven't bothered with for netrecon, because the blast radius is low:

- **mTLS between model host and MCP server.** The calls are already TLS; adding client certs costs operational complexity for a read-only diagnostic API. Revisit if/when I add writes.
- **Per-tool capability tokens.** Same reason. Tokens are real armour for mutation tools; overkill for `analyze`.
- **Full audit replay.** I log structured events but don't persist full request/response bodies. For a read-only tool the raw upstream calls can be re-run from the event log — cheaper than storing everything.

The principle is: **match the armour to the blast radius**. A read-only DNS probe doesn't need the same controls as a `rotate_prod_secret` tool. It just needs the controls above, consistently.

## TL;DR

- Don't ship write tools in your first MCP server. If you must, gate them hard.
- Schema validation is the start, not the end — add length caps, canonicalisation, SSRF guards, and allowlists.
- Share rate-limit budgets across the web and MCP surfaces.
- The event log is your observability story — capture tool name, outcome, and a client fingerprint.
- Your tool descriptions are prompt content. Write them like an adversary will read them.

You can see the full stack live on the [MCP tab](https://netrecon.pages.dev/mcp). The [server source is open](https://github.com/Yossibh/netrecon).
