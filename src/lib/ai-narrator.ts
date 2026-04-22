// Phase B — AI-narrated diff.
//
// Takes a DiffResult + the two snapshots and asks a language model to explain:
//   - what changed in plain English
//   - how severe it looks
//   - the most likely cause (deploy, CDN config, vendor-side change, takeover)
//   - what to check next
//
// Hard anti-hallucination constraints:
//   1. Output is bound to a JSON schema — no free-form prose.
//   2. Every "citation" the model emits must reference a real change.path in
//      the diff we gave it. We drop any citation that doesn't match.
//   3. If the diff has 0 changes, we short-circuit with a canned "no changes"
//      response — we don't burn neurons asking the model to describe nothing.
//   4. We cap the number of changes sent to the model (MAX_CHANGES_IN_PROMPT)
//      so huge diffs don't blow the context or the daily neuron budget.
//
// The model binding is Cloudflare Workers AI (`env.AI.run`). The default model
// is llama-3.3-70b-instruct-fp8-fast, chosen because:
//   - It supports JSON-schema-constrained output ("response_format").
//   - 70b handles multi-hop reasoning (link a CSP change to a script-src add).
//   - fp8-fast keeps per-call latency tolerable for an interactive UI.
//
// If the env exposes no AI binding (e.g. local vitest) we throw a clearly
// typed error so callers can surface a 503 instead of a cryptic crash.

import type { DiffResult, DiffChange } from './diff';

export const NARRATOR_VERSION = 1;
export const DEFAULT_MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';
export const MAX_CHANGES_IN_PROMPT = 40;
export const MAX_VALUE_CHARS = 500;

export type Severity = 'info' | 'notice' | 'warning' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';

export interface NarrationCitation {
  path: string;
  why: string;
}

export interface Narration {
  summary: string;
  severity: Severity;
  likely_causes: string[];
  suggested_checks: string[];
  confidence: Confidence;
  citations: NarrationCitation[];
  model: string;
  version: number;
}

export interface AiBinding {
  run(
    model: string,
    input: Record<string, unknown>,
  ): Promise<unknown>;
}

// JSON schema the model must emit. We keep it tight — every field required,
// enums for anything categorical, string length caps to prevent runaway prose.
export const NARRATION_SCHEMA = {
  type: 'object',
  required: [
    'summary',
    'severity',
    'likely_causes',
    'suggested_checks',
    'confidence',
    'citations',
  ],
  properties: {
    summary: { type: 'string', maxLength: 400 },
    severity: { type: 'string', enum: ['info', 'notice', 'warning', 'critical'] },
    likely_causes: {
      type: 'array',
      maxItems: 5,
      items: { type: 'string', maxLength: 200 },
    },
    suggested_checks: {
      type: 'array',
      maxItems: 5,
      items: { type: 'string', maxLength: 200 },
    },
    confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
    citations: {
      type: 'array',
      maxItems: 20,
      items: {
        type: 'object',
        required: ['path', 'why'],
        properties: {
          path: { type: 'string', maxLength: 200 },
          why: { type: 'string', maxLength: 200 },
        },
      },
    },
  },
} as const;

const SYSTEM_PROMPT = [
  'You are a senior SRE reviewing the diff between two snapshots of the same',
  'public endpoint taken at different times. Your job is to explain what',
  'changed, how alarming it is, and what the user should investigate next.',
  '',
  'Rules:',
  '- Only describe what the CHANGES list shows. Do not invent fields.',
  '- Every claim you make must be supported by a citation pointing at a',
  '  change.path from the list.',
  '- severity guidance:',
  '  critical = missing security header, CSP weakened, cookie lost Secure/',
  '             HttpOnly, mixed content, third-party takeover candidate.',
  '  warning  = CSP tightened wrong, preload removed, SRI coverage dropped,',
  '             new third-party host, redirect chain changed shape.',
  '  notice   = cache policy changed, server banner changed, sitemap shifted.',
  '  info     = cosmetic (title, OG tags, ordering) with no security impact.',
  '- confidence guidance:',
  '  low    = diff is ambiguous, could be transient.',
  '  medium = clear change but cause uncertain.',
  '  high   = change is self-explanatory (e.g., HSTS disabled).',
  '- Keep summary under 400 chars.',
  '- Output valid JSON matching the provided schema. No markdown, no prose.',
].join('\n');

function truncateValue(v: unknown): unknown {
  if (typeof v === 'string' && v.length > MAX_VALUE_CHARS) {
    return v.slice(0, MAX_VALUE_CHARS) + `…(+${v.length - MAX_VALUE_CHARS} chars)`;
  }
  if (Array.isArray(v) && v.length > 20) {
    return [...v.slice(0, 20), `…(+${v.length - 20} items)`];
  }
  return v;
}

// Build a compact, model-friendly representation of the diff. The snapshot
// shape is intentionally NOT sent — only the change list. The model reasons
// about "what changed", not the full snapshot, which keeps the context small
// and reduces the temptation to make up fields.
export function buildPrompt(
  targetInput: string,
  a: { id: string; capturedAt: string },
  b: { id: string; capturedAt: string },
  diff: DiffResult,
): { system: string; user: string; citableChanges: DiffChange[] } {
  const trimmed = diff.changes.slice(0, MAX_CHANGES_IN_PROMPT);
  const overflow = diff.changes.length - trimmed.length;

  const payload = {
    target: targetInput,
    a: { id: a.id, capturedAt: a.capturedAt },
    b: { id: b.id, capturedAt: b.capturedAt },
    total_changes: diff.changes.length,
    changes_in_prompt: trimmed.length,
    overflow_changes: overflow > 0 ? overflow : 0,
    changes: trimmed.map((c) => ({
      path: c.path,
      kind: c.kind,
      before: truncateValue(c.before),
      after: truncateValue(c.after),
    })),
  };

  const user = [
    'Snapshot A → Snapshot B diff for the target below.',
    'Explain the changes in the JSON format described by the schema.',
    '',
    '```json',
    JSON.stringify(payload, null, 2),
    '```',
    overflow > 0
      ? `\n(Note: ${overflow} additional changes were truncated for brevity.)`
      : '',
  ]
    .filter(Boolean)
    .join('\n');

  return { system: SYSTEM_PROMPT, user, citableChanges: trimmed };
}

function clampStr(v: unknown, max: number): string {
  if (typeof v !== 'string') return '';
  return v.length > max ? v.slice(0, max) : v;
}

function asArrayOfStrings(v: unknown, maxItems: number, maxLen: number): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const item of v) {
    if (typeof item !== 'string') continue;
    out.push(item.length > maxLen ? item.slice(0, maxLen) : item);
    if (out.length >= maxItems) break;
  }
  return out;
}

// Strict server-side validation. The schema binding on the Workers AI side
// should already enforce this, but we never trust the model's output without
// re-checking here. Any deviation is fixed by clamping, not rejected — a
// slightly clamped narration is more useful than a 500 error.
export function normalizeNarration(
  raw: unknown,
  citableChanges: DiffChange[],
  model: string,
): Narration {
  const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;

  const severityIn = typeof r.severity === 'string' ? r.severity.toLowerCase() : '';
  const severity: Severity = (['info', 'notice', 'warning', 'critical'] as const).includes(
    severityIn as Severity,
  )
    ? (severityIn as Severity)
    : 'info';

  const confidenceIn = typeof r.confidence === 'string' ? r.confidence.toLowerCase() : '';
  const confidence: Confidence = (['low', 'medium', 'high'] as const).includes(
    confidenceIn as Confidence,
  )
    ? (confidenceIn as Confidence)
    : 'low';

  // Drop any citation whose path is not literally in the diff we sent. This is
  // the main anti-hallucination lever — if the model invents a field name, the
  // citation vanishes, which lowers confidence in the rest.
  const validPaths = new Set(citableChanges.map((c) => c.path));
  const rawCitations = Array.isArray(r.citations) ? r.citations : [];
  const citations: NarrationCitation[] = [];
  for (const c of rawCitations) {
    if (!c || typeof c !== 'object') continue;
    const cc = c as Record<string, unknown>;
    const path = clampStr(cc.path, 200);
    const why = clampStr(cc.why, 200);
    if (!path || !why) continue;
    if (!validPaths.has(path)) continue;
    citations.push({ path, why });
    if (citations.length >= 20) break;
  }

  return {
    summary: clampStr(r.summary, 400) || 'No narrative returned.',
    severity,
    likely_causes: asArrayOfStrings(r.likely_causes, 5, 200),
    suggested_checks: asArrayOfStrings(r.suggested_checks, 5, 200),
    confidence,
    citations,
    model,
    version: NARRATOR_VERSION,
  };
}

export function emptyDiffNarration(model: string): Narration {
  return {
    summary: 'No externally-observable changes between these two snapshots.',
    severity: 'info',
    likely_causes: ['The target\'s public surface is unchanged in the signals netrecon tracks.'],
    suggested_checks: [
      'If you expected a change, take a fresh snapshot — the deploy may not have rolled out yet.',
      'Browser-rendered changes (DOM after JS) are not yet tracked; Phase D will cover them.',
    ],
    confidence: 'high',
    citations: [],
    model,
    version: NARRATOR_VERSION,
  };
}

export interface NarrateOptions {
  model?: string;
}

// Extract a JSON object from Workers AI's response shape. The Llama family
// returns `{ response: "..." }`; some models return `{ response: {...} }`
// already parsed. We handle both, and we also tolerate markdown-fenced JSON
// ("```json\n{...}\n```") in case the model slipped.
function extractJson(raw: unknown): unknown {
  if (raw && typeof raw === 'object' && 'response' in raw) {
    const resp = (raw as { response: unknown }).response;
    if (resp && typeof resp === 'object') return resp;
    if (typeof resp === 'string') return parseJsonLoose(resp);
  }
  if (typeof raw === 'string') return parseJsonLoose(raw);
  return raw;
}

function parseJsonLoose(s: string): unknown {
  const trimmed = s.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    // try to extract the first {...} block
    const start = trimmed.indexOf('{');
    const end = trimmed.lastIndexOf('}');
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(trimmed.slice(start, end + 1));
      } catch {
        /* fall through */
      }
    }
    return {};
  }
}

// Exported for tests.
export const _internals = { extractJson, parseJsonLoose, truncateValue };

export async function narrateDiff(
  ai: AiBinding,
  targetInput: string,
  a: { id: string; capturedAt: string },
  b: { id: string; capturedAt: string },
  diff: DiffResult,
  opts: NarrateOptions = {},
): Promise<Narration> {
  const model = opts.model || DEFAULT_MODEL;
  if (diff.equal || diff.changes.length === 0) {
    return emptyDiffNarration(model);
  }

  const { system, user, citableChanges } = buildPrompt(targetInput, a, b, diff);
  const raw = await ai.run(model, {
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
    response_format: {
      type: 'json_schema',
      json_schema: NARRATION_SCHEMA,
    },
    max_tokens: 800,
    temperature: 0.2,
  });

  const parsed = extractJson(raw);
  return normalizeNarration(parsed, citableChanges, model);
}
