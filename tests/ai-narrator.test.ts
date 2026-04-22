import { describe, it, expect, vi } from 'vitest';
import {
  buildPrompt,
  normalizeNarration,
  emptyDiffNarration,
  narrateDiff,
  NARRATOR_VERSION,
  DEFAULT_MODEL,
  _internals,
  type AiBinding,
} from '../src/lib/ai-narrator';
import type { DiffResult, DiffChange } from '../src/lib/diff';

const a = { id: 's_1', capturedAt: '2026-01-01T00:00:00Z' };
const b = { id: 's_2', capturedAt: '2026-01-02T00:00:00Z' };

const sampleDiff: DiffResult = {
  equal: false,
  changes: [
    { path: 'headers.strict-transport-security', kind: 'removed', before: 'max-age=63072000', after: undefined },
    { path: 'setCookie[session].secure', kind: 'changed', before: true, after: false },
  ],
};

describe('buildPrompt', () => {
  it('only sends the change list (not full snapshots) to the model', () => {
    const { user } = buildPrompt('https://example.com/', a, b, sampleDiff);
    expect(user).toContain('strict-transport-security');
    expect(user).toContain('setCookie[session].secure');
    expect(user).toContain('"total_changes": 2');
  });

  it('truncates oversized change lists and reports overflow', () => {
    const many: DiffChange[] = Array.from({ length: 60 }, (_, i) => ({
      path: `h.${i}`, kind: 'added', before: undefined, after: String(i),
    }));
    const diff: DiffResult = { equal: false, changes: many };
    const { user, citableChanges } = buildPrompt('https://x/', a, b, diff);
    expect(citableChanges.length).toBe(40);
    expect(user).toContain('"overflow_changes": 20');
  });

  it('truncates large string values to keep context small', () => {
    const huge = 'x'.repeat(2000);
    const diff: DiffResult = {
      equal: false,
      changes: [{ path: 'body', kind: 'changed', before: 'small', after: huge }],
    };
    const { user } = buildPrompt('https://x/', a, b, diff);
    expect(user.length).toBeLessThan(3000);
    expect(user).toContain('…(+1500 chars)');
  });
});

describe('normalizeNarration', () => {
  const citable: DiffChange[] = sampleDiff.changes;

  it('coerces a valid model response unchanged', () => {
    const n = normalizeNarration(
      {
        summary: 'HSTS dropped; session cookie lost Secure.',
        severity: 'critical',
        likely_causes: ['Reverse proxy misconfig'],
        suggested_checks: ['curl -I to verify headers'],
        confidence: 'high',
        citations: [
          { path: 'headers.strict-transport-security', why: 'HSTS removed' },
          { path: 'setCookie[session].secure', why: 'Secure flag flipped off' },
        ],
      },
      citable,
      'test-model',
    );
    expect(n.severity).toBe('critical');
    expect(n.citations).toHaveLength(2);
    expect(n.model).toBe('test-model');
    expect(n.version).toBe(NARRATOR_VERSION);
  });

  it('drops citations pointing at paths not in the diff (hallucination guard)', () => {
    const n = normalizeNarration(
      {
        summary: 'ok',
        severity: 'info',
        likely_causes: [],
        suggested_checks: [],
        confidence: 'low',
        citations: [
          { path: 'headers.strict-transport-security', why: 'real' },
          { path: 'headers.invented-header', why: 'hallucinated' },
          { path: 'tls.fakeField', why: 'also fake' },
        ],
      },
      citable,
      'm',
    );
    expect(n.citations).toHaveLength(1);
    expect(n.citations[0].path).toBe('headers.strict-transport-security');
  });

  it('falls back to safe defaults for bad severity/confidence', () => {
    const n = normalizeNarration(
      { summary: 'x', severity: 'APOCALYPSE', confidence: 'YES' },
      citable,
      'm',
    );
    expect(n.severity).toBe('info');
    expect(n.confidence).toBe('low');
  });

  it('clamps overly long summary/list items', () => {
    const n = normalizeNarration(
      {
        summary: 'a'.repeat(1000),
        severity: 'info',
        likely_causes: ['b'.repeat(500)],
        suggested_checks: [],
        confidence: 'high',
        citations: [],
      },
      citable,
      'm',
    );
    expect(n.summary.length).toBe(400);
    expect(n.likely_causes[0].length).toBe(200);
  });

  it('enforces max array sizes', () => {
    const many = Array.from({ length: 50 }, (_, i) => `cause ${i}`);
    const n = normalizeNarration(
      { summary: 's', severity: 'info', likely_causes: many, suggested_checks: [], confidence: 'low', citations: [] },
      citable,
      'm',
    );
    expect(n.likely_causes.length).toBe(5);
  });

  it('handles garbage input without throwing', () => {
    const n = normalizeNarration(null, citable, 'm');
    expect(n.summary).toBe('No narrative returned.');
    expect(n.severity).toBe('info');
    expect(n.confidence).toBe('low');
  });
});

describe('extractJson', () => {
  it('parses Workers AI "response: object" shape', () => {
    expect(_internals.extractJson({ response: { summary: 'hi' } })).toEqual({ summary: 'hi' });
  });
  it('parses Workers AI "response: string" shape', () => {
    expect(_internals.extractJson({ response: '{"summary":"hi"}' })).toEqual({ summary: 'hi' });
  });
  it('extracts JSON from markdown-fenced output', () => {
    const s = 'Here is the response:\n```json\n{"summary":"hi"}\n```';
    expect(_internals.parseJsonLoose(s)).toEqual({ summary: 'hi' });
  });
  it('returns {} for totally unparseable input', () => {
    expect(_internals.parseJsonLoose('not json at all')).toEqual({});
  });
});

describe('narrateDiff', () => {
  it('short-circuits on empty diff without calling the model', async () => {
    const ai: AiBinding = { run: vi.fn() };
    const n = await narrateDiff(ai, 'https://x/', a, b, { equal: true, changes: [] });
    expect(ai.run).not.toHaveBeenCalled();
    expect(n.severity).toBe('info');
    expect(n.summary).toMatch(/no.*changes/i);
  });

  it('calls the model with the default model and a bound JSON schema', async () => {
    const ai: AiBinding = {
      run: vi.fn().mockResolvedValue({
        response: {
          summary: 'HSTS removed',
          severity: 'critical',
          likely_causes: ['deploy regression'],
          suggested_checks: ['check origin config'],
          confidence: 'high',
          citations: [{ path: 'headers.strict-transport-security', why: 'gone' }],
        },
      }),
    };
    const n = await narrateDiff(ai, 'https://x/', a, b, sampleDiff);
    expect(ai.run).toHaveBeenCalledOnce();
    const [model, input] = (ai.run as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(model).toBe(DEFAULT_MODEL);
    expect((input as { response_format: { type: string } }).response_format.type).toBe('json_schema');
    expect(n.severity).toBe('critical');
    expect(n.citations[0].path).toBe('headers.strict-transport-security');
  });

  it('honors a custom model override', async () => {
    const ai: AiBinding = { run: vi.fn().mockResolvedValue({ response: {} }) };
    await narrateDiff(ai, 'https://x/', a, b, sampleDiff, { model: '@cf/other' });
    expect((ai.run as ReturnType<typeof vi.fn>).mock.calls[0][0]).toBe('@cf/other');
  });

  it('emptyDiffNarration uses the passed model', () => {
    expect(emptyDiffNarration('m').model).toBe('m');
  });
});
