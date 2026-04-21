import { describe, it, expect } from 'vitest';
import {
  detectKinds,
  decodeJwt,
  decodeBase64,
  decodeUrl,
  decodeHex,
  decodeJson,
  decodeUuid,
  decodeUlid,
  decodeTimestamp,
  decodeAuto,
} from '../src/lib/decoders';

// Sample JWT (alg=HS256) - payload {"sub":"1234567890","name":"John Doe","iat":1516239022}
const SAMPLE_JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

describe('detectKinds', () => {
  it('detects JWT', () => {
    expect(detectKinds(SAMPLE_JWT)).toContain('jwt');
  });

  it('detects base64', () => {
    expect(detectKinds('aGVsbG8gd29ybGQ=')).toContain('base64');
  });

  it('detects hex', () => {
    expect(detectKinds('deadbeefcafe')).toContain('hex');
  });

  it('detects JSON', () => {
    expect(detectKinds('{"a":1}')).toContain('json');
  });

  it('detects UUID', () => {
    expect(detectKinds('550e8400-e29b-41d4-a716-446655440000')).toContain('uuid');
  });

  it('detects ULID', () => {
    expect(detectKinds('01ARZ3NDEKTSV4RRFFQ69G5FAV')).toContain('ulid');
  });

  it('detects Unix timestamp', () => {
    expect(detectKinds('1700000000')).toContain('timestamp');
  });

  it('detects URL-encoded', () => {
    expect(detectKinds('hello%20world')).toContain('url');
  });

  it('empty input returns nothing', () => {
    expect(detectKinds('')).toEqual([]);
  });
});

describe('decodeJwt', () => {
  it('decodes header + payload', () => {
    const r = decodeJwt(SAMPLE_JWT);
    expect(r.ok).toBe(true);
    expect(r.details?.header).toMatchObject({ alg: 'HS256', typ: 'JWT' });
    expect(r.details?.payload).toMatchObject({ sub: '1234567890', name: 'John Doe' });
  });

  it('always emits a "not verified" note', () => {
    const r = decodeJwt(SAMPLE_JWT);
    expect(r.notes?.some((n) => /not verified/i.test(n))).toBe(true);
  });

  it('rejects malformed input', () => {
    expect(decodeJwt('not.a.jwt.token').ok).toBe(false);
    expect(decodeJwt('hello').ok).toBe(false);
  });
});

describe('decodeBase64', () => {
  it('decodes printable ASCII', () => {
    const r = decodeBase64('aGVsbG8gd29ybGQ=');
    expect(r.ok).toBe(true);
    expect(r.output).toBe('hello world');
  });

  it('tolerates missing padding', () => {
    expect(decodeBase64('aGVsbG8').ok).toBe(true);
  });

  it('accepts base64url alphabet when urlSafe=true', () => {
    const r = decodeBase64('aGVsbG8td29ybGQ', true);
    expect(r.ok).toBe(true);
  });
});

describe('decodeUrl', () => {
  it('decodes percent-encoding', () => {
    expect(decodeUrl('hello%20world').output).toBe('hello world');
  });
});

describe('decodeHex', () => {
  it('decodes printable text', () => {
    expect(decodeHex('68656c6c6f').output).toBe('hello');
  });

  it('rejects odd length', () => {
    expect(decodeHex('abc').ok).toBe(false);
  });
});

describe('decodeJson', () => {
  it('pretty-prints', () => {
    const r = decodeJson('{"a":1,"b":[2,3]}');
    expect(r.ok).toBe(true);
    expect(r.output).toContain('\n');
  });

  it('reports parse errors', () => {
    expect(decodeJson('{bad').ok).toBe(false);
  });
});

describe('decodeUuid', () => {
  it('decodes v4', () => {
    const r = decodeUuid('550e8400-e29b-41d4-a716-446655440000');
    expect(r.ok).toBe(true);
    expect(r.details?.version).toBe(4);
  });

  it('extracts timestamp from v1', () => {
    const r = decodeUuid('c232ab00-9414-11ec-b3c8-9e6bdeced846');
    expect(r.ok).toBe(true);
    expect(r.details?.version).toBe(1);
    expect(r.details?.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

describe('decodeUlid', () => {
  it('extracts timestamp', () => {
    const r = decodeUlid('01ARZ3NDEKTSV4RRFFQ69G5FAV');
    expect(r.ok).toBe(true);
    expect(r.details?.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

describe('decodeTimestamp', () => {
  it('decodes seconds', () => {
    expect(decodeTimestamp('1700000000').output).toBe(new Date(1700000000000).toISOString());
  });

  it('decodes milliseconds', () => {
    expect(decodeTimestamp('1700000000000').output).toBe(new Date(1700000000000).toISOString());
  });
});

describe('decodeAuto', () => {
  it('returns multiple successful interpretations', () => {
    // "deadbeefcafe" is valid hex AND valid base64
    const results = decodeAuto('deadbeefcafe');
    const kinds = results.map((r) => r.kind);
    expect(kinds).toContain('hex');
  });

  it('ignores unknown inputs', () => {
    expect(decodeAuto('').length).toBe(0);
  });
});
