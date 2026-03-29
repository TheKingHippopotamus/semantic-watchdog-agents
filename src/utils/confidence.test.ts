// ============================================================
// CodeSentinel — Unit Tests: Confidence Utilities
// ============================================================

import { describe, it, expect } from 'vitest';
import {
  filterByConfidence,
  sortFindings,
  deduplicateFindings,
  summarizeFindings,
  generateFindingId,
} from './confidence.js';
import type { Finding } from '../types.js';

// ---------------------------------------------------------------------------
// Test helper
// ---------------------------------------------------------------------------

let _idCounter = 0;

/**
 * Create a minimal valid Finding.  All required fields are provided;
 * optional fields can be overridden via the partial override argument.
 */
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  _idCounter += 1;
  return {
    id: `test-finding-${_idCounter}`,
    layer: 'static',
    type: 'dead-code',
    severity: 'warning',
    confidence: 0.80,
    file: 'src/utils/example.ts',
    line: 10,
    message: 'Unused export detected.',
    tool: 'ts-prune',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// filterByConfidence
// ---------------------------------------------------------------------------

describe('filterByConfidence', () => {
  it('splits findings correctly when threshold is 0.90', () => {
    const findings = [
      makeFinding({ confidence: 0.95 }),
      makeFinding({ confidence: 0.85 }),
      makeFinding({ confidence: 0.70 }),
    ];

    const { passed, suppressed } = filterByConfidence(findings, 0.90);

    expect(passed).toHaveLength(1);
    expect(suppressed).toHaveLength(2);
    expect(passed[0].confidence).toBe(0.95);
  });

  it('treats a finding exactly at the threshold as passed', () => {
    const findings = [makeFinding({ confidence: 0.90 })];

    const { passed, suppressed } = filterByConfidence(findings, 0.90);

    expect(passed).toHaveLength(1);
    expect(suppressed).toHaveLength(0);
  });

  it('returns both arrays empty for an empty input', () => {
    const { passed, suppressed } = filterByConfidence([], 0.80);

    expect(passed).toHaveLength(0);
    expect(suppressed).toHaveLength(0);
  });

  it('returns suppressed empty when all findings are above the threshold', () => {
    const findings = [
      makeFinding({ confidence: 0.91 }),
      makeFinding({ confidence: 0.95 }),
      makeFinding({ confidence: 1.0 }),
    ];

    const { passed, suppressed } = filterByConfidence(findings, 0.90);

    expect(passed).toHaveLength(3);
    expect(suppressed).toHaveLength(0);
  });

  it('does not mutate the input array', () => {
    const findings = [
      makeFinding({ confidence: 0.95 }),
      makeFinding({ confidence: 0.60 }),
    ];
    const original = [...findings];

    filterByConfidence(findings, 0.80);

    expect(findings).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// sortFindings
// ---------------------------------------------------------------------------

describe('sortFindings', () => {
  it('orders errors before warnings before info', () => {
    const findings = [
      makeFinding({ severity: 'info',    confidence: 0.90 }),
      makeFinding({ severity: 'warning', confidence: 0.90 }),
      makeFinding({ severity: 'error',   confidence: 0.90 }),
    ];

    const sorted = sortFindings(findings);

    expect(sorted[0].severity).toBe('error');
    expect(sorted[1].severity).toBe('warning');
    expect(sorted[2].severity).toBe('info');
  });

  it('within the same severity bucket, higher confidence comes first', () => {
    const findings = [
      makeFinding({ severity: 'warning', confidence: 0.70 }),
      makeFinding({ severity: 'warning', confidence: 0.95 }),
      makeFinding({ severity: 'warning', confidence: 0.80 }),
    ];

    const sorted = sortFindings(findings);

    expect(sorted[0].confidence).toBe(0.95);
    expect(sorted[1].confidence).toBe(0.80);
    expect(sorted[2].confidence).toBe(0.70);
  });

  it('correctly interleaves severity and confidence in a mixed array', () => {
    const findings = [
      makeFinding({ severity: 'info',    confidence: 0.99 }),
      makeFinding({ severity: 'error',   confidence: 0.60 }),
      makeFinding({ severity: 'warning', confidence: 0.85 }),
      makeFinding({ severity: 'error',   confidence: 0.95 }),
    ];

    const sorted = sortFindings(findings);

    expect(sorted[0].severity).toBe('error');
    expect(sorted[0].confidence).toBe(0.95);
    expect(sorted[1].severity).toBe('error');
    expect(sorted[1].confidence).toBe(0.60);
    expect(sorted[2].severity).toBe('warning');
    expect(sorted[3].severity).toBe('info');
  });

  it('does not mutate the input array', () => {
    const findings = [
      makeFinding({ severity: 'info' }),
      makeFinding({ severity: 'error' }),
    ];
    const original = [...findings];

    sortFindings(findings);

    expect(findings).toEqual(original);
  });

  it('returns an empty array unchanged', () => {
    expect(sortFindings([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// deduplicateFindings
// ---------------------------------------------------------------------------

describe('deduplicateFindings', () => {
  it('keeps the highest-confidence finding when file + line + type match', () => {
    const low  = makeFinding({ file: 'src/a.ts', line: 5, type: 'dead-code', confidence: 0.60 });
    const high = makeFinding({ file: 'src/a.ts', line: 5, type: 'dead-code', confidence: 0.90 });

    const result = deduplicateFindings([low, high]);

    expect(result).toHaveLength(1);
    expect(result[0].confidence).toBe(0.90);
  });

  it('keeps the first finding on an exact confidence tie', () => {
    const first  = makeFinding({ id: 'first',  file: 'src/a.ts', line: 5, type: 'dead-code', confidence: 0.80 });
    const second = makeFinding({ id: 'second', file: 'src/a.ts', line: 5, type: 'dead-code', confidence: 0.80 });

    const result = deduplicateFindings([first, second]);

    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('first');
  });

  it('keeps both findings when they are in different files', () => {
    const a = makeFinding({ file: 'src/a.ts', line: 5, type: 'dead-code', confidence: 0.80 });
    const b = makeFinding({ file: 'src/b.ts', line: 5, type: 'dead-code', confidence: 0.80 });

    const result = deduplicateFindings([a, b]);

    expect(result).toHaveLength(2);
  });

  it('keeps both findings when lines differ', () => {
    const a = makeFinding({ file: 'src/a.ts', line: 1, type: 'dead-code' });
    const b = makeFinding({ file: 'src/a.ts', line: 2, type: 'dead-code' });

    const result = deduplicateFindings([a, b]);

    expect(result).toHaveLength(2);
  });

  it('keeps both findings when types differ', () => {
    const a = makeFinding({ file: 'src/a.ts', line: 5, type: 'dead-code' });
    const b = makeFinding({ file: 'src/a.ts', line: 5, type: 'circular-dep' });

    const result = deduplicateFindings([a, b]);

    expect(result).toHaveLength(2);
  });

  it('treats two findings without a line number as the same location', () => {
    const first  = makeFinding({ id: 'no-line-first',  file: 'src/a.ts', line: undefined, type: 'dep-vuln', confidence: 0.75 });
    const second = makeFinding({ id: 'no-line-second', file: 'src/a.ts', line: undefined, type: 'dep-vuln', confidence: 0.85 });

    const result = deduplicateFindings([first, second]);

    expect(result).toHaveLength(1);
    expect(result[0].confidence).toBe(0.85);
  });

  it('preserves order of first-seen winners', () => {
    const a = makeFinding({ id: 'a', file: 'src/a.ts', line: 1, type: 'dead-code', confidence: 0.80 });
    const b = makeFinding({ id: 'b', file: 'src/b.ts', line: 1, type: 'dead-code', confidence: 0.80 });
    const c = makeFinding({ id: 'c', file: 'src/c.ts', line: 1, type: 'dead-code', confidence: 0.80 });

    const result = deduplicateFindings([a, b, c]);

    expect(result.map((f) => f.id)).toEqual(['a', 'b', 'c']);
  });

  it('returns an empty array for empty input', () => {
    expect(deduplicateFindings([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// summarizeFindings
// ---------------------------------------------------------------------------

describe('summarizeFindings', () => {
  it('returns all-zero summary for empty input', () => {
    const summary = summarizeFindings([]);

    expect(summary.total).toBe(0);
    expect(summary.errors).toBe(0);
    expect(summary.warnings).toBe(0);
    expect(summary.info).toBe(0);
    expect(summary.byLayer).toEqual({});
    expect(summary.byTool).toEqual({});
  });

  it('counts total correctly', () => {
    const findings = [
      makeFinding({ severity: 'error' }),
      makeFinding({ severity: 'warning' }),
      makeFinding({ severity: 'info' }),
    ];

    expect(summarizeFindings(findings).total).toBe(3);
  });

  it('counts errors, warnings, and info correctly', () => {
    const findings = [
      makeFinding({ severity: 'error' }),
      makeFinding({ severity: 'error' }),
      makeFinding({ severity: 'warning' }),
      makeFinding({ severity: 'info' }),
      makeFinding({ severity: 'info' }),
      makeFinding({ severity: 'info' }),
    ];

    const summary = summarizeFindings(findings);

    expect(summary.errors).toBe(2);
    expect(summary.warnings).toBe(1);
    expect(summary.info).toBe(3);
  });

  it('groups by layer correctly', () => {
    const findings = [
      makeFinding({ layer: 'static' }),
      makeFinding({ layer: 'static' }),
      makeFinding({ layer: 'secrets' }),
      makeFinding({ layer: 'semantic' }),
    ];

    const { byLayer } = summarizeFindings(findings);

    expect(byLayer['static']).toBe(2);
    expect(byLayer['secrets']).toBe(1);
    expect(byLayer['semantic']).toBe(1);
  });

  it('groups by tool correctly', () => {
    const findings = [
      makeFinding({ tool: 'ts-prune' }),
      makeFinding({ tool: 'ts-prune' }),
      makeFinding({ tool: 'gitleaks' }),
    ];

    const { byTool } = summarizeFindings(findings);

    expect(byTool['ts-prune']).toBe(2);
    expect(byTool['gitleaks']).toBe(1);
  });

  it('only includes layers and tools with at least one finding', () => {
    const findings = [makeFinding({ layer: 'static', tool: 'ts-prune' })];

    const summary = summarizeFindings(findings);

    expect(Object.keys(summary.byLayer)).toEqual(['static']);
    expect(Object.keys(summary.byTool)).toEqual(['ts-prune']);
  });

  it('total equals errors + warnings + info', () => {
    const findings = [
      makeFinding({ severity: 'error' }),
      makeFinding({ severity: 'warning' }),
      makeFinding({ severity: 'warning' }),
      makeFinding({ severity: 'info' }),
    ];

    const summary = summarizeFindings(findings);

    expect(summary.total).toBe(summary.errors + summary.warnings + summary.info);
  });
});

// ---------------------------------------------------------------------------
// generateFindingId
// ---------------------------------------------------------------------------

describe('generateFindingId', () => {
  it('includes layer, type, and file in the generated ID', () => {
    const id = generateFindingId('semantic', 'duplicate', 'src/utils/helper.ts');

    expect(id).toContain('SEMANTIC');
    expect(id).toContain('DUPLICATE');
    expect(id).toContain('src/utils/helper.ts');
  });

  it('appends the line number after a colon when provided', () => {
    const id = generateFindingId('semantic', 'duplicate', 'src/utils/helper.ts', 42);

    expect(id).toMatch(/:42$/);
  });

  it('omits the colon-and-line suffix when line is undefined', () => {
    const id = generateFindingId('static', 'dead-code', 'src/old.ts');

    expect(id).not.toContain(':');
  });

  it('is deterministic — same inputs produce the same output', () => {
    const a = generateFindingId('static', 'circular-dep', 'src/index.ts', 10);
    const b = generateFindingId('static', 'circular-dep', 'src/index.ts', 10);

    expect(a).toBe(b);
  });

  it('produces different IDs for different layers', () => {
    const a = generateFindingId('static',   'dead-code', 'src/x.ts', 1);
    const b = generateFindingId('semantic', 'dead-code', 'src/x.ts', 1);

    expect(a).not.toBe(b);
  });

  it('produces different IDs for different types', () => {
    const a = generateFindingId('static', 'dead-code',    'src/x.ts', 1);
    const b = generateFindingId('static', 'circular-dep', 'src/x.ts', 1);

    expect(a).not.toBe(b);
  });

  it('produces different IDs for different files', () => {
    const a = generateFindingId('static', 'dead-code', 'src/a.ts', 1);
    const b = generateFindingId('static', 'dead-code', 'src/b.ts', 1);

    expect(a).not.toBe(b);
  });

  it('uppercases layer and type regardless of input case', () => {
    const id = generateFindingId('Semantic', 'Duplicate', 'src/x.ts');

    expect(id).toMatch(/^SEMANTIC-DUPLICATE-/);
  });

  it('sanitizes special characters in layer and type', () => {
    // Dots and slashes in layer/type should be collapsed into hyphens.
    const id = generateFindingId('static.v2', 'dead_code', 'src/x.ts');

    // The file portion is preserved; only layer and type segments are sanitized.
    expect(id).toMatch(/^STATIC-V2-DEAD-CODE-/);
  });

  it('matches the documented format: LAYER-TYPE-file:line', () => {
    const id = generateFindingId('SEMANTIC', 'DUP', 'src/a.ts', 42);

    expect(id).toBe('SEMANTIC-DUP-src/a.ts:42');
  });

  it('matches the documented format without line: LAYER-TYPE-file', () => {
    const id = generateFindingId('STATIC', 'DEAD-FILE', 'src/old.ts');

    expect(id).toBe('STATIC-DEAD-FILE-src/old.ts');
  });
});
