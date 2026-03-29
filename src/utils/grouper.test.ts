import { describe, it, expect } from 'vitest';
import { groupDuplicateFindings, getDirectoryPair } from './grouper.js';
import type { Finding } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal semantic-duplication Finding for use in grouper tests.
 * Both file paths must be absolute so relative() works correctly.
 */
function makeDupFinding(
  fileA: string,
  fileB: string,
  similarity = 0.92,
  id?: string,
): Finding {
  return {
    id: id ?? `dup-${Math.random().toString(36).slice(2)}`,
    layer: 'semantic',
    type: 'semantic-duplication',
    severity: 'warning',
    confidence: 0.9,
    file: fileA,
    message: `Similar functions detected between ${fileA} and ${fileB}`,
    tool: 'codebert-duplication',
    related: [fileB],
    meta: { similarity },
  };
}

/**
 * Build a non-duplication finding (e.g. a security finding).
 */
function makeOtherFinding(file: string, id?: string): Finding {
  return {
    id: id ?? `other-${Math.random().toString(36).slice(2)}`,
    layer: 'static',
    type: 'security-issue',
    severity: 'error',
    confidence: 0.95,
    file,
    message: 'SQL injection risk',
    tool: 'security',
  };
}

const ROOT = '/repo';

// ---------------------------------------------------------------------------
// getDirectoryPair
// ---------------------------------------------------------------------------

describe('getDirectoryPair', () => {
  it('returns the top-level directory names for two files in different dirs', () => {
    const [dirA, dirB] = getDirectoryPair(
      '/repo/mcp_server/tools/connect.py',
      '/repo/src/golem_3dmcp/tools/connect.py',
      '/repo',
    );
    expect(dirA).toBe('mcp_server');
    expect(dirB).toBe('src');
  });

  it('returns the same directory name when both files share the top-level dir', () => {
    const [dirA, dirB] = getDirectoryPair(
      '/repo/src/utils/a.ts',
      '/repo/src/services/b.ts',
      '/repo',
    );
    expect(dirA).toBe('src');
    expect(dirB).toBe('src');
  });

  it('returns "." for files directly in rootDir (no subdirectory)', () => {
    const [dirA] = getDirectoryPair('/repo/index.ts', '/repo/app.ts', '/repo');
    expect(dirA).toBe('.');
  });
});

// ---------------------------------------------------------------------------
// groupDuplicateFindings — collapsing large groups
// ---------------------------------------------------------------------------

describe('groupDuplicateFindings', () => {

  // -------------------------------------------------------------------------
  // 10 duplicate findings between dir-a/ and dir-b/ → collapsed to 1 summary
  // -------------------------------------------------------------------------

  it('collapses 10 duplicate findings from the same directory pair into 1 summary finding', () => {
    const findings: Finding[] = [];

    for (let i = 0; i < 10; i++) {
      findings.push(makeDupFinding(
        `${ROOT}/dir-a/module-${i}.ts`,
        `${ROOT}/dir-b/module-${i}.ts`,
        0.90 + i * 0.005,
      ));
    }

    const result = groupDuplicateFindings(findings, ROOT);

    // All 10 individuals should be collapsed into exactly 1 summary.
    expect(result).toHaveLength(1);

    const summary = result[0];
    expect(summary.type).toBe('semantic-duplication');
    expect(summary.layer).toBe('semantic');
    expect(summary.meta?.pairCount).toBe(10);
  });

  // -------------------------------------------------------------------------
  // Summary meta contains pairCount and avgSimilarity
  // -------------------------------------------------------------------------

  it('summary finding includes pairCount and avgSimilarity in meta', () => {
    const findings: Finding[] = Array.from({ length: 6 }, (_, i) =>
      makeDupFinding(
        `${ROOT}/alpha/f${i}.ts`,
        `${ROOT}/beta/f${i}.ts`,
        0.80 + i * 0.02,
      ),
    );

    const result = groupDuplicateFindings(findings, ROOT);
    const summary = result.find((f) => f.type === 'semantic-duplication');

    expect(summary).toBeDefined();
    expect(typeof summary?.meta?.pairCount).toBe('number');
    expect(summary?.meta?.pairCount).toBe(6);
    expect(typeof summary?.meta?.avgSimilarity).toBe('number');

    // avgSimilarity should be the mean of the similarity values.
    const similarities = [0.80, 0.82, 0.84, 0.86, 0.88, 0.90];
    const expected = similarities.reduce((s, v) => s + v, 0) / similarities.length;
    expect(summary?.meta?.avgSimilarity as number).toBeCloseTo(expected, 5);
  });

  // -------------------------------------------------------------------------
  // 3 duplicate findings (below threshold of 5) → kept as individuals
  // -------------------------------------------------------------------------

  it('keeps individual findings when the group size is at or below MIN_GROUP_SIZE (5)', () => {
    const findings: Finding[] = Array.from({ length: 3 }, (_, i) =>
      makeDupFinding(
        `${ROOT}/left/file-${i}.ts`,
        `${ROOT}/right/file-${i}.ts`,
      ),
    );

    const result = groupDuplicateFindings(findings, ROOT);

    // 3 is below the threshold of 5, so all 3 originals should pass through.
    expect(result).toHaveLength(3);
    for (const f of result) {
      expect(f.type).toBe('semantic-duplication');
    }
  });

  // -------------------------------------------------------------------------
  // Exactly MIN_GROUP_SIZE (5) → kept as individuals (boundary: <= not <)
  // -------------------------------------------------------------------------

  it('keeps findings as individuals when the count equals exactly 5 (boundary of <= MIN_GROUP_SIZE)', () => {
    const findings: Finding[] = Array.from({ length: 5 }, (_, i) =>
      makeDupFinding(
        `${ROOT}/foo/x${i}.ts`,
        `${ROOT}/bar/x${i}.ts`,
      ),
    );

    const result = groupDuplicateFindings(findings, ROOT);

    // 5 <= 5 → no collapsing; all 5 pass through unchanged.
    expect(result).toHaveLength(5);
  });

  // -------------------------------------------------------------------------
  // Non-duplication findings pass through unchanged
  // -------------------------------------------------------------------------

  it('passes non-duplication findings through without modification', () => {
    const other1 = makeOtherFinding(`${ROOT}/src/api.ts`, 'other-1');
    const other2 = makeOtherFinding(`${ROOT}/src/db.ts`, 'other-2');
    const findings: Finding[] = [other1, other2];

    const result = groupDuplicateFindings(findings, ROOT);

    expect(result).toHaveLength(2);
    expect(result.find((f) => f.id === 'other-1')).toBeDefined();
    expect(result.find((f) => f.id === 'other-2')).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Mixed: large dup group + non-dup findings → summary + non-dups preserved
  // -------------------------------------------------------------------------

  it('returns summaries + non-duplication findings when both are present', () => {
    const dups = Array.from({ length: 8 }, (_, i) =>
      makeDupFinding(`${ROOT}/service-a/m${i}.ts`, `${ROOT}/service-b/m${i}.ts`),
    );
    const others = [
      makeOtherFinding(`${ROOT}/src/handler.ts`, 'sec-1'),
      makeOtherFinding(`${ROOT}/src/router.ts`, 'sec-2'),
    ];

    const result = groupDuplicateFindings([...dups, ...others], ROOT);

    // 1 summary for the 8-finding group + 2 non-dup findings.
    expect(result).toHaveLength(3);

    const summary = result.find((f) => f.type === 'semantic-duplication');
    expect(summary?.meta?.pairCount).toBe(8);

    const secFindings = result.filter((f) => f.type === 'security-issue');
    expect(secFindings).toHaveLength(2);
  });

  // -------------------------------------------------------------------------
  // Empty input
  // -------------------------------------------------------------------------

  it('returns an empty array when given no findings', () => {
    expect(groupDuplicateFindings([], ROOT)).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // Input array is not mutated
  // -------------------------------------------------------------------------

  it('does not mutate the input findings array', () => {
    const findings: Finding[] = Array.from({ length: 7 }, (_, i) =>
      makeDupFinding(`${ROOT}/p/f${i}.ts`, `${ROOT}/q/f${i}.ts`),
    );
    const copy = [...findings];

    groupDuplicateFindings(findings, ROOT);

    expect(findings).toHaveLength(copy.length);
    for (let i = 0; i < findings.length; i++) {
      expect(findings[i]).toBe(copy[i]);
    }
  });

  // -------------------------------------------------------------------------
  // Canonical pair key is order-independent
  // -------------------------------------------------------------------------

  it('groups findings regardless of which file is listed as primary vs related', () => {
    // First batch: A is primary, B is related.
    const forward = Array.from({ length: 4 }, (_, i) =>
      makeDupFinding(`${ROOT}/x-dir/f${i}.ts`, `${ROOT}/y-dir/f${i}.ts`),
    );
    // Second batch: B is primary, A is related — same logical pair, reversed.
    const reversed = Array.from({ length: 4 }, (_, i) =>
      makeDupFinding(`${ROOT}/y-dir/g${i}.ts`, `${ROOT}/x-dir/g${i}.ts`),
    );

    const result = groupDuplicateFindings([...forward, ...reversed], ROOT);

    // Both directions should collapse into a single summary because the
    // canonical key sorts dir names alphabetically.
    expect(result).toHaveLength(1);
    expect(result[0].meta?.pairCount).toBe(8);
  });
});
