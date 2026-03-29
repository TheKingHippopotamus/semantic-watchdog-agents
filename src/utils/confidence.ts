// ============================================================
// CodeSentinel — Confidence Gate & Finding Utilities
// ============================================================

import type { Finding } from '../types.js';

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

/** Severity rank used for sort ordering — lower rank = higher priority. */
const SEVERITY_RANK: Record<string, number> = {
  error: 0,
  warning: 1,
  info: 2,
};

// ---------------------------------------------------------------------------
// filterByConfidence
// ---------------------------------------------------------------------------

/**
 * Split an array of findings into two groups based on a confidence threshold.
 *
 * - `passed`     — findings whose `confidence` is >= `threshold`
 * - `suppressed` — findings whose `confidence` is <  `threshold`
 *
 * Neither array is sorted; callers should sort if needed.
 * The input array is not mutated.
 */
export function filterByConfidence(
  findings: Finding[],
  threshold: number,
): { passed: Finding[]; suppressed: Finding[] } {
  const passed: Finding[] = [];
  const suppressed: Finding[] = [];

  for (const finding of findings) {
    if (finding.confidence >= threshold) {
      passed.push(finding);
    } else {
      suppressed.push(finding);
    }
  }

  return { passed, suppressed };
}

// ---------------------------------------------------------------------------
// sortFindings
// ---------------------------------------------------------------------------

/**
 * Return a new array of findings sorted by:
 *   1. Severity — errors first, then warnings, then info
 *   2. Confidence descending within the same severity bucket
 *
 * The input array is not mutated.
 */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const severityDelta =
      (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3);

    if (severityDelta !== 0) {
      return severityDelta;
    }

    // Secondary sort: higher confidence first.
    return b.confidence - a.confidence;
  });
}

// ---------------------------------------------------------------------------
// deduplicateFindings
// ---------------------------------------------------------------------------

/**
 * Remove duplicate findings that refer to the same logical issue.
 *
 * Two findings are considered duplicates when they share the same:
 *   - `file`
 *   - `line`  (both undefined counts as the same)
 *   - `type`
 *
 * When duplicates exist, the one with the highest `confidence` is kept.
 * In the case of a tie, the first occurrence in the input array wins.
 *
 * The input array is not mutated. Return order matches the order in which
 * winners were first encountered in the input.
 */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  /** Composite key → best-confidence finding seen so far. */
  const best = new Map<string, Finding>();
  /** Preserve insertion order of keys for deterministic output. */
  const keyOrder: string[] = [];

  for (const finding of findings) {
    const key = buildDeduplicationKey(finding);

    const existing = best.get(key);
    if (existing === undefined) {
      best.set(key, finding);
      keyOrder.push(key);
    } else if (finding.confidence > existing.confidence) {
      best.set(key, finding);
      // Do NOT push to keyOrder — the key is already registered; we only
      // replace the value.
    }
  }

  return keyOrder.map((key) => best.get(key) as Finding);
}

/**
 * Derive a stable deduplication key from a finding's file, line, and type.
 * Undefined line is represented as the empty string so it participates in
 * the key without a separate code path.
 */
function buildDeduplicationKey(finding: Finding): string {
  const line = finding.line !== undefined ? String(finding.line) : '';
  return `${finding.file}\x00${line}\x00${finding.type}`;
}

// ---------------------------------------------------------------------------
// summarizeFindings
// ---------------------------------------------------------------------------

/** Aggregated statistics over a collection of findings. */
export interface FindingSummary {
  total: number;
  errors: number;
  warnings: number;
  info: number;
  /** Count of findings grouped by analyzer layer (static, secrets, semantic). */
  byLayer: Record<string, number>;
  /** Count of findings grouped by the tool that produced them. */
  byTool: Record<string, number>;
}

/**
 * Compute summary statistics over an array of findings.
 *
 * All counts are non-negative integers.
 * `byLayer` and `byTool` will only contain keys that have at least one finding.
 * The input array is not mutated.
 */
export function summarizeFindings(findings: Finding[]): FindingSummary {
  const summary: FindingSummary = {
    total: findings.length,
    errors: 0,
    warnings: 0,
    info: 0,
    byLayer: {},
    byTool: {},
  };

  for (const finding of findings) {
    // Severity counters.
    switch (finding.severity) {
      case 'error':
        summary.errors++;
        break;
      case 'warning':
        summary.warnings++;
        break;
      case 'info':
        summary.info++;
        break;
    }

    // Per-layer counter.
    summary.byLayer[finding.layer] =
      (summary.byLayer[finding.layer] ?? 0) + 1;

    // Per-tool counter.
    summary.byTool[finding.tool] =
      (summary.byTool[finding.tool] ?? 0) + 1;
  }

  return summary;
}

// ---------------------------------------------------------------------------
// generateFindingId
// ---------------------------------------------------------------------------

/**
 * Generate a deterministic, human-readable finding ID.
 *
 * Format:
 *   - With line:    `<LAYER>-<TYPE>-<file>:<line>`  e.g. `SEMANTIC-DUP-src/a.ts:42`
 *   - Without line: `<LAYER>-<TYPE>-<file>`          e.g. `STATIC-DEAD-FILE-src/old.ts`
 *
 * Rules:
 * - `layer` and `type` are uppercased and stripped of characters that would
 *   break common ID parsers (kept: A-Z, 0-9, hyphen).
 * - `file` is kept as-is (paths are meaningful and must remain readable).
 * - `line` is appended after a colon when provided.
 *
 * This function is pure and has no side effects.
 */
export function generateFindingId(
  layer: string,
  type: string,
  file: string,
  line?: number,
): string {
  const sanitizedLayer = sanitizeIdSegment(layer);
  const sanitizedType = sanitizeIdSegment(type);

  const prefix = `${sanitizedLayer}-${sanitizedType}-${file}`;

  return line !== undefined ? `${prefix}:${line}` : prefix;
}

/**
 * Uppercase the segment and replace any character that is not A-Z, 0-9, or
 * hyphen with a hyphen, then collapse consecutive hyphens into one.
 */
function sanitizeIdSegment(segment: string): string {
  return segment
    .toUpperCase()
    .replace(/[^A-Z0-9-]/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^-|-$/g, '');
}
