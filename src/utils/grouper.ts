// ============================================================
// CodeSentinel — Duplication Finding Grouper
// ============================================================
//
// When a large codebase has two mirrored directory trees (e.g.
// mcp_server/ and src/golem_3dmcp/) the duplication analyzer
// correctly identifies every similar function pair — but the
// result is hundreds of individual findings that obscure the
// real insight: "these two directories are nearly identical."
//
// This module collapses those floods into directory-level
// summary findings when a directory pair has more than
// MIN_GROUP_SIZE individual findings.  Individual findings that
// don't belong to a large group are passed through unchanged.
//
// Entry points:
//   groupDuplicateFindings(findings)  — main pipeline step
//   getDirectoryPair(fileA, fileB, rootDir) — exposed for testing
// ============================================================

import { randomUUID } from 'node:crypto';
import { relative, dirname, sep, posix } from 'node:path';
import type { Finding } from '../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Minimum number of findings sharing a directory pair before collapsing. */
const MIN_GROUP_SIZE = 5;

// ---------------------------------------------------------------------------
// getDirectoryPair
// ---------------------------------------------------------------------------

/**
 * Derive the top-level directory name (relative to rootDir) for each of the
 * two files in a duplicate pair.
 *
 * "Top-level" means the first path component after rootDir.
 * Files that sit directly in rootDir (no subdirectory) are represented as
 * "." so they still form a valid pair key.
 *
 * Both paths are normalised to POSIX separators so the key is
 * platform-independent.
 *
 * @example
 *   getDirectoryPair(
 *     '/repo/mcp_server/tools/connect.py',
 *     '/repo/src/golem_3dmcp/tools/connect.py',
 *     '/repo',
 *   )
 *   // → ['mcp_server', 'src']
 */
export function getDirectoryPair(
  fileA: string,
  fileB: string,
  rootDir: string,
): [string, string] {
  const dirA = topLevelDir(fileA, rootDir);
  const dirB = topLevelDir(fileB, rootDir);
  return [dirA, dirB];
}

// ---------------------------------------------------------------------------
// groupDuplicateFindings
// ---------------------------------------------------------------------------

/**
 * Collapse floods of per-function semantic-duplication findings into
 * directory-level summaries when two directories share more than
 * MIN_GROUP_SIZE duplicate pairs.
 *
 * Algorithm:
 *   1. Separate semantic-duplication findings from all other findings.
 *   2. For each duplication finding extract the directory pair (dirA, dirB).
 *   3. Accumulate findings by canonical (sorted) directory pair key.
 *   4. Groups with > MIN_GROUP_SIZE findings → one summary Finding.
 *   5. Groups with <= MIN_GROUP_SIZE findings → kept as-is.
 *   6. Return non-duplication findings + summaries + ungrouped individuals.
 *
 * The input array is not mutated.
 */
export function groupDuplicateFindings(
  findings: Finding[],
  rootDir: string,
): Finding[] {
  // ── Separate duplication findings from everything else ─────────────────────
  const dupFindings: Finding[] = [];
  const otherFindings: Finding[] = [];

  for (const f of findings) {
    if (f.type === 'semantic-duplication') {
      dupFindings.push(f);
    } else {
      otherFindings.push(f);
    }
  }

  if (dupFindings.length === 0) {
    return findings;
  }

  // ── Bucket findings by canonical directory pair ────────────────────────────
  const groups = new Map<string, Finding[]>();

  for (const finding of dupFindings) {
    const relatedFile = finding.related?.[0];
    if (!relatedFile) {
      // No related file — can't derive a pair; keep as individual.
      addToGroup(groups, '__ungrouped__', finding);
      continue;
    }

    const [dirA, dirB] = getDirectoryPair(finding.file, relatedFile, rootDir);

    // Canonical key: sort so (mcp_server, src) and (src, mcp_server) collapse
    // into the same bucket regardless of which file is A vs B.
    const key = [dirA, dirB].sort().join('\x00');
    addToGroup(groups, key, finding);
  }

  // ── Collapse large groups; pass through small groups ─────────────────────
  const collapsed: Finding[] = [];

  for (const [key, group] of groups) {
    if (key === '__ungrouped__' || group.length <= MIN_GROUP_SIZE) {
      // Keep all findings in this group as individuals.
      collapsed.push(...group);
      continue;
    }

    const [rawDirA, rawDirB] = key.split('\x00') as [string, string];
    collapsed.push(buildSummaryFinding(rawDirA, rawDirB, group, rootDir));
  }

  return [...otherFindings, ...collapsed];
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function addToGroup(map: Map<string, Finding[]>, key: string, finding: Finding): void {
  const existing = map.get(key);
  if (existing) {
    existing.push(finding);
  } else {
    map.set(key, [finding]);
  }
}

/**
 * Extract the first path component relative to rootDir.
 * Absolute paths outside rootDir fall back to their own dirname basename.
 */
function topLevelDir(filePath: string, rootDir: string): string {
  // relative() returns e.g. "mcp_server/tools/connect.py" or "../outside/x.py"
  const rel = relative(rootDir, filePath);

  // Normalise to forward slashes for consistent splitting on all platforms.
  const posixRel = rel.split(sep).join(posix.sep);

  // Split on first slash — the first segment is the top-level directory.
  const firstSlash = posixRel.indexOf('/');
  if (firstSlash === -1) {
    // File is directly inside rootDir (no subdirectory) or IS rootDir.
    return dirname(posixRel) === '.' ? '.' : posixRel;
  }

  return posixRel.slice(0, firstSlash);
}

/**
 * Build a single summary Finding representing a large group of duplicates
 * between two directories.
 */
function buildSummaryFinding(
  dirA: string,
  dirB: string,
  group: Finding[],
  rootDir: string,
): Finding {
  const pairCount = group.length;

  // Average similarity across the group (stored in meta.similarity per finding).
  const similarities = group
    .map((f) => {
      const s = (f.meta as Record<string, unknown> | undefined)?.similarity;
      return typeof s === 'number' ? s : null;
    })
    .filter((s): s is number => s !== null);

  const avgSimilarity =
    similarities.length > 0
      ? similarities.reduce((sum, s) => sum + s, 0) / similarities.length
      : 0;

  const maxConfidence = group.reduce((max, f) => Math.max(max, f.confidence), 0);

  // Collect the top 5 individual pairs for the meta.topPairs field.
  const topPairs = group.slice(0, 5).map((f) => ({
    file: f.file,
    related: f.related?.[0] ?? '',
    message: f.message,
    similarity: (f.meta as Record<string, unknown> | undefined)?.similarity ?? null,
  }));

  const avgPct = (avgSimilarity * 100).toFixed(1);
  const message =
    `Directory ${dirA}/ and ${dirB}/ have ${pairCount} semantically similar ` +
    `function pairs (avg ${avgPct}% similarity)`;

  return {
    id: randomUUID(),
    layer: 'semantic',
    type: 'semantic-duplication',
    severity: 'warning',
    confidence: maxConfidence,
    // Use rootDir as the "file" anchor for a directory-level finding.
    file: rootDir,
    message,
    tool: 'codebert-duplication',
    suggestion:
      `These directories appear to be near-copies of each other. ` +
      `Consider consolidating into a single shared module to eliminate the ` +
      `${pairCount} duplicate function pairs and reduce maintenance burden.`,
    related: [dirB],
    meta: {
      pairCount,
      avgSimilarity,
      topPairs,
      dirA,
      dirB,
    },
  };
}
