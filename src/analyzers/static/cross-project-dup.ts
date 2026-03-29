// ============================================================
// CodeSentinel — Cross-Project Duplication Analyzer
// ============================================================
//
// Detects three categories of code duplication across the
// top-level directories (services, apps, packages) of a
// monorepo or multi-project root:
//
//   1. exact-file-duplicate   — identical SHA-256 hash
//      File A and File B share the same content verbatim.
//      confidence: 1.0, severity: warning
//
//   2. near-duplicate-file    — same basename, >90% line similarity
//      Detects copy-paste drift: config.py in service-a vs service-b
//      that have diverged slightly since the copy.
//      confidence: similarity ratio, severity: warning
//
//   3. duplicate-type-name    — same exported interface/type name
//      in two or more top-level directories (TypeScript only).
//      confidence: 0.85, severity: info
//
// Design decisions:
//   - Only compares direct children of rootDir (top-level dirs).
//     Descending into sub-trees for cross-dir comparison would be
//     O(n²) on file count — too slow and too noisy for the signal.
//   - Hash comparison is O(n) with a Map — fast even for 10k files.
//   - Line similarity uses LCS-free counting: sort both line sets
//     and count intersecting lines / total unique lines. Good enough
//     for copy-paste detection without pulling in diff libraries.
//   - Caps at 100 findings (sorted by confidence desc) to prevent
//     flooding the terminal on badly structured monorepos.
//
// ============================================================

import { readdir as readdirNative, readFile, stat } from 'node:fs/promises';
import type { Dirent } from 'node:fs';
import { join, basename, relative } from 'node:path';
import { createHash } from 'node:crypto';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';

// Node 22+ changed Dirent generics — cast to string-based Dirent
async function readdir(dir: string): Promise<Dirent[]> {
  const entries = await readdirNative(dir, { withFileTypes: true });
  return entries as unknown as Dirent[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Directories that are always skipped when collecting files. */
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  '__pycache__',
  '.venv',
  'venv',
  '.cache',
  'coverage',
  '.next',
  '.nuxt',
  '.mypy_cache',
  '.pytest_cache',
  '.tox',
]);

/** Minimum line-similarity ratio to flag as a near-duplicate (0–1). */
const NEAR_DUPLICATE_THRESHOLD = 0.90;

/** Maximum number of findings emitted — sorted by confidence desc. */
const MAX_FINDINGS = 100;

/** Minimum file size in bytes — skip empty / trivially small files. */
const MIN_FILE_BYTES = 50;

/** TypeScript export pattern for interface / type names. */
const EXPORT_TYPE_RE = /^export\s+(?:interface|type)\s+(\w+)/gm;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Stable deterministic finding ID.
 * Format: cpd-{sha1 of subject string}
 */
function makeId(subject: string): string {
  return `cpd-${createHash('sha1').update(subject).digest('hex').slice(0, 12)}`;
}

/** True iff a directory name should be skipped regardless of config. */
function shouldSkip(name: string): boolean {
  return SKIP_DIRS.has(name) || name.startsWith('.');
}

/** SHA-256 of raw file content. */
function sha256(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Recursively collect all file paths within a directory.
 * Returns absolute paths, skipping ignored sub-directories.
 */
async function collectFilesUnder(dir: string): Promise<string[]> {
  const results: string[] = [];

  let entries: Dirent[];
  try {
    entries = await readdir(dir);
  } catch {
    return results;
  }

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      if (shouldSkip(entry.name)) continue;
      const sub = await collectFilesUnder(fullPath);
      results.push(...sub);
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }

  return results;
}

/**
 * Compute line-based similarity between two text files.
 *
 * Algorithm: multiset intersection.
 *   similarity = |intersection(A, B)| / |union(A, B)|
 *
 * This is a fast approximation of Jaccard similarity over line sets.
 * It handles reordering (e.g. moved import blocks) better than a naive
 * sequential diff while remaining O(n) with a Map.
 */
function lineSimilarity(contentA: string, contentB: string): number {
  const linesA = contentA.split('\n').map(l => l.trim()).filter(l => l.length > 0);
  const linesB = contentB.split('\n').map(l => l.trim()).filter(l => l.length > 0);

  if (linesA.length === 0 && linesB.length === 0) return 1.0;
  if (linesA.length === 0 || linesB.length === 0) return 0.0;

  // Count occurrences in A
  const countA = new Map<string, number>();
  for (const line of linesA) {
    countA.set(line, (countA.get(line) ?? 0) + 1);
  }

  // Count occurrences in B
  const countB = new Map<string, number>();
  for (const line of linesB) {
    countB.set(line, (countB.get(line) ?? 0) + 1);
  }

  // Intersection: sum of min(countA[line], countB[line])
  let intersection = 0;
  for (const [line, cntA] of countA) {
    const cntB = countB.get(line) ?? 0;
    intersection += Math.min(cntA, cntB);
  }

  // Union: |A| + |B| - intersection
  const union = linesA.length + linesB.length - intersection;
  return union === 0 ? 1.0 : intersection / union;
}

/**
 * Extract exported interface and type names from TypeScript source text.
 * Returns a deduplicated array of names.
 */
function extractExportedTypeNames(source: string): string[] {
  const names = new Set<string>();
  let match: RegExpExecArray | null;
  const re = new RegExp(EXPORT_TYPE_RE.source, 'gm');
  while ((match = re.exec(source)) !== null) {
    names.add(match[1]);
  }
  return Array.from(names);
}

// ---------------------------------------------------------------------------
// File metadata accumulated per top-level directory
// ---------------------------------------------------------------------------

interface FileInfo {
  /** Absolute path */
  path: string;
  /** Owning top-level directory (absolute) */
  topDir: string;
  /** File name only */
  name: string;
  /** SHA-256 hex of content — populated lazily */
  hash?: string;
  /** Raw buffer — held temporarily for similarity comparison */
  buf?: Buffer;
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

export class CrossProjectDuplicationAnalyzer implements Analyzer {
  readonly name = 'cross-project-duplication';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { rootDir } = context;

    // ── 1. Enumerate top-level directories ──────────────────────────────────
    let topLevelEntries: Dirent[];
    try {
      topLevelEntries = await readdir(rootDir);
    } catch {
      return [];
    }

    const topDirs = topLevelEntries
      .filter(e => e.isDirectory() && !shouldSkip(e.name))
      .map(e => join(rootDir, e.name));

    // Need at least two top-level directories to detect cross-project dups.
    if (topDirs.length < 2) {
      return [];
    }

    // ── 2. Collect files under each top-level directory ─────────────────────
    // Map: topDir -> FileInfo[]
    const filesByTopDir = new Map<string, FileInfo[]>();

    await Promise.all(
      topDirs.map(async (topDir) => {
        const paths = await collectFilesUnder(topDir);
        const infos: FileInfo[] = paths.map(p => ({
          path: p,
          topDir,
          name: basename(p),
        }));
        filesByTopDir.set(topDir, infos);
      }),
    );

    const allFiles: FileInfo[] = [];
    for (const infos of filesByTopDir.values()) {
      allFiles.push(...infos);
    }

    // Read file contents (skip files below minimum size)
    await Promise.all(
      allFiles.map(async (info) => {
        try {
          const s = await stat(info.path);
          if (s.size < MIN_FILE_BYTES) return;
          info.buf = await readFile(info.path);
          info.hash = sha256(info.buf);
        } catch {
          // Unreadable file — leave hash/buf undefined, skip in comparisons.
        }
      }),
    );

    const findings: Finding[] = [];

    // ── 3. Exact duplicates — same hash, different top-level dirs ────────────
    // Build: hash -> FileInfo[] (only files that were successfully read)
    const byHash = new Map<string, FileInfo[]>();
    for (const info of allFiles) {
      if (!info.hash) continue;
      const group = byHash.get(info.hash);
      if (group) {
        group.push(info);
      } else {
        byHash.set(info.hash, [info]);
      }
    }

    for (const [, group] of byHash) {
      // Must span at least two distinct top-level directories.
      const dirs = new Set(group.map(f => f.topDir));
      if (dirs.size < 2) continue;

      // Emit one finding per unique pair of (topDir A, topDir B) to keep
      // the output actionable rather than combinatorial.
      const dirList = Array.from(dirs);
      for (let i = 0; i < dirList.length - 1; i++) {
        for (let j = i + 1; j < dirList.length; j++) {
          const fileA = group.find(f => f.topDir === dirList[i])!;
          const fileB = group.find(f => f.topDir === dirList[j])!;

          const relA = relative(rootDir, fileA.path);
          const relB = relative(rootDir, fileB.path);

          findings.push({
            id: makeId(`exact:${fileA.path}:${fileB.path}`),
            layer: 'static',
            type: 'exact-file-duplicate',
            severity: 'warning',
            confidence: 1.0,
            file: fileA.path,
            message: `Files "${relA}" and "${relB}" are identical (same SHA-256). Consider extracting to a shared module.`,
            tool: 'cross-project-duplication',
            suggestion: 'Extract the shared file into a common package (e.g. packages/shared or libs/common) and import it from both locations.',
            related: [fileB.path],
            meta: {
              hash: fileA.hash,
              peerFile: fileB.path,
              topDirA: fileA.topDir,
              topDirB: fileB.topDir,
            },
          });
        }
      }
    }

    // ── 4. Near-duplicate files — same basename, >90% line similarity ────────
    // Build: basename -> FileInfo[] grouped across top-level directories.
    const byBasename = new Map<string, FileInfo[]>();
    for (const info of allFiles) {
      if (!info.buf) continue;
      const group = byBasename.get(info.name);
      if (group) {
        group.push(info);
      } else {
        byBasename.set(info.name, [info]);
      }
    }

    for (const [name, group] of byBasename) {
      // Only interested in files that appear in multiple top-level dirs.
      const dirs = new Set(group.map(f => f.topDir));
      if (dirs.size < 2) continue;

      const dirList = Array.from(dirs);
      for (let i = 0; i < dirList.length - 1; i++) {
        for (let j = i + 1; j < dirList.length; j++) {
          const fileA = group.find(f => f.topDir === dirList[i])!;
          const fileB = group.find(f => f.topDir === dirList[j])!;

          // Skip if they are exact duplicates — already reported above.
          if (fileA.hash && fileA.hash === fileB.hash) continue;

          const textA = fileA.buf!.toString('utf8');
          const textB = fileB.buf!.toString('utf8');
          const similarity = lineSimilarity(textA, textB);

          if (similarity < NEAR_DUPLICATE_THRESHOLD) continue;

          const relA = relative(rootDir, fileA.path);
          const relB = relative(rootDir, fileB.path);
          const pct = Math.round(similarity * 100);

          findings.push({
            id: makeId(`near:${fileA.path}:${fileB.path}`),
            layer: 'static',
            type: 'near-duplicate-file',
            severity: 'warning',
            confidence: similarity,
            file: fileA.path,
            message: `"${name}" is duplicated across projects with ${pct}% similarity: "${relA}" and "${relB}". Consider extracting to a shared module.`,
            tool: 'cross-project-duplication',
            suggestion: 'Consolidate into a shared package. If intentional divergence is expected, document why each copy exists.',
            related: [fileB.path],
            meta: {
              similarity,
              peerFile: fileB.path,
              topDirA: fileA.topDir,
              topDirB: fileB.topDir,
            },
          });
        }
      }
    }

    // ── 5. Duplicate exported type names across top-level directories ────────
    // Build: typeName -> Set<topDir> of directories that export it.
    const typesByName = new Map<string, Map<string, string>>(); // name -> topDir -> filePath

    for (const info of allFiles) {
      if (!info.buf) continue;
      if (!info.name.endsWith('.ts') && !info.name.endsWith('.tsx')) continue;

      const source = info.buf.toString('utf8');
      const names = extractExportedTypeNames(source);

      for (const typeName of names) {
        let topDirMap = typesByName.get(typeName);
        if (!topDirMap) {
          topDirMap = new Map();
          typesByName.set(typeName, topDirMap);
        }
        // Record the first file per top-level directory that exports this name.
        if (!topDirMap.has(info.topDir)) {
          topDirMap.set(info.topDir, info.path);
        }
      }
    }

    for (const [typeName, topDirMap] of typesByName) {
      if (topDirMap.size < 2) continue;

      const occurrences = Array.from(topDirMap.entries()); // [topDir, filePath][]
      const relPaths = occurrences.map(([, p]) => relative(rootDir, p));

      // Primary file is the first occurrence alphabetically for determinism.
      occurrences.sort((a, b) => a[1].localeCompare(b[1]));
      const [, primaryFile] = occurrences[0];

      findings.push({
        id: makeId(`type:${typeName}:${occurrences.map(([, p]) => p).join(':')}`),
        layer: 'static',
        type: 'duplicate-type-name',
        severity: 'info',
        confidence: 0.85,
        file: primaryFile,
        message: `Exported type/interface "${typeName}" is defined in ${topDirMap.size} separate projects: ${relPaths.join(', ')}. This may indicate copy-pasted type definitions.`,
        tool: 'cross-project-duplication',
        suggestion: 'Move the shared type into a common types package and import it in each project.',
        related: occurrences.slice(1).map(([, p]) => p),
        meta: {
          typeName,
          locations: relPaths,
        },
      });
    }

    // ── 6. Cap and sort ──────────────────────────────────────────────────────
    findings.sort((a, b) => b.confidence - a.confidence);
    return findings.slice(0, MAX_FINDINGS);
  }
}
