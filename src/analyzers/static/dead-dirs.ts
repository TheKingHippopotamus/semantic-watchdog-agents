// ============================================================
// CodeSentinel — Dead / Empty Directory Analyzer
// ============================================================
//
// Detects three categories of structural dead weight:
//
//   1. empty-directory    — directories with zero code files
//   2. duplicate-directory — two directories sharing >80% of filenames
//   3. disconnected-directory — directories whose code files are never
//      imported by files outside that directory
//
// All scanning is performed with node:fs/promises against the
// rootDir resolved from AnalysisContext. The standard ignore
// list (node_modules, .git, dist, etc.) is respected.
// ============================================================

import { readdir as readdirNative, stat } from 'node:fs/promises';
import type { Dirent } from 'node:fs';

// Node 22+ @types/node changed Dirent generics — cast to string-based Dirent
async function readdir(dir: string): Promise<Dirent[]> {
  const entries = await readdirNative(dir, { withFileTypes: true });
  return entries as unknown as Dirent[];
}
import { join, relative, dirname, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Directories that are always skipped regardless of config.ignore. */
const ALWAYS_IGNORE = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.cache',
  'coverage',
  '__pycache__',
  '.mypy_cache',
  '.pytest_cache',
  '.venv',
  'venv',
  '.tox',
]);

/** File extensions considered "code" for disconnected-directory analysis. */
const CODE_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.rb', '.go', '.java', '.kt', '.rs',
  '.c', '.cpp', '.cc', '.h', '.hpp',
  '.cs', '.swift', '.scala', '.clj',
  '.vue', '.svelte',
]);

/** Overlap threshold above which two directories are considered near-duplicates. */
const DUPLICATE_THRESHOLD = 0.80;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Stable deterministic ID for a finding.
 * Format: dda-{sha1 of "type:subject"}
 */
function makeId(type: string, subject: string): string {
  const raw = `${type}:${subject}`;
  return `dda-${createHash('sha1').update(raw).digest('hex').slice(0, 12)}`;
}

/** True if a directory segment should be skipped. */
function shouldIgnoreDir(name: string): boolean {
  return ALWAYS_IGNORE.has(name) || name.startsWith('.');
}

/**
 * Recursively collect all file paths beneath a directory.
 * Returns absolute paths. Skips ignored directory names.
 */
async function collectFiles(dir: string): Promise<string[]> {
  const results: string[] = [];

  let entries: Awaited<ReturnType<typeof readdir>>;
  try {
    entries = await readdir(dir);
  } catch {
    // Permission denied or other OS error — skip.
    return results;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (shouldIgnoreDir(entry.name)) continue;
      const sub = await collectFiles(join(dir, entry.name));
      results.push(...sub);
    } else if (entry.isFile()) {
      results.push(join(dir, entry.name));
    }
  }

  return results;
}

/**
 * Return all immediate subdirectories of a directory.
 * Skips ignored names.
 */
async function getTopLevelDirs(rootDir: string): Promise<string[]> {
  let entries: Awaited<ReturnType<typeof readdir>>;
  try {
    entries = await readdir(rootDir);
  } catch {
    return [];
  }

  const dirs: string[] = [];
  for (const entry of entries) {
    if (entry.isDirectory() && !shouldIgnoreDir(entry.name)) {
      dirs.push(join(rootDir, entry.name));
    }
  }
  return dirs;
}

/**
 * Compute Jaccard similarity between two sets of filenames.
 * Returns a value in [0, 1].
 */
function filenameOverlap(setA: Set<string>, setB: Set<string>): number {
  if (setA.size === 0 && setB.size === 0) return 1.0;
  if (setA.size === 0 || setB.size === 0) return 0.0;

  let intersection = 0;
  for (const name of setA) {
    if (setB.has(name)) intersection++;
  }

  // Use the smaller set as the denominator (overlap %, not Jaccard)
  // so that A=[a,b,c] and B=[a,b,c,d] gives 3/3 = 100% from A's perspective
  // and 3/4 = 75% from B's perspective — we take the average (87.5%).
  const overlapFromA = intersection / setA.size;
  const overlapFromB = intersection / setB.size;
  return (overlapFromA + overlapFromB) / 2;
}

/**
 * Extract import/require paths from a file's raw text.
 * Handles:
 *   import ... from 'path'
 *   import('path')
 *   require('path')
 *
 * Returns the raw specifier strings (not resolved absolute paths).
 */
function extractImportSpecifiers(content: string): string[] {
  const specifiers: string[] = [];

  // ES module static imports / exports
  const staticImport = /(?:import|export)\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = staticImport.exec(content)) !== null) {
    specifiers.push(m[1]);
  }

  // Dynamic import() and require()
  const dynamic = /(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  while ((m = dynamic.exec(content)) !== null) {
    specifiers.push(m[1]);
  }

  return specifiers;
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

export class DeadDirectoryAnalyzer implements Analyzer {
  readonly name = 'dead-dirs';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { rootDir } = context;

    // Guard: rootDir must be a directory.
    try {
      const s = await stat(rootDir);
      if (!s.isDirectory()) return [];
    } catch {
      return [];
    }

    const findings: Finding[] = [];

    // Run all three detection passes in parallel — they are independent.
    const [emptyFindings, duplicateFindings, disconnectedFindings] = await Promise.all([
      this.detectEmptyDirectories(rootDir),
      this.detectDuplicateDirectories(rootDir),
      this.detectDisconnectedDirectories(rootDir, context.files),
    ]);

    findings.push(...emptyFindings, ...duplicateFindings, ...disconnectedFindings);
    return findings;
  }

  // ── Pass 1: Empty directories ─────────────────────────────────────────────

  /**
   * Walk the entire tree under rootDir and report directories that contain
   * zero files (after recursively descending into all subdirectories).
   */
  private async detectEmptyDirectories(rootDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    await this.walkForEmpty(rootDir, rootDir, findings);
    return findings;
  }

  /**
   * Recursive DFS. Returns true if the directory (or any descendant) contains
   * at least one file, so the caller can decide whether to flag the parent.
   */
  private async walkForEmpty(
    rootDir: string,
    dir: string,
    findings: Finding[],
  ): Promise<boolean> {
    let entries: Awaited<ReturnType<typeof readdir>>;
    try {
      entries = await readdir(dir);
    } catch {
      return false;
    }

    if (entries.length === 0) {
      // Completely empty directory — flag it.
      const relPath = relative(rootDir, dir);
      findings.push({
        id: makeId('empty-directory', dir),
        layer: 'static',
        type: 'empty-directory',
        severity: 'warning',
        confidence: 1.0,
        file: relPath,
        message: `Empty directory: ${relPath} contains no files`,
        tool: 'dead-dirs',
        suggestion: 'Remove the directory if it is no longer needed, or add a placeholder file if it is intentional.',
      });
      return false;
    }

    let hasFile = false;

    for (const entry of entries) {
      if (entry.isFile()) {
        hasFile = true;
      } else if (entry.isDirectory()) {
        if (shouldIgnoreDir(entry.name)) continue;
        const childHasFile = await this.walkForEmpty(
          rootDir,
          join(dir, entry.name),
          findings,
        );
        if (childHasFile) hasFile = true;
      }
    }

    if (!hasFile && entries.some((e) => e.isDirectory() && !shouldIgnoreDir(e.name))) {
      // Directory that only contains subdirectories, all of which are empty.
      // The subdirectories are already reported — no need to double-report this parent.
    }

    return hasFile;
  }

  // ── Pass 2: Near-duplicate directories ───────────────────────────────────

  /**
   * Compare every pair of immediate subdirectories under rootDir.
   * Flag pairs where the filename overlap exceeds DUPLICATE_THRESHOLD.
   */
  private async detectDuplicateDirectories(rootDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const topLevelDirs = await getTopLevelDirs(rootDir);

    if (topLevelDirs.length < 2) return findings;

    // Build a map of dir → Set<basename> for each top-level directory.
    const dirFilenames = new Map<string, Set<string>>();

    await Promise.all(
      topLevelDirs.map(async (dir) => {
        const files = await collectFiles(dir);
        const names = new Set(files.map((f) => basename(f)));
        dirFilenames.set(dir, names);
      }),
    );

    // Compare every pair (i, j) where i < j to avoid duplicate reports.
    const dirs = Array.from(dirFilenames.keys());
    for (let i = 0; i < dirs.length; i++) {
      for (let j = i + 1; j < dirs.length; j++) {
        const dirA = dirs[i];
        const dirB = dirs[j];
        const namesA = dirFilenames.get(dirA)!;
        const namesB = dirFilenames.get(dirB)!;

        // Skip pairs where both directories have zero files.
        if (namesA.size === 0 && namesB.size === 0) continue;

        const overlap = filenameOverlap(namesA, namesB);
        if (overlap >= DUPLICATE_THRESHOLD) {
          const relA = relative(rootDir, dirA);
          const relB = relative(rootDir, dirB);
          const pct = Math.round(overlap * 100);

          findings.push({
            id: makeId('duplicate-directory', `${dirA}::${dirB}`),
            layer: 'static',
            type: 'duplicate-directory',
            severity: 'warning',
            confidence: overlap,
            file: relA,
            message: `Directories "${relA}" and "${relB}" share ${pct}% of filenames — possible copy or stale refactor leftover`,
            tool: 'dead-dirs',
            suggestion: 'Consolidate the two directories or delete the stale copy.',
            related: [relB],
            meta: { dirA: relA, dirB: relB, overlapPct: pct },
          });
        }
      }
    }

    return findings;
  }

  // ── Pass 3: Disconnected directories ──────────────────────────────────────

  /**
   * For each top-level directory, check whether any of its code files are
   * imported by files that live outside that directory.
   *
   * If no outside file imports from the directory (directly or via a
   * relative path), the directory is flagged as disconnected.
   *
   * Implementation uses a simple regex import extractor on file contents
   * rather than a full AST — fast and dependency-free.
   */
  private async detectDisconnectedDirectories(
    rootDir: string,
    contextFiles: string[],
  ): Promise<Finding[]> {
    const findings: Finding[] = [];
    const topLevelDirs = await getTopLevelDirs(rootDir);

    if (topLevelDirs.length === 0) return findings;

    // Bucket context files by their top-level directory.
    // Files directly in rootDir (not in any subdir) are placed under ''.
    const filesByTopDir = new Map<string, string[]>();
    const outsideFiles: string[] = []; // files not under any top-level dir

    for (const file of contextFiles) {
      const rel = relative(rootDir, file);
      const segments = rel.split('/');

      if (segments.length <= 1) {
        // File sits directly in rootDir.
        outsideFiles.push(file);
        continue;
      }

      const topDirName = segments[0];
      const topDirAbs = join(rootDir, topDirName);

      if (!filesByTopDir.has(topDirAbs)) {
        filesByTopDir.set(topDirAbs, []);
      }
      filesByTopDir.get(topDirAbs)!.push(file);
    }

    // For each top-level directory, determine if any outside file imports it.
    for (const dir of topLevelDirs) {
      const filesInDir = filesByTopDir.get(dir) ?? [];

      // Skip directories that have no code files.
      const codeFilesInDir = filesInDir.filter((f) =>
        CODE_EXTENSIONS.has(`.${f.split('.').pop() ?? ''}`),
      );

      if (codeFilesInDir.length === 0) continue;

      const dirBasename = basename(dir);
      const relDir = relative(rootDir, dir);

      // Files that are NOT inside this directory.
      const externalFiles = contextFiles.filter((f) => !f.startsWith(dir + '/') && f !== dir);

      let referenced = false;

      for (const extFile of externalFiles) {
        if (referenced) break;

        let content: string;
        try {
          content = readFileSync(extFile, 'utf8');
        } catch {
          continue;
        }

        const specifiers = extractImportSpecifiers(content);

        for (const specifier of specifiers) {
          // Match if the specifier references this directory by:
          //   a. Relative path containing the dir basename (e.g., './utils', '../utils/foo')
          //   b. Bare module-style path starting with the dir basename (e.g., 'utils/helper')
          if (
            specifier.includes(`/${dirBasename}`) ||
            specifier.startsWith(`./${dirBasename}`) ||
            specifier.startsWith(`../${dirBasename}`) ||
            specifier === dirBasename ||
            specifier.startsWith(`${dirBasename}/`)
          ) {
            referenced = true;
            break;
          }
        }
      }

      if (!referenced) {
        findings.push({
          id: makeId('disconnected-directory', dir),
          layer: 'static',
          type: 'disconnected-directory',
          severity: 'info',
          confidence: 0.80,
          file: relDir,
          message: `Directory "${relDir}" contains code files but none appear to be imported from outside it`,
          tool: 'dead-dirs',
          suggestion: 'Verify this directory is intentionally isolated. If not, check for missing imports or remove the directory.',
          meta: { codeFileCount: codeFilesInDir.length },
        });
      }
    }

    return findings;
  }
}
