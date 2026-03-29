// ============================================================
// CodeSentinel — Test Coverage Gap Analyzer
// ============================================================
//
// Detects source files that SHOULD have tests but DO NOT.
// This is NOT about running tests or measuring line coverage —
// it is purely a file-system check: does a companion test file
// exist for every source file?
//
// For each source file (TS/JS/PY) the analyzer probes the four
// canonical companion locations:
//
//   src/services/auth.service.ts  →
//     src/services/auth.service.test.ts
//     src/services/auth.service.spec.ts
//     src/services/__tests__/auth.service.test.ts
//     tests/services/auth.service.test.ts
//     (same four patterns for .spec.ts, and mirrored for .js / .py)
//
// Finding types:
//   missing-test-file   — no companion found at all
//   empty-test-file     — companion exists but has < 10 non-blank lines
//
// Severity escalation:
//   Business-critical directories (services, api, routes, controllers,
//   handlers) → 'warning'
//   Everything else                                      → 'info'
//
// A summary finding is always appended:
//   "X of Y source files have corresponding test files (Z% coverage)"
//
// Files skipped:
//   node_modules, .git, dist, test files themselves,
//   config files, TypeScript declaration files (.d.ts),
//   and anything listed in config.ignore.
// ============================================================

import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, dirname, join, relative, sep } from 'node:path';
import type { Analyzer, AnalysisContext, Finding, Severity } from '../../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Supported source extensions — files we expect tests for.
 * Declaration files (.d.ts) are excluded at the scan level below.
 */
const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py']);

/**
 * Extensions used in test-file probe paths.
 * For each source extension we probe both `.test` and `.spec` variants.
 */
const TEST_EXTENSIONS: Record<string, string[]> = {
  '.ts':  ['.test.ts',  '.spec.ts'],
  '.tsx': ['.test.tsx', '.spec.tsx'],
  '.js':  ['.test.js',  '.spec.js'],
  '.jsx': ['.test.jsx', '.spec.jsx'],
  '.mjs': ['.test.mjs', '.spec.mjs'],
  '.cjs': ['.test.cjs', '.spec.cjs'],
  '.py':  ['_test.py',  '.test.py'],
};

/**
 * Directories whose presence in the file path marks the file as
 * business-critical → escalate severity to 'warning'.
 */
const CRITICAL_DIRS = new Set([
  'services',
  'service',
  'api',
  'routes',
  'route',
  'controllers',
  'controller',
  'handlers',
  'handler',
]);

/**
 * A test file has "empty coverage" if it contains fewer than this many
 * non-blank lines.
 */
const EMPTY_TEST_LINE_THRESHOLD = 10;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Deterministic finding ID: sha1 of "type:file".
 * Stable across runs — safe for deduplication in reporters.
 */
function makeId(type: string, file: string, extra?: string): string {
  return createHash('sha1')
    .update(`${type}:${file}:${extra ?? ''}`)
    .digest('hex')
    .slice(0, 12);
}

/** Extract the file extension including the dot.  Returns '' if none. */
function fileExt(filePath: string): string {
  // Handle compound extensions like .test.ts before returning.
  const base = basename(filePath);
  const firstDot = base.indexOf('.');
  return firstDot === -1 ? '' : base.slice(firstDot);
}

/** True when the file has a .d.ts / .d.mts / .d.cts declaration extension. */
function isDeclarationFile(filePath: string): boolean {
  return /\.d\.[cm]?ts$/.test(filePath);
}

/**
 * True when the file itself is a test/spec file.
 * Catches: *.test.*, *.spec.*, *_test.*, files inside __tests__ directories.
 */
function isTestFile(filePath: string): boolean {
  const base = basename(filePath);
  if (/\.(test|spec)\.[a-z]+$/i.test(base)) return true;
  if (/_test\.[a-z]+$/i.test(base)) return true;
  // Check for __tests__ directory segment anywhere in the path.
  const parts = filePath.split(sep);
  return parts.some((p) => p === '__tests__' || p === '__specs__');
}

/**
 * True when the file is likely a configuration file and does not need tests.
 * Matches common config naming patterns.
 */
function isConfigFile(filePath: string): boolean {
  const base = basename(filePath).toLowerCase();
  return (
    /^\.?[a-z\-_]+\.config\.[a-z]+$/.test(base) ||   // *.config.ts|js
    /^\.?[a-z\-_]+rc(\.[a-z]+)?$/.test(base) ||       // .eslintrc, .babelrc
    base === 'jest.config.ts' ||
    base === 'jest.config.js' ||
    base === 'vite.config.ts' ||
    base === 'vite.config.js' ||
    base === 'webpack.config.js' ||
    base === 'rollup.config.js' ||
    base === 'tsconfig.json' ||
    base === 'package.json' ||
    base === 'package-lock.json' ||
    base === 'yarn.lock' ||
    base === 'setup.py' ||
    base === 'setup.cfg' ||
    base === 'pyproject.toml'
  );
}

/**
 * True when any segment of the path (split on OS separator) falls inside an
 * explicitly ignored directory — node_modules, .git, dist, etc.
 */
function isInIgnoredDir(filePath: string, ignoreDirs: Set<string>): boolean {
  const parts = filePath.split(sep);
  return parts.some((p) => ignoreDirs.has(p));
}

/**
 * True when the file path falls under one of the business-critical
 * directory names (anywhere in the path).
 */
function isCriticalPath(filePath: string): boolean {
  const parts = filePath.split(sep);
  return parts.some((p) => CRITICAL_DIRS.has(p.toLowerCase()));
}

/**
 * Build the list of candidate test-file absolute paths for a given source
 * file.  We probe four locations per variant (test/spec).
 *
 * Given: /project/src/services/auth.service.ts
 * Stem:  auth.service
 * Ext:   .ts
 *
 * Returns paths for:
 *   /project/src/services/auth.service.test.ts          (sibling)
 *   /project/src/services/auth.service.spec.ts          (sibling)
 *   /project/src/services/__tests__/auth.service.test.ts (__tests__ folder)
 *   /project/src/services/__tests__/auth.service.spec.ts (__tests__ folder)
 *   /project/tests/services/auth.service.test.ts        (top-level tests/)
 *   /project/tests/services/auth.service.spec.ts        (top-level tests/)
 */
function buildCandidatePaths(
  sourceFile: string,
  rootDir: string,
): string[] {
  const dir = dirname(sourceFile);
  const base = basename(sourceFile);

  // Find the simple extension (.ts, .js, .py, …) stripping any compound part.
  // We need the trailing extension only, e.g. ".ts" from "auth.service.ts".
  const lastDot = base.lastIndexOf('.');
  const simpleExt = lastDot === -1 ? '' : base.slice(lastDot);
  const stem = lastDot === -1 ? base : base.slice(0, lastDot);

  const testExts = TEST_EXTENSIONS[simpleExt] ?? [];
  if (testExts.length === 0) return [];

  const candidates: string[] = [];

  for (const testExt of testExts) {
    const testBase = `${stem}${testExt}`;

    // 1. Sibling: same directory
    candidates.push(join(dir, testBase));

    // 2. __tests__ sub-directory of the file's directory
    candidates.push(join(dir, '__tests__', testBase));

    // 3. Top-level tests/ mirroring the relative path from rootDir
    const relDir = relative(rootDir, dir);
    candidates.push(join(rootDir, 'tests', relDir, testBase));

    // 4. Top-level test/ (singular) mirroring the relative path
    candidates.push(join(rootDir, 'test', relDir, testBase));
  }

  return candidates;
}

/**
 * Count non-blank lines in the given file.
 * Returns -1 when the file cannot be read.
 */
function countNonBlankLines(filePath: string): number {
  try {
    const content = readFileSync(filePath, 'utf-8');
    return content.split('\n').filter((l) => l.trim().length > 0).length;
  } catch {
    return -1;
  }
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

export class TestCoverageAnalyzer implements Analyzer {
  readonly name = 'test-coverage';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { files, rootDir, config } = context;

    // Hard-coded dirs to always exclude, merged with config.ignore names.
    const ignoreDirNames = new Set<string>([
      'node_modules',
      '.git',
      'dist',
      'build',
      'coverage',
      '.next',
      '.nuxt',
      '__pycache__',
      '.venv',
      'vendor',
    ]);

    // config.ignore entries can be bare names ("dist") or relative paths.
    // For the isInIgnoredDir check we only need the bare directory name
    // segment — add any bare (no-slash) entries.
    for (const entry of config.ignore) {
      if (!entry.includes('/') && !entry.includes(sep)) {
        ignoreDirNames.add(entry);
      }
    }

    const findings: Finding[] = [];

    let sourceFileCount = 0;
    let coveredFileCount = 0;

    for (const filePath of files) {
      // ── Skip ignored directories ───────────────────────────────────────
      if (isInIgnoredDir(filePath, ignoreDirNames)) continue;

      // ── Extension gate ────────────────────────────────────────────────
      const ext = fileExt(filePath);
      // ext from fileExt includes the compound prefix, e.g. ".test.ts"
      // We need the simple trailing extension for the SOURCE_EXTENSIONS lookup.
      const lastDot = filePath.lastIndexOf('.');
      const simpleExt = lastDot === -1 ? '' : filePath.slice(lastDot);

      if (!SOURCE_EXTENSIONS.has(simpleExt)) continue;

      // ── Skip declaration files ────────────────────────────────────────
      if (isDeclarationFile(filePath)) continue;

      // ── Skip the test files themselves ────────────────────────────────
      if (isTestFile(filePath)) continue;

      // ── Skip config files ─────────────────────────────────────────────
      if (isConfigFile(filePath)) continue;

      // ── Also skip the compound ext case detected by fileExt ───────────
      // e.g. "index.test.ts" would have ext=".test.ts" → already caught
      // by isTestFile, but double-check: if compound ext contains "test"
      // or "spec" that's a test file.
      if (ext !== simpleExt && /\.(test|spec)\.[a-z]+$/i.test(ext)) continue;

      sourceFileCount++;

      // ── Find companion test file ───────────────────────────────────────
      const candidates = buildCandidatePaths(filePath, rootDir);

      let foundTestFile: string | undefined;
      for (const candidate of candidates) {
        if (existsSync(candidate)) {
          foundTestFile = candidate;
          break;
        }
      }

      const severity: Severity = isCriticalPath(filePath) ? 'warning' : 'info';
      const relSource = relative(rootDir, filePath);

      if (!foundTestFile) {
        // ── Missing test file ──────────────────────────────────────────
        findings.push({
          id: makeId('missing-test-file', filePath),
          layer: 'static',
          tool: 'test-coverage',
          type: 'missing-test-file',
          severity,
          confidence: 0.90,
          file: filePath,
          message: `No test file found for ${relSource}`,
          suggestion:
            severity === 'warning'
              ? `This is a business-critical file (${relSource}). Add tests to ensure correctness under change.`
              : `Consider adding a test file alongside this module. Expected: ${basename(filePath, simpleExt)}.test${simpleExt}`,
          meta: {
            sourceFile: relSource,
            probedLocations: candidates.map((c) => relative(rootDir, c)),
          },
        });
      } else {
        // ── Test file exists — check if it is empty ────────────────────
        const nonBlankLines = countNonBlankLines(foundTestFile);
        const relTest = relative(rootDir, foundTestFile);

        if (nonBlankLines >= 0 && nonBlankLines < EMPTY_TEST_LINE_THRESHOLD) {
          findings.push({
            id: makeId('empty-test-file', filePath),
            layer: 'static',
            tool: 'test-coverage',
            type: 'empty-test-file',
            severity,
            confidence: 0.90,
            file: foundTestFile,
            message: `Test file for ${relSource} exists but contains only ${nonBlankLines} non-blank line(s) — effectively empty`,
            suggestion: `Implement meaningful test cases in ${relTest}. Stub files provide false confidence.`,
            meta: {
              sourceFile: relSource,
              testFile: relTest,
              nonBlankLines,
            },
          });
        } else {
          coveredFileCount++;
        }
      }
    }

    // ── Summary finding ────────────────────────────────────────────────────
    if (sourceFileCount > 0) {
      const percent =
        sourceFileCount === 0
          ? 0
          : Math.round((coveredFileCount / sourceFileCount) * 100);

      const summaryLevel: Severity =
        percent < 50 ? 'warning' : 'info';

      findings.push({
        id: makeId('test-coverage-summary', rootDir),
        layer: 'static',
        tool: 'test-coverage',
        type: 'test-coverage-summary',
        severity: summaryLevel,
        confidence: 1.0,
        file: rootDir,
        message: `${coveredFileCount} of ${sourceFileCount} source files have corresponding test files (${percent}% coverage)`,
        meta: {
          sourceFileCount,
          coveredFileCount,
          missingCount: sourceFileCount - coveredFileCount,
          coveragePercent: percent,
        },
      });
    }

    return findings;
  }
}

export default new TestCoverageAnalyzer();
