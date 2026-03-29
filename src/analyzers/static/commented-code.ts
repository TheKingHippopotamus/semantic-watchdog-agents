// ============================================================
// CodeSentinel — Commented-Out Code Analyzer
// Layer: static | Tool: commented-code
// ============================================================
//
// Detects blocks of commented-out code using heuristics.
// Operates entirely on raw file text — no AST required.
//
// Supported languages:
//   JS/TS  — consecutive // lines that match code patterns
//   Python — consecutive # lines that match code patterns
//
// Conservative by design: requires 3+ consecutive matching
// lines to constitute a "block" finding, reducing false
// positives on legitimate inline commentary.
//
// Explicitly skipped:
//   - License/copyright headers (first N lines of file)
//   - JSDoc/docstring block comments (/** ... */ / """ ... """)
//   - TODO/FIXME/NOTE/HACK single-line comments (handled by todo-tracker)
//   - Test files (*.test.ts, *.spec.ts, etc.)
// ============================================================

import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Minimum consecutive matching comment lines to emit a finding. */
const MIN_BLOCK_SIZE = 3;

/**
 * Number of lines at the top of a file to treat as a potential license
 * header. Lines inside this window are never flagged.
 */
const LICENSE_HEADER_LINES = 10;

/** Confidence for all findings — heuristic, not AST-certain. */
const CONFIDENCE = 0.85;

// ---------------------------------------------------------------------------
// Regex patterns
// ---------------------------------------------------------------------------

/** JS/TS file extensions. */
const JS_TS_EXT = /\.(js|mjs|cjs|ts|mts|cts|jsx|tsx)$/;

/** Python file extensions. */
const PYTHON_EXT = /\.py$/;

/** Test file pattern — skip entirely. */
const TEST_FILE = /\.(test|spec)\.(js|mjs|cjs|ts|mts|cts|jsx|tsx)$/;

/**
 * Prefixes that indicate a commented-out code line in JS/TS.
 * Anchored after stripping leading whitespace.
 *
 * Note the trailing space on each prefix — this avoids matching
 * prose sentences that happen to start with a keyword (e.g. "// import
 * things from the store" would still match "// import " but that's
 * genuinely code-like, which is acceptable for this heuristic).
 */
const JS_CODE_PREFIXES: ReadonlyArray<string> = [
  '// const ',
  '// let ',
  '// var ',
  '// function ',
  '// class ',
  '// import ',
  '// export ',
  '// if (',
  '// for (',
  '// while (',
  '// return ',
  '// throw ',
];

/**
 * Prefixes that indicate a commented-out code line in Python.
 */
const PY_CODE_PREFIXES: ReadonlyArray<string> = [
  '# def ',
  '# class ',
  '# import ',
  '# from ',
  '# if ',
  '# for ',
  '# while ',
  '# return ',
];

/**
 * Single-line comment patterns that should NOT be flagged
 * (handled by the todo-tracker or are clearly not code).
 * Applied to the trimmed line before prefix matching.
 */
const SKIP_LINE_PATTERNS: ReadonlyArray<RegExp> = [
  /^\/\/\s*(TODO|FIXME|HACK|NOTE|XXX|OPTIMIZE|BUG)[\s:]/i,
  /^#\s*(TODO|FIXME|HACK|NOTE|XXX|OPTIMIZE|BUG)[\s:]/i,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Return true if the trimmed line matches any of the skip patterns.
 * These are single-line markers that are explicitly out of scope.
 */
function isSkipLine(trimmed: string): boolean {
  return SKIP_LINE_PATTERNS.some((re) => re.test(trimmed));
}

/**
 * Return true if the trimmed line looks like a commented-out code line
 * for JS/TS files.
 */
function isJsCodeLine(trimmed: string): boolean {
  if (isSkipLine(trimmed)) return false;
  return JS_CODE_PREFIXES.some((prefix) => trimmed.startsWith(prefix));
}

/**
 * Return true if the trimmed line looks like a commented-out code line
 * for Python files.
 */
function isPyCodeLine(trimmed: string): boolean {
  if (isSkipLine(trimmed)) return false;
  return PY_CODE_PREFIXES.some((prefix) => trimmed.startsWith(prefix));
}

/**
 * Build a stable finding ID from file + start line.
 * Falls back to UUID if inputs are empty.
 */
function buildFindingId(file: string, startLine: number): string {
  if (file && startLine > 0) {
    const raw = `commented-code:${file}:${startLine}`;
    let hash = 0;
    for (let i = 0; i < raw.length; i++) {
      hash = (Math.imul(31, hash) + raw.charCodeAt(i)) >>> 0;
    }
    return `cc-${hash.toString(16).padStart(8, '0')}`;
  }
  return randomUUID();
}

/**
 * Truncate and clean a line for use in a finding message preview.
 * Strips the leading comment marker and excess whitespace.
 */
function previewLine(raw: string): string {
  const trimmed = raw.trim();
  // Remove leading // or # comment markers for the preview
  const stripped = trimmed.replace(/^\/\/\s*/, '').replace(/^#\s*/, '');
  return stripped.length > 80 ? stripped.slice(0, 77) + '...' : stripped;
}

// ---------------------------------------------------------------------------
// Block flusher
// ---------------------------------------------------------------------------

/**
 * Given a completed run of matching comment lines, emit a Finding if the
 * block meets the minimum size threshold.
 */
function flushBlock(
  block: Array<{ lineNumber: number; raw: string }>,
  filePath: string,
  findings: Finding[],
): void {
  if (block.length < MIN_BLOCK_SIZE) return;

  const startLine = block[0].lineNumber;
  const preview = previewLine(block[0].raw);

  findings.push({
    id: buildFindingId(filePath, startLine),
    layer: 'static',
    tool: 'commented-code',
    type: 'commented-out-code',
    severity: 'info',
    confidence: CONFIDENCE,
    file: filePath,
    line: startLine,
    endLine: block[block.length - 1].lineNumber,
    message: `Commented-out code block (${block.length} lines) starting with: ${preview}`,
    suggestion: 'Remove commented-out code. Use version control to recover deleted code instead.',
    meta: {
      blockSize: block.length,
    },
  });
}

// ---------------------------------------------------------------------------
// Per-file analysis
// ---------------------------------------------------------------------------

/**
 * Analyse a JS/TS file for consecutive commented-out code lines.
 *
 * Algorithm:
 *   Walk lines. For each line past the license header window, check if it
 *   is a // code line. Accumulate into a running block. When the run breaks
 *   (non-matching line), flush the block.
 */
function analyzeJsTs(lines: string[], filePath: string): Finding[] {
  const findings: Finding[] = [];
  let block: Array<{ lineNumber: number; raw: string }> = [];

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1; // 1-indexed
    const trimmed = lines[i].trim();

    // Skip lines inside the license header window.
    if (lineNumber <= LICENSE_HEADER_LINES) continue;

    if (isJsCodeLine(trimmed)) {
      block.push({ lineNumber, raw: lines[i] });
    } else {
      flushBlock(block, filePath, findings);
      block = [];
    }
  }

  // Flush any trailing block at end of file.
  flushBlock(block, filePath, findings);

  return findings;
}

/**
 * Analyse a Python file for consecutive commented-out code lines.
 *
 * Triple-quoted strings used as block comments are intentionally skipped:
 * they are valid docstring syntax and distinguishing code from prose
 * inside them would require full AST parsing, making the heuristic
 * unreliable. We focus only on # line comments for Python.
 */
function analyzePython(lines: string[], filePath: string): Finding[] {
  const findings: Finding[] = [];
  let block: Array<{ lineNumber: number; raw: string }> = [];

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const trimmed = lines[i].trim();

    if (lineNumber <= LICENSE_HEADER_LINES) continue;

    if (isPyCodeLine(trimmed)) {
      block.push({ lineNumber, raw: lines[i] });
    } else {
      flushBlock(block, filePath, findings);
      block = [];
    }
  }

  flushBlock(block, filePath, findings);

  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/**
 * Detects blocks of commented-out code in JS/TS and Python source files.
 *
 * Uses line-level heuristics — no AST, no external dependencies.
 * Conservative by design: requires 3+ consecutive matching lines and
 * skips license headers, test files, and todo-style comments.
 */
export class CommentedCodeAnalyzer implements Analyzer {
  readonly name = 'CommentedCode';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const targetFiles = (context.changedFiles ?? context.files).filter(
      (f) => !TEST_FILE.test(f) && (JS_TS_EXT.test(f) || PYTHON_EXT.test(f)),
    );

    if (targetFiles.length === 0) return [];

    const allFindings: Finding[] = [];

    await Promise.allSettled(
      targetFiles.map(async (filePath) => {
        let content: string;
        try {
          content = await readFile(filePath, 'utf8');
        } catch {
          // Unreadable file — skip silently. The OS permission issue or
          // race condition is not our concern here.
          return;
        }

        const lines = content.split('\n');
        let fileFindings: Finding[];

        if (JS_TS_EXT.test(filePath)) {
          fileFindings = analyzeJsTs(lines, filePath);
        } else {
          fileFindings = analyzePython(lines, filePath);
        }

        allFindings.push(...fileFindings);
      }),
    );

    return allFindings;
  }
}
