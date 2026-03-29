// ============================================================
// CodeSentinel — Python Dead Code Analyzer (vulture adapter)
// ============================================================
//
// Strategy:
//   1. Attempt to invoke `vulture <dir> --min-confidence 80`
//      via child_process and parse its line-based output.
//   2. If vulture is not installed (ENOENT) fall back to a
//      regex-based detector that catches:
//        - Unused imports (import X / from X import Y where the
//          imported name never appears in the rest of the file)
//        - Duplicate imports (same module imported more than once)
//        - Unused function parameters (basic textual heuristic)
//
// Only .py files are processed; all others are silently skipped.
// ============================================================

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { relative } from 'node:path';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Stable deterministic finding ID.
 * Format: py-deadcode-{sha1 of "type:file:detail:line"}
 */
function makeId(
  type: string,
  file: string,
  detail: string,
  line?: number,
): string {
  const raw = `${type}:${file}:${detail}:${line ?? 0}`;
  return `py-deadcode-${createHash('sha1').update(raw).digest('hex').slice(0, 12)}`;
}

/** Shorten a path to be relative to rootDir for human-readable messages. */
function rel(rootDir: string, filePath: string): string {
  return relative(rootDir, filePath);
}

// ---------------------------------------------------------------------------
// Vulture output parser
// ---------------------------------------------------------------------------

/**
 * Vulture line format:
 *   path/to/file.py:42: unused import 'os' (90% confidence)
 *   path/to/file.py:10: unused variable 'x' (60% confidence)
 *
 * We parse: file, line, description, confidence.
 */
const VULTURE_LINE_RE =
  /^(.+\.py):(\d+):\s+(.+?)\s+\((\d+)%\s+confidence\)\s*$/;

interface VultureEntry {
  file: string;
  line: number;
  description: string;
  confidence: number;
}

function parseVultureOutput(stdout: string, rootDir: string): VultureEntry[] {
  const entries: VultureEntry[] = [];

  for (const raw of stdout.split('\n')) {
    const line = raw.trim();
    if (!line) continue;

    const m = VULTURE_LINE_RE.exec(line);
    if (!m) continue;

    const [, filePart, linePart, description, confPart] = m;

    // vulture emits paths relative to its cwd (rootDir) — make absolute.
    const file = filePart.startsWith('/')
      ? filePart
      : `${rootDir}/${filePart}`;

    entries.push({
      file,
      line: parseInt(linePart, 10),
      description: description.trim(),
      confidence: parseInt(confPart, 10) / 100,
    });
  }

  return entries;
}

/**
 * Map a vulture description to a Finding type string and severity.
 * Examples:
 *   "unused import 'os'"       → type: unused-import,   severity: warning
 *   "unused variable 'x'"     → type: unused-variable,  severity: info
 *   "unused function 'foo'"   → type: unused-function,  severity: warning
 *   "unused attribute 'bar'"  → type: unused-attribute, severity: warning
 *   "unreachable code"        → type: unreachable-code, severity: warning
 */
function classifyVultureDescription(description: string): {
  type: string;
  severity: Finding['severity'];
} {
  const lower = description.toLowerCase();

  if (lower.startsWith('unused import')) {
    return { type: 'unused-import', severity: 'warning' };
  }
  if (lower.startsWith('unused variable')) {
    return { type: 'unused-variable', severity: 'info' };
  }
  if (lower.startsWith('unused function')) {
    return { type: 'unused-function', severity: 'warning' };
  }
  if (lower.startsWith('unused class')) {
    return { type: 'unused-class', severity: 'warning' };
  }
  if (lower.startsWith('unused attribute')) {
    return { type: 'unused-attribute', severity: 'warning' };
  }
  if (lower.startsWith('unused method')) {
    return { type: 'unused-method', severity: 'warning' };
  }
  if (lower.startsWith('unused property')) {
    return { type: 'unused-property', severity: 'warning' };
  }
  if (lower.includes('unreachable')) {
    return { type: 'unreachable-code', severity: 'warning' };
  }

  return { type: 'py-dead-code', severity: 'warning' };
}

function vultureEntriesToFindings(
  entries: VultureEntry[],
  rootDir: string,
): Finding[] {
  return entries.map((entry) => {
    const { type, severity } = classifyVultureDescription(entry.description);
    const shortFile = rel(rootDir, entry.file);

    return {
      id: makeId(type, entry.file, entry.description, entry.line),
      layer: 'static' as const,
      type,
      severity,
      confidence: entry.confidence,
      file: entry.file,
      line: entry.line,
      message: `${entry.description} in ${shortFile}:${entry.line}`,
      tool: 'vulture',
      suggestion: buildVultureSuggestion(type),
    };
  });
}

function buildVultureSuggestion(type: string): string {
  switch (type) {
    case 'unused-import':
      return 'Remove the import statement or add a `# noqa` comment if it is a re-export.';
    case 'unused-variable':
      return 'Remove the variable or prefix its name with `_` to signal intentional non-use.';
    case 'unused-function':
    case 'unused-method':
      return 'Remove the definition or add it to `__all__` if it is a public API.';
    case 'unused-class':
      return 'Remove the class or verify it is referenced through dynamic dispatch.';
    case 'unused-attribute':
    case 'unused-property':
      return 'Remove the attribute or ensure it is accessed somewhere in the codebase.';
    case 'unreachable-code':
      return 'Remove or fix the unreachable code block.';
    default:
      return 'Review and remove the dead code if it is no longer needed.';
  }
}

// ---------------------------------------------------------------------------
// Regex fallback — operates on a single Python file's text
// ---------------------------------------------------------------------------

/**
 * Parsed import record from a Python file.
 */
interface PyImport {
  /** The name as it will be referenced in the source (`import os` → `os`,
   *  `import os.path as osp` → `osp`, `from os import path` → `path`). */
  name: string;
  /** Original import statement for display. */
  statement: string;
  /** 1-based line number. */
  line: number;
  /** Canonical module string (e.g. "os", "os.path"). */
  module: string;
}

/**
 * Returns all `import X`, `import X as Y`, `from M import X`, and
 * `from M import X as Y` statements at the top-level of the file.
 *
 * "Top-level" is approximated by stopping at the first non-import,
 * non-comment, non-blank, non-docstring line — good enough for the
 * heuristic fallback.
 */
function extractImports(lines: string[]): PyImport[] {
  const imports: PyImport[] = [];

  // Match: import foo, import foo.bar, import foo as bar
  const IMPORT_RE = /^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?\s*(?:#.*)?$/;
  // Match: from foo import bar, from foo import bar as baz
  // Also handles `from foo import (bar, baz)` partially — we simplify to single-name
  const FROM_IMPORT_RE =
    /^\s*from\s+([\w.]+)\s+import\s+(\w+)(?:\s+as\s+(\w+))?\s*(?:#.*)?$/;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();

    // Stop scanning once we are clearly inside a function/class body.
    // A line that starts with `def ` or `class ` at column 0 signals that
    // module-level imports are done (crude but effective for the fallback).
    if (/^(def |class )\w/.test(trimmed) && i > 0) {
      // Keep going — imports can technically appear after class defs in the
      // same module, but they are unusual. We collect ALL matching lines.
    }

    const imp = IMPORT_RE.exec(trimmed);
    if (imp) {
      const [, module, alias] = imp;
      const name = alias ?? module.split('.')[0];
      imports.push({
        name,
        statement: trimmed,
        line: i + 1,
        module,
      });
      continue;
    }

    const fromImp = FROM_IMPORT_RE.exec(trimmed);
    if (fromImp) {
      const [, module, symbol, alias] = fromImp;
      const name = alias ?? symbol;
      imports.push({
        name,
        statement: trimmed,
        line: i + 1,
        module,
      });
    }
  }

  return imports;
}

/**
 * Returns true when `name` appears anywhere in `text` outside of its own
 * import line.  We use a word-boundary regex to avoid false positives such as
 * `os` matching inside `osmosis`.
 */
function nameUsedInText(name: string, text: string, importLine: number): boolean {
  // Build a version of the text with the import line removed so we do not
  // count the declaration itself.
  const lines = text.split('\n');
  lines.splice(importLine - 1, 1, '');
  const textWithoutImport = lines.join('\n');

  // Escape any regex special chars in the identifier (identifiers typically
  // have none, but be safe).
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`\\b${escaped}\\b`);
  return re.test(textWithoutImport);
}

interface RegexFinding {
  type:
    | 'unused-import'
    | 'duplicate-import'
    | 'unused-parameter';
  name: string;
  line: number;
  extra?: string;
}

/**
 * Detect unused imports and duplicate imports in a single Python file.
 */
function detectImportIssues(
  lines: string[],
  fullText: string,
): RegexFinding[] {
  const findings: RegexFinding[] = [];
  const imports = extractImports(lines);

  // Duplicate detection: track (module → first import line)
  const seen = new Map<string, number>();

  for (const imp of imports) {
    // Duplicate check: same module + same local name imported twice.
    const key = `${imp.module}::${imp.name}`;
    if (seen.has(key)) {
      findings.push({
        type: 'duplicate-import',
        name: imp.module,
        line: imp.line,
        extra: `first seen at line ${seen.get(key)}`,
      });
    } else {
      seen.set(key, imp.line);
    }

    // Unused check: name never referenced outside the import statement.
    if (!nameUsedInText(imp.name, fullText, imp.line)) {
      findings.push({
        type: 'unused-import',
        name: imp.name,
        line: imp.line,
        extra: imp.statement,
      });
    }
  }

  return findings;
}

/**
 * Detect unused function parameters in a single Python file.
 *
 * Approach:
 *   - Find every `def funcName(param1, param2, ...):` block.
 *   - Extract the function body (lines with greater indentation).
 *   - Report any parameter name that never appears in the body.
 *
 * Limitations (acceptable for a heuristic fallback):
 *   - Does not parse type annotations — `param: SomeType` is handled.
 *   - Ignores *args, **kwargs, `self`, `cls`.
 *   - Does not handle multi-line parameter lists.
 *   - Indentation-based body extraction may be fooled by nested functions.
 */
function detectUnusedParams(lines: string[]): RegexFinding[] {
  const findings: RegexFinding[] = [];

  // Matches: def funcname(param1, param2=default, *args, **kwargs):
  const DEF_RE = /^(\s*)def\s+\w+\s*\(([^)]*)\)\s*(?:->\s*[^:]+)?\s*:/;

  for (let i = 0; i < lines.length; i++) {
    const m = DEF_RE.exec(lines[i]);
    if (!m) continue;

    const baseIndent = m[1].length;
    const rawParams = m[2];

    // Parse parameter names, stripping annotations, defaults, */**/self/cls.
    const paramNames: string[] = [];
    for (const rawParam of rawParams.split(',')) {
      const stripped = rawParam
        .replace(/\*\*?/, '')     // remove ** or *
        .replace(/:.*/, '')       // remove annotation
        .replace(/=.*/, '')       // remove default
        .trim();

      if (
        !stripped ||
        stripped === 'self' ||
        stripped === 'cls' ||
        stripped.startsWith('/')  // positional-only separator
      ) {
        continue;
      }

      // Only accept valid Python identifiers.
      if (/^\w+$/.test(stripped)) {
        paramNames.push(stripped);
      }
    }

    if (paramNames.length === 0) continue;

    // Collect body: lines after the def with strictly greater indentation.
    const bodyLines: string[] = [];
    for (let j = i + 1; j < lines.length; j++) {
      const bodyLine = lines[j];
      const trimmedBody = bodyLine.trimStart();

      // Blank lines or comment-only lines are part of the body.
      if (trimmedBody === '' || trimmedBody.startsWith('#')) {
        bodyLines.push(bodyLine);
        continue;
      }

      const lineIndent = bodyLine.length - trimmedBody.length;
      if (lineIndent > baseIndent) {
        bodyLines.push(bodyLine);
      } else {
        // Back to base or shallower indent — body is over.
        break;
      }
    }

    const bodyText = bodyLines.join('\n');

    for (const param of paramNames) {
      const escaped = param.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(`\\b${escaped}\\b`);
      if (!re.test(bodyText)) {
        findings.push({
          type: 'unused-parameter',
          name: param,
          line: i + 1,
        });
      }
    }
  }

  return findings;
}

/**
 * Run all regex-based detections on a single .py file and return Finding[].
 */
async function analyzeFileWithRegex(
  filePath: string,
  rootDir: string,
): Promise<Finding[]> {
  let source: string;
  try {
    source = await readFile(filePath, 'utf8');
  } catch {
    return [];
  }

  const lines = source.split('\n');
  const findings: Finding[] = [];
  const shortFile = rel(rootDir, filePath);

  // ── Import issues ──────────────────────────────────────────────────────────
  const importIssues = detectImportIssues(lines, source);

  for (const issue of importIssues) {
    if (issue.type === 'unused-import') {
      findings.push({
        id: makeId('unused-import', filePath, issue.name, issue.line),
        layer: 'static' as const,
        type: 'unused-import',
        severity: 'warning',
        confidence: 0.7,
        file: filePath,
        line: issue.line,
        message: `Unused import '${issue.name}' in ${shortFile}:${issue.line}`,
        tool: 'regex-fallback',
        suggestion:
          'Remove the import statement if the name is not used, or add `# noqa` if it is a deliberate re-export.',
        meta: { statement: issue.extra },
      });
    } else if (issue.type === 'duplicate-import') {
      findings.push({
        id: makeId('duplicate-import', filePath, issue.name, issue.line),
        layer: 'static' as const,
        type: 'duplicate-import',
        severity: 'warning',
        confidence: 0.9,
        file: filePath,
        line: issue.line,
        message: `Duplicate import '${issue.name}' in ${shortFile}:${issue.line} (${issue.extra ?? ''})`,
        tool: 'regex-fallback',
        suggestion: 'Remove the duplicate import statement.',
      });
    }
  }

  // ── Unused parameters ─────────────────────────────────────────────────────
  const paramIssues = detectUnusedParams(lines);

  for (const issue of paramIssues) {
    findings.push({
      id: makeId('unused-parameter', filePath, issue.name, issue.line),
      layer: 'static' as const,
      type: 'unused-parameter',
      severity: 'info',
      confidence: 0.6,
      file: filePath,
      line: issue.line,
      message: `Unused parameter '${issue.name}' in function at ${shortFile}:${issue.line}`,
      tool: 'regex-fallback',
      suggestion:
        "Prefix the parameter with `_` (e.g. `_param`) to signal intentional non-use, or remove it if the caller doesn't require it.",
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

export class PythonDeadCodeAnalyzer implements Analyzer {
  readonly name = 'python-dead-code';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { rootDir, files, changedFiles } = context;

    // Filter to Python files only.
    const targetFiles = (changedFiles ?? files).filter((f) =>
      f.endsWith('.py'),
    );

    if (targetFiles.length === 0) {
      return [];
    }

    // ── Try vulture first ──────────────────────────────────────────────────
    const vultureResult = await this.tryVulture(rootDir);

    if (vultureResult !== null) {
      // Vulture ran successfully — filter to files in scope.
      const targetSet = new Set(targetFiles);
      return vultureResult.filter((f) => targetSet.has(f.file));
    }

    // ── Regex fallback ─────────────────────────────────────────────────────
    const allFindings: Finding[] = [];

    await Promise.all(
      targetFiles.map(async (filePath) => {
        const fileFindings = await analyzeFileWithRegex(filePath, rootDir);
        allFindings.push(...fileFindings);
      }),
    );

    return allFindings;
  }

  /**
   * Attempt to run vulture against rootDir.
   *
   * Returns:
   *   - Finding[] when vulture executed and produced parseable output.
   *   - null when vulture is not installed (ENOENT) — triggers fallback.
   *
   * Any other error is logged and treated as "vulture unavailable" so the
   * fallback kicks in rather than surfacing an unintelligible stack trace.
   */
  private async tryVulture(rootDir: string): Promise<Finding[] | null> {
    let stdout: string;

    try {
      const result = await execFileAsync(
        'vulture',
        [rootDir, '--min-confidence', '80'],
        {
          cwd: rootDir,
          // vulture can be slow on large repos; 3 min ceiling
          timeout: 180_000,
          maxBuffer: 20 * 1024 * 1024, // 20 MB
        },
      );
      stdout = result.stdout;
    } catch (err: unknown) {
      const execErr = err as NodeJS.ErrnoException & {
        stdout?: string;
        stderr?: string;
        code?: string | number;
      };

      // ENOENT → vulture not installed; use fallback silently.
      if (execErr.code === 'ENOENT') {
        return null;
      }

      // vulture exits with code 1 when it finds dead code (not an error).
      // execFile rejects in that case but stdout may still contain results.
      if (execErr.stdout) {
        stdout = execErr.stdout;
      } else {
        // Some other failure (timeout, permission denied, etc.) — log and
        // fall back to regex.
        const reason =
          execErr.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
            ? 'vulture output exceeded buffer limit'
            : execErr.message ?? String(err);
        console.warn(
          `[python-dead-code] vulture execution failed, using regex fallback: ${reason}`,
        );
        return null;
      }
    }

    const trimmed = stdout.trim();
    if (!trimmed) {
      // Vulture ran and found nothing — return empty (no fallback needed).
      return [];
    }

    const entries = parseVultureOutput(trimmed, rootDir);
    return vultureEntriesToFindings(entries, rootDir);
  }
}
