// ============================================================
// CodeSentinel — Python Security Analyzer
// Layer: static | Tools: bandit (primary), regex (fallback)
// ============================================================
//
// Strategy:
//   1. Probe for the `bandit` binary via `which` / `where`.
//   2. If found, run `bandit -r <dir> -f json --severity-level medium`
//      and map its JSON output to Finding[].
//   3. If not found, fall through to built-in regex pattern scanning
//      over every .py file in the analysis context.
//
// Only .py files are ever processed — all other files are skipped
// unconditionally at the per-file level.
// ============================================================

import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import type { Analyzer, AnalysisContext, Finding, Severity } from '../../types.js';

const execFileAsync = promisify(execFile);

// ── Constants ────────────────────────────────────────────────────────────────

const PYTHON_EXTENSION = '.py';

// ── Bandit JSON schema ────────────────────────────────────────────────────────

/**
 * A single issue emitted by `bandit -f json`.
 * Only the fields we consume are declared; the schema has more.
 */
interface BanditIssue {
  filename: string;
  line_number: number;
  line_range: number[];
  issue_text: string;
  issue_severity: 'LOW' | 'MEDIUM' | 'HIGH';
  issue_confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  test_id: string;
  test_name: string;
  more_info: string;
}

interface BanditOutput {
  results: BanditIssue[];
  errors?: Array<{ filename: string; reason: string }>;
}

// ── Regex pattern catalogue ───────────────────────────────────────────────────

interface RegexRule {
  /** Unique rule identifier — used as Finding.type */
  id: string;
  /** Human-readable name */
  name: string;
  /** Pattern to test against each source line */
  pattern: RegExp;
  severity: Severity;
  confidence: number;
  message: string;
  suggestion: string;
}

/**
 * All regex rules are tested line-by-line against the file content.
 * Rules with negative-lookahead exclusions (e.g. yaml.load safe-loader
 * check) compile their lookahead into the pattern directly.
 */
const REGEX_RULES: RegexRule[] = [
  {
    id: 'py-eval',
    name: 'Arbitrary code execution via eval()',
    pattern: /\beval\s*\(/,
    severity: 'error',
    confidence: 0.9,
    message: 'Use of eval() allows arbitrary code execution',
    suggestion: 'Avoid eval(). Use ast.literal_eval() for safe expression parsing or redesign to eliminate dynamic evaluation.',
  },
  {
    id: 'py-exec',
    name: 'Arbitrary code execution via exec()',
    pattern: /\bexec\s*\(/,
    severity: 'error',
    confidence: 0.9,
    message: 'Use of exec() allows arbitrary code execution',
    suggestion: 'Avoid exec(). Refactor dynamic code generation to static function dispatch or a plugin registry.',
  },
  {
    id: 'py-pickle-load',
    name: 'Insecure deserialization via pickle',
    pattern: /\bpickle\.loads?\s*\(/,
    severity: 'error',
    confidence: 0.95,
    message: 'pickle.load / pickle.loads deserializes arbitrary objects — deserialization attack vector',
    suggestion: 'Never unpickle data from untrusted sources. Use json, msgpack, or protobuf for data exchange.',
  },
  {
    id: 'py-yaml-unsafe-load',
    name: 'Insecure YAML deserialization',
    // Match yaml.load( that is NOT followed by Loader=SafeLoader or Loader=yaml.SafeLoader
    // The negative lookahead covers the argument immediately after the opening paren
    // as well as cases where the Loader kwarg appears anywhere before the closing paren
    // by checking the remainder of the line.
    pattern: /\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)/,
    severity: 'error',
    confidence: 0.9,
    message: 'yaml.load() without Loader=SafeLoader can execute arbitrary Python objects',
    suggestion: 'Replace with yaml.safe_load() or explicitly pass Loader=yaml.SafeLoader.',
  },
  {
    id: 'py-subprocess-shell',
    name: 'Command injection via subprocess with shell=True',
    pattern: /\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/,
    severity: 'error',
    confidence: 0.9,
    message: 'subprocess called with shell=True enables command injection if any argument is user-controlled',
    suggestion: 'Pass arguments as a list and omit shell=True. If shell features are required, sanitize all inputs rigorously.',
  },
  {
    id: 'py-os-system',
    name: 'Command injection via os.system()',
    pattern: /\bos\.system\s*\(/,
    severity: 'error',
    confidence: 0.85,
    message: 'os.system() passes commands to the shell — command injection risk',
    suggestion: 'Replace with subprocess.run([...]) using a list of arguments to avoid shell interpretation.',
  },
  {
    id: 'py-dynamic-import',
    name: 'Dynamic import via __import__()',
    pattern: /\b__import__\s*\(/,
    severity: 'warning',
    confidence: 0.8,
    message: '__import__() with dynamic module names can load attacker-controlled code',
    suggestion: 'Use importlib.import_module() with an explicit allowlist of permitted module names.',
  },
  {
    id: 'py-input-py2',
    name: 'Python 2 input() evaluates expressions',
    // input() in a Python 2 file — heuristic: file contains 'print ' (no parens) or python2 shebang
    // We flag the call site and let the message explain the context.
    pattern: /\binput\s*\(/,
    severity: 'warning',
    confidence: 0.6,
    message: 'input() in Python 2 evaluates the expression — equivalent to eval(raw_input())',
    suggestion: 'In Python 2, use raw_input() instead. In Python 3, input() is safe but still validate the value.',
  },
  {
    id: 'py-bare-except',
    name: 'Silent error swallowing via bare except',
    // Matches `except:` or `except Exception:` (with optional `as e`) followed by pass
    // We do a two-part match: first detect the except clause, then check if the body is pass.
    // Since we scan line by line we split this into two rules detected via a stateful pass.
    pattern: /^\s*except\s*(?:Exception(?:\s+as\s+\w+)?\s*)?:/,
    severity: 'warning',
    confidence: 0.7,
    message: 'Bare except clause may silently swallow exceptions including KeyboardInterrupt and SystemExit',
    suggestion: 'Catch specific exception types. At minimum log the error before ignoring it.',
  },
  {
    id: 'py-assert-validation',
    name: 'assert used for input validation',
    pattern: /^\s*assert\b/,
    severity: 'warning',
    confidence: 0.65,
    message: 'assert statements are stripped when Python runs with -O (optimize flag) — do not use for validation',
    suggestion: 'Replace with explicit if/raise for security or input validation checks.',
  },
  {
    id: 'py-weak-hash-md5',
    name: 'Weak hashing algorithm MD5',
    pattern: /\bhashlib\.md5\b/,
    severity: 'warning',
    confidence: 0.85,
    message: 'MD5 is cryptographically broken and unsuitable for security-sensitive hashing',
    suggestion: 'Use hashlib.sha256() or hashlib.sha3_256() for security purposes. MD5 is acceptable only for checksums.',
  },
  {
    id: 'py-weak-hash-sha1',
    name: 'Weak hashing algorithm SHA-1',
    pattern: /\bhashlib\.sha1\b/,
    severity: 'warning',
    confidence: 0.8,
    message: 'SHA-1 is cryptographically weak and collision-prone',
    suggestion: 'Use hashlib.sha256() or hashlib.sha3_256() instead. SHA-1 is deprecated for all security uses.',
  },
];

// ── Severity / confidence mapping for bandit output ──────────────────────────

/**
 * Maps bandit's textual severity to our Finding severity.
 * bandit HIGH → error, MEDIUM → warning, LOW → info.
 */
function mapBanditSeverity(severity: BanditIssue['issue_severity']): Severity {
  switch (severity) {
    case 'HIGH':   return 'error';
    case 'MEDIUM': return 'warning';
    case 'LOW':    return 'info';
  }
}

/**
 * Maps bandit's textual confidence to a 0–1 float.
 * HIGH → 0.9, MEDIUM → 0.75, LOW → 0.6.
 */
function mapBanditConfidence(confidence: BanditIssue['issue_confidence']): number {
  switch (confidence) {
    case 'HIGH':   return 0.9;
    case 'MEDIUM': return 0.75;
    case 'LOW':    return 0.6;
  }
}

// ── Binary probe ─────────────────────────────────────────────────────────────

/**
 * Returns the absolute path of the bandit binary, or null if not installed.
 * Mirrors the same pattern used by the Gitleaks adapter.
 */
async function resolveBanditBinary(): Promise<string | null> {
  const command = process.platform === 'win32' ? 'where' : 'which';
  try {
    const { stdout } = await execFileAsync(command, ['bandit']);
    const resolved = stdout.trim().split('\n')[0].trim();
    return resolved.length > 0 ? resolved : null;
  } catch {
    return null;
  }
}

// ── Bandit runner ─────────────────────────────────────────────────────────────

/**
 * Spawns `bandit -r <dir> -f json --severity-level medium` and parses the
 * JSON report into Finding[].
 *
 * bandit exits 1 when issues are found — we handle that as a normal result.
 */
async function runBandit(binary: string, rootDir: string): Promise<Finding[]> {
  const args = [
    '-r', rootDir,
    '-f', 'json',
    '--severity-level', 'medium',
    '--quiet',
  ];

  let stdout: string;

  try {
    const result = await execFileAsync(binary, args, {
      maxBuffer: 64 * 1024 * 1024,  // 64 MB
    });
    stdout = result.stdout;
  } catch (err: unknown) {
    // bandit exits 1 when issues are found — execFile rejects, but stdout
    // contains the JSON report. Extract it from the error object.
    if (
      err !== null &&
      typeof err === 'object' &&
      'stdout' in err &&
      typeof (err as { stdout: unknown }).stdout === 'string'
    ) {
      stdout = (err as { stdout: string }).stdout;
    } else {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[codesentinel/bandit] spawn error: ${message}\n`);
      return [];
    }
  }

  return parseBanditOutput(stdout);
}

function parseBanditOutput(stdout: string): Finding[] {
  const trimmed = stdout.trim();
  if (!trimmed) {
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    process.stderr.write(
      `[codesentinel/bandit] failed to parse JSON output: ${trimmed.slice(0, 200)}\n`,
    );
    return [];
  }

  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !Array.isArray((parsed as BanditOutput).results)
  ) {
    return [];
  }

  const output = parsed as BanditOutput;
  const findings: Finding[] = [];

  for (const issue of output.results) {
    if (!isBanditIssue(issue)) {
      continue;
    }

    findings.push({
      id: randomUUID(),
      layer: 'static',
      type: issue.test_id,
      severity: mapBanditSeverity(issue.issue_severity),
      confidence: mapBanditConfidence(issue.issue_confidence),
      file: issue.filename,
      line: issue.line_number,
      endLine:
        Array.isArray(issue.line_range) && issue.line_range.length > 1
          ? issue.line_range[issue.line_range.length - 1]
          : undefined,
      message: issue.issue_text,
      tool: 'bandit',
      suggestion: issue.more_info
        ? `See bandit documentation: ${issue.more_info}`
        : undefined,
      meta: {
        testName: issue.test_name,
        banditSeverity: issue.issue_severity,
        banditConfidence: issue.issue_confidence,
      },
    });
  }

  return findings;
}

function isBanditIssue(value: unknown): value is BanditIssue {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v['filename'] === 'string' &&
    typeof v['line_number'] === 'number' &&
    typeof v['issue_text'] === 'string' &&
    typeof v['issue_severity'] === 'string' &&
    typeof v['issue_confidence'] === 'string' &&
    typeof v['test_id'] === 'string'
  );
}

// ── Regex fallback ────────────────────────────────────────────────────────────

/**
 * Scans a single Python file line-by-line against all REGEX_RULES.
 *
 * Additional stateful logic for 'py-bare-except': when we detect a bare
 * except clause we peek at the next non-empty line to confirm the body is
 * `pass` before emitting the finding. This avoids false positives where
 * the except block actually handles the error.
 */
async function scanFileWithRegex(filePath: string): Promise<Finding[]> {
  let source: string;
  try {
    source = await readFile(filePath, 'utf-8');
  } catch {
    // File unreadable — skip silently
    return [];
  }

  const lines = source.split('\n');
  const findings: Finding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNumber = i + 1;  // 1-indexed

    for (const rule of REGEX_RULES) {
      if (!rule.pattern.test(line)) {
        continue;
      }

      // Special case: 'py-bare-except' — only emit if followed by `pass`
      if (rule.id === 'py-bare-except') {
        const bodyLine = findNextNonEmptyLine(lines, i + 1);
        if (bodyLine === null || !/^\s*pass\s*(?:#.*)?$/.test(bodyLine)) {
          // The except block has real handling — not a silent swallow
          continue;
        }
      }

      findings.push({
        id: randomUUID(),
        layer: 'static',
        type: rule.id,
        severity: rule.severity,
        confidence: rule.confidence,
        file: filePath,
        line: lineNumber,
        message: rule.message,
        tool: 'python-security-regex',
        suggestion: rule.suggestion,
        meta: {
          ruleName: rule.name,
          matchedLine: line.trim(),
        },
      });
    }
  }

  return findings;
}

/**
 * Returns the content of the next non-empty/non-comment line starting from
 * `startIndex`, or null if the end of file is reached.
 */
function findNextNonEmptyLine(lines: string[], startIndex: number): string | null {
  for (let i = startIndex; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed.length > 0 && !trimmed.startsWith('#')) {
      return lines[i];
    }
  }
  return null;
}

// ── Analyzer implementation ───────────────────────────────────────────────────

export class PythonSecurityAnalyzer implements Analyzer {
  readonly name = 'python-security';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    if (!context.config.analyzers.static.security) {
      return [];
    }

    // Scope to Python files only — either changed or all
    const targetFiles = (context.changedFiles ?? context.files).filter(
      (f) => f.endsWith(PYTHON_EXTENSION),
    );

    if (targetFiles.length === 0) {
      return [];
    }

    const binary = await resolveBanditBinary();

    if (binary !== null) {
      // Run bandit over the full rootDir so cross-file analysis is accurate.
      // changedFiles scoping is intentionally not applied here — bandit
      // runs at directory level and re-scanning is cheap relative to spawn overhead.
      return runBandit(binary, context.rootDir);
    }

    // Fallback: regex scan per file, in parallel
    process.stderr.write(
      '[codesentinel/python-security] bandit not found — using built-in regex scanner\n',
    );

    const results = await Promise.allSettled(
      targetFiles.map((f) => scanFileWithRegex(f)),
    );

    const findings: Finding[] = [];
    for (const result of results) {
      if (result.status === 'fulfilled') {
        findings.push(...result.value);
      }
    }

    return findings;
  }
}
