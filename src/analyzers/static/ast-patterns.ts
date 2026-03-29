// ============================================================
// CodeSentinel — AST-Grep Security Pattern Analyzer
// ============================================================
// Uses @ast-grep/napi to detect common security vulnerabilities
// via structural AST pattern matching across JS/TS source files.
// ============================================================

import { readFile } from 'node:fs/promises';
import { extname } from 'node:path';
import { parse, Lang } from '@ast-grep/napi';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';

// ─── Language Resolution ───────────────────────────────────────────────────

const EXT_TO_LANG: Readonly<Record<string, Lang>> = {
  '.js':  Lang.JavaScript,
  '.mjs': Lang.JavaScript,
  '.cjs': Lang.JavaScript,
  '.jsx': Lang.JavaScript,
  '.ts':  Lang.TypeScript,
  '.mts': Lang.TypeScript,
  '.cts': Lang.TypeScript,
  '.tsx': Lang.Tsx,
};

function langForFile(filePath: string): Lang | null {
  return EXT_TO_LANG[extname(filePath).toLowerCase()] ?? null;
}

// ─── Pattern Definitions ───────────────────────────────────────────────────

interface PatternDef {
  /** Unique pattern identifier, becomes Finding.type */
  id: string;
  /** Human-readable title */
  title: string;
  /** ast-grep pattern string */
  pattern: string;
  severity: Finding['severity'];
  /** 0–1 confidence in this pattern producing true positives */
  confidence: number;
  message: string;
  suggestion: string;
}

/**
 * Patterns targeting JS/TS constructs.
 *
 * $$$  — zero-or-more nodes (spread metavar)
 * $A   — exactly one named node
 *
 * Ordering: higher-severity patterns first so that when two patterns
 * match the same node the primary one is more likely to surface.
 */
const SECURITY_PATTERNS: readonly PatternDef[] = [
  // ── eval() ──────────────────────────────────────────────────────────────
  {
    id:         'eval-usage',
    title:      'eval() call detected',
    pattern:    'eval($$$)',
    severity:   'error',
    confidence: 0.95,
    message:    'eval() executes arbitrary code and is a critical security risk. Avoid under all circumstances.',
    suggestion: 'Replace with a safer alternative: JSON.parse() for data, Function constructors only for controlled sandboxing, or redesign to avoid dynamic code execution entirely.',
  },

  // ── new Function() ──────────────────────────────────────────────────────
  {
    id:         'new-function-dynamic',
    title:      'new Function() with non-literal arguments',
    pattern:    'new Function($$$)',
    severity:   'error',
    confidence: 0.85,
    message:    'new Function() with dynamic arguments executes arbitrary code at runtime and is equivalent to eval().',
    suggestion: 'Use a predefined function or a safe expression evaluator. Never pass user-controlled data to new Function().',
  },

  // ── child_process.exec() ────────────────────────────────────────────────
  {
    id:         'child-process-exec',
    title:      'child_process.exec() with potentially dynamic command',
    pattern:    'exec($$$)',
    severity:   'error',
    confidence: 0.80,
    message:    'child_process.exec() spawns a shell and is susceptible to command injection when its argument is not a hard-coded literal.',
    suggestion: 'Prefer execFile() or spawn() with an argument array to avoid shell expansion. Validate and sanitize all inputs before use.',
  },
  {
    id:         'child-process-exec-member',
    title:      'child_process.exec() via member access',
    pattern:    '$_.exec($$$)',
    severity:   'error',
    confidence: 0.75,
    message:    'child_process.exec() called via member expression may execute shell commands built from dynamic data.',
    suggestion: 'Switch to execFile() / spawn() with an explicit args array. Never interpolate user input into shell strings.',
  },

  // ── innerHTML ───────────────────────────────────────────────────────────
  {
    id:         'inner-html-assignment',
    title:      'innerHTML assignment (potential XSS)',
    pattern:    '$EL.innerHTML = $VAL',
    severity:   'warning',
    confidence: 0.90,
    message:    'Assigning to innerHTML with dynamic content can introduce cross-site scripting (XSS) vulnerabilities.',
    suggestion: 'Use textContent for plain text. For HTML use a sanitiser such as DOMPurify, or construct DOM nodes programmatically.',
  },
  {
    id:         'outer-html-assignment',
    title:      'outerHTML assignment (potential XSS)',
    pattern:    '$EL.outerHTML = $VAL',
    severity:   'warning',
    confidence: 0.90,
    message:    'Assigning to outerHTML with dynamic content can introduce XSS vulnerabilities.',
    suggestion: 'Reconstruct the element via DOM APIs or sanitise the value with DOMPurify before assignment.',
  },

  // ── dangerouslySetInnerHTML ──────────────────────────────────────────────
  {
    id:         'dangerously-set-inner-html',
    title:      'dangerouslySetInnerHTML usage (React XSS risk)',
    pattern:    'dangerouslySetInnerHTML={$$$}',
    severity:   'warning',
    confidence: 0.95,
    message:    'dangerouslySetInnerHTML bypasses React\'s XSS protections. Any unsanitised input becomes an injection vector.',
    suggestion: 'Sanitise the HTML string with DOMPurify before passing it. Prefer rendering React components instead of raw HTML where possible.',
  },

  // ── SQL string concatenation — template literals ─────────────────────────
  {
    id:         'sql-injection-template-select',
    title:      'SQL SELECT via template literal (injection risk)',
    pattern:    '`SELECT $$$`',
    severity:   'error',
    confidence: 0.80,
    message:    'SQL query built with a template literal. If the expression contains user-controlled data, this is a SQL injection vulnerability.',
    suggestion: 'Use parameterised queries or a prepared-statement API (e.g. knex, pg\'s $1 placeholders, mysql2\'s ?).',
  },
  {
    id:         'sql-injection-template-insert',
    title:      'SQL INSERT via template literal (injection risk)',
    pattern:    '`INSERT $$$`',
    severity:   'error',
    confidence: 0.80,
    message:    'SQL INSERT query built with a template literal is susceptible to SQL injection.',
    suggestion: 'Use parameterised queries or an ORM that handles escaping.',
  },
  {
    id:         'sql-injection-template-update',
    title:      'SQL UPDATE via template literal (injection risk)',
    pattern:    '`UPDATE $$$`',
    severity:   'error',
    confidence: 0.80,
    message:    'SQL UPDATE query built with a template literal is susceptible to SQL injection.',
    suggestion: 'Use parameterised queries or an ORM that handles escaping.',
  },
  {
    id:         'sql-injection-template-delete',
    title:      'SQL DELETE via template literal (injection risk)',
    pattern:    '`DELETE $$$`',
    severity:   'error',
    confidence: 0.80,
    message:    'SQL DELETE query built with a template literal is susceptible to SQL injection.',
    suggestion: 'Use parameterised queries or an ORM that handles escaping.',
  },

  // ── fs.readFile with dynamic path ────────────────────────────────────────
  {
    id:         'fs-readfile-dynamic-path',
    title:      'fs.readFile() with potentially dynamic path',
    pattern:    'fs.readFile($PATH, $$$)',
    severity:   'warning',
    confidence: 0.75,
    message:    'fs.readFile() called with a path variable. If the path originates from user input this may allow path traversal attacks.',
    suggestion: 'Resolve paths against a known root with path.resolve() and verify the result stays within the intended directory. Reject paths containing "..".',
  },
  {
    id:         'fs-readfile-sync-dynamic-path',
    title:      'fs.readFileSync() with potentially dynamic path',
    pattern:    'fs.readFileSync($PATH, $$$)',
    severity:   'warning',
    confidence: 0.75,
    message:    'fs.readFileSync() called with a path variable. Unsanitised user-supplied paths enable path traversal.',
    suggestion: 'Canonicalise the path with path.resolve() and assert it is a child of the expected base directory.',
  },

  // ── fs.writeFile with dynamic path ──────────────────────────────────────
  {
    id:         'fs-writefile-dynamic-path',
    title:      'fs.writeFile() with potentially dynamic path',
    pattern:    'fs.writeFile($PATH, $$$)',
    severity:   'warning',
    confidence: 0.75,
    message:    'fs.writeFile() called with a path variable. Attacker-controlled paths allow arbitrary file writes.',
    suggestion: 'Validate and canonicalise the destination path. Ensure it resolves inside a safe, controlled directory.',
  },
  {
    id:         'fs-writefile-sync-dynamic-path',
    title:      'fs.writeFileSync() with potentially dynamic path',
    pattern:    'fs.writeFileSync($PATH, $$$)',
    severity:   'warning',
    confidence: 0.75,
    message:    'fs.writeFileSync() called with a path variable. Attacker-controlled paths allow arbitrary file writes.',
    suggestion: 'Validate and canonicalise the destination path. Ensure it resolves inside a safe, controlled directory.',
  },
] as const;

// ─── Literal-argument Guard ────────────────────────────────────────────────

/**
 * Kinds that represent syntactically fixed values — i.e. not influenced by
 * runtime data. Used to reduce false positives on patterns where passing a
 * literal is generally safe (e.g. `new Function("x", "return x")` is still
 * risky but not an _injection_ risk the same way a variable is).
 *
 * We intentionally keep this list narrow so we err on the side of flagging.
 */
const LITERAL_KINDS = new Set([
  'string',
  'number',
  'template_string',          // un-interpolated template literal
  'true',
  'false',
  'null',
  'undefined',
]);

/**
 * Returns true when every argument node in a call is a literal kind —
 * meaning there is no runtime-variable data flowing in.
 *
 * This is deliberately conservative: if any argument is not a literal we
 * assume the worst.
 */
function allArgsAreLiterals(node: ReturnType<ReturnType<typeof parse>['root']>): boolean {
  const args = node.children().filter(
    (c) => String(c.kind()) === 'arguments',
  );
  if (args.length === 0) return false;
  const argList = args[0]!.children().filter(
    (c) => String(c.kind()) !== '(' && String(c.kind()) !== ')' && String(c.kind()) !== ',',
  );
  if (argList.length === 0) return false;
  return argList.every((a) => LITERAL_KINDS.has(String(a.kind())));
}

// ─── ID generation ────────────────────────────────────────────────────────

let _seq = 0;
function nextId(): string {
  return `ast-grep-${Date.now()}-${(_seq++).toString(36)}`;
}

// ─── Main Analyzer ────────────────────────────────────────────────────────

export class AstPatternAnalyzer implements Analyzer {
  readonly name  = 'ast-grep-security';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { confidenceThreshold } = context.config;
    const findings: Finding[] = [];

    // Work only on files parseable as JS/TS
    const targets = context.files.filter((f) => langForFile(f) !== null);

    for (const filePath of targets) {
      const lang = langForFile(filePath)!;
      let source: string;

      try {
        source = await readFile(filePath, 'utf-8');
      } catch (err) {
        // Unreadable files are silently skipped — permissions or race condition
        continue;
      }

      let root: ReturnType<ReturnType<typeof parse>['root']>;
      try {
        root = parse(lang, source).root();
      } catch {
        // Syntax errors are not security findings; skip gracefully
        continue;
      }

      for (const def of SECURITY_PATTERNS) {
        if (def.confidence < confidenceThreshold) continue;

        let matches: ReturnType<typeof root.findAll>;
        try {
          matches = root.findAll(def.pattern);
        } catch {
          // Pattern unsupported for this language variant — skip silently
          continue;
        }

        for (const match of matches) {
          // ── Literal-only argument guard ──────────────────────────────
          // For patterns where dynamic data is the actual risk, skip
          // call sites where every argument is a compile-time literal.
          // This reduces noise on harmless uses like:
          //   new Function("a", "return a + 1")  (still worth reviewing
          //   but not an injection risk per se — we keep it flagged).
          // We only suppress for fs.readFile/writeFile family when the
          // path is a plain string literal.
          if (
            (def.id === 'fs-readfile-dynamic-path'       ||
             def.id === 'fs-readfile-sync-dynamic-path'  ||
             def.id === 'fs-writefile-dynamic-path'      ||
             def.id === 'fs-writefile-sync-dynamic-path')
          ) {
            const pathArg = match.getMatch('PATH');
            if (pathArg && LITERAL_KINDS.has(String(pathArg.kind()))) {
              // Hard-coded path — not a dynamic-path finding
              continue;
            }
          }

          // For new Function() only flag when at least one arg is non-literal
          if (def.id === 'new-function-dynamic' && allArgsAreLiterals(match)) {
            continue;
          }

          const rng  = match.range();
          // ast-grep lines are 0-indexed; Finding.line is 1-indexed
          const line    = rng.start.line + 1;
          const endLine = rng.end.line + 1;

          findings.push({
            id:         nextId(),
            layer:      'static',
            type:       def.id,
            severity:   def.severity,
            confidence: def.confidence,
            file:       filePath,
            line,
            endLine:    endLine !== line ? endLine : undefined,
            message:    def.message,
            tool:       'ast-grep',
            suggestion: def.suggestion,
            meta: {
              patternTitle: def.title,
              matchedText:  match.text(),
              kind:         String(match.kind()),
            },
          });
        }
      }
    }

    return findings;
  }
}

// Default export for dynamic import / registry patterns
export default AstPatternAnalyzer;
