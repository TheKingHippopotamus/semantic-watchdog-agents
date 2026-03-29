// ============================================================
// CodeSentinel — ESLint Security Analyzer Adapter
// Layer: static | Tool: eslint-plugin-security
// ============================================================

import { randomUUID } from 'node:crypto';
import { ESLint } from 'eslint';
import securityPlugin from 'eslint-plugin-security';
import type { Analyzer, AnalysisContext, Finding, Severity } from '../../types.js';

// ESLint's flat-config rule severity: 0 = off, 1 = warn, 2 = error
type EslintNumericSeverity = 0 | 1 | 2;

/**
 * All rule IDs exported by eslint-plugin-security v3.
 *
 * We enumerate them explicitly rather than relying on the plugin's `recommended`
 * config so we can guarantee every rule is enabled — the recommended config
 * turns some rules off by default (e.g. detect-object-injection).
 */
const SECURITY_RULES: ReadonlyArray<string> = [
  'detect-buffer-noassert',
  'detect-child-process',
  'detect-disable-mustache-escape',
  'detect-eval-with-expression',
  'detect-new-buffer',
  'detect-no-csrf-before-method-override',
  'detect-non-literal-fs-filename',
  'detect-non-literal-regexp',
  'detect-non-literal-require',
  'detect-object-injection',
  'detect-possible-timing-attacks',
  'detect-pseudoRandomBytes',
  'detect-unsafe-regex',
  'detect-bidi-characters',
];

/**
 * Map ESLint numeric severity to our Finding severity.
 *   2 (error)   → 'error'
 *   1 (warning) → 'warning'
 *   0 (off)     → should never reach here, but fall back to 'info'
 */
function mapSeverity(eslintSeverity: EslintNumericSeverity): Severity {
  switch (eslintSeverity) {
    case 2:
      return 'error';
    case 1:
      return 'warning';
    default:
      return 'info';
  }
}

/**
 * Confidence is a function of ESLint-reported severity:
 *   error   → 0.95 (rule fired with high certainty)
 *   warning → 0.90 (rule fired but may be a false positive)
 *   info    → 0.80 (fallback — should not normally occur)
 */
function mapConfidence(severity: Severity): number {
  switch (severity) {
    case 'error':
      return 0.95;
    case 'warning':
      return 0.90;
    default:
      return 0.80;
  }
}

/**
 * Build a deterministic finding ID from rule + file + line so that identical
 * findings across repeated scans remain stable (useful for suppression lists
 * and deduplication in the reporter layer).
 */
function buildFindingId(ruleId: string, file: string, line: number): string {
  // Prefer stable IDs when we have enough signal; fall back to UUID otherwise.
  if (ruleId && file && line > 0) {
    // Simple digest-free hash — not cryptographic, just stable
    const raw = `eslint-security:${ruleId}:${file}:${line}`;
    let hash = 0;
    for (let i = 0; i < raw.length; i++) {
      hash = (Math.imul(31, hash) + raw.charCodeAt(i)) >>> 0;
    }
    return `sec-${hash.toString(16).padStart(8, '0')}`;
  }
  return randomUUID();
}

/**
 * ESLint security analyzer adapter.
 *
 * Uses ESLint's programmatic API with flat config (ESLint 9+) and
 * eslint-plugin-security to detect common Node.js/JS security anti-patterns.
 */
export class SecurityAnalyzer implements Analyzer {
  readonly name = 'ESLint Security';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { files } = context;

    // Only lint JS/TS files — ESLint has no business parsing CSS, JSON, etc.
    const lintableFiles = files.filter((f) =>
      /\.(js|mjs|cjs|ts|mts|cts|jsx|tsx)$/.test(f),
    );

    if (lintableFiles.length === 0) {
      return [];
    }

    // Build the rules map: every known security rule set to "warn" (1).
    // We emit warnings rather than errors at the lint level so ESLint does not
    // treat the run as a hard failure.  Severity in our Finding output is then
    // determined by what the linter actually reports back.
    const rulesConfig: Record<string, EslintNumericSeverity> = {};
    for (const rule of SECURITY_RULES) {
      rulesConfig[`security/${rule}`] = 1;
    }

    // Also add any rules the plugin exposes that we haven't explicitly listed,
    // in case the installed version has added new ones.
    const pluginRules = securityPlugin.rules ?? {};
    for (const ruleId of Object.keys(pluginRules)) {
      const qualifiedId = `security/${ruleId}`;
      if (!(qualifiedId in rulesConfig)) {
        rulesConfig[qualifiedId] = 1;
      }
    }

    // ESLint 9 flat config.  We pass `overrideConfigFile: false` to prevent
    // ESLint from merging in any eslint.config.js present in the project —
    // we want an isolated, reproducible security scan regardless of the
    // project's own ESLint setup.
    let eslint: ESLint;
    try {
      eslint = new ESLint({
        overrideConfigFile: true, // "true" in v9 means "use only what we provide"
        overrideConfig: [
          {
            plugins: {
              security: securityPlugin,
            },
            rules: rulesConfig,
          },
        ],
        // Do not apply project-level ignore patterns for our scan.
        // We respect our own context.config.ignore at the file-selection layer.
        ignore: false,
      });
    } catch (initErr) {
      const message = initErr instanceof Error ? initErr.message : String(initErr);
      // Return a single meta-finding so the caller knows the analyzer failed
      // rather than silently returning an empty result.
      return [buildInitErrorFinding(message)];
    }

    const findings: Finding[] = [];

    // Lint in batches to avoid overwhelming ESLint with thousands of files at
    // once — each batch still runs in a single ESLint instance so plugin
    // initialisation cost is paid once.
    const BATCH_SIZE = 50;
    for (let i = 0; i < lintableFiles.length; i += BATCH_SIZE) {
      const batch = lintableFiles.slice(i, i + BATCH_SIZE);

      let results: ESLint.LintResult[];
      try {
        results = await eslint.lintFiles(batch);
      } catch (lintErr) {
        // A batch-level error (e.g. a file that cannot be parsed at all) should
        // not abort the entire analysis — skip the batch and continue.
        const message = lintErr instanceof Error ? lintErr.message : String(lintErr);
        findings.push(buildRuntimeErrorFinding(message, batch));
        continue;
      }

      for (const result of results) {
        for (const message of result.messages) {
          // Skip messages without a rule ID (parse errors, fatal errors).
          // We handle parse/fatal errors separately below.
          if (!message.ruleId) {
            if (message.fatal) {
              findings.push(buildParseErrorFinding(result.filePath, message.message));
            }
            continue;
          }

          const eslintSeverity = (message.severity ?? 1) as EslintNumericSeverity;
          const severity = mapSeverity(eslintSeverity);
          const confidence = mapConfidence(severity);
          const line = message.line ?? 1;

          const finding: Finding = {
            id: buildFindingId(message.ruleId, result.filePath, line),
            layer: 'static',
            type: message.ruleId,
            severity,
            confidence,
            file: result.filePath,
            line,
            ...(message.endLine != null ? { endLine: message.endLine } : {}),
            message: message.message,
            tool: 'eslint-plugin-security',
            ...(message.fix != null
              ? { suggestion: 'An auto-fix is available (run eslint --fix).' }
              : {}),
            meta: {
              column: message.column,
              endColumn: message.endColumn,
              ruleId: message.ruleId,
              nodeType: message.nodeType,
            },
          };

          findings.push(finding);
        }
      }
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// Internal helpers for error findings
// ---------------------------------------------------------------------------

function buildInitErrorFinding(errorMessage: string): Finding {
  return {
    id: randomUUID(),
    layer: 'static',
    type: 'analyzer/init-error',
    severity: 'error',
    confidence: 1.0,
    file: '',
    line: 0,
    message: `SecurityAnalyzer failed to initialise ESLint: ${errorMessage}`,
    tool: 'eslint-plugin-security',
    meta: { analyzerError: true },
  };
}

function buildRuntimeErrorFinding(
  errorMessage: string,
  affectedFiles: string[],
): Finding {
  return {
    id: randomUUID(),
    layer: 'static',
    type: 'analyzer/runtime-error',
    severity: 'warning',
    confidence: 1.0,
    file: affectedFiles[0] ?? '',
    line: 0,
    message: `ESLint batch error (${affectedFiles.length} file(s) skipped): ${errorMessage}`,
    tool: 'eslint-plugin-security',
    meta: { analyzerError: true, affectedFiles },
  };
}

function buildParseErrorFinding(filePath: string, errorMessage: string): Finding {
  return {
    id: randomUUID(),
    layer: 'static',
    type: 'analyzer/parse-error',
    severity: 'warning',
    confidence: 1.0,
    file: filePath,
    line: 0,
    message: `ESLint could not parse file: ${errorMessage}`,
    tool: 'eslint-plugin-security',
    meta: { analyzerError: true },
  };
}
