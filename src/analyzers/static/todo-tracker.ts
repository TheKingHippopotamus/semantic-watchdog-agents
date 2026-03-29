// ============================================================
// CodeSentinel — TODO/FIXME/HACK Comment Tracker
// ============================================================
//
// Scans all files in the analysis context for well-known
// technical-debt comment markers:
//
//   TODO        → severity 'info'   (planned work, not urgent)
//   FIXME       → severity 'warning' (known breakage, needs fixing)
//   HACK        → severity 'warning' (intentional shortcut, fragile)
//   XXX         → severity 'warning' (danger, review required)
//   WORKAROUND  → severity 'warning' (non-canonical solution)
//   TEMP/TEMPORARY → severity 'warning' (should be removed)
//   DEPRECATED  → severity 'warning' (in comments, not decorators)
//
// All findings are deterministic (confidence: 1.0), layer: 'static'.
// Binary files and unreadable files are silently skipped.
// Files matching context.config.ignore patterns are excluded.
// ============================================================

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import type { Analyzer, AnalysisContext, Finding, Severity } from '../../types.js';

// ---------------------------------------------------------------------------
// Marker definitions
// ---------------------------------------------------------------------------

interface MarkerDef {
  /** Regex that matches the marker keyword inside a comment context. */
  pattern: RegExp;
  /** Finding type emitted for this marker. */
  type: string;
  /** Severity level. */
  severity: Severity;
}

/**
 * Ordered list of markers.  Each entry's regex is applied to the full
 * trimmed line so we can capture the surrounding comment text.
 *
 * All patterns are case-insensitive to catch `todo`, `Todo`, `TODO` etc.
 *
 * DEPRECATED is matched only inside comment syntax (#, //, /*, *) to
 * avoid false-positives from @deprecated JSDoc tags or decorator usage —
 * those are structural annotations, not comment reminders.
 */
const MARKERS: MarkerDef[] = [
  {
    pattern: /(?:^|[\s/\-*#;!])TODO\b/i,
    type: 'todo-comment',
    severity: 'info',
  },
  {
    pattern: /(?:^|[\s/\-*#;!])FIXME\b/i,
    type: 'fixme-comment',
    severity: 'warning',
  },
  {
    pattern: /(?:^|[\s/\-*#;!])HACK\b/i,
    type: 'hack-comment',
    severity: 'warning',
  },
  {
    pattern: /(?:^|[\s/\-*#;!])XXX\b/i,
    type: 'xxx-comment',
    severity: 'warning',
  },
  {
    pattern: /(?:^|[\s/\-*#;!])WORKAROUND\b/i,
    type: 'workaround-comment',
    severity: 'warning',
  },
  {
    // Match TEMP or TEMPORARY
    pattern: /(?:^|[\s/\-*#;!])TEMP(?:ORARY)?\b/i,
    type: 'temp-comment',
    severity: 'warning',
  },
  {
    // Only match DEPRECATED when it appears after a comment-opening token.
    // This prevents matching `@deprecated` JSDoc tags (which start with @)
    // and TypeScript `@deprecated` decorator-adjacent annotations.
    pattern: /(?:[/\-*#;!]+\s*)DEPRECATED\b/i,
    type: 'deprecated-comment',
    severity: 'warning',
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Deterministic finding ID: sha1 of "type:file:line".
 * Same issue always produces the same ID across runs — stable for deduplication.
 */
function makeId(type: string, file: string, line: number): string {
  return createHash('sha1')
    .update(`${type}:${file}:${line}`)
    .digest('hex')
    .slice(0, 12);
}

/**
 * Return true when the Buffer's first 8 KB contains a null byte —
 * a reliable heuristic for binary content.
 */
function looksLikeBinary(buf: Buffer): boolean {
  const sampleLength = Math.min(buf.length, 8192);
  for (let i = 0; i < sampleLength; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

/**
 * Build a Set of ignore path prefixes from the config's ignore array.
 * We normalise to absolute paths so that membership tests are O(1).
 */
function buildIgnoreSet(rootDir: string, ignorePatterns: string[]): Set<string> {
  const set = new Set<string>();
  for (const pattern of ignorePatterns) {
    // Support both absolute entries and relative names like "node_modules"
    if (pattern.startsWith('/')) {
      set.add(pattern);
    } else {
      set.add(join(rootDir, pattern));
    }
  }
  return set;
}

/**
 * Return true if the file path falls inside any of the ignore prefixes.
 */
function isIgnored(filePath: string, ignorePrefixes: Set<string>): boolean {
  for (const prefix of ignorePrefixes) {
    if (filePath === prefix || filePath.startsWith(prefix + '/')) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

export class TodoTrackerAnalyzer implements Analyzer {
  readonly name = 'todo-tracker';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { files, rootDir, config } = context;

    // Build the hard-coded ignore prefixes plus anything from config.
    const baseIgnore = ['node_modules', '.git', 'dist', ...config.ignore];
    const ignorePrefixes = buildIgnoreSet(rootDir, baseIgnore);

    const findings: Finding[] = [];

    for (const filePath of files) {
      // ── Ignore check ─────────────────────────────────────────────────────
      if (isIgnored(filePath, ignorePrefixes)) {
        continue;
      }

      // ── Read file ────────────────────────────────────────────────────────
      let buf: Buffer;
      try {
        buf = readFileSync(filePath);
      } catch {
        // Unreadable file (permissions, broken symlink, etc.) — skip silently.
        continue;
      }

      // ── Skip binary files ────────────────────────────────────────────────
      if (looksLikeBinary(buf)) {
        continue;
      }

      const content = buf.toString('utf-8');
      const lines = content.split('\n');

      // ── Scan line by line ────────────────────────────────────────────────
      for (let i = 0; i < lines.length; i++) {
        const lineNumber = i + 1; // 1-based
        const line = lines[i];

        for (const marker of MARKERS) {
          if (!marker.pattern.test(line)) {
            continue;
          }

          // Truncate the comment text at 200 characters for the message.
          const commentText = line.trim().slice(0, 200);

          findings.push({
            id: makeId(marker.type, filePath, lineNumber),
            layer: 'static',
            tool: 'todo-tracker',
            type: marker.type,
            severity: marker.severity,
            confidence: 1.0,
            file: filePath,
            line: lineNumber,
            message: `${marker.type.replace('-comment', '').toUpperCase()} comment found: ${commentText}`,
            suggestion:
              marker.severity === 'info'
                ? 'Track this TODO in the issue tracker and remove the comment once resolved.'
                : 'Address this comment — it indicates known technical debt or fragile code.',
            meta: {
              markerType: marker.type,
              commentText,
            },
          });

          // One finding per line per marker — first match wins to avoid
          // double-reporting a line that contains e.g. both HACK and FIXME.
          break;
        }
      }
    }

    return findings;
  }
}

export default new TodoTrackerAnalyzer();
