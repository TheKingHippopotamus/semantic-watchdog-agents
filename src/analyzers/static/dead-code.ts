// ============================================================
// CodeSentinel — Dead Code Analyzer (knip adapter)
// ============================================================
// knip has no programmatic API. We invoke `npx knip --reporter json`
// as a child process and parse the JSON output into Finding[].
// ============================================================

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';

const execFileAsync = promisify(execFile);

// ── knip JSON output types ────────────────────────────────────────────────────

interface KnipIssueItem {
  name: string;
  line?: number;
  col?: number;
  pos?: number;
}

interface KnipEnumMember extends KnipIssueItem {
  namespace: string;
}

interface KnipFileIssue {
  file: string;
  owners?: string[];
  /** Unused production dependencies */
  dependencies?: KnipIssueItem[];
  /** Unused devDependencies */
  devDependencies?: KnipIssueItem[];
  /** Dependencies referenced in code but not listed in package.json */
  unlisted?: KnipIssueItem[];
  /** Unused exports (values) */
  exports?: KnipIssueItem[];
  /** Unused exported types */
  types?: KnipIssueItem[];
  /** Unused enum members */
  enumMembers?: KnipEnumMember[];
  /** Duplicate exports */
  duplicates?: string[];
}

interface KnipJsonOutput {
  /** One entry per file that has any finding */
  issues: KnipFileIssue[];
  /** Files that are entirely unreferenced */
  files?: string[];
}

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Stable, deterministic ID for a finding so duplicate runs produce the same ID.
 * Format: knip-{sha1 of "type:file:name:line"}
 */
function makeId(type: string, file: string, name: string, line?: number): string {
  const raw = `${type}:${file}:${name}:${line ?? 0}`;
  return `knip-${createHash('sha1').update(raw).digest('hex').slice(0, 12)}`;
}

/**
 * Convert an absolute path to a path relative to rootDir so messages are
 * readable regardless of where the tool is invoked.
 */
function rel(rootDir: string, filePath: string): string {
  return relative(rootDir, filePath);
}

// ── adapter ───────────────────────────────────────────────────────────────────

export class DeadCodeAnalyzer implements Analyzer {
  readonly name = 'dead-code';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { rootDir } = context;

    let stdout: string;

    // SEC-02: Resolve knip from the project's own node_modules to avoid
    // executing unpinned registry code via `npx --yes`. The `--yes` flag is
    // intentionally absent from the fallback as well — if knip is not
    // installed, the invocation will fail rather than silently pull a
    // potentially-compromised release from the registry.
    const localKnipBin = join(rootDir, 'node_modules', '.bin', 'knip');
    const [cmd, args] = existsSync(localKnipBin)
      ? ([localKnipBin, ['--reporter', 'json', '--no-exit-code']] as const)
      : (['npx', ['knip', '--reporter', 'json', '--no-exit-code']] as const);

    try {
      const result = await execFileAsync(
        cmd,
        args,
        {
          cwd: rootDir,
          // knip can be slow on large repos; 5 min ceiling
          timeout: 300_000,
          maxBuffer: 50 * 1024 * 1024, // 50 MB
        },
      );
      stdout = result.stdout;
    } catch (err: unknown) {
      // execFile rejects when the process exits non-zero OR times out.
      // We still try to parse stdout if it was populated (knip may exit 1
      // when it finds issues despite --no-exit-code not being honoured by
      // older versions).
      const execErr = err as NodeJS.ErrnoException & { stdout?: string; stderr?: string };

      if (execErr.stdout) {
        stdout = execErr.stdout;
      } else {
        const reason =
          execErr.code === 'ENOENT'
            ? 'knip binary not found — install knip as a project dependency (`npm install --save-dev knip`)'
            : execErr.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
              ? 'knip output exceeded buffer limit'
              : execErr.message ?? String(err);
        console.warn(`[dead-code] knip execution failed: ${reason}`);
        return [];
      }
    }

    const trimmed = stdout.trim();
    if (!trimmed) {
      return [];
    }

    let parsed: KnipJsonOutput;
    try {
      parsed = JSON.parse(trimmed) as KnipJsonOutput;
    } catch {
      console.warn('[dead-code] Failed to parse knip JSON output — unexpected format');
      return [];
    }

    const findings: Finding[] = [];

    // ── 1. Entirely unused files ──────────────────────────────────────────────
    if (Array.isArray(parsed.files)) {
      for (const filePath of parsed.files) {
        findings.push({
          id: makeId('unused-file', filePath, filePath),
          layer: 'static',
          type: 'unused-file',
          severity: 'warning',
          confidence: 1.0,
          file: filePath,
          message: `Unused file: ${rel(rootDir, filePath)} is never imported or referenced`,
          tool: 'knip',
          suggestion: 'Remove the file if it is no longer needed, or add an entry point reference to it.',
        });
      }
    }

    // ── 2. Per-file issues ────────────────────────────────────────────────────
    if (Array.isArray(parsed.issues)) {
      for (const issue of parsed.issues) {
        const { file } = issue;
        const shortFile = rel(rootDir, file);

        // 2a. Unused exports (values)
        for (const item of issue.exports ?? []) {
          findings.push({
            id: makeId('unused-export', file, item.name, item.line),
            layer: 'static',
            type: 'unused-export',
            severity: 'warning',
            confidence: 1.0,
            file,
            line: item.line,
            message: `Unused export \`${item.name}\` in ${shortFile}`,
            tool: 'knip',
            suggestion: `Remove the export or mark it as intentional with a \`@public\` JSDoc tag.`,
            meta: { col: item.col, pos: item.pos },
          });
        }

        // 2b. Unused exported types
        for (const item of issue.types ?? []) {
          findings.push({
            id: makeId('unused-type-export', file, item.name, item.line),
            layer: 'static',
            type: 'unused-type-export',
            severity: 'warning',
            confidence: 1.0,
            file,
            line: item.line,
            message: `Unused exported type \`${item.name}\` in ${shortFile}`,
            tool: 'knip',
            suggestion: 'Remove the type export or import it somewhere in the project.',
            meta: { col: item.col, pos: item.pos },
          });
        }

        // 2c. Unused enum members
        for (const item of issue.enumMembers ?? []) {
          findings.push({
            id: makeId('unused-enum-member', file, `${item.namespace}.${item.name}`, item.line),
            layer: 'static',
            type: 'unused-enum-member',
            severity: 'warning',
            confidence: 1.0,
            file,
            line: item.line,
            message: `Unused enum member \`${item.namespace}.${item.name}\` in ${shortFile}`,
            tool: 'knip',
            suggestion: 'Remove the unused enum member.',
            meta: { col: item.col, pos: item.pos, namespace: item.namespace },
          });
        }

        // 2d. Unused production dependencies
        for (const item of issue.dependencies ?? []) {
          findings.push({
            id: makeId('unused-dependency', file, item.name, item.line),
            layer: 'static',
            type: 'unused-dependency',
            severity: 'warning',
            confidence: 1.0,
            file,
            line: item.line,
            message: `Unused dependency \`${item.name}\` listed in package.json but never imported`,
            tool: 'knip',
            suggestion: `Run \`npm uninstall ${item.name}\` to remove the unused dependency.`,
          });
        }

        // 2e. Unused devDependencies
        for (const item of issue.devDependencies ?? []) {
          findings.push({
            id: makeId('unused-dev-dependency', file, item.name, item.line),
            layer: 'static',
            type: 'unused-dev-dependency',
            severity: 'info',
            confidence: 1.0,
            file,
            line: item.line,
            message: `Unused devDependency \`${item.name}\` listed in package.json but never referenced`,
            tool: 'knip',
            suggestion: `Run \`npm uninstall --save-dev ${item.name}\` if it is not needed.`,
          });
        }

        // 2f. Unlisted (used but not declared in package.json)
        for (const item of issue.unlisted ?? []) {
          findings.push({
            id: makeId('unlisted-dependency', file, item.name),
            layer: 'static',
            type: 'unlisted-dependency',
            severity: 'error',
            confidence: 1.0,
            file,
            message: `Unlisted dependency \`${item.name}\` is imported in ${shortFile} but missing from package.json`,
            tool: 'knip',
            suggestion: `Run \`npm install ${item.name}\` and add it to package.json.`,
          });
        }

        // 2g. Duplicate exports (same name exported from multiple files)
        for (const name of issue.duplicates ?? []) {
          findings.push({
            id: makeId('duplicate-export', file, name),
            layer: 'static',
            type: 'duplicate-export',
            severity: 'info',
            confidence: 1.0,
            file,
            message: `Duplicate export \`${name}\` in ${shortFile} — the same name is exported from multiple files`,
            tool: 'knip',
            suggestion: 'Consolidate exports to a single canonical location.',
          });
        }
      }
    }

    return findings;
  }
}
