import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import madge from 'madge';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';

// ---------------------------------------------------------------------------
// MadgeCircularAnalyzer
//
// Detects circular dependency chains using madge's programmatic API.
// Each distinct cycle becomes one Finding — severity 'warning', confidence 1.0,
// layer 'static', tool 'madge'.
//
// The `file` field is set to the first module in the cycle (the canonical
// "entry point" of the loop). The full chain is captured in `message`,
// `related`, and `meta.chain` so callers can render it however they need.
//
// Error handling: any failure in madge (missing binary, unsupported syntax,
// etc.) is caught and logged; the analyzer returns [] rather than throwing.
// ---------------------------------------------------------------------------

export class MadgeCircularAnalyzer implements Analyzer {
  readonly name = 'madge-circular';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    if (!context.config.analyzers.static.circularDeps) {
      return [];
    }

    const { rootDir, config } = context;

    let circles: string[][];

    try {
      const instance = await madge(rootDir, {
        baseDir: rootDir,
        fileExtensions: ['ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs'],
        excludeRegExp: buildExcludePattern(config.ignore),
        detectiveOptions: {
          // Support TypeScript path aliases and ES modules
          es6: { mixedImports: true },
          ts: { mixedImports: true },
        },
      });

      circles = instance.circular();
    } catch (err) {
      // Non-fatal: madge can fail on certain syntax (e.g., decorators without
      // a tsconfig, or missing peer deps). Log and return clean.
      const message = err instanceof Error ? err.message : String(err);
      console.warn(`[codesentinel] madge failed — skipping circular analysis: ${message}`);
      return [];
    }

    if (circles.length === 0) {
      return [];
    }

    return circles.map((chain) => buildFinding(chain, rootDir));
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Converts the ignore list from SentinelConfig into a single RegExp that
 * madge's `excludeRegExp` option accepts.
 *
 * Each entry is treated as a literal path segment to exclude (not a glob).
 * node_modules is always excluded regardless of config.
 */
function buildExcludePattern(ignore: string[]): RegExp[] {
  const segments = Array.from(new Set(['node_modules', ...ignore]));
  return segments.map((s) => new RegExp(escapeRegExp(s)));
}

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Builds a unified Finding for a single circular dependency chain.
 *
 * @param chain  Array of relative module paths forming the cycle, as returned
 *               by madge. The cycle wraps back to chain[0] implicitly.
 * @param rootDir  Absolute project root — used to construct absolute file paths.
 */
function buildFinding(chain: string[], rootDir: string): Finding {
  // Render as: A → B → C → A
  const rendered = [...chain, chain[0]].join(' -> ');

  // `file` is the first module in the chain — the canonical representative.
  const firstFile = join(rootDir, chain[0]);

  // All modules in the chain (absolute paths) go into `related` so reporters
  // can highlight every affected file, not just the entry.
  const related = chain.map((seg) => join(rootDir, seg));

  return {
    id: randomUUID(),
    layer: 'static',
    type: 'circular-dependency',
    severity: 'warning',
    confidence: 1.0,
    file: firstFile,
    message: `Circular dependency detected: ${rendered}`,
    tool: 'madge',
    suggestion:
      'Break the cycle by extracting shared logic into a new module that neither participant imports, ' +
      'or by restructuring the dependency direction.',
    related,
    meta: {
      chain,
      chainLength: chain.length,
      renderedChain: rendered,
    },
  };
}
