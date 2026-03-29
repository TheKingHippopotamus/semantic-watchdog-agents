// ============================================================
// CodeSentinel — Dependency-Cruiser Analyzer Adapter
// Layer: static | Tool: dependency-cruiser
//
// Detects:
//   1. Orphan modules     — files with no dependents and no dependencies
//   2. Forbidden paths    — dependency edges that violate user-defined rules
//   3. Unresolved imports — import specifiers that could not be resolved
// ============================================================

import { cruise } from 'dependency-cruiser';
import { createHash } from 'node:crypto';
import { relative } from 'node:path';
import type { Analyzer, AnalysisContext, Finding, Severity } from '../../types.js';

// ── dependency-cruiser output types (inline to avoid missing @types) ──────────

interface DCDependency {
  readonly module: string;
  readonly resolved: string;
  readonly couldNotResolve: boolean;
  readonly circular?: boolean;
  readonly valid?: boolean;
  readonly rules?: ReadonlyArray<{ name: string; severity: string }>;
  readonly dependencyTypes?: ReadonlyArray<string>;
}

interface DCModule {
  readonly source: string;
  readonly orphan?: boolean;
  readonly valid?: boolean;
  readonly rules?: ReadonlyArray<{ name: string; severity: string }>;
  readonly dependencies: ReadonlyArray<DCDependency>;
  readonly dependents?: ReadonlyArray<string>;
}

interface DCViolation {
  readonly from: string;
  readonly to: string;
  readonly type: 'dependency' | 'module' | 'reachability' | 'cycle' | 'instability' | 'folder';
  readonly rule: { readonly name: string; readonly severity: string };
  readonly cycle?: ReadonlyArray<string>;
  readonly via?: ReadonlyArray<string>;
}

interface DCSummary {
  readonly violations: ReadonlyArray<DCViolation>;
  readonly error: number;
  readonly warn: number;
  readonly info: number;
}

interface DCOutput {
  readonly modules: ReadonlyArray<DCModule>;
  readonly summary: DCSummary;
}

interface DCReporterOutput {
  readonly output: string | DCOutput;
  readonly exitCode: number;
}

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Map a dependency-cruiser severity string to CodeSentinel Severity.
 * dependency-cruiser uses 'error' | 'warn' | 'info' | 'ignore'.
 * CodeSentinel uses 'error' | 'warning' | 'info'.
 */
function mapSeverity(dcSeverity: string): Severity {
  switch (dcSeverity) {
    case 'error':
      return 'error';
    case 'warn':
      return 'warning';
    default:
      return 'info';
  }
}

/**
 * Produce a stable, deterministic finding ID from its key fields.
 * Format: DEP-<type>-<hex8>
 */
function makeId(type: string, ...parts: string[]): string {
  const hash = createHash('sha1').update(parts.join('\0')).digest('hex').slice(0, 8);
  return `DEP-${type.toUpperCase().replace(/-/g, '_')}-${hash}`;
}

/**
 * Resolve the output JSON from a cruise() call.
 * The API returns IReporterOutput whose `output` field is typed as `string`
 * but is actually a pre-serialized JSON string when outputType is 'json',
 * or a plain object when outputType is not specified.
 * We handle both defensively.
 */
function parseCruiseOutput(raw: unknown): DCOutput {
  if (typeof raw === 'string') {
    return JSON.parse(raw) as DCOutput;
  }
  return raw as DCOutput;
}

// ── analyzer ──────────────────────────────────────────────────────────────────

export class DependencyAnalyzer implements Analyzer {
  readonly name = 'dependency-cruiser';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { rootDir, config } = context;

    // Skip entirely if the dependencies sub-analyzer is disabled.
    if (!config.analyzers.static.dependencies) {
      return [];
    }

    // Build the list of entry points for the cruise.
    // dependency-cruiser walks the full import graph starting from these.
    // We pass the root directory; dependency-cruiser will discover files.
    const entryPoints = [rootDir];

    let cruiseOutput: DCOutput;

    try {
      const result = (await cruise(entryPoints, {
        outputType: 'json',
        // Exclude the same directories CodeSentinel globally ignores.
        // The 'exclude' option accepts a plain regex string directly.
        exclude: buildExcludePattern(config.ignore),
        // Enable orphan detection as a built-in rule.
        // This is dependency-cruiser's native "no-orphans" rule.
        ruleSet: {
          forbidden: [
            {
              name: 'no-orphans',
              comment: 'Modules that are not reachable from any other module',
              severity: 'warn',
              from: { orphan: true },
              to: {},
            },
          ],
        },
        // Ensure TypeScript paths and tsconfig paths are resolved correctly
        // when a tsconfig.json is present.
        tsConfig: {
          fileName: 'tsconfig.json',
        },
      })) as DCReporterOutput;

      cruiseOutput = parseCruiseOutput(result.output);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.warn(
        `[dependency-cruiser] Analysis failed — skipping dependency findings. Reason: ${message}`,
      );
      return [];
    }

    const findings: Finding[] = [];

    // ── 1. Orphan modules ────────────────────────────────────────────────────
    // dependency-cruiser marks a module as orphan when it has no dependencies
    // AND no other module depends on it.  The built-in rule fires this as a
    // violation, but we also cross-check the module-level `orphan` flag
    // directly so we don't require the ruleSet to catch them.
    const orphanSources = new Set<string>();

    for (const mod of cruiseOutput.modules) {
      if (mod.orphan === true && !orphanSources.has(mod.source)) {
        orphanSources.add(mod.source);
        const filePath = resolveSource(rootDir, mod.source);

        findings.push({
          id: makeId('orphan', mod.source),
          layer: 'static',
          type: 'orphan-module',
          severity: 'warning',
          confidence: 1.0,
          file: filePath,
          message: `Orphan module: no other module imports "${relative(rootDir, filePath)}" and it imports nothing`,
          tool: 'dependency-cruiser',
          suggestion:
            'Either connect this module to the rest of the codebase or remove it if it is dead code.',
          meta: { source: mod.source },
        });
      }
    }

    // ── 2. Violations (forbidden dependency paths) ───────────────────────────
    // Violations are emitted into summary.violations when a ruleSet is active.
    // We surface every non-orphan violation (orphans are already reported above).
    for (const violation of cruiseOutput.summary.violations) {
      // Skip violations that were already captured as orphan findings.
      if (violation.rule.name === 'no-orphans') {
        continue;
      }

      // Only handle dependency-type violations (not folder/instability metrics).
      if (violation.type !== 'dependency' && violation.type !== 'cycle') {
        continue;
      }

      const severity = mapSeverity(violation.rule.severity);
      const fromPath = resolveSource(rootDir, violation.from);

      const cycleDesc =
        violation.cycle && violation.cycle.length > 0
          ? ` (cycle: ${violation.cycle.join(' → ')})`
          : '';

      findings.push({
        id: makeId('forbidden', violation.rule.name, violation.from, violation.to),
        layer: 'static',
        type: 'forbidden-dependency',
        severity,
        confidence: 1.0,
        file: fromPath,
        message: `Forbidden dependency path: "${relative(rootDir, fromPath)}" → "${violation.to}" violates rule "${violation.rule.name}"${cycleDesc}`,
        tool: 'dependency-cruiser',
        suggestion: `Review the dependency from "${violation.from}" to "${violation.to}" and refactor to comply with the architectural rule "${violation.rule.name}".`,
        related: [violation.to],
        meta: {
          ruleName: violation.rule.name,
          from: violation.from,
          to: violation.to,
          violationType: violation.type,
          cycle: violation.cycle ?? [],
        },
      });
    }

    // ── 3. Unresolved imports ────────────────────────────────────────────────
    // Each dependency on a module can carry `couldNotResolve: true` when
    // dependency-cruiser cannot map the import specifier to a real file.
    // This is deterministic — if resolution fails, it will always fail.
    for (const mod of cruiseOutput.modules) {
      for (const dep of mod.dependencies) {
        if (!dep.couldNotResolve) continue;

        // Skip built-in Node core modules — they are intentionally
        // "unresolvable" as files but are not a problem.
        if (isNodeCoreModule(dep)) continue;

        const filePath = resolveSource(rootDir, mod.source);

        findings.push({
          id: makeId('unresolved', mod.source, dep.module),
          layer: 'static',
          type: 'unresolved-import',
          severity: 'error',
          confidence: 1.0,
          file: filePath,
          message: `Unresolved import: "${dep.module}" in "${relative(rootDir, filePath)}" could not be resolved to a file`,
          tool: 'dependency-cruiser',
          suggestion:
            'Verify the import path is correct, the module is installed (check package.json), and that any path aliases are configured in tsconfig or webpack.',
          meta: {
            importSpecifier: dep.module,
            resolvedAttempt: dep.resolved,
          },
        });
      }
    }

    return findings;
  }
}

// ── private utilities ─────────────────────────────────────────────────────────

/**
 * Convert the CodeSentinel ignore list into a single regex pattern string
 * accepted by dependency-cruiser's `exclude` option.
 *
 * dependency-cruiser tests this regex against each module's source path,
 * so we match any path segment that equals an ignored name.
 */
function buildExcludePattern(ignoreList: string[]): string {
  if (ignoreList.length === 0) return '(?!x)x'; // match nothing
  const escaped = ignoreList.map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return `(^|[/\\\\])(${escaped.join('|')})([/\\\\]|$)`;
}

/**
 * Resolve a module source path from dependency-cruiser (which may be relative
 * to rootDir or absolute) to an absolute path.
 */
function resolveSource(rootDir: string, source: string): string {
  if (source.startsWith('/')) return source;
  return `${rootDir}/${source}`;
}

/**
 * Return true if a dependency refers to a Node.js core built-in
 * (e.g. 'path', 'fs', 'node:path').
 * Core modules are never resolvable as files; flagging them as errors
 * would be a false positive.
 */
function isNodeCoreModule(dep: DCDependency): boolean {
  if (dep.dependencyTypes && dep.dependencyTypes.includes('core')) {
    return true;
  }
  // Fallback: match the node: prefix protocol and known core names.
  const specifier = dep.module.startsWith('node:') ? dep.module.slice(5) : dep.module;
  return NODE_CORE_MODULES.has(specifier);
}

// Minimal set — dependency-cruiser's own detection via dependencyTypes is
// authoritative; this list is a belt-and-suspenders fallback.
const NODE_CORE_MODULES = new Set<string>([
  'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
  'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
  'events', 'fs', 'http', 'http2', 'https', 'inspector', 'module', 'net',
  'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring',
  'readline', 'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls',
  'trace_events', 'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads',
  'zlib',
]);
