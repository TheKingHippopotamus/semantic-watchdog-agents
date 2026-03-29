// ============================================================
// CodeSentinel — Orchestrator
// ============================================================
//
// Central coordinator for all analysis layers. Responsibilities:
//
//   1. Build AnalysisContext from a root directory and optional
//      changed-file list.
//   2. Run Layer 1 (static) analyzers in parallel via
//      Promise.allSettled — failures are warned and skipped.
//   3. Run Layer 2 (secrets) analyzers in parallel alongside
//      Layer 1 (no dependency).
//   4. Run Layer 3 (semantic) analyzers after Layer 1 completes
//      so orphan findings from the static layer can be passed
//      to the IntentAnalyzer.
//   5. Collect all findings, apply the confidence gate, sort by
//      severity then confidence desc.
//   6. Select and invoke the configured reporter.
//
// Incremental scanning: when changedFiles is provided, each
// analyzer uses changedFiles to limit re-work where possible.
// The context is still built with the full file list so
// cross-file analysis (duplication, drift) remains accurate.
//
// Timing: each analyzer invocation is timed. Results are logged
// at debug level for performance profiling.
// ============================================================

import { join } from 'node:path';
import type {
  Finding,
  SentinelConfig,
  AnalysisContext,
  Analyzer,
  Reporter,
  FileChangeEvent,
  OrchestratorLike,
} from './types.js';
import { getCacheDir } from './analyzers/semantic/cache.js';
import { scanFiles, getIgnorePatterns } from './utils/git.js';
import { groupDuplicateFindings } from './utils/grouper.js';

// ── Static analyzers ─────────────────────────────────────────────────────────
import { DependencyAnalyzer } from './analyzers/static/dependencies.js';
import { MadgeCircularAnalyzer as CircularAnalyzer } from './analyzers/static/circular.js';
import { DeadCodeAnalyzer } from './analyzers/static/dead-code.js';
import { SecurityAnalyzer } from './analyzers/static/security.js';
import { AstPatternAnalyzer } from './analyzers/static/ast-patterns.js';
import { ComplexityAnalyzer } from './analyzers/static/complexity.js';
import { TodoTrackerAnalyzer } from './analyzers/static/todo-tracker.js';
import { CommentedCodeAnalyzer } from './analyzers/static/commented-code.js';
import { PythonSecurityAnalyzer } from './analyzers/static/python-security.js';
import { DockerSecurityAnalyzer } from './analyzers/static/docker-security.js';
import { PythonDeadCodeAnalyzer } from './analyzers/static/python-deadcode.js';
import { TestCoverageAnalyzer } from './analyzers/static/test-coverage.js';
import { DeadDirectoryAnalyzer } from './analyzers/static/dead-dirs.js';
import { CrossProjectDuplicationAnalyzer } from './analyzers/static/cross-project-dup.js';
import { ConfigStalenessAnalyzer } from './analyzers/static/config-staleness.js';

// ── Secrets analyzers ────────────────────────────────────────────────────────
import { GitleaksAnalyzer } from './analyzers/secrets/gitleaks.js';
import { RegexFallbackAnalyzer as RegexSecretAnalyzer } from './analyzers/secrets/fallback.js';

// ── Semantic analyzers ───────────────────────────────────────────────────────
import { Embedder } from './analyzers/semantic/embedder.js';
import { SemanticDuplicationAnalyzer as DuplicationAnalyzer } from './analyzers/semantic/duplication.js';
import { DriftAnalyzer } from './analyzers/semantic/drift.js';
import { IntentAnalyzer } from './analyzers/semantic/intent.js';

// ── Reporters ────────────────────────────────────────────────────────────────
import { TerminalReporter } from './reporter/terminal.js';
import { JsonReporter } from './reporter/json.js';
import { SarifReporter } from './reporter/sarif.js';
import { AgentReporter } from './reporter/agent.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Per-analyzer timing record collected during each scan. */
interface AnalyzerTiming {
  name: string;
  layer: string;
  durationMs: number;
  findingCount: number;
  status: 'ok' | 'error';
  error?: string;
}

// ---------------------------------------------------------------------------
// Severity ordering for sort
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<Finding['severity'], number> = {
  error:   0,
  warning: 1,
  info:    2,
};

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

export class Orchestrator implements OrchestratorLike {
  private readonly config: SentinelConfig;

  constructor(config: SentinelConfig) {
    this.config = config;
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Run a full (or incremental) analysis scan.
   *
   * @param rootDir       Absolute path to the project root.
   * @param changedFiles  Optional list of changed file absolute paths.
   *                      When provided, analyzers that support incremental
   *                      analysis will restrict work to these files while
   *                      cross-file analyzers still operate on the full set.
   * @returns             Filtered and sorted Finding array.
   */
  async scan(rootDir: string, changedFiles?: string[]): Promise<Finding[]> {
    const context = await this.buildContext(rootDir, changedFiles);

    if (context.files.length === 0) {
      return [];
    }

    const timings: AnalyzerTiming[] = [];
    const allFindings: Finding[] = [];

    // ── Layer 1 + Layer 2 in parallel ───────────────────────────────────────
    const [layer1Findings, layer2Findings] = await Promise.all([
      this.runLayer1(context, timings),
      this.runLayer2(context, timings),
    ]);

    allFindings.push(...layer1Findings, ...layer2Findings);

    // ── Layer 3 (semantic) — after Layer 1 so orphans are available ─────────
    const orphanFindings = layer1Findings.filter(
      (f) => f.type === 'orphan-module',
    );

    const layer3Findings = await this.runLayer3(context, orphanFindings, timings);
    allFindings.push(...layer3Findings);

    // ── Apply confidence gate ────────────────────────────────────────────────
    const threshold = this.config.confidenceThreshold;
    const gated = allFindings.filter((f) => f.confidence >= threshold);

    // ── Collapse per-function duplication floods into directory summaries ─────
    // When two directories contain many semantically similar function pairs the
    // raw findings list can grow to hundreds of entries that obscure the real
    // signal.  groupDuplicateFindings collapses any directory pair that has
    // more than 5 findings into a single summary finding, keeping the rest.
    const grouped = groupDuplicateFindings(gated, rootDir);

    // ── Sort: errors first, then by confidence desc ──────────────────────────
    const sorted = sortFindings(grouped);

    this.logTimings(timings);

    return sorted;
  }

  /**
   * Invoke the configured reporter with the provided findings.
   */
  async report(findings: Finding[]): Promise<void> {
    const reporter = this.selectReporter();
    await reporter.report(findings, this.config);
  }

  /**
   * Run a full scan starting at the configured rootDir.
   * Convenience wrapper used by the CLI's scan and watch commands.
   */
  async runFullScan(): Promise<Finding[]> {
    return this.scan(this.config.rootDir);
  }

  /**
   * Implements OrchestratorLike — re-run analysis scoped to changed files
   * then emit findings via the configured reporter.
   * Called by the Watcher on each debounced batch of file-system events.
   */
  async runOnChanges(events: FileChangeEvent[]): Promise<void> {
    const changedFiles = events.map((e) => e.path);
    const findings = await this.scan(this.config.rootDir, changedFiles);
    await this.report(findings);
  }

  /**
   * Return the absolute path of the embedding cache directory for the
   * configured rootDir.  Used by the CLI's clear-cache command.
   */
  getCachePath(): string {
    return getCacheDir(this.config.rootDir);
  }

  // ── Context building ───────────────────────────────────────────────────────

  private async buildContext(
    rootDir: string,
    changedFiles?: string[],
  ): Promise<AnalysisContext> {
    // Merge config.ignore with .gitignore / .sentinelignore patterns.
    const ignorePatterns = [
      ...this.config.ignore,
      ...getIgnorePatterns(rootDir),
    ];

    // scanFiles returns relative paths — normalise to absolute.
    const relativeFiles = await scanFiles(rootDir, ignorePatterns);
    const absoluteFiles = relativeFiles.map((rel) => join(rootDir, rel));

    // Normalise changedFiles to absolute paths if provided.
    let resolvedChangedFiles: string[] | undefined;
    if (changedFiles && changedFiles.length > 0) {
      resolvedChangedFiles = changedFiles.map((f) =>
        f.startsWith('/') ? f : join(rootDir, f),
      );

      // Filter changed files to only those that exist in the scanned set.
      const absoluteSet = new Set(absoluteFiles);
      resolvedChangedFiles = resolvedChangedFiles.filter((f) =>
        absoluteSet.has(f),
      );
    }

    return {
      rootDir,
      files: absoluteFiles,
      changedFiles: resolvedChangedFiles,
      config: this.config,
    };
  }

  // ── Layer runners ──────────────────────────────────────────────────────────

  /**
   * Layer 1: static analyzers.
   * All six run in parallel via Promise.allSettled.
   * Returns the merged finding array from all succeeded analyzers.
   */
  private async runLayer1(
    context: AnalysisContext,
    timings: AnalyzerTiming[],
  ): Promise<Finding[]> {
    if (!this.config.analyzers.static.enabled) {
      return [];
    }

    const analyzers: Analyzer[] = [];

    if (this.config.analyzers.static.dependencies) {
      analyzers.push(new DependencyAnalyzer());
    }

    if (this.config.analyzers.static.circularDeps) {
      analyzers.push(new CircularAnalyzer());
    }

    if (this.config.analyzers.static.deadCode) {
      analyzers.push(new DeadCodeAnalyzer());
      analyzers.push(new PythonDeadCodeAnalyzer());
      analyzers.push(new DeadDirectoryAnalyzer());
    }

    if (this.config.analyzers.static.security) {
      analyzers.push(new SecurityAnalyzer());
      analyzers.push(new AstPatternAnalyzer());
      analyzers.push(new PythonSecurityAnalyzer());
      analyzers.push(new DockerSecurityAnalyzer());
    }

    if (this.config.analyzers.static.complexity) {
      analyzers.push(new ComplexityAnalyzer());
    }

    // TODO tracker runs unconditionally whenever the static layer is enabled.
    // It is a pure text scan (no AST, no external process) so it is always fast.
    analyzers.push(new TodoTrackerAnalyzer());

    // Commented-out code detector runs unconditionally — pure text scan,
    // no external process. Conservative (3+ consecutive lines) to keep noise low.
    analyzers.push(new CommentedCodeAnalyzer());

    // Config staleness detector runs unconditionally — scans config files for
    // dead path references, hardcoded localhost URLs, stale ports, and duplicate
    // keys across config files. Pure file-system + text scan, no external process.
    analyzers.push(new ConfigStalenessAnalyzer());

    if (this.config.analyzers.static.testCoverage) {
      analyzers.push(new TestCoverageAnalyzer());
    }

    if (this.config.analyzers.static.crossProjectDuplication) {
      analyzers.push(new CrossProjectDuplicationAnalyzer());
    }

    return this.runAnalyzersParallel(analyzers, context, timings);
  }

  /**
   * Layer 2: secrets analyzers.
   * Gitleaks and regex fallback run in parallel.
   */
  private async runLayer2(
    context: AnalysisContext,
    timings: AnalyzerTiming[],
  ): Promise<Finding[]> {
    if (!this.config.analyzers.secrets.enabled) {
      return [];
    }

    const analyzers: Analyzer[] = [];

    if (this.config.analyzers.secrets.useGitleaks) {
      analyzers.push(new GitleaksAnalyzer());
    }

    if (this.config.analyzers.secrets.regexFallback) {
      analyzers.push(new RegexSecretAnalyzer());
    }

    return this.runAnalyzersParallel(analyzers, context, timings);
  }

  /**
   * Layer 3: semantic analyzers.
   *
   * Duplication and Drift run in parallel.
   * IntentAnalyzer runs after both — it receives orphan findings from
   * the static layer to identify which files need intent recovery.
   *
   * @param orphanFindings  Findings with type 'orphan-module' from Layer 1.
   */
  private async runLayer3(
    context: AnalysisContext,
    orphanFindings: Finding[],
    timings: AnalyzerTiming[],
  ): Promise<Finding[]> {
    if (!this.config.analyzers.semantic.enabled) {
      return [];
    }

    // ── Shared Embedder — load the 125 MB model exactly once ────────────────
    // All three semantic analyzers accept an optional embedder parameter for
    // injection.  We create and initialise a single instance here so the model
    // is loaded once rather than three times.
    const embedder = new Embedder();
    await embedder.init();

    // ── Duplication + Drift in parallel ─────────────────────────────────────
    const baseAnalyzers: Analyzer[] = [];

    if (this.config.analyzers.semantic.duplication) {
      baseAnalyzers.push(new DuplicationAnalyzer(embedder));
    }

    if (this.config.analyzers.semantic.drift) {
      baseAnalyzers.push(new DriftAnalyzer(embedder));
    }

    const baseFindings = await this.runAnalyzersParallel(
      baseAnalyzers,
      context,
      timings,
    );

    // ── Intent recovery — requires orphan findings from Layer 1 ─────────────
    const intentFindings = await this.runIntentAnalyzer(
      context,
      orphanFindings,
      timings,
      embedder,
    );

    // Dispose the ONNX session now that all semantic work is complete.
    // This prevents the mutex destructor race on macOS during Node.js shutdown
    // (libc++abi: terminating due to uncaught exception ... mutex lock failed).
    embedder.dispose();

    return [...baseFindings, ...intentFindings];
  }

  /**
   * Run the IntentAnalyzer against the orphan files identified in Layer 1.
   * When incremental mode is active, restrict intent recovery to orphans
   * that overlap with the changed file set.
   */
  private async runIntentAnalyzer(
    context: AnalysisContext,
    orphanFindings: Finding[],
    timings: AnalyzerTiming[],
    embedder?: Embedder,
  ): Promise<Finding[]> {
    if (
      !this.config.analyzers.semantic.intentRecovery ||
      orphanFindings.length === 0
    ) {
      return [];
    }

    let orphanFiles = orphanFindings
      .map((f) => f.file)
      .filter((p) => p.length > 0);

    // In incremental mode, only recover intent for orphans in changed files.
    if (context.changedFiles && context.changedFiles.length > 0) {
      const changedSet = new Set(context.changedFiles);
      orphanFiles = orphanFiles.filter((p) => changedSet.has(p));

      if (orphanFiles.length === 0) {
        return [];
      }
    }

    const analyzer = new IntentAnalyzer(embedder);
    const start = Date.now();

    let findings: Finding[];
    let status: 'ok' | 'error' = 'ok';
    let errorMessage: string | undefined;

    // Pass orphan paths through context.meta.orphanFiles — the preferred
    // stateless mechanism documented in intent.ts.
    const contextWithOrphans: AnalysisContext & { meta: Record<string, unknown> } = {
      ...context,
      meta: { ...(context as AnalysisContext & { meta?: Record<string, unknown> }).meta, orphanFiles },
    };

    try {
      findings = await analyzer.analyze(contextWithOrphans);
    } catch (err) {
      errorMessage = err instanceof Error ? err.message : String(err);
      console.warn(
        `[codesentinel] Analyzer "${analyzer.name}" failed — skipping: ${errorMessage}`,
      );
      findings = [];
      status = 'error';
    }

    timings.push({
      name: analyzer.name,
      layer: analyzer.layer,
      durationMs: Date.now() - start,
      findingCount: findings.length,
      status,
      error: errorMessage,
    });

    return findings;
  }

  // ── Parallel runner ────────────────────────────────────────────────────────

  /**
   * Run an array of analyzers concurrently via Promise.allSettled.
   *
   * Failures are warned and excluded from results — one broken analyzer
   * never aborts the entire scan. Timing is recorded per analyzer.
   */
  private async runAnalyzersParallel(
    analyzers: Analyzer[],
    context: AnalysisContext,
    timings: AnalyzerTiming[],
  ): Promise<Finding[]> {
    if (analyzers.length === 0) {
      return [];
    }

    // Wrap each analyzer invocation to capture timing.
    const timedRuns = analyzers.map(async (analyzer) => {
      const start = Date.now();
      const findings = await analyzer.analyze(context);
      return { analyzer, findings, durationMs: Date.now() - start };
    });

    const results = await Promise.allSettled(timedRuns);
    const allFindings: Finding[] = [];

    for (const result of results) {
      if (result.status === 'fulfilled') {
        const { analyzer, findings, durationMs } = result.value;

        timings.push({
          name: analyzer.name,
          layer: analyzer.layer,
          durationMs,
          findingCount: findings.length,
          status: 'ok',
        });

        allFindings.push(...findings);
      } else {
        // Promise.allSettled — reason is the rejection value.
        // We cannot easily access the analyzer name here, so we log generically.
        const errorMessage =
          result.reason instanceof Error
            ? result.reason.message
            : String(result.reason);

        console.warn(
          `[codesentinel] An analyzer failed unexpectedly — skipping: ${errorMessage}`,
        );

        // Record a failure entry with unknown name (the timing wrapper itself threw).
        timings.push({
          name: 'unknown',
          layer: 'unknown',
          durationMs: 0,
          findingCount: 0,
          status: 'error',
          error: errorMessage,
        });
      }
    }

    return allFindings;
  }

  // ── Reporter selection ─────────────────────────────────────────────────────

  private selectReporter(): Reporter {
    switch (this.config.output.format) {
      case 'json':
        return new JsonReporter();
      case 'sarif':
        return new SarifReporter();
      case 'agent':
        return new AgentReporter();
      case 'terminal':
      default:
        return new TerminalReporter();
    }
  }

  // ── Logging ────────────────────────────────────────────────────────────────

  /**
   * Log per-analyzer timing when verbose mode is enabled.
   * Output goes to stderr so it does not pollute JSON/SARIF stdout.
   */
  private logTimings(timings: AnalyzerTiming[]): void {
    if (!this.config.output.verbose) {
      return;
    }

    const total = timings.reduce((sum, t) => sum + t.durationMs, 0);

    process.stderr.write('\n[codesentinel] Analyzer timings:\n');

    for (const t of timings) {
      const status = t.status === 'error' ? ` [ERROR: ${t.error ?? 'unknown'}]` : '';
      process.stderr.write(
        `  ${t.layer}/${t.name}: ${t.durationMs}ms, ${t.findingCount} finding(s)${status}\n`,
      );
    }

    process.stderr.write(`  Total: ${total}ms\n\n`);
  }
}

// ---------------------------------------------------------------------------
// Sorting
// ---------------------------------------------------------------------------

/**
 * Sort findings by:
 *   1. Severity ascending (error → warning → info)
 *   2. Confidence descending within the same severity
 */
function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const severityDiff =
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (severityDiff !== 0) return severityDiff;
    return b.confidence - a.confidence;
  });
}
