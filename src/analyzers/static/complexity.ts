// ============================================================
// CodeSentinel — Complexity Analyzer (typhonjs-escomplex)
// ============================================================
//
// Analyzes JS/TS files for:
//   - Cyclomatic complexity per function (flags above threshold, default 20)
//   - Maintainability index per module (flags if < 20)
//   - Halstead difficulty per function (flags statistical outliers at mean + 2σ)
//
// All findings are deterministic (confidence: 1.0), layer: 'static'.
// Unparseable files are skipped with a console.warn — never throw.
// ============================================================

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import escomplex from 'typhonjs-escomplex';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';

// ── Shapes returned by typhonjs-escomplex ───────────────────

interface HalsteadMetrics {
  vocabulary: number;
  difficulty: number;
  volume: number;
  effort: number;
  bugs: number;
  time: number;
}

interface FunctionReport {
  name: string;
  line: number;
  sloc: { logical: number; physical: number };
  params: number;
  cyclomatic: number;
  cyclomaticDensity: number;
  halstead: HalsteadMetrics;
}

interface ModuleReport {
  maintainability: number;
  dependencies: unknown[];
  aggregate: {
    sloc: { logical: number; physical: number };
    params: number;
    cyclomatic: number;
    cyclomaticDensity: number;
    halstead: HalsteadMetrics;
  };
  functions: FunctionReport[];
}

// ── Constants ───────────────────────────────────────────────

/** Maintainability index below this is considered poor (scale 0–171). */
const MAINTAINABILITY_LOW_THRESHOLD = 20;

/** JS/TS file extensions we can feed to typhonjs-escomplex. */
const SUPPORTED_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts']);

// ── Helpers ─────────────────────────────────────────────────

function fileExtension(filePath: string): string {
  const dot = filePath.lastIndexOf('.');
  return dot === -1 ? '' : filePath.slice(dot);
}

function isSupportedFile(filePath: string): boolean {
  return SUPPORTED_EXTENSIONS.has(fileExtension(filePath));
}

/**
 * Deterministic finding ID derived from file path + finding type + line so
 * the same issue always gets the same ID across runs.
 */
function makeId(type: string, file: string, line?: number): string {
  const raw = `${type}:${file}:${line ?? 0}`;
  return createHash('sha1').update(raw).digest('hex').slice(0, 12);
}

/**
 * Compute mean and population standard deviation over an array of numbers.
 * Returns { mean: 0, stddev: 0 } for empty or single-element arrays.
 */
function stats(values: number[]): { mean: number; stddev: number } {
  if (values.length === 0) return { mean: 0, stddev: 0 };
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / values.length;
  return { mean, stddev: Math.sqrt(variance) };
}

// ── Analyzer Implementation ──────────────────────────────────

export class ComplexityAnalyzer implements Analyzer {
  readonly name = 'complexity';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { files, config } = context;
    const complexityThreshold: number =
      config.analyzers.static.complexityThreshold ?? 20;

    const targetFiles = files.filter(isSupportedFile);
    if (targetFiles.length === 0) return [];

    const findings: Finding[] = [];

    // ── Per-file analysis ────────────────────────────────────
    //
    // We analyze each file independently with analyzeModule so that a parse
    // failure in one file never aborts the rest.  We collect all Halstead
    // difficulty values first (across all files) and then apply the outlier
    // threshold in a second pass — but since analyzeModule is synchronous and
    // cheap, we just do one loop and accumulate findings then post-process.

    // First pass: collect module reports.
    const moduleResults: Array<{ file: string; report: ModuleReport }> = [];

    for (const filePath of targetFiles) {
      let source: string;
      try {
        source = readFileSync(filePath, 'utf-8');
      } catch (err) {
        console.warn(`[complexity] Cannot read file, skipping: ${filePath}`, err);
        continue;
      }

      // typhonjs-escomplex supports TypeScript natively via Babel parser.
      let report: ModuleReport;
      try {
        report = escomplex.analyzeModule(source) as ModuleReport;
      } catch (err) {
        console.warn(`[complexity] Cannot parse file, skipping: ${filePath}`, err);
        continue;
      }

      moduleResults.push({ file: filePath, report });
    }

    // ── Compute global Halstead difficulty stats for outlier detection ──────
    //
    // Collect all per-function Halstead difficulty values so we can flag
    // functions that are more than 2 standard deviations above the mean.
    const allDifficulties: number[] = [];
    for (const { report } of moduleResults) {
      for (const fn of (report.functions ?? [])) {
        if (fn.halstead.difficulty > 0) {
          allDifficulties.push(fn.halstead.difficulty);
        }
      }
    }
    const { mean: diffMean, stddev: diffStddev } = stats(allDifficulties);
    const halsteadOutlierThreshold = diffMean + 2 * diffStddev;

    // ── Second pass: emit findings ──────────────────────────
    for (const { file, report } of moduleResults) {
      // 1. Maintainability index — module level
      //    Scale is 0–171; < 20 is poor, < 65 is moderate (we flag < 20 as error).
      if (report.maintainability < MAINTAINABILITY_LOW_THRESHOLD) {
        findings.push({
          id: makeId('complexity.maintainability', file),
          layer: 'static',
          type: 'complexity.maintainability',
          severity: 'error',
          confidence: 1.0,
          file,
          message:
            `Maintainability index is ${report.maintainability.toFixed(1)} ` +
            `(threshold: ${MAINTAINABILITY_LOW_THRESHOLD}). ` +
            `This module is critically difficult to maintain.`,
          tool: 'typhonjs-escomplex',
          suggestion:
            'Break this module into smaller, focused units. ' +
            'Extract logic into well-named helper functions. ' +
            'Reduce nesting depth and cyclomatic complexity.',
          meta: {
            maintainability: report.maintainability,
            aggregateCyclomatic: report.aggregate.cyclomatic,
            aggregateHalsteadDifficulty: report.aggregate.halstead.difficulty,
            lloc: report.aggregate.sloc.logical,
          },
        });
      }

      // 2. Cyclomatic complexity + Halstead difficulty — function level
      for (const fn of (report.functions ?? [])) {
        const fnName = fn.name || '<anonymous>';

        // Cyclomatic complexity
        if (fn.cyclomatic > complexityThreshold) {
          findings.push({
            id: makeId('complexity.cyclomatic', file, fn.line),
            layer: 'static',
            type: 'complexity.cyclomatic',
            severity: fn.cyclomatic > complexityThreshold * 2 ? 'error' : 'warning',
            confidence: 1.0,
            file,
            line: fn.line,
            message:
              `Function '${fnName}' has cyclomatic complexity ${fn.cyclomatic} ` +
              `(threshold: ${complexityThreshold}).`,
            tool: 'typhonjs-escomplex',
            suggestion:
              'Reduce branching by extracting conditions into named predicates, ' +
              'using early returns, or decomposing into smaller functions.',
            meta: {
              functionName: fnName,
              cyclomatic: fn.cyclomatic,
              cyclomaticDensity: fn.cyclomaticDensity,
              lloc: fn.sloc.logical,
              params: fn.params,
            },
          });
        }

        // Halstead difficulty outlier (only when we have a meaningful sample)
        //
        // We need at least 2 data points for stddev to be non-zero, and we
        // only flag when the function's difficulty meaningfully exceeds the
        // population (> mean + 2σ and > 10 absolute to avoid noise on tiny
        // files where the whole codebase is trivial).
        if (
          allDifficulties.length >= 2 &&
          diffStddev > 0 &&
          fn.halstead.difficulty > halsteadOutlierThreshold &&
          fn.halstead.difficulty > 10
        ) {
          findings.push({
            id: makeId('complexity.halstead', file, fn.line),
            layer: 'static',
            type: 'complexity.halstead',
            severity: 'warning',
            confidence: 1.0,
            file,
            line: fn.line,
            message:
              `Function '${fnName}' has Halstead difficulty ${fn.halstead.difficulty.toFixed(2)} ` +
              `(population mean: ${diffMean.toFixed(2)}, +2σ threshold: ${halsteadOutlierThreshold.toFixed(2)}). ` +
              `This is a statistical outlier in cognitive load.`,
            tool: 'typhonjs-escomplex',
            suggestion:
              'Simplify operator/operand diversity. ' +
              'Replace magic values with named constants. ' +
              'Decompose complex expressions.',
            meta: {
              functionName: fnName,
              halsteadDifficulty: fn.halstead.difficulty,
              halsteadVolume: fn.halstead.volume,
              halsteadEffort: fn.halstead.effort,
              populationMean: diffMean,
              populationStddev: diffStddev,
              outlierThreshold: halsteadOutlierThreshold,
            },
          });
        }
      }
    }

    return findings;
  }
}

export default new ComplexityAnalyzer();
