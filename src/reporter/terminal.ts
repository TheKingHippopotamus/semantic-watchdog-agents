// ============================================================
// CodeSentinel — Terminal Reporter
// Layer: output | Format: human-readable colored terminal
// ============================================================

import chalk from 'chalk';
import type { Reporter, Finding, SentinelConfig, AnalyzerLayer, Severity } from '../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const LAYER_LABELS: Record<AnalyzerLayer, string> = {
  static:   'Static',
  secrets:  'Secrets',
  semantic: 'Semantic',
};

const SEVERITY_ORDER: Record<Severity, number> = {
  error:   0,
  warning: 1,
  info:    2,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  error:   '✖',
  warning: '⚠',
  info:    '●',
};

/**
 * Apply severity color to a string.
 */
function colorBySeverity(severity: Severity, text: string): string {
  switch (severity) {
    case 'error':   return chalk.red(text);
    case 'warning': return chalk.yellow(text);
    case 'info':    return chalk.gray(text);
  }
}

/**
 * Format confidence as a colored percentage badge, e.g. [98%].
 *   >= 0.95 → green
 *   >= 0.85 → yellow
 *   <  0.85 → gray
 */
function confidenceBadge(confidence: number): string {
  const pct = Math.round(confidence * 100);
  const text = `[${pct}%]`;
  if (confidence >= 0.95) return chalk.green(text);
  if (confidence >= 0.85) return chalk.yellow(text);
  return chalk.gray(text);
}

/**
 * Format a file location string: path:line or just path when no line.
 */
function formatLocation(finding: Finding): string {
  if (finding.line != null && finding.line > 0) {
    return `${finding.file}:${finding.line}`;
  }
  return finding.file || '(unknown file)';
}

/**
 * Sort findings within a group: severity asc (error first), then confidence desc.
 */
function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const severityDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (severityDiff !== 0) return severityDiff;
    return b.confidence - a.confidence;
  });
}

/**
 * Render a single finding line + optional suggestion.
 */
function renderFinding(finding: Finding, dimmed = false): void {
  const icon   = SEVERITY_ICONS[finding.severity];
  const badge  = confidenceBadge(finding.confidence);
  const loc    = chalk.dim(formatLocation(finding));
  const msg    = finding.message;
  const prefix = `  ${colorBySeverity(finding.severity, icon)}`;

  if (dimmed) {
    // Below-threshold: render entirely in gray
    process.stdout.write(`${chalk.gray(`  ${icon} ${formatLocation(finding)}  ${msg}`)} ${chalk.gray(badge)}\n`);
  } else {
    process.stdout.write(`${prefix} ${loc}  ${msg} ${badge}\n`);
  }

  if (finding.suggestion && !dimmed) {
    process.stdout.write(`    ${chalk.dim('→')} ${chalk.dim(finding.suggestion)}\n`);
  }
}

// ---------------------------------------------------------------------------
// Reporter implementation
// ---------------------------------------------------------------------------

export class TerminalReporter implements Reporter {
  readonly name = 'terminal';

  async report(findings: Finding[], config: SentinelConfig): Promise<void> {
    const threshold = config.confidenceThreshold;

    // Partition into active (above threshold) and suppressed (below threshold)
    const active:     Finding[] = findings.filter(f => f.confidence >= threshold);
    const suppressed: Finding[] = findings.filter(f => f.confidence <  threshold);

    const errors   = active.filter(f => f.severity === 'error').length;
    const warnings = active.filter(f => f.severity === 'warning').length;

    // -----------------------------------------------------------------------
    // Header
    // -----------------------------------------------------------------------
    process.stdout.write('\n');
    process.stdout.write(
      chalk.bold(`CodeSentinel — ${active.length} finding${active.length !== 1 ? 's' : ''} `) +
      chalk.red(`(${errors} error${errors !== 1 ? 's' : ''}`) +
      chalk.reset(', ') +
      chalk.yellow(`${warnings} warning${warnings !== 1 ? 's' : ''})`) +
      '\n',
    );
    process.stdout.write(chalk.dim('─'.repeat(72)) + '\n');

    // -----------------------------------------------------------------------
    // Findings grouped by layer
    // -----------------------------------------------------------------------
    const layers: AnalyzerLayer[] = ['static', 'secrets', 'semantic'];

    for (const layer of layers) {
      const layerFindings = active.filter(f => f.layer === layer);
      if (layerFindings.length === 0) continue;

      const sorted = sortFindings(layerFindings);

      process.stdout.write('\n');
      process.stdout.write(chalk.bold.underline(LAYER_LABELS[layer]) + chalk.dim(` (${layerFindings.length})`) + '\n');

      for (const finding of sorted) {
        renderFinding(finding);
      }
    }

    // -----------------------------------------------------------------------
    // Suppressed findings (verbose mode only)
    // -----------------------------------------------------------------------
    if (config.output.verbose && suppressed.length > 0) {
      const sortedSuppressed = sortFindings(suppressed);

      process.stdout.write('\n');
      process.stdout.write(
        chalk.dim(`Suppressed (below ${Math.round(threshold * 100)}% confidence threshold) — ${suppressed.length} finding${suppressed.length !== 1 ? 's' : ''}`) +
        '\n',
      );

      for (const finding of sortedSuppressed) {
        renderFinding(finding, /* dimmed */ true);
      }
    }

    // -----------------------------------------------------------------------
    // Summary footer
    // -----------------------------------------------------------------------
    process.stdout.write('\n');
    process.stdout.write(chalk.dim('─'.repeat(72)) + '\n');

    // Per-layer counts for the footer
    const footerParts: string[] = [];
    for (const layer of layers) {
      const count = active.filter(f => f.layer === layer).length;
      if (count > 0) {
        footerParts.push(`${LAYER_LABELS[layer]}: ${count}`);
      }
    }

    if (footerParts.length > 0) {
      process.stdout.write(chalk.dim('Breakdown  ') + footerParts.join(chalk.dim('  ·  ')) + '\n');
    }

    if (suppressed.length > 0 && !config.output.verbose) {
      process.stdout.write(
        chalk.dim(`${suppressed.length} finding${suppressed.length !== 1 ? 's' : ''} suppressed — run with --verbose to show\n`),
      );
    }

    process.stdout.write('\n');
  }
}
