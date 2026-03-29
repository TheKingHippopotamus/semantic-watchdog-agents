// ============================================================
// CodeSentinel — Agent / LLM Reporter
// Produces structured Markdown optimised for Claude consumption
// ============================================================

import { writeFileSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import type { Reporter, Finding, SentinelConfig } from '../types.js';

// ---------------------------------------------------------------------------
// Actionability tiers
// ---------------------------------------------------------------------------

/**
 * Three-tier action classification:
 *
 *   FIX_NOW   — High-confidence errors or secrets (action required, do it today)
 *   REVIEW    — Medium-confidence warnings or borderline errors (needs human judgement)
 *   CONSIDER  — Low-severity or low-confidence informational findings (nice to have)
 */
type ActionTier = 'fix_now' | 'review' | 'consider';

function classifyTier(finding: Finding): ActionTier {
  if (finding.severity === 'error' && finding.confidence >= 0.9) {
    return 'fix_now';
  }
  if (finding.severity === 'error' && finding.confidence < 0.9) {
    return 'review';
  }
  if (finding.severity === 'warning' && finding.confidence >= 0.85) {
    return 'review';
  }
  if (finding.severity === 'warning') {
    return 'consider';
  }
  // info always goes to consider
  return 'consider';
}

// ---------------------------------------------------------------------------
// Label helpers
// ---------------------------------------------------------------------------

function severityLabel(severity: Finding['severity']): string {
  switch (severity) {
    case 'error':
      return 'ERROR';
    case 'warning':
      return 'WARNING';
    case 'info':
      return 'INFO';
  }
}

function layerLabel(layer: Finding['layer']): string {
  switch (layer) {
    case 'static':
      return 'Static Analysis';
    case 'secrets':
      return 'Secrets Detection';
    case 'semantic':
      return 'Semantic AI';
  }
}

// ---------------------------------------------------------------------------
// Action recommendation per finding type
// ---------------------------------------------------------------------------

/**
 * Returns a concrete recommended action for the finding.
 * Falls back to the finding's own suggestion, then a generic message.
 */
function recommendedAction(finding: Finding): string {
  if (finding.layer === 'secrets') {
    return (
      finding.suggestion ??
      'Remove the exposed credential from the codebase immediately, rotate the secret, ' +
      'and audit git history (use `git filter-repo` or BFG to purge historical commits).'
    );
  }

  if (finding.type.includes('circular') || finding.type.includes('cycle')) {
    return (
      finding.suggestion ??
      'Break the circular dependency by extracting shared logic into a third module that ' +
      'both dependents import, or invert the dependency using a shared interface/event.'
    );
  }

  if (finding.type.includes('dead') || finding.type.includes('unused')) {
    return (
      finding.suggestion ??
      'Verify the symbol is not accessed via dynamic import or string reflection, then ' +
      'delete it. Confirm no external packages re-export it before removal.'
    );
  }

  if (finding.type.includes('duplicate') || finding.type.includes('duplication')) {
    return (
      finding.suggestion ??
      'Extract the duplicated logic into a shared utility function and import it in both locations. ' +
      'Check for subtle differences in the two copies before merging.'
    );
  }

  if (finding.type.includes('drift')) {
    return (
      finding.suggestion ??
      `Move the file to the suggested directory and update all import paths. ` +
      `Run the full test suite after moving to confirm no broken imports.`
    );
  }

  if (finding.type.includes('complexity')) {
    return (
      finding.suggestion ??
      'Reduce cyclomatic complexity by splitting the function into smaller, single-purpose ' +
      'helpers. Aim for complexity <= 10 per function. Consider early-return guards over nested conditionals.'
    );
  }

  if (finding.type.includes('eval') || finding.type.includes('inject')) {
    return (
      finding.suggestion ??
      'Replace dynamic evaluation with a safe alternative. If dynamic dispatch is required, ' +
      'use an allow-list of known identifiers rather than executing arbitrary input.'
    );
  }

  if (finding.type.includes('regex')) {
    return (
      finding.suggestion ??
      'Audit the regular expression for ReDoS vulnerability. Consider using a linear-time ' +
      'regex engine or imposing a timeout on the match operation.'
    );
  }

  return finding.suggestion ?? 'Review the finding in context and apply the minimal safe change.';
}

// ---------------------------------------------------------------------------
// Single finding block formatter
// ---------------------------------------------------------------------------

function formatFinding(finding: Finding, rootDir: string): string {
  const label = severityLabel(finding.severity);
  const confidencePct = `${Math.round(finding.confidence * 100)}%`;
  const relPath = finding.file ? relative(rootDir, finding.file) : '(no file)';
  const location = finding.line != null && finding.line > 0
    ? `${relPath}:${finding.line}`
    : relPath;

  const lines: string[] = [
    `### [${label}] ${finding.message}`,
    `**Location:** \`${location}\``,
    `**Confidence:** ${confidencePct}  |  **Tool:** ${finding.tool}  |  **Layer:** ${layerLabel(finding.layer)}`,
    '',
    `**Action:** ${recommendedAction(finding)}`,
  ];

  if (finding.related && finding.related.length > 0) {
    const relatedList = finding.related
      .map((f) => `\`${relative(rootDir, f)}\``)
      .join(', ');
    lines.push('', `**Related files:** ${relatedList}`);
  }

  if (finding.meta && Object.keys(finding.meta).length > 0) {
    const metaEntries = Object.entries(finding.meta)
      .filter(([, v]) => v !== null && v !== undefined && !Array.isArray(v))
      .map(([k, v]) => `${k}: ${String(v)}`);
    if (metaEntries.length > 0) {
      lines.push('', `**Detail:** ${metaEntries.join(' | ')}`);
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Summary statistics
// ---------------------------------------------------------------------------

interface ReportStats {
  totalFindings: number;
  fixNowCount: number;
  reviewCount: number;
  considerCount: number;
  aboveThresholdCount: number;
  uniqueFiles: number;
  byLayer: Record<Finding['layer'], number>;
  bySeverity: Record<Finding['severity'], number>;
  toolsUsed: string[];
  hotspotFiles: Array<{ file: string; count: number }>;
}

function computeStats(findings: Finding[], config: SentinelConfig): ReportStats {
  const fileCount = new Map<string, number>();
  const byLayer: Record<Finding['layer'], number> = { static: 0, secrets: 0, semantic: 0 };
  const bySeverity: Record<Finding['severity'], number> = { error: 0, warning: 0, info: 0 };
  const toolSet = new Set<string>();
  let fixNow = 0;
  let review = 0;
  let consider = 0;
  let aboveThreshold = 0;

  for (const f of findings) {
    byLayer[f.layer]++;
    bySeverity[f.severity]++;
    toolSet.add(f.tool);

    if (f.file) {
      fileCount.set(f.file, (fileCount.get(f.file) ?? 0) + 1);
    }

    if (f.confidence >= config.confidenceThreshold) {
      aboveThreshold++;
    }

    const tier = classifyTier(f);
    if (tier === 'fix_now') fixNow++;
    else if (tier === 'review') review++;
    else consider++;
  }

  const hotspotFiles = Array.from(fileCount.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([file, count]) => ({ file: relative(config.rootDir, file), count }));

  return {
    totalFindings: findings.length,
    fixNowCount: fixNow,
    reviewCount: review,
    considerCount: consider,
    aboveThresholdCount: aboveThreshold,
    uniqueFiles: fileCount.size,
    byLayer,
    bySeverity,
    toolsUsed: Array.from(toolSet).sort(),
    hotspotFiles,
  };
}

// ---------------------------------------------------------------------------
// Full report builder
// ---------------------------------------------------------------------------

function buildReport(findings: Finding[], config: SentinelConfig): string {
  const stats = computeStats(findings, config);
  const sections: string[] = [];

  // Header
  sections.push('# CodeSentinel Report');
  sections.push('');

  // Executive summary block — machine-parseable
  sections.push('## Executive Summary');
  sections.push('');
  sections.push('```');
  sections.push(`Total findings   : ${stats.totalFindings}`);
  sections.push(`Fix now          : ${stats.fixNowCount}  (high-confidence errors)`);
  sections.push(`Review           : ${stats.reviewCount}  (warnings / borderline errors)`);
  sections.push(`Consider         : ${stats.considerCount}  (low-severity / informational)`);
  sections.push(`Above ${Math.round(config.confidenceThreshold * 100)}% threshold: ${stats.aboveThresholdCount}`);
  sections.push(`Files affected   : ${stats.uniqueFiles}`);
  sections.push(`Tools used       : ${stats.toolsUsed.join(', ') || 'none'}`);
  sections.push('');
  sections.push(`By layer    — static: ${stats.byLayer.static}  |  secrets: ${stats.byLayer.secrets}  |  semantic: ${stats.byLayer.semantic}`);
  sections.push(`By severity — error: ${stats.bySeverity.error}  |  warning: ${stats.bySeverity.warning}  |  info: ${stats.bySeverity.info}`);
  sections.push('```');
  sections.push('');

  // Hotspot files
  if (stats.hotspotFiles.length > 0) {
    sections.push('### Key Areas of Concern');
    sections.push('');
    for (const { file, count } of stats.hotspotFiles) {
      sections.push(`- \`${file}\` — ${count} finding${count !== 1 ? 's' : ''}`);
    }
    sections.push('');
  }

  // Tier 1: Fix Now
  const fixNowFindings = findings.filter((f) => classifyTier(f) === 'fix_now');
  sections.push('---');
  sections.push('');
  sections.push('## Critical Findings — Fix Now');
  sections.push('');
  if (fixNowFindings.length === 0) {
    sections.push('_No critical findings. Good._');
  } else {
    sections.push(
      `> **${fixNowFindings.length} finding${fixNowFindings.length !== 1 ? 's' : ''}** require immediate action. ` +
      `These are high-confidence errors that should be resolved before the next deploy.`,
    );
    sections.push('');
    for (const finding of fixNowFindings) {
      sections.push(formatFinding(finding, config.rootDir));
      sections.push('');
    }
  }

  // Tier 2: Review
  const reviewFindings = findings.filter((f) => classifyTier(f) === 'review');
  sections.push('---');
  sections.push('');
  sections.push('## Warnings — Review Required');
  sections.push('');
  if (reviewFindings.length === 0) {
    sections.push('_No review-level findings._');
  } else {
    sections.push(
      `> **${reviewFindings.length} finding${reviewFindings.length !== 1 ? 's' : ''}** warrant review. ` +
      `These may be false positives or lower-urgency issues — apply judgement.`,
    );
    sections.push('');
    for (const finding of reviewFindings) {
      sections.push(formatFinding(finding, config.rootDir));
      sections.push('');
    }
  }

  // Tier 3: Consider
  const considerFindings = findings.filter((f) => classifyTier(f) === 'consider');
  sections.push('---');
  sections.push('');
  sections.push('## Informational — Consider');
  sections.push('');
  if (considerFindings.length === 0) {
    sections.push('_No informational findings._');
  } else {
    sections.push(
      `> **${considerFindings.length} finding${considerFindings.length !== 1 ? 's' : ''}** are low-severity. ` +
      `Address during routine maintenance or skip with justification.`,
    );
    sections.push('');
    for (const finding of considerFindings) {
      sections.push(formatFinding(finding, config.rootDir));
      sections.push('');
    }
  }

  // Agent instruction footer
  sections.push('---');
  sections.push('');
  sections.push('## Agent Instructions');
  sections.push('');
  sections.push(
    'When acting on this report as an AI agent, follow this priority order:',
  );
  sections.push('');
  sections.push('1. **Fix Now first.** Work through every finding in the "Fix Now" section before touching anything else.');
  sections.push('2. **One finding at a time.** Fix, then run the relevant analyzer again to confirm the finding is gone before moving to the next.');
  sections.push('3. **Do not touch unrelated code.** Limit each change to the minimum diff required to resolve the finding.');
  sections.push('4. **Secrets must be rotated externally.** Removing a secret from code does not invalidate it — flag for human rotation.');
  sections.push('5. **Re-run CodeSentinel after all fixes** to confirm the finding count dropped to zero and no regressions were introduced.');

  return sections.join('\n');
}

// ---------------------------------------------------------------------------
// Reporter implementation
// ---------------------------------------------------------------------------

export class AgentReporter implements Reporter {
  readonly name = 'agent';

  async report(findings: Finding[], config: SentinelConfig): Promise<void> {
    const report = buildReport(findings, config);

    const outputPath = (config.output as Record<string, unknown>)['outputFile'] as string | undefined;
    if (outputPath) {
      const absolutePath = resolve(config.rootDir, outputPath);
      writeFileSync(absolutePath, report, 'utf-8');
    } else {
      process.stdout.write(report + '\n');
    }
  }
}
