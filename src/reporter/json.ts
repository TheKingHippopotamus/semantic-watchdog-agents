// ============================================================
// CodeSentinel — JSON Reporter
// Layer: output | Format: machine-readable JSON to stdout
// ============================================================

import type { Reporter, Finding, SentinelConfig } from '../types.js';

// ---------------------------------------------------------------------------
// Schema types (what we emit — a strict subset of internal types)
// ---------------------------------------------------------------------------

interface JsonFinding {
  id:          string;
  layer:       string;
  type:        string;
  severity:    string;
  confidence:  number;
  file:        string;
  line?:       number;
  endLine?:    number;
  message:     string;
  tool:        string;
  suggestion?: string;
  related?:    string[];
  meta?:       Record<string, unknown>;
}

interface JsonSummary {
  total:    number;
  errors:   number;
  warnings: number;
  info:     number;
}

interface JsonReport {
  version:    string;
  timestamp:  string;
  rootDir:    string;
  summary:    JsonSummary;
  findings:   JsonFinding[];
  suppressed?: JsonFinding[];
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const PACKAGE_VERSION = '0.1.0';

/**
 * Map a Finding to its serialisable JSON representation.
 * We omit undefined optional fields so the output stays minimal.
 */
function toJsonFinding(finding: Finding): JsonFinding {
  const out: JsonFinding = {
    id:         finding.id,
    layer:      finding.layer,
    type:       finding.type,
    severity:   finding.severity,
    confidence: finding.confidence,
    file:       finding.file,
    message:    finding.message,
    tool:       finding.tool,
  };

  if (finding.line     != null) out.line    = finding.line;
  if (finding.endLine  != null) out.endLine = finding.endLine;
  if (finding.suggestion)       out.suggestion = finding.suggestion;
  if (finding.related?.length)  out.related = finding.related;
  if (finding.meta && Object.keys(finding.meta).length > 0) {
    out.meta = finding.meta;
  }

  return out;
}

/**
 * Build the summary block from a set of active findings.
 */
function buildSummary(active: Finding[]): JsonSummary {
  return {
    total:    active.length,
    errors:   active.filter(f => f.severity === 'error').length,
    warnings: active.filter(f => f.severity === 'warning').length,
    info:     active.filter(f => f.severity === 'info').length,
  };
}

// ---------------------------------------------------------------------------
// Reporter implementation
// ---------------------------------------------------------------------------

export class JsonReporter implements Reporter {
  readonly name = 'json';

  async report(findings: Finding[], config: SentinelConfig): Promise<void> {
    const threshold = config.confidenceThreshold;

    const active:     Finding[] = findings.filter(f => f.confidence >= threshold);
    const suppressed: Finding[] = findings.filter(f => f.confidence <  threshold);

    const report: JsonReport = {
      version:   PACKAGE_VERSION,
      timestamp: new Date().toISOString(),
      rootDir:   config.rootDir,
      summary:   buildSummary(active),
      findings:  active.map(toJsonFinding),
    };

    if (config.output.verbose && suppressed.length > 0) {
      report.suppressed = suppressed.map(toJsonFinding);
    }

    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  }
}
