// ============================================================
// CodeSentinel — SARIF v2.1.0 Reporter
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// ============================================================

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Reporter, Finding, SentinelConfig } from '../types.js';

// ---------------------------------------------------------------------------
// SARIF schema types — only the subset we emit
// ---------------------------------------------------------------------------

interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

interface SarifRegion {
  startLine: number;
  endLine?: number;
}

interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region?: SarifRegion;
}

interface SarifLocation {
  physicalLocation?: SarifPhysicalLocation;
  message?: { text: string };
}

interface SarifFix {
  description: { text: string };
}

interface SarifPropertyBag {
  confidence?: number;
  layer?: string;
  findingType?: string;
  relatedFiles?: string[];
  [key: string]: unknown;
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: SarifLocation[];
  rank?: number;
  fixes?: SarifFix[];
  relatedLocations?: SarifLocation[];
  properties?: SarifPropertyBag;
}

interface SarifReportingDescriptor {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  properties?: Record<string, unknown>;
}

interface SarifToolDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifReportingDescriptor[];
}

interface SarifTool {
  driver: SarifToolDriver;
}

interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  originalUriBaseIds?: Record<string, SarifArtifactLocation>;
}

interface SarifLog {
  version: '2.1.0';
  $schema: string;
  runs: SarifRun[];
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

/**
 * Map our internal severity levels to SARIF result levels.
 *
 * SARIF level options: 'error' | 'warning' | 'note' | 'none'
 * We never produce 'none' — that is reserved for informational pass results.
 */
function toSarifLevel(severity: Finding['severity']): SarifResult['level'] {
  switch (severity) {
    case 'error':
      return 'error';
    case 'warning':
      return 'warning';
    case 'info':
      return 'note';
  }
}

// ---------------------------------------------------------------------------
// URI helpers
// ---------------------------------------------------------------------------

/**
 * Convert an absolute file path to a URI relative to the repository root.
 * SARIF recommends using uriBaseId tokens (%SRCROOT%) so that the log is
 * portable — different machines need only set that base.
 */
function toRelativeUri(filePath: string, rootDir: string): string {
  if (!filePath) return '';
  const root = rootDir.endsWith('/') ? rootDir : `${rootDir}/`;
  if (filePath.startsWith(root)) {
    // Encode spaces and special chars; leave slashes intact
    return filePath.slice(root.length).replace(/ /g, '%20');
  }
  // Absolute path that doesn't share rootDir — emit as file:// URI
  return `file://${filePath.replace(/ /g, '%20')}`;
}

// ---------------------------------------------------------------------------
// Rule descriptor builder
// ---------------------------------------------------------------------------

/**
 * Build a SARIF ruleDescriptor from a representative Finding for that rule.
 * The ruleId is `{tool}/{type}` so it is globally unique within the run.
 */
function buildRuleDescriptor(ruleId: string, finding: Finding): SarifReportingDescriptor {
  return {
    id: ruleId,
    name: finding.type,
    shortDescription: { text: `[${finding.layer}] ${finding.type}` },
    fullDescription: { text: finding.message },
    properties: {
      layer: finding.layer,
      tool: finding.tool,
    },
  };
}

// ---------------------------------------------------------------------------
// Result builder
// ---------------------------------------------------------------------------

function buildSarifResult(finding: Finding, rootDir: string): SarifResult {
  const ruleId = `${finding.tool}/${finding.type}`;
  const level = toSarifLevel(finding.severity);

  // Confidence expressed as rank: SARIF rank is 0–100 (float)
  const rank = Math.round(finding.confidence * 100 * 10) / 10;

  const location: SarifLocation = {};
  if (finding.file) {
    location.physicalLocation = {
      artifactLocation: {
        uri: toRelativeUri(finding.file, rootDir),
        uriBaseId: '%SRCROOT%',
      },
    };

    if (finding.line != null && finding.line > 0) {
      location.physicalLocation.region = {
        startLine: finding.line,
        ...(finding.endLine != null ? { endLine: finding.endLine } : {}),
      };
    }
  }

  const result: SarifResult = {
    ruleId,
    level,
    message: { text: finding.message },
    locations: finding.file ? [location] : [],
    rank,
    properties: {
      confidence: finding.confidence,
      layer: finding.layer,
      findingType: finding.type,
    },
  };

  if (finding.suggestion) {
    result.fixes = [{ description: { text: finding.suggestion } }];
  }

  if (finding.related && finding.related.length > 0) {
    result.relatedLocations = finding.related.map((relPath, index) => ({
      message: { text: `Related file ${index + 1}` },
      physicalLocation: {
        artifactLocation: {
          uri: toRelativeUri(relPath, rootDir),
          uriBaseId: '%SRCROOT%',
        },
      },
    }));

    if (result.properties) {
      result.properties.relatedFiles = finding.related;
    }
  }

  // Preserve any tool-specific metadata
  if (finding.meta && Object.keys(finding.meta).length > 0) {
    result.properties = { ...result.properties, ...finding.meta };
  }

  return result;
}

// ---------------------------------------------------------------------------
// Run builder — one SARIF run per tool
// ---------------------------------------------------------------------------

interface RunAccumulator {
  rules: Map<string, SarifReportingDescriptor>;
  results: SarifResult[];
}

function buildSarifLog(findings: Finding[], config: SentinelConfig): SarifLog {
  // Group findings by tool name — each tool becomes one SARIF run
  const byTool = new Map<string, RunAccumulator>();

  for (const finding of findings) {
    const toolName = finding.tool || 'unknown';
    if (!byTool.has(toolName)) {
      byTool.set(toolName, { rules: new Map(), results: [] });
    }

    const acc = byTool.get(toolName)!;
    const ruleId = `${finding.tool}/${finding.type}`;

    // Register rule descriptor (once per unique ruleId)
    if (!acc.rules.has(ruleId)) {
      acc.rules.set(ruleId, buildRuleDescriptor(ruleId, finding));
    }

    acc.results.push(buildSarifResult(finding, config.rootDir));
  }

  // If no findings at all, emit a single empty run so the file is valid
  if (byTool.size === 0) {
    byTool.set('codesentinel', { rules: new Map(), results: [] });
  }

  const runs: SarifRun[] = Array.from(byTool.entries()).map(([toolName, acc]) => ({
    tool: {
      driver: {
        name: toolName,
        version: '0.1.0',
        informationUri: 'https://github.com/codesentinel/codesentinel',
        rules: Array.from(acc.rules.values()),
      },
    },
    results: acc.results,
    originalUriBaseIds: {
      '%SRCROOT%': {
        uri: `file://${config.rootDir.endsWith('/') ? config.rootDir : `${config.rootDir}/`}`,
      },
    },
  }));

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs,
  };
}

// ---------------------------------------------------------------------------
// Reporter implementation
// ---------------------------------------------------------------------------

export class SarifReporter implements Reporter {
  readonly name = 'sarif';

  async report(findings: Finding[], config: SentinelConfig): Promise<void> {
    const log = buildSarifLog(findings, config);
    const json = JSON.stringify(log, null, 2);

    // Write to file if an output path is configured, otherwise stdout
    const outputPath = (config.output as Record<string, unknown>)['outputFile'] as string | undefined;
    if (outputPath) {
      const absolutePath = resolve(config.rootDir, outputPath);
      writeFileSync(absolutePath, json, 'utf-8');
    } else {
      process.stdout.write(json + '\n');
    }
  }
}
