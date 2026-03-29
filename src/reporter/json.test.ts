// ============================================================
// CodeSentinel — JSON Reporter unit tests
// ============================================================

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { JsonReporter } from './json.js';
import type { Finding, SentinelConfig } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(overrides: Partial<SentinelConfig['output']> = {}): SentinelConfig {
  return {
    rootDir: '/project',
    confidenceThreshold: 0.7,
    ignore: [],
    analyzers: {
      static: {
        enabled: true,
        deadCode: true,
        circularDeps: true,
        dependencies: true,
        security: true,
        complexity: true,
        complexityThreshold: 10,
      },
      secrets: {
        enabled: true,
        useGitleaks: true,
        regexFallback: true,
      },
      semantic: {
        enabled: true,
        model: 'test-model',
        duplication: true,
        duplicationThreshold: 0.9,
        drift: true,
        intentRecovery: true,
      },
    },
    watch: { enabled: false, debounceMs: 300 },
    output: {
      format: 'json',
      verbose: false,
      ...overrides,
    },
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'F001',
    layer: 'static',
    type: 'dead-code',
    severity: 'warning',
    confidence: 0.9,
    file: 'src/foo.ts',
    message: 'Unused export "bar"',
    tool: 'ts-prune',
    ...overrides,
  };
}

/**
 * Collect all output flushed via process.stdout.write during the
 * execution of `fn`, then restore the original write.
 */
async function captureStdout(fn: () => Promise<void>): Promise<string> {
  const chunks: string[] = [];
  const spy = vi
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: unknown) => {
      chunks.push(String(chunk));
      return true;
    });

  try {
    await fn();
  } finally {
    spy.mockRestore();
  }

  return chunks.join('');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('JsonReporter', () => {
  let reporter: JsonReporter;

  beforeEach(() => {
    reporter = new JsonReporter();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  it('reporter.name is "json"', () => {
    expect(reporter.name).toBe('json');
  });

  // -------------------------------------------------------------------------
  describe('report with findings', () => {
    it('outputs valid JSON', async () => {
      const config = makeConfig();
      const findings = [
        makeFinding({ severity: 'error', confidence: 0.95 }),
        makeFinding({ id: 'F002', severity: 'warning', confidence: 0.8 }),
        makeFinding({ id: 'F003', severity: 'info', confidence: 0.75 }),
      ];

      const raw = await captureStdout(() => reporter.report(findings, config));

      expect(() => JSON.parse(raw)).not.toThrow();
    });

    it('summary counts match findings', async () => {
      const config = makeConfig();
      const findings = [
        makeFinding({ id: 'F001', severity: 'error',   confidence: 0.9 }),
        makeFinding({ id: 'F002', severity: 'error',   confidence: 0.8 }),
        makeFinding({ id: 'F003', severity: 'warning', confidence: 0.75 }),
        makeFinding({ id: 'F004', severity: 'info',    confidence: 0.95 }),
      ];

      const raw = await captureStdout(() => reporter.report(findings, config));
      const report = JSON.parse(raw);

      expect(report.summary.total).toBe(4);
      expect(report.summary.errors).toBe(2);
      expect(report.summary.warnings).toBe(1);
      expect(report.summary.info).toBe(1);
    });

    it('findings array contains all active findings', async () => {
      const config = makeConfig();
      const findings = [
        makeFinding({ id: 'F001', confidence: 0.9 }),
        makeFinding({ id: 'F002', confidence: 0.8 }),
      ];

      const raw = await captureStdout(() => reporter.report(findings, config));
      const report = JSON.parse(raw);

      expect(report.findings).toHaveLength(2);
      expect(report.findings.map((f: { id: string }) => f.id)).toEqual(['F001', 'F002']);
    });

    it('required fields are present on each finding', async () => {
      const config = makeConfig();
      const findings = [makeFinding()];

      const raw = await captureStdout(() => reporter.report(findings, config));
      const report = JSON.parse(raw);
      const f = report.findings[0];

      expect(f).toMatchObject({
        id:         'F001',
        layer:      'static',
        type:       'dead-code',
        severity:   'warning',
        confidence: 0.9,
        file:       'src/foo.ts',
        message:    'Unused export "bar"',
        tool:       'ts-prune',
      });
    });

    it('rootDir matches config', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() => reporter.report([makeFinding()], config));
      const report = JSON.parse(raw);

      expect(report.rootDir).toBe('/project');
    });
  });

  // -------------------------------------------------------------------------
  describe('report with empty findings', () => {
    it('outputs valid JSON', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() => reporter.report([], config));

      expect(() => JSON.parse(raw)).not.toThrow();
    });

    it('summary is all zeroes', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() => reporter.report([], config));
      const report = JSON.parse(raw);

      expect(report.summary).toEqual({ total: 0, errors: 0, warnings: 0, info: 0 });
    });

    it('findings array is empty', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() => reporter.report([], config));
      const report = JSON.parse(raw);

      expect(report.findings).toEqual([]);
    });
  });

  // -------------------------------------------------------------------------
  describe('confidence threshold filtering', () => {
    it('excludes findings below threshold from summary and findings array', async () => {
      const config = makeConfig(); // threshold = 0.7
      const findings = [
        makeFinding({ id: 'F001', confidence: 0.9 }),   // active
        makeFinding({ id: 'F002', confidence: 0.69 }),  // suppressed
      ];

      const raw = await captureStdout(() => reporter.report(findings, config));
      const report = JSON.parse(raw);

      expect(report.summary.total).toBe(1);
      expect(report.findings).toHaveLength(1);
      expect(report.findings[0].id).toBe('F001');
    });

    it('includes findings at exactly the threshold boundary', async () => {
      const config = makeConfig(); // threshold = 0.7
      const findings = [makeFinding({ id: 'F001', confidence: 0.7 })];

      const raw = await captureStdout(() => reporter.report(findings, config));
      const report = JSON.parse(raw);

      expect(report.summary.total).toBe(1);
      expect(report.findings[0].id).toBe('F001');
    });
  });

  // -------------------------------------------------------------------------
  describe('verbose mode', () => {
    it('includes suppressed array when verbose=true and there are suppressed findings', async () => {
      const config = makeConfig({ verbose: true });
      const findings = [
        makeFinding({ id: 'F001', confidence: 0.9 }),   // active
        makeFinding({ id: 'F002', confidence: 0.5 }),   // suppressed
      ];

      const raw = await captureStdout(() => reporter.report(findings, config));
      const report = JSON.parse(raw);

      expect(report.suppressed).toBeDefined();
      expect(report.suppressed).toHaveLength(1);
      expect(report.suppressed[0].id).toBe('F002');
    });

    it('does not include suppressed key when verbose=true but no findings are suppressed', async () => {
      const config = makeConfig({ verbose: true });
      const findings = [makeFinding({ confidence: 0.9 })];

      const raw = await captureStdout(() => reporter.report(findings, config));
      const report = JSON.parse(raw);

      expect(Object.prototype.hasOwnProperty.call(report, 'suppressed')).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  describe('non-verbose mode', () => {
    it('does not include suppressed key even when findings are suppressed', async () => {
      const config = makeConfig({ verbose: false });
      const findings = [
        makeFinding({ id: 'F001', confidence: 0.9 }),
        makeFinding({ id: 'F002', confidence: 0.3 }),  // would be suppressed
      ];

      const raw = await captureStdout(() => reporter.report(findings, config));
      const report = JSON.parse(raw);

      expect(Object.prototype.hasOwnProperty.call(report, 'suppressed')).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  describe('optional finding fields', () => {
    it('omits line and endLine when undefined', async () => {
      const config = makeConfig();
      // makeFinding does not set line/endLine by default
      const raw = await captureStdout(() => reporter.report([makeFinding()], config));
      const f = JSON.parse(raw).findings[0];

      expect(Object.prototype.hasOwnProperty.call(f, 'line')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(f, 'endLine')).toBe(false);
    });

    it('includes line and endLine when provided', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() =>
        reporter.report([makeFinding({ line: 42, endLine: 55 })], config),
      );
      const f = JSON.parse(raw).findings[0];

      expect(f.line).toBe(42);
      expect(f.endLine).toBe(55);
    });

    it('omits suggestion when undefined', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() => reporter.report([makeFinding()], config));
      const f = JSON.parse(raw).findings[0];

      expect(Object.prototype.hasOwnProperty.call(f, 'suggestion')).toBe(false);
    });

    it('includes suggestion when provided', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() =>
        reporter.report([makeFinding({ suggestion: 'Remove unused export' })], config),
      );
      const f = JSON.parse(raw).findings[0];

      expect(f.suggestion).toBe('Remove unused export');
    });

    it('omits related when undefined', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() => reporter.report([makeFinding()], config));
      const f = JSON.parse(raw).findings[0];

      expect(Object.prototype.hasOwnProperty.call(f, 'related')).toBe(false);
    });

    it('omits related when empty array', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() =>
        reporter.report([makeFinding({ related: [] })], config),
      );
      const f = JSON.parse(raw).findings[0];

      expect(Object.prototype.hasOwnProperty.call(f, 'related')).toBe(false);
    });

    it('includes related when non-empty', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() =>
        reporter.report([makeFinding({ related: ['src/bar.ts', 'src/baz.ts'] })], config),
      );
      const f = JSON.parse(raw).findings[0];

      expect(f.related).toEqual(['src/bar.ts', 'src/baz.ts']);
    });

    it('omits meta when undefined', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() => reporter.report([makeFinding()], config));
      const f = JSON.parse(raw).findings[0];

      expect(Object.prototype.hasOwnProperty.call(f, 'meta')).toBe(false);
    });

    it('omits meta when empty object', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() =>
        reporter.report([makeFinding({ meta: {} })], config),
      );
      const f = JSON.parse(raw).findings[0];

      expect(Object.prototype.hasOwnProperty.call(f, 'meta')).toBe(false);
    });

    it('includes meta when populated', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() =>
        reporter.report([makeFinding({ meta: { ruleId: 'no-unused', score: 42 } })], config),
      );
      const f = JSON.parse(raw).findings[0];

      expect(f.meta).toEqual({ ruleId: 'no-unused', score: 42 });
    });
  });

  // -------------------------------------------------------------------------
  describe('timestamp', () => {
    it('is a valid ISO-8601 string', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() => reporter.report([], config));
      const report = JSON.parse(raw);

      const parsed = new Date(report.timestamp);
      expect(parsed.toString()).not.toBe('Invalid Date');
      // Verify round-trip: toISOString() output always ends with 'Z'
      expect(report.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    });

    it('is recent (within 5 seconds of now)', async () => {
      const before = Date.now();
      const config = makeConfig();
      const raw = await captureStdout(() => reporter.report([], config));
      const after = Date.now();

      const ts = new Date(JSON.parse(raw).timestamp).getTime();
      expect(ts).toBeGreaterThanOrEqual(before);
      expect(ts).toBeLessThanOrEqual(after + 5000);
    });
  });

  // -------------------------------------------------------------------------
  describe('output format', () => {
    it('output ends with a newline', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() => reporter.report([], config));

      expect(raw.endsWith('\n')).toBe(true);
    });

    it('version field is present', async () => {
      const config = makeConfig();
      const raw = await captureStdout(() => reporter.report([], config));
      const report = JSON.parse(raw);

      expect(typeof report.version).toBe('string');
      expect(report.version.length).toBeGreaterThan(0);
    });
  });
});
