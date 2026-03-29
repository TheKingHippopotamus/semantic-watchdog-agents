import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { TestCoverageAnalyzer } from './test-coverage.js';
import type { AnalysisContext, SentinelConfig } from '../../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(ignore: string[] = []): SentinelConfig {
  return {
    rootDir: '',
    confidenceThreshold: 0.5,
    ignore,
    analyzers: {
      static: {
        enabled: true,
        deadCode: false,
        circularDeps: false,
        dependencies: false,
        security: false,
        complexity: false,
        complexityThreshold: 10,
        testCoverage: true,
      },
      secrets: {
        enabled: false,
        useGitleaks: false,
        regexFallback: false,
      },
      semantic: {
        enabled: false,
        model: '',
        duplication: false,
        duplicationThreshold: 0.85,
        drift: false,
        intentRecovery: false,
      },
    },
    watch: { enabled: false, debounceMs: 300 },
    output: { format: 'terminal', verbose: false },
  };
}

/**
 * Create an AnalysisContext that lists all provided absolute file paths.
 * rootDir is required for the analyzer's candidate-path building logic.
 */
function makeContext(files: string[], rootDir: string, ignore: string[] = []): AnalysisContext {
  return { rootDir, files, config: makeConfig(ignore) };
}

/**
 * Write a file at an absolute path, creating intermediate directories if needed.
 */
function touch(absPath: string, content = 'export const x = 1;\n'): void {
  mkdirSync(join(absPath, '..'), { recursive: true });
  writeFileSync(absPath, content, 'utf-8');
}

// ---------------------------------------------------------------------------
// Each test creates its own isolated temp directory and cleans up after itself.
// ---------------------------------------------------------------------------

let currentTmpDir: string | undefined;

afterEach(() => {
  if (currentTmpDir) {
    rmSync(currentTmpDir, { recursive: true, force: true });
    currentTmpDir = undefined;
  }
});

function freshDir(prefix = 'tc-test-'): string {
  currentTmpDir = mkdtempSync(join(tmpdir(), prefix));
  return currentTmpDir;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('TestCoverageAnalyzer', () => {
  const analyzer = new TestCoverageAnalyzer();

  it('has correct name and layer', () => {
    expect(analyzer.name).toBe('test-coverage');
    expect(analyzer.layer).toBe('static');
  });

  // -------------------------------------------------------------------------
  // Source file without test file → missing-test-file finding
  // -------------------------------------------------------------------------

  it('emits a missing-test-file finding when src/foo.ts has no test companion', async () => {
    const root = freshDir('tc-missing-');
    const fooTs = join(root, 'src', 'foo.ts');
    touch(fooTs);

    const findings = await analyzer.analyze(makeContext([fooTs], root));

    const missing = findings.filter((f) => f.type === 'missing-test-file');
    expect(missing.length).toBeGreaterThanOrEqual(1);
    expect(missing[0].file).toBe(fooTs);
    expect(missing[0].layer).toBe('static');
    expect(missing[0].tool).toBe('test-coverage');
    expect(missing[0].confidence).toBeCloseTo(0.90, 5);
  });

  // -------------------------------------------------------------------------
  // Source file WITH sibling test file → no missing-test-file finding
  // -------------------------------------------------------------------------

  it('does not emit a finding when src/bar.ts has a sibling bar.test.ts', async () => {
    const root = freshDir('tc-covered-');
    const barTs = join(root, 'src', 'bar.ts');
    const barTest = join(root, 'src', 'bar.test.ts');
    touch(barTs);
    // Write a real test file with enough non-blank lines to exceed the threshold.
    touch(barTest, [
      "import { describe, it, expect } from 'vitest';",
      "import { bar } from './bar.js';",
      '',
      "describe('bar', () => {",
      "  it('returns true', () => {",
      '    expect(bar()).toBe(true);',
      '  });',
      '',
      "  it('handles edge case', () => {",
      '    expect(bar()).toBeDefined();',
      '  });',
      '});',
      '',
    ].join('\n'));

    const findings = await analyzer.analyze(makeContext([barTs, barTest], root));

    const missing = findings.filter((f) => f.type === 'missing-test-file' && f.file === barTs);
    expect(missing).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Service file (critical path) → severity 'warning'
  // -------------------------------------------------------------------------

  it('escalates severity to warning for service files without tests', async () => {
    const root = freshDir('tc-service-');
    const serviceFile = join(root, 'src', 'services', 'auth.service.ts');
    touch(serviceFile);

    const findings = await analyzer.analyze(makeContext([serviceFile], root));

    const missing = findings.filter((f) => f.type === 'missing-test-file' && f.file === serviceFile);
    expect(missing.length).toBeGreaterThanOrEqual(1);
    expect(missing[0].severity).toBe('warning');
  });

  // -------------------------------------------------------------------------
  // Non-critical file without tests → severity 'info'
  // -------------------------------------------------------------------------

  it('uses severity info for non-critical source files without tests', async () => {
    const root = freshDir('tc-info-');
    const utilFile = join(root, 'src', 'utils', 'helper.ts');
    touch(utilFile);

    const findings = await analyzer.analyze(makeContext([utilFile], root));

    const missing = findings.filter((f) => f.type === 'missing-test-file' && f.file === utilFile);
    expect(missing.length).toBeGreaterThanOrEqual(1);
    expect(missing[0].severity).toBe('info');
  });

  // -------------------------------------------------------------------------
  // Summary finding is always appended
  // -------------------------------------------------------------------------

  it('appends a test-coverage-summary finding with coverage percentage in the message', async () => {
    const root = freshDir('tc-summary-');
    const fooTs = join(root, 'src', 'foo.ts');
    const barTs = join(root, 'src', 'bar.ts');
    const barTest = join(root, 'src', 'bar.test.ts');
    touch(fooTs);
    touch(barTs);
    touch(barTest, [
      "import { describe, it, expect } from 'vitest';",
      "describe('bar', () => {",
      "  it('works', () => { expect(1).toBe(1); });",
      "  it('also works', () => { expect(2).toBe(2); });",
      "  it('more', () => { expect(3).toBe(3); });",
      "  it('extra', () => { expect(4).toBe(4); });",
      "  it('another', () => { expect(5).toBe(5); });",
      "  it('and more', () => { expect(6).toBe(6); });",
      "  it('final', () => { expect(7).toBe(7); });",
      '});',
    ].join('\n'));

    const findings = await analyzer.analyze(makeContext([fooTs, barTs, barTest], root));

    const summary = findings.filter((f) => f.type === 'test-coverage-summary');
    expect(summary.length).toBe(1);
    expect(summary[0].tool).toBe('test-coverage');
    expect(summary[0].layer).toBe('static');
    expect(summary[0].confidence).toBe(1.0);
    // Message must contain coverage percentage
    expect(summary[0].message).toMatch(/\d+%/);
    // Meta should contain numeric fields
    expect(typeof summary[0].meta?.sourceFileCount).toBe('number');
    expect(typeof summary[0].meta?.coveredFileCount).toBe('number');
    expect(typeof summary[0].meta?.coveragePercent).toBe('number');
  });

  // -------------------------------------------------------------------------
  // Test file itself is not treated as a source file requiring coverage
  // -------------------------------------------------------------------------

  it('does not emit a missing-test-file finding for a test file itself', async () => {
    const root = freshDir('tc-testfile-');
    const testFile = join(root, 'src', 'math.test.ts');
    touch(testFile);

    const findings = await analyzer.analyze(makeContext([testFile], root));

    // Either no summary (no source files found) or no missing-test-file finding
    // for the test file path.
    const missing = findings.filter(
      (f) => f.type === 'missing-test-file' && f.file === testFile,
    );
    expect(missing).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Declaration files are skipped
  // -------------------------------------------------------------------------

  it('does not emit a finding for .d.ts declaration files', async () => {
    const root = freshDir('tc-dts-');
    const dtsFile = join(root, 'src', 'types.d.ts');
    touch(dtsFile, 'export type Foo = string;\n');

    const findings = await analyzer.analyze(makeContext([dtsFile], root));

    const missing = findings.filter(
      (f) => f.type === 'missing-test-file' && f.file === dtsFile,
    );
    expect(missing).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Empty test file → empty-test-file finding
  // -------------------------------------------------------------------------

  it('emits an empty-test-file finding when the companion test has fewer than 10 non-blank lines', async () => {
    const root = freshDir('tc-empty-test-');
    const srcFile = join(root, 'src', 'widget.ts');
    const testFile = join(root, 'src', 'widget.test.ts');
    touch(srcFile);
    // Write a stub with only 3 non-blank lines — below the 10-line threshold.
    touch(testFile, "import { describe } from 'vitest';\ndescribe('widget', () => {});\n");

    const findings = await analyzer.analyze(makeContext([srcFile, testFile], root));

    const emptyTest = findings.filter((f) => f.type === 'empty-test-file');
    expect(emptyTest.length).toBeGreaterThanOrEqual(1);
    expect(emptyTest[0].tool).toBe('test-coverage');
    expect(emptyTest[0].layer).toBe('static');
    expect(emptyTest[0].confidence).toBeCloseTo(0.90, 5);
  });

  // -------------------------------------------------------------------------
  // Summary coverage percentage accuracy
  // -------------------------------------------------------------------------

  it('reports 0% coverage when no source files have tests', async () => {
    const root = freshDir('tc-zero-pct-');
    const aTs = join(root, 'src', 'a.ts');
    const bTs = join(root, 'src', 'b.ts');
    touch(aTs);
    touch(bTs);

    const findings = await analyzer.analyze(makeContext([aTs, bTs], root));

    const summary = findings.find((f) => f.type === 'test-coverage-summary');
    expect(summary).toBeDefined();
    expect(summary?.meta?.coveragePercent).toBe(0);
    expect(summary?.meta?.coveredFileCount).toBe(0);
    expect(summary?.meta?.sourceFileCount).toBe(2);
  });
});
