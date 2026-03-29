import { describe, it, expect, afterAll } from 'vitest';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { TodoTrackerAnalyzer } from './todo-tracker.js';
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
        testCoverage: false,
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

function makeContext(files: string[], rootDir: string, ignore: string[] = []): AnalysisContext {
  return { rootDir, files, config: makeConfig(ignore) };
}

// ---------------------------------------------------------------------------
// Temp directory — shared across all tests, cleaned up in afterAll
// ---------------------------------------------------------------------------

const TEMP_DIR = mkdtempSync(join(tmpdir(), 'todo-tracker-test-'));
const tempFiles: string[] = [];

function temp(name: string, content: string): string {
  const filePath = join(TEMP_DIR, name);
  writeFileSync(filePath, content, 'utf-8');
  tempFiles.push(filePath);
  return filePath;
}

afterAll(() => {
  for (const f of tempFiles) {
    try { unlinkSync(f); } catch { /* ignore */ }
  }
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('TodoTrackerAnalyzer', () => {
  const analyzer = new TodoTrackerAnalyzer();

  it('has correct name and layer', () => {
    expect(analyzer.name).toBe('todo-tracker');
    expect(analyzer.layer).toBe('static');
  });

  // -------------------------------------------------------------------------
  // TODO → type 'todo-comment', severity 'info'
  // -------------------------------------------------------------------------

  it('detects // TODO comment and emits type todo-comment with severity info', async () => {
    const file = temp('todo.ts', `
function doSomething() {
  // TODO: fix this properly
  return null;
}
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.type === 'todo-comment');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].severity).toBe('info');
    expect(match[0].confidence).toBe(1.0);
    expect(match[0].file).toBe(file);
    expect(match[0].layer).toBe('static');
    expect(match[0].tool).toBe('todo-tracker');
  });

  // -------------------------------------------------------------------------
  // FIXME → type 'fixme-comment', severity 'warning'
  // -------------------------------------------------------------------------

  it('detects # FIXME comment and emits type fixme-comment with severity warning', async () => {
    const file = temp('fixme.py', `
def calculate():
    # FIXME: broken calculation
    return 0
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.type === 'fixme-comment');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].severity).toBe('warning');
    expect(match[0].confidence).toBe(1.0);
    expect(match[0].file).toBe(file);
  });

  // -------------------------------------------------------------------------
  // HACK → type 'hack-comment', severity 'warning'
  // -------------------------------------------------------------------------

  it('detects // HACK comment and emits type hack-comment with severity warning', async () => {
    const file = temp('hack.ts', `
export function parseDate(input: string) {
  // HACK: workaround for date-fns timezone issue
  return new Date(input + 'Z');
}
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.type === 'hack-comment');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].severity).toBe('warning');
    expect(match[0].confidence).toBe(1.0);
    expect(match[0].file).toBe(file);
  });

  // -------------------------------------------------------------------------
  // DEPRECATED → type 'deprecated-comment', severity 'warning'
  // -------------------------------------------------------------------------

  it('detects // DEPRECATED comment and emits type deprecated-comment with severity warning', async () => {
    const file = temp('deprecated.ts', `
// DEPRECATED: use v2 API instead
export function legacyFetch(url: string) {
  return fetch(url);
}
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.type === 'deprecated-comment');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].severity).toBe('warning');
    expect(match[0].confidence).toBe(1.0);
    expect(match[0].file).toBe(file);
  });

  // -------------------------------------------------------------------------
  // No markers → empty findings
  // -------------------------------------------------------------------------

  it('returns no findings for a file with no recognized markers', async () => {
    const file = temp('clean.ts', `
// This is a regular comment explaining the function.
// It spans multiple lines but contains no debt markers.
export function add(a: number, b: number): number {
  return a + b;
}
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    // Filter to only findings from this specific file to avoid cross-test noise.
    const fromFile = findings.filter((f) => f.file === file);
    expect(fromFile).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Severity contract: TODO=info, FIXME/HACK=warning
  // -------------------------------------------------------------------------

  it('assigns info severity to TODO and warning severity to FIXME and HACK', async () => {
    const file = temp('severity-mix.ts', `
// TODO: add input validation
// FIXME: null pointer on empty input
// HACK: bypass type check
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const fromFile = findings.filter((f) => f.file === file);

    const todo = fromFile.find((f) => f.type === 'todo-comment');
    const fixme = fromFile.find((f) => f.type === 'fixme-comment');
    const hack = fromFile.find((f) => f.type === 'hack-comment');

    expect(todo?.severity).toBe('info');
    expect(fixme?.severity).toBe('warning');
    expect(hack?.severity).toBe('warning');
  });

  // -------------------------------------------------------------------------
  // All findings have confidence 1.0
  // -------------------------------------------------------------------------

  it('emits confidence 1.0 for all marker types', async () => {
    const file = temp('confidence.ts', `
// TODO: task one
// FIXME: broken
// HACK: shortcut
// DEPRECATED: old api
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));
    const fromFile = findings.filter((f) => f.file === file);

    for (const f of fromFile) {
      expect(f.confidence).toBe(1.0);
    }
  });

  // -------------------------------------------------------------------------
  // Finding shape
  // -------------------------------------------------------------------------

  it('emits findings with required Finding fields populated', async () => {
    const file = temp('shape.ts', `// TODO: check this`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.file === file && f.type === 'todo-comment');
    expect(match.length).toBeGreaterThanOrEqual(1);

    const f = match[0];
    expect(typeof f.id).toBe('string');
    expect(f.id.length).toBeGreaterThan(0);
    expect(f.layer).toBe('static');
    expect(f.tool).toBe('todo-tracker');
    expect(typeof f.line).toBe('number');
    expect(f.line).toBeGreaterThan(0);
    expect(typeof f.message).toBe('string');
    expect(f.message.length).toBeGreaterThan(0);
  });

  // -------------------------------------------------------------------------
  // Line number accuracy
  // -------------------------------------------------------------------------

  it('reports the correct 1-based line number for the marker', async () => {
    const file = temp('line-number.ts', `const x = 1;\nconst y = 2;\n// TODO: fix this\nconst z = 3;\n`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.file === file && f.type === 'todo-comment');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].line).toBe(3);
  });

  // -------------------------------------------------------------------------
  // Ignored file is skipped
  // -------------------------------------------------------------------------

  it('skips files in config.ignore directories', async () => {
    const ignoredDir = mkdtempSync(join(tmpdir(), 'todo-ignored-'));
    const ignoredFile = join(ignoredDir, 'should-skip.ts');
    writeFileSync(ignoredFile, '// TODO: this should not be reported\n', 'utf-8');

    try {
      const findings = await analyzer.analyze({
        rootDir: ignoredDir,
        files: [ignoredFile],
        config: makeConfig([ignoredDir]),
      });
      const fromFile = findings.filter((f) => f.file === ignoredFile);
      expect(fromFile).toHaveLength(0);
    } finally {
      try { unlinkSync(ignoredFile); } catch { /* ignore */ }
    }
  });
});
