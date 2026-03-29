import { describe, it, expect, afterAll } from 'vitest';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { CommentedCodeAnalyzer } from './commented-code.js';
import type { AnalysisContext, SentinelConfig } from '../../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(): SentinelConfig {
  return {
    rootDir: '',
    confidenceThreshold: 0.5,
    ignore: [],
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

function makeContext(files: string[], rootDir: string): AnalysisContext {
  return { rootDir, files, config: makeConfig() };
}

// ---------------------------------------------------------------------------
// Temp directory — shared across all tests, cleaned up in afterAll
// ---------------------------------------------------------------------------

const TEMP_DIR = mkdtempSync(join(tmpdir(), 'commented-code-test-'));
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

describe('CommentedCodeAnalyzer', () => {
  const analyzer = new CommentedCodeAnalyzer();

  it('has correct name and layer', () => {
    expect(analyzer.name).toBe('CommentedCode');
    expect(analyzer.layer).toBe('static');
  });

  // -------------------------------------------------------------------------
  // 3+ consecutive commented-out code lines → finding
  // -------------------------------------------------------------------------

  it('detects a block of 3+ consecutive commented-out JS/TS lines', async () => {
    // Place the block after the 10-line license header window.
    const file = temp('block-ts.ts', `
// normal comment line 1
// normal comment line 2
// normal comment line 3
// normal comment line 4
// normal comment line 5
// normal comment line 6
// normal comment line 7
// normal comment line 8
// normal comment line 9
// normal comment line 10
// normal comment line 11
// const x = 1;
// const y = 2;
// const z = 3;
export function live() { return true; }
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.file === file && f.type === 'commented-out-code');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].layer).toBe('static');
    expect(match[0].tool).toBe('commented-code');
    expect(match[0].severity).toBe('info');
    expect(match[0].confidence).toBeCloseTo(0.85, 5);
  });

  // -------------------------------------------------------------------------
  // Regular prose comments → no finding
  // -------------------------------------------------------------------------

  it('does not flag regular prose comment lines', async () => {
    const file = temp('prose-comments.ts', `
// This module handles user authentication.
// It delegates to the AuthService which wraps the external OAuth provider.
// All tokens are stored in the secure cookie store.
// See the auth architecture doc for details.
// Make sure to update this if the cookie name changes.
// Reviewed by the security team in Q1 2025.
// The timeout values below are in milliseconds.
// Longer timeouts are used for refresh token operations.
// Short timeouts for interactive login to avoid session fixation.
// This block intentionally has no return value.
// Read the README before modifying this file.
// Another prose comment.
export function authenticate() { return true; }
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.file === file && f.type === 'commented-out-code');
    expect(match).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Single commented line → no finding (below the 3-line threshold)
  // -------------------------------------------------------------------------

  it('does not emit a finding for a single commented-out code line', async () => {
    const file = temp('single-line.ts', `
// filler line 1
// filler line 2
// filler line 3
// filler line 4
// filler line 5
// filler line 6
// filler line 7
// filler line 8
// filler line 9
// filler line 10
// filler line 11
// const x = 1;
export function doWork() { return 42; }
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.file === file && f.type === 'commented-out-code');
    expect(match).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Two consecutive commented lines → no finding (below 3-line threshold)
  // -------------------------------------------------------------------------

  it('does not emit a finding for two consecutive commented-out code lines', async () => {
    const file = temp('two-lines.ts', `
// filler 1
// filler 2
// filler 3
// filler 4
// filler 5
// filler 6
// filler 7
// filler 8
// filler 9
// filler 10
// filler 11
// const a = 1;
// const b = 2;
export const result = 0;
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.file === file && f.type === 'commented-out-code');
    expect(match).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // License header in first 10 lines → not flagged
  // -------------------------------------------------------------------------

  it('does not flag commented-out code patterns inside the license header window (first 10 lines)', async () => {
    // These look like code prefixes but live within the first 10 lines.
    // The analyzer explicitly skips lines 1-10 as a license header window.
    const file = temp('license-header.ts', `// Copyright (c) 2025 Acme Corp. All rights reserved.
// const LICENSE_VERSION = '1.0';
// const AUTHOR = 'acme';
// export const TERMS = 'MIT';
// Licensed under the MIT License.
// Permission is hereby granted, free of charge.
// To any person obtaining a copy of this software.
// const CONDITIONS = true;
// const WARRANTY = false;
// import permissions from './license';
export const APP_VERSION = '1.0.0';
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.file === file && f.type === 'commented-out-code');
    expect(match).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // TODO comment → not flagged as commented-out code
  // -------------------------------------------------------------------------

  it('does not flag TODO/FIXME/HACK comment lines as commented-out code', async () => {
    const file = temp('todo-not-code.ts', `
// filler 1
// filler 2
// filler 3
// filler 4
// filler 5
// filler 6
// filler 7
// filler 8
// filler 9
// filler 10
// filler 11
// TODO: add const x here
// FIXME: const y is broken
// HACK: const z bypass
export function noop() {}
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    // Skip-line patterns exclude TODO/FIXME/HACK — they should NOT count
    // as code lines and therefore the block should not reach MIN_BLOCK_SIZE.
    const match = findings.filter((f) => f.file === file && f.type === 'commented-out-code');
    expect(match).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Python file — 3+ consecutive commented-out code lines
  // -------------------------------------------------------------------------

  it('detects commented-out code in Python files using # prefix', async () => {
    const file = temp('block-py.py', `
# normal comment 1
# normal comment 2
# normal comment 3
# normal comment 4
# normal comment 5
# normal comment 6
# normal comment 7
# normal comment 8
# normal comment 9
# normal comment 10
# normal comment 11
# def old_function():
# for item in items:
# return result
def live_function():
    pass
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.file === file && f.type === 'commented-out-code');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].layer).toBe('static');
    expect(match[0].tool).toBe('commented-code');
  });

  // -------------------------------------------------------------------------
  // Test files are skipped entirely
  // -------------------------------------------------------------------------

  it('skips files matching the .test.ts pattern', async () => {
    // The analyzer explicitly excludes test files.
    const file = temp('skip-this.test.ts', `
// padding 1
// padding 2
// padding 3
// padding 4
// padding 5
// padding 6
// padding 7
// padding 8
// padding 9
// padding 10
// padding 11
// const x = 1;
// const y = 2;
// const z = 3;
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.file === file);
    expect(match).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Finding shape
  // -------------------------------------------------------------------------

  it('emits a finding with blockSize in meta and correct endLine', async () => {
    const file = temp('meta-check.ts', `
// line 1
// line 2
// line 3
// line 4
// line 5
// line 6
// line 7
// line 8
// line 9
// line 10
// line 11
// const alpha = 1;
// const beta = 2;
// const gamma = 3;
export const live = true;
`);
    const findings = await analyzer.analyze(makeContext([file], TEMP_DIR));

    const match = findings.filter((f) => f.file === file && f.type === 'commented-out-code');
    expect(match.length).toBeGreaterThanOrEqual(1);

    const f = match[0];
    expect(typeof f.id).toBe('string');
    expect(f.id.length).toBeGreaterThan(0);
    expect(typeof f.line).toBe('number');
    expect(typeof f.endLine).toBe('number');
    expect((f.endLine as number)).toBeGreaterThanOrEqual((f.line as number) + 2);
    expect(typeof f.meta?.blockSize).toBe('number');
    expect(f.meta?.blockSize).toBeGreaterThanOrEqual(3);
  });
});
