import { describe, it, expect, afterAll } from 'vitest';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { RegexFallbackAnalyzer } from './fallback.js';
import type { AnalysisContext, SentinelConfig } from '../../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal valid SentinelConfig — only fields the analyzer touches matter */
function makeConfig(): SentinelConfig {
  return {
    rootDir: '',
    confidenceThreshold: 0.5,
    ignore: [],
    analyzers: {
      static: {
        enabled: false,
        deadCode: false,
        circularDeps: false,
        dependencies: false,
        security: false,
        complexity: false,
        complexityThreshold: 10,
      },
      secrets: {
        enabled: true,
        useGitleaks: false,
        regexFallback: true,
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

/** Write content to a named temp file, return the absolute path */
function writeTempFile(dir: string, name: string, content: string): string {
  const filePath = join(dir, name);
  writeFileSync(filePath, content, 'utf-8');
  return filePath;
}

/** Build an AnalysisContext for a list of absolute file paths */
function makeContext(files: string[], rootDir?: string): AnalysisContext {
  return {
    // Default to TEMP_DIR so scanAllFiles only walks the isolated test
    // directory, not the entire OS tmpdir (which contains macOS system
    // entries that cause EPERM or pick up secrets from unrelated tests).
    rootDir: rootDir ?? TEMP_DIR,
    files,
    config: makeConfig(),
  };
}

// ---------------------------------------------------------------------------
// Temp directory — shared across all tests, cleaned up in afterAll
// ---------------------------------------------------------------------------

const TEMP_DIR = mkdtempSync(join(tmpdir(), 'fallback-test-'));
const tempFiles: string[] = [];

function temp(name: string, content: string): string {
  const p = writeTempFile(TEMP_DIR, name, content);
  tempFiles.push(p);
  return p;
}

afterAll(() => {
  for (const f of tempFiles) {
    try { unlinkSync(f); } catch { /* ignore */ }
  }
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RegexFallbackAnalyzer', () => {
  const analyzer = new RegexFallbackAnalyzer();

  it('has correct name and layer', () => {
    expect(analyzer.name).toBe('regex-fallback');
    expect(analyzer.layer).toBe('secrets');
  });

  // -------------------------------------------------------------------------
  // AWS Access Key ID
  // -------------------------------------------------------------------------

  it('detects AWS Access Key ID with confidence >= 0.90', async () => {
    const file = temp('aws-key.ts', `
const ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
`);
    const findings = await analyzer.analyze(makeContext([file]));

    const match = findings.filter(f => f.type === 'aws-access-key-id');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].confidence).toBeGreaterThanOrEqual(0.90);
    expect(match[0].file).toBe(file);
    expect(match[0].layer).toBe('secrets');
    expect(match[0].severity).toBe('error');
  });

  // -------------------------------------------------------------------------
  // GitHub Token
  // -------------------------------------------------------------------------

  it('detects a GitHub personal access token (ghp_ prefix)', async () => {
    const file = temp('github-token.ts', `
const TOKEN = 'ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE';
`);
    const findings = await analyzer.analyze(makeContext([file]));

    const match = findings.filter(f => f.type === 'github-token');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].confidence).toBeGreaterThanOrEqual(0.90);
    expect(match[0].file).toBe(file);
  });

  // -------------------------------------------------------------------------
  // Stripe Key
  // -------------------------------------------------------------------------

  it('detects a database connection string', async () => {
    const file = temp('db-conn.ts', `
const dbUrl = 'postgresql://admin:SuperSecret123@db.example.com:5432/mydb';
`);
    const findings = await analyzer.analyze(makeContext([file]));

    const match = findings.filter(f => f.type === 'database-connection-string');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].file).toBe(file);
  });

  // -------------------------------------------------------------------------
  // RSA Private Key
  // -------------------------------------------------------------------------

  it('detects RSA private key block header', async () => {
    const file = temp('private-key.pem', `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4xdTa...
-----END RSA PRIVATE KEY-----
`);
    const findings = await analyzer.analyze(makeContext([file]));

    const match = findings.filter(f => f.type === 'rsa-private-key');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].confidence).toBeGreaterThanOrEqual(0.90);
    expect(match[0].file).toBe(file);
  });

  // -------------------------------------------------------------------------
  // Database Connection String
  // -------------------------------------------------------------------------

  it('detects a PostgreSQL connection string with embedded credentials', async () => {
    // Password must pass isHighEntropy(m, 2.5) and must not contain '@' or
    // whitespace (the capture group is [^@\s]{4,}). Use a mixed-case hex-like
    // password that scores well above the 2.5 Shannon entropy threshold.
    const file = temp('db-config.ts', `
const DB_URL = 'postgres://user:Xk9mN2vQ8rLp3zW1@db.example.com/mydb';
`);
    const findings = await analyzer.analyze(makeContext([file]));

    const match = findings.filter(f => f.type === 'database-connection-string');
    expect(match.length).toBeGreaterThanOrEqual(1);
    expect(match[0].file).toBe(file);
  });

  // -------------------------------------------------------------------------
  // Clean file — no findings
  // -------------------------------------------------------------------------

  it('returns no findings for a file with no secrets', async () => {
    // Use an isolated directory containing ONLY the clean file so that other
    // test files with real-looking secrets do not leak into this assertion.
    const cleanDir = mkdtempSync(join(tmpdir(), 'sentinel-clean-'));
    const file = writeTempFile(cleanDir, 'clean.ts', `
export function add(a: number, b: number): number {
  return a + b;
}

const greeting = 'Hello, world!';
const port = 3000;
`);
    try {
      const findings = await analyzer.analyze(makeContext([file], cleanDir));
      expect(findings).toHaveLength(0);
    } finally {
      try { unlinkSync(file); } catch { /* ignore */ }
    }
  });

  // -------------------------------------------------------------------------
  // Placeholder passwords — should NOT be detected
  // -------------------------------------------------------------------------

  it('does not flag placeholder password = "changeme"', async () => {
    const file = temp('placeholder-password.ts', `
const config = {
  password: "changeme",
};
`);
    const findings = await analyzer.analyze(makeContext([file]));

    // The plaintext-password pattern matches but the validate() function
    // explicitly excludes 'changeme' — no finding should survive.
    const match = findings.filter(f => f.type === 'plaintext-password');
    expect(match).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // SEC-03: Lines exceeding 4096 chars must be skipped (ReDoS guard)
  // -------------------------------------------------------------------------

  it('skips lines longer than 4096 characters and produces no findings', async () => {
    // Embed a real-looking AWS key inside a 5000-char line — the guard must
    // fire before any pattern is applied, so no finding should be emitted.
    const longLine = 'x'.repeat(2048) + 'AKIAIOSFODNN7EXAMPLE' + 'y'.repeat(2048);
    expect(longLine.length).toBeGreaterThan(4096);

    // Use an isolated directory containing only this one file so that other
    // test files with shorter secrets do not pollute the finding count.
    const longLineDir = mkdtempSync(join(tmpdir(), 'sentinel-longline-'));
    const file = writeTempFile(longLineDir, 'long-line.ts', longLine);
    try {
      const findings = await analyzer.analyze(makeContext([file], longLineDir));
      // No findings should come from the oversized line
      expect(findings).toHaveLength(0);
    } finally {
      try { unlinkSync(file); } catch { /* ignore */ }
    }
  });

  // -------------------------------------------------------------------------
  // Multiple files in a single context
  // -------------------------------------------------------------------------

  it('scans multiple files and attributes findings to the correct file', async () => {
    const fileA = temp('multi-a.ts', `const key = 'AKIAIOSFODNN7EXAMPLE';`);
    const fileB = temp('multi-b.ts', `export const greeting = 'Hello';`);
    const fileC = temp('multi-c.ts', `const token = 'ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE';`);

    const findings = await analyzer.analyze(makeContext([fileA, fileB, fileC]));

    const filesWithFindings = new Set(findings.map(f => f.file));
    expect(filesWithFindings.has(fileA)).toBe(true);
    expect(filesWithFindings.has(fileB)).toBe(false);
    expect(filesWithFindings.has(fileC)).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Finding shape — every finding must conform to the Finding interface
  // -------------------------------------------------------------------------

  it('emits findings that conform to the Finding interface', async () => {
    // Use an isolated directory so we only get findings from this one file.
    const shapeDir = mkdtempSync(join(tmpdir(), 'sentinel-shape-'));
    const file = writeTempFile(shapeDir, 'shape-check.ts', `const k = 'AKIAIOSFODNN7EXAMPLE';`);
    try {
      const findings = await analyzer.analyze(makeContext([file], shapeDir));

      expect(findings.length).toBeGreaterThanOrEqual(1);
      for (const f of findings) {
        expect(typeof f.id).toBe('string');
        expect(f.id.length).toBeGreaterThan(0);
        expect(f.layer).toBe('secrets');
        expect(typeof f.type).toBe('string');
        expect(['error', 'warning', 'info']).toContain(f.severity);
        expect(f.confidence).toBeGreaterThanOrEqual(0);
        expect(f.confidence).toBeLessThanOrEqual(1);
        expect(f.file).toBe(file);
        expect(typeof f.line).toBe('number');
        expect(typeof f.message).toBe('string');
        expect(f.tool).toBe('regex-fallback');
      }
    } finally {
      try { unlinkSync(file); } catch { /* ignore */ }
    }
  });

  // -------------------------------------------------------------------------
  // Confidence is reduced in test files
  // -------------------------------------------------------------------------

  it('reduces confidence by 0.15 when scanning a .test.ts file', async () => {
    // Use an isolated directory so the only aws-access-key-id finding comes
    // from the .test.ts file — not from other test fixtures in TEMP_DIR.
    const testFileDir = mkdtempSync(join(tmpdir(), 'sentinel-testfile-'));
    const file = writeTempFile(testFileDir, 'secrets.test.ts', `const k = 'AKIAIOSFODNN7EXAMPLE';`);
    try {
      const findings = await analyzer.analyze(makeContext([file], testFileDir));

      const match = findings.filter(f => f.type === 'aws-access-key-id' && f.file === file);
      expect(match.length).toBeGreaterThanOrEqual(1);
      // AWS key base confidence = 0.95; reduced by 0.15 → 0.80
      expect(match[0].confidence).toBeCloseTo(0.80, 5);
      expect(match[0].meta?.inTestFile).toBe(true);
    } finally {
      try { unlinkSync(file); } catch { /* ignore */ }
    }
  });

  // -------------------------------------------------------------------------
  // Redaction — message must not contain the full secret
  // -------------------------------------------------------------------------

  it('redacts the secret value in the finding message (shows only first 4 chars + ...)', async () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const file = temp('redaction.ts', `const k = '${secret}';`);
    const findings = await analyzer.analyze(makeContext([file]));

    const match = findings.filter(f => f.type === 'aws-access-key-id');
    expect(match.length).toBeGreaterThanOrEqual(1);
    // Full secret must NOT appear in the message
    expect(match[0].message).not.toContain(secret);
    // First 4 chars + ellipsis should appear
    expect(match[0].message).toContain('AKIA...');
  });

  // -------------------------------------------------------------------------
  // Unreadable / non-existent file — must be skipped silently
  // -------------------------------------------------------------------------

  it('skips a non-existent file without throwing', async () => {
    // Use a freshly created empty directory as rootDir so scanAllFiles finds
    // no other test files and the empty result is unambiguous.
    const emptyDir = mkdtempSync(join(tmpdir(), 'sentinel-empty-'));
    const missing = join(emptyDir, 'does-not-exist.ts');
    try {
      await expect(
        analyzer.analyze(makeContext([missing], emptyDir))
      ).resolves.toEqual([]);
    } finally {
      try { unlinkSync(emptyDir); } catch { /* ignore */ }
    }
  });
});
