import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig } from './config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTempDir(): string {
  const dir = join(tmpdir(), `sentinel-test-${process.pid}-${Date.now()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeJson(filePath: string, data: unknown): void {
  writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

function writeText(filePath: string, content: string): void {
  writeFileSync(filePath, content, 'utf-8');
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('loadConfig', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = makeTempDir();
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  // -------------------------------------------------------------------------
  // Defaults
  // -------------------------------------------------------------------------

  describe('with no config files present', () => {
    it('returns a config whose rootDir equals the supplied directory', () => {
      const config = loadConfig(tempDir);
      expect(config.rootDir).toBe(tempDir);
    });

    it('uses the supplied rootDir rather than process.cwd()', () => {
      // Ensure the two paths differ so the assertion is meaningful
      expect(tempDir).not.toBe(process.cwd());
      const config = loadConfig(tempDir);
      expect(config.rootDir).toBe(tempDir);
    });

    it('sets confidenceThreshold to 0.9', () => {
      const config = loadConfig(tempDir);
      expect(config.confidenceThreshold).toBe(0.9);
    });

    it('enables all three analyzers by default', () => {
      const config = loadConfig(tempDir);
      expect(config.analyzers.static.enabled).toBe(true);
      expect(config.analyzers.secrets.enabled).toBe(true);
      expect(config.analyzers.semantic.enabled).toBe(true);
    });

    it('includes standard patterns in the ignore list', () => {
      const config = loadConfig(tempDir);
      expect(config.ignore).toContain('node_modules');
      expect(config.ignore).toContain('.git');
      expect(config.ignore).toContain('dist');
    });

    it('disables watch mode by default', () => {
      const config = loadConfig(tempDir);
      expect(config.watch.enabled).toBe(false);
    });

    it('defaults output format to terminal', () => {
      const config = loadConfig(tempDir);
      expect(config.output.format).toBe('terminal');
    });

    it('defaults verbose to false', () => {
      const config = loadConfig(tempDir);
      expect(config.output.verbose).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // .sentinelrc.json present
  // -------------------------------------------------------------------------

  describe('with a .sentinelrc.json file', () => {
    it('merges user config over defaults', () => {
      writeJson(join(tempDir, '.sentinelrc.json'), {
        confidenceThreshold: 0.75,
      });

      const config = loadConfig(tempDir);
      expect(config.confidenceThreshold).toBe(0.75);
    });

    it('deep-merges nested analyzer options without clobbering unset keys', () => {
      writeJson(join(tempDir, '.sentinelrc.json'), {
        analyzers: {
          static: {
            enabled: false,
          },
        },
      });

      const config = loadConfig(tempDir);
      // Overridden key
      expect(config.analyzers.static.enabled).toBe(false);
      // Keys not in user config survive the merge
      expect(config.analyzers.static.deadCode).toBe(true);
      expect(config.analyzers.static.complexityThreshold).toBe(20);
      // Sibling analyzers are untouched
      expect(config.analyzers.secrets.enabled).toBe(true);
      expect(config.analyzers.semantic.enabled).toBe(true);
    });

    it('merges output overrides while preserving unset output keys', () => {
      writeJson(join(tempDir, '.sentinelrc.json'), {
        output: {
          verbose: true,
        },
      });

      const config = loadConfig(tempDir);
      expect(config.output.verbose).toBe(true);
      expect(config.output.format).toBe('terminal');
    });

    it('replaces the ignore array when provided in user config', () => {
      writeJson(join(tempDir, '.sentinelrc.json'), {
        ignore: ['custom-dir'],
      });

      const config = loadConfig(tempDir);
      expect(config.ignore).toEqual(['custom-dir']);
    });

    // SEC-05 ---------------------------------------------------------------

    it('SEC-05: ignores rootDir in user config — rootDir is always the supplied directory', () => {
      const attackPath = '/etc/passwd';
      writeJson(join(tempDir, '.sentinelrc.json'), {
        rootDir: attackPath,
      });

      const config = loadConfig(tempDir);
      expect(config.rootDir).toBe(tempDir);
      expect(config.rootDir).not.toBe(attackPath);
    });

    it('SEC-05: rootDir stays correct even when user config rootDir is a relative traversal', () => {
      writeJson(join(tempDir, '.sentinelrc.json'), {
        rootDir: '../../sensitive-data',
      });

      const config = loadConfig(tempDir);
      expect(config.rootDir).toBe(tempDir);
    });
  });

  // -------------------------------------------------------------------------
  // .sentinelignore present
  // -------------------------------------------------------------------------

  describe('with a .sentinelignore file', () => {
    it('appends non-comment, non-empty lines to the default ignore list', () => {
      writeText(
        join(tempDir, '.sentinelignore'),
        [
          '# This is a comment — should be skipped',
          '',
          'my-generated-dir',
          '  legacy-module  ',
          '',
        ].join('\n'),
      );

      const config = loadConfig(tempDir);
      expect(config.ignore).toContain('my-generated-dir');
      expect(config.ignore).toContain('legacy-module');
    });

    it('does not add comment lines to the ignore list', () => {
      writeText(join(tempDir, '.sentinelignore'), '# just a comment\n');

      const config = loadConfig(tempDir);
      expect(config.ignore).not.toContain('# just a comment');
    });

    it('does not add blank lines to the ignore list', () => {
      writeText(join(tempDir, '.sentinelignore'), '\n\n\n');

      const config = loadConfig(tempDir);
      // Every entry in ignore must be a non-empty string
      for (const pattern of config.ignore) {
        expect(pattern.trim().length).toBeGreaterThan(0);
      }
    });

    it('preserves default ignore patterns when .sentinelignore is present', () => {
      writeText(join(tempDir, '.sentinelignore'), 'extra-dir\n');

      const config = loadConfig(tempDir);
      expect(config.ignore).toContain('node_modules');
      expect(config.ignore).toContain('.git');
      expect(config.ignore).toContain('extra-dir');
    });
  });

  // -------------------------------------------------------------------------
  // Priority: .sentinelrc.json takes precedence over .sentinelignore
  // -------------------------------------------------------------------------

  describe('when both .sentinelrc.json and .sentinelignore are present', () => {
    it('uses .sentinelrc.json and does not read .sentinelignore', () => {
      // The implementation returns as soon as it finds a rc file, so
      // .sentinelignore patterns must NOT appear when a rc file is present.
      writeJson(join(tempDir, '.sentinelrc.json'), {
        confidenceThreshold: 0.8,
      });
      writeText(join(tempDir, '.sentinelignore'), 'should-not-appear\n');

      const config = loadConfig(tempDir);
      expect(config.confidenceThreshold).toBe(0.8);
      expect(config.ignore).not.toContain('should-not-appear');
    });
  });

  // -------------------------------------------------------------------------
  // Analyzer defaults — explicit coverage
  // -------------------------------------------------------------------------

  describe('default analyzer settings', () => {
    it('static analyzer has all sub-options enabled by default', () => {
      const { analyzers } = loadConfig(tempDir);
      expect(analyzers.static.deadCode).toBe(true);
      expect(analyzers.static.circularDeps).toBe(true);
      expect(analyzers.static.dependencies).toBe(true);
      expect(analyzers.static.security).toBe(true);
      expect(analyzers.static.complexity).toBe(true);
      expect(analyzers.static.complexityThreshold).toBe(20);
    });

    it('secrets analyzer uses gitleaks with regex fallback by default', () => {
      const { analyzers } = loadConfig(tempDir);
      expect(analyzers.secrets.useGitleaks).toBe(true);
      expect(analyzers.secrets.regexFallback).toBe(true);
    });

    it('semantic analyzer has duplication, drift, and intentRecovery enabled by default', () => {
      const { analyzers } = loadConfig(tempDir);
      expect(analyzers.semantic.duplication).toBe(true);
      expect(analyzers.semantic.duplicationThreshold).toBe(0.97);
      expect(analyzers.semantic.drift).toBe(true);
      expect(analyzers.semantic.intentRecovery).toBe(true);
    });
  });
});
