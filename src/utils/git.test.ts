import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getIgnorePatterns, isCodeFile, getRelativePath, scanFiles } from './git.js';

// ---------------------------------------------------------------------------
// isCodeFile
// ---------------------------------------------------------------------------

describe('isCodeFile', () => {
  describe('returns true for recognized code extensions', () => {
    const codeFiles = [
      'app.ts',
      'index.js',
      'component.tsx',
      'page.jsx',
      'script.py',
      'main.go',
      'Server.java',
      'lib.rb',
      'memory.rs',
      'module.c',
      'parser.cpp',
      'defs.h',
      'defs.hpp',
      'Program.cs',
      'controller.php',
      'View.swift',
      'Activity.kt',
    ];

    for (const file of codeFiles) {
      it(`${file} → true`, () => {
        expect(isCodeFile(file)).toBe(true);
      });
    }
  });

  describe('returns false for non-code extensions', () => {
    const nonCodeFiles = [
      'README.md',
      'config.json',
      'notes.txt',
      'logo.png',
      'banner.jpg',
      'archive.zip',
      'data.csv',
      'styles.css',
      'page.html',
      'Makefile',
      '',
    ];

    for (const file of nonCodeFiles) {
      it(`"${file}" → false`, () => {
        expect(isCodeFile(file)).toBe(false);
      });
    }
  });

  it('is case-sensitive: .TS (uppercase) is not a code file', () => {
    expect(isCodeFile('main.TS')).toBe(false);
  });

  it('is case-sensitive: .PY (uppercase) is not a code file', () => {
    expect(isCodeFile('script.PY')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// getRelativePath
// ---------------------------------------------------------------------------

describe('getRelativePath', () => {
  it('returns the relative POSIX path from rootDir to a direct child file', () => {
    expect(getRelativePath('/project', '/project/index.ts')).toBe('index.ts');
  });

  it('returns a nested relative POSIX path', () => {
    expect(getRelativePath('/project', '/project/src/utils/git.ts')).toBe('src/utils/git.ts');
  });

  it('uses forward slashes regardless of input separator style', () => {
    // On macOS/Linux the paths already use POSIX separators.
    // The replace(/\\/g, '/') in the implementation makes Windows paths safe.
    const result = getRelativePath('/project', '/project/src/components/Button.tsx');
    expect(result).not.toContain('\\');
  });

  it('returns an empty string when filePath equals rootDir', () => {
    expect(getRelativePath('/project', '/project')).toBe('');
  });

  it('handles deeply nested paths', () => {
    const root = '/home/user/workspace/my-app';
    const file = '/home/user/workspace/my-app/src/features/auth/handlers/login.ts';
    expect(getRelativePath(root, file)).toBe('src/features/auth/handlers/login.ts');
  });
});

// ---------------------------------------------------------------------------
// getIgnorePatterns — uses temp directories
// ---------------------------------------------------------------------------

describe('getIgnorePatterns', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'sentinel-test-ignore-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns an empty array when neither .gitignore nor .sentinelignore exist', () => {
    expect(getIgnorePatterns(tmpDir)).toEqual([]);
  });

  it('returns patterns from .gitignore, skipping comments and blank lines', () => {
    writeFileSync(join(tmpDir, '.gitignore'), [
      '# This is a comment',
      '',
      'node_modules',
      'dist/',
      '*.log',
      '  ',
      '# another comment',
      'build/',
    ].join('\n'));

    const patterns = getIgnorePatterns(tmpDir);

    expect(patterns).toContain('node_modules');
    expect(patterns).toContain('dist/');
    expect(patterns).toContain('*.log');
    expect(patterns).toContain('build/');
    // Comments and blank lines must not appear.
    expect(patterns.some((p) => p.startsWith('#'))).toBe(false);
    expect(patterns).not.toContain('');
  });

  it('returns patterns from .sentinelignore alone', () => {
    writeFileSync(join(tmpDir, '.sentinelignore'), [
      '# sentinel specific',
      'coverage/',
      '*.snap',
    ].join('\n'));

    const patterns = getIgnorePatterns(tmpDir);

    expect(patterns).toContain('coverage/');
    expect(patterns).toContain('*.snap');
    expect(patterns.some((p) => p.startsWith('#'))).toBe(false);
  });

  it('returns combined patterns when both files exist', () => {
    writeFileSync(join(tmpDir, '.gitignore'), 'node_modules\ndist/\n');
    writeFileSync(join(tmpDir, '.sentinelignore'), 'coverage/\n*.snap\n');

    const patterns = getIgnorePatterns(tmpDir);

    expect(patterns).toContain('node_modules');
    expect(patterns).toContain('dist/');
    expect(patterns).toContain('coverage/');
    expect(patterns).toContain('*.snap');
  });

  it('.gitignore patterns appear before .sentinelignore patterns', () => {
    writeFileSync(join(tmpDir, '.gitignore'), 'first-gitignore\n');
    writeFileSync(join(tmpDir, '.sentinelignore'), 'first-sentinel\n');

    const patterns = getIgnorePatterns(tmpDir);
    const gitIdx = patterns.indexOf('first-gitignore');
    const sentinelIdx = patterns.indexOf('first-sentinel');

    expect(gitIdx).toBeGreaterThanOrEqual(0);
    expect(sentinelIdx).toBeGreaterThanOrEqual(0);
    expect(gitIdx).toBeLessThan(sentinelIdx);
  });

  it('handles inline trailing whitespace on pattern lines', () => {
    writeFileSync(join(tmpDir, '.gitignore'), 'tmp   \n  dist  \n');
    const patterns = getIgnorePatterns(tmpDir);
    // The implementation trims each line.
    expect(patterns).toContain('tmp');
    expect(patterns).toContain('dist');
  });

  it('returns an empty array for a completely blank ignore file', () => {
    writeFileSync(join(tmpDir, '.gitignore'), '\n\n  \n\n');
    expect(getIgnorePatterns(tmpDir)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// scanFiles — uses temp directories
// ---------------------------------------------------------------------------

describe('scanFiles', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'sentinel-test-scan-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  // Helper: create a file (and any intermediate directories).
  function touch(relPath: string, content = ''): void {
    const abs = join(tmpDir, relPath);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, content);
  }

  it('returns an empty array for an empty directory', async () => {
    const results = await scanFiles(tmpDir, []);
    expect(results).toEqual([]);
  });

  it('returns only code files from a flat directory', async () => {
    touch('index.ts');
    touch('README.md');
    touch('config.json');
    touch('script.py');
    touch('logo.png');

    const results = await scanFiles(tmpDir, []);

    expect(results).toContain('index.ts');
    expect(results).toContain('script.py');
    expect(results).not.toContain('README.md');
    expect(results).not.toContain('config.json');
    expect(results).not.toContain('logo.png');
  });

  it('recurses into subdirectories and returns relative POSIX paths', async () => {
    touch('src/app.ts');
    touch('src/utils/helper.js');
    touch('src/utils/helper.test.ts');
    touch('docs/guide.md');

    const results = await scanFiles(tmpDir, []);

    expect(results).toContain('src/app.ts');
    expect(results).toContain('src/utils/helper.js');
    expect(results).toContain('src/utils/helper.test.ts');
    expect(results).not.toContain('docs/guide.md');
  });

  it('returns results in sorted order', async () => {
    touch('zebra.ts');
    touch('alpha.ts');
    touch('middle.ts');

    const results = await scanFiles(tmpDir, []);

    expect(results).toEqual([...results].sort());
  });

  it('automatically skips node_modules at any depth', async () => {
    touch('src/index.ts');
    touch('node_modules/lodash/index.js');
    touch('src/node_modules/local-pkg/index.ts');

    const results = await scanFiles(tmpDir, []);

    expect(results).toContain('src/index.ts');
    expect(results.some((p) => p.includes('node_modules'))).toBe(false);
  });

  it('automatically skips .git at any depth', async () => {
    touch('src/index.ts');
    touch('.git/hooks/pre-commit');
    touch('.git/config');

    const results = await scanFiles(tmpDir, []);

    expect(results).toContain('src/index.ts');
    expect(results.some((p) => p.includes('.git'))).toBe(false);
  });

  it('respects a simple filename ignore pattern (no slash → basename match at any depth)', async () => {
    touch('src/index.ts');
    touch('src/generated.ts');
    touch('lib/generated.ts');

    const results = await scanFiles(tmpDir, ['generated.ts']);

    expect(results).toContain('src/index.ts');
    expect(results).not.toContain('src/generated.ts');
    expect(results).not.toContain('lib/generated.ts');
  });

  it('respects a directory ignore pattern (trailing slash)', async () => {
    touch('src/index.ts');
    touch('dist/bundle.js');
    touch('dist/helpers/util.ts');

    const results = await scanFiles(tmpDir, ['dist/']);

    expect(results).toContain('src/index.ts');
    expect(results.some((p) => p.startsWith('dist/'))).toBe(false);
  });

  it('respects a glob wildcard pattern (*.d.ts)', async () => {
    touch('src/types.d.ts');
    touch('src/index.ts');

    const results = await scanFiles(tmpDir, ['*.d.ts']);

    expect(results).toContain('src/index.ts');
    expect(results).not.toContain('src/types.d.ts');
  });

  it('respects an anchored pattern with leading slash', async () => {
    touch('build/output.js');
    touch('src/build/nested.js');

    // Leading slash anchors to root — should only match top-level `build/`.
    const results = await scanFiles(tmpDir, ['/build']);

    expect(results).toContain('src/build/nested.js');
    expect(results).not.toContain('build/output.js');
  });

  it('respects an internal-slash pattern (anchored directory path)', async () => {
    touch('src/generated/api.ts');
    touch('src/manual/service.ts');

    const results = await scanFiles(tmpDir, ['src/generated']);

    expect(results).toContain('src/manual/service.ts');
    expect(results).not.toContain('src/generated/api.ts');
  });

  it('respects a double-star glob pattern (**/*.test.ts)', async () => {
    touch('src/utils/helper.ts');
    touch('src/utils/helper.test.ts');
    touch('tests/integration/api.test.ts');

    const results = await scanFiles(tmpDir, ['**/*.test.ts']);

    expect(results).toContain('src/utils/helper.ts');
    expect(results).not.toContain('src/utils/helper.test.ts');
    expect(results).not.toContain('tests/integration/api.test.ts');
  });

  it('applies multiple ignore patterns together', async () => {
    touch('src/index.ts');
    touch('src/index.test.ts');
    touch('dist/bundle.js');
    touch('docs/README.md');

    const results = await scanFiles(tmpDir, ['dist/', '**/*.test.ts']);

    expect(results).toContain('src/index.ts');
    expect(results).not.toContain('src/index.test.ts');
    expect(results).not.toContain('dist/bundle.js');
    // Non-code file is excluded regardless of ignore patterns.
    expect(results).not.toContain('docs/README.md');
  });

  it('does not follow symlinks that create directory loops', async () => {
    touch('src/index.ts');
    // Create a symlink inside src/ that points back to the root — a loop.
    const loopLink = join(tmpDir, 'src', 'loop');
    try {
      symlinkSync(tmpDir, loopLink);
    } catch {
      // If symlink creation fails (e.g. permission), skip the test body.
      return;
    }

    // Should complete without hanging or throwing.
    const results = await scanFiles(tmpDir, []);
    expect(results).toContain('src/index.ts');
  });

  it('returns paths with forward slashes only (no backslashes)', async () => {
    touch('a/b/c/deep.ts');

    const results = await scanFiles(tmpDir, []);

    for (const r of results) {
      expect(r).not.toContain('\\');
    }
  });
});
