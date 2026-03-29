// ============================================================
// CodeSentinel — Git & File System Utilities
// ============================================================

import { readFileSync } from 'node:fs';
import { readdir, lstat, stat } from 'node:fs/promises';
import { join, relative, extname } from 'node:path';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * All source code extensions recognized by CodeSentinel.
 * Stored as a Set for O(1) membership checks.
 */
const CODE_EXTENSIONS = new Set<string>([
  '.js', '.ts', '.jsx', '.tsx',
  '.py',
  '.go',
  '.java',
  '.rb',
  '.rs',
  '.c', '.cpp', '.h', '.hpp',
  '.cs',
  '.php',
  '.swift',
  '.kt',
]);

/**
 * Config and environment file extensions recognized for secret scanning.
 * `.env*` files are handled separately by basename prefix matching in
 * `isSecretScanFile` because they have no fixed extension.
 *
 * `.md` is included so that secrets embedded in README / documentation files
 * are flagged (with reduced confidence when inside a code block — see the
 * RegexFallbackAnalyzer markdown handling).
 */
const SECRET_SCAN_EXTENSIONS = new Set<string>([
  '.json',
  '.yaml', '.yml',
  '.ini',
  '.toml',
  '.cfg',
  '.conf',
  '.properties',
  '.xml',
  '.md',
  // Certificate / key material files — private key headers inside these are
  // exactly the kind of secret we scan for.
  '.pem', '.key', '.crt', '.cer', '.p12', '.pfx',
]);

// ---------------------------------------------------------------------------
// getIgnorePatterns
// ---------------------------------------------------------------------------

/**
 * Read .gitignore and .sentinelignore from rootDir and return combined
 * ignore patterns as an array of non-empty, non-comment strings.
 *
 * - Patterns are returned as-is; callers pass them to scanFiles.
 * - Missing ignore files are silently skipped.
 * - Duplicate patterns are preserved (callers can deduplicate if needed).
 *
 * This function is intentionally synchronous. It is called once at startup
 * before any async work begins, and the caller needs the complete pattern list
 * before initiating the scan.
 */
export function getIgnorePatterns(rootDir: string): string[] {
  const patterns: string[] = [];

  for (const filename of ['.gitignore', '.sentinelignore']) {
    const filePath = join(rootDir, filename);
    try {
      const raw = readFileSync(filePath, 'utf8');
      for (const line of raw.split('\n')) {
        const trimmed = line.trim();
        if (trimmed.length > 0 && !trimmed.startsWith('#')) {
          patterns.push(trimmed);
        }
      }
    } catch {
      // File does not exist or is not readable — skip silently.
    }
  }

  return patterns;
}

// ---------------------------------------------------------------------------
// isCodeFile
// ---------------------------------------------------------------------------

/**
 * Returns true when the file extension is in the known code extensions set.
 * The check is case-sensitive (Unix file systems are case-sensitive).
 */
export function isCodeFile(filePath: string): boolean {
  return CODE_EXTENSIONS.has(extname(filePath));
}

// ---------------------------------------------------------------------------
// isSecretScanFile
// ---------------------------------------------------------------------------

/**
 * Returns true when the file should be included in a secret scan pass.
 *
 * Covers:
 * - All code files (delegates to isCodeFile so the list stays in sync)
 * - `.env`, `.env.local`, `.env.production`, `.env.development`,
 *   `.env.example`, `.env.test`, and any other `.env*` variant
 * - Config/manifest formats: JSON, YAML, INI, TOML, CFG, CONF,
 *   Properties, XML
 *
 * The check is deliberately case-sensitive (Unix file systems are).
 */
export function isSecretScanFile(filePath: string): boolean {
  if (isCodeFile(filePath)) {
    return true;
  }

  // Path.basename gives us "foo.env.local" → we want basename, not extname,
  // because `.env` and `.env.local` have no conventional "extension".
  const base = filePath.includes('/')
    ? filePath.slice(filePath.lastIndexOf('/') + 1)
    : filePath;

  // Any filename that starts with ".env" — e.g. .env, .env.local, .env.test
  if (base.startsWith('.env')) {
    return true;
  }

  // .gitignore and .dockerignore may contain secrets in comments (e.g. tokens
  // pasted as reminders, or base64-encoded credentials).  Include them so the
  // secret scanner inspects these files.
  if (base === '.gitignore' || base === '.dockerignore') {
    return true;
  }

  return SECRET_SCAN_EXTENSIONS.has(extname(filePath));
}

// ---------------------------------------------------------------------------
// getRelativePath
// ---------------------------------------------------------------------------

/**
 * Returns the path of filePath relative to rootDir.
 * Uses POSIX separators on all platforms for consistent output.
 */
export function getRelativePath(rootDir: string, filePath: string): string {
  return relative(rootDir, filePath).replace(/\\/g, '/');
}

// ---------------------------------------------------------------------------
// Internal ignore-pattern matching
// ---------------------------------------------------------------------------

/**
 * Minimal gitignore-style pattern compiler.
 *
 * Rules implemented:
 * - Patterns ending with "/" match directories only.
 * - Patterns containing a "/" are anchored to the root.
 * - Patterns without "/" match the basename at any depth.
 * - "**" matches any sequence including path separators.
 * - "*" matches any sequence except "/".
 * - "?" matches exactly one non-"/" character.
 */
function patternToRegex(pattern: string): RegExp {
  const isDirectoryOnly = pattern.endsWith('/');
  let p = isDirectoryOnly ? pattern.slice(0, -1) : pattern;

  // A leading `/` means "anchored to root" in gitignore semantics.
  // Strip it — the regex `^` will enforce the anchoring.
  const hasLeadingSlash = p.startsWith('/');
  if (hasLeadingSlash) {
    p = p.slice(1);
  }

  // A pattern is anchored when it originally started with `/`, or contains
  // an internal `/` (e.g. `src/foo`).
  const isAnchored = hasLeadingSlash || p.includes('/');

  // Unanchored patterns match the basename at any directory depth.
  if (!isAnchored) {
    p = '**/' + p;
  }

  // Build the regex source by processing the pattern left-to-right so we can
  // handle `**` before `*` without confusing them.
  let regexSource = '';
  let i = 0;
  while (i < p.length) {
    const ch = p[i];

    if (ch === '*' && p[i + 1] === '*') {
      // `**` — matches everything including path separators.
      regexSource += '.*';
      i += 2;
      // Consume optional trailing slash after `**` (e.g. `**/foo`).
      if (p[i] === '/') {
        regexSource += '/?';
        i++;
      }
    } else if (ch === '*') {
      // `*` — matches anything except `/`.
      regexSource += '[^/]*';
      i++;
    } else if (ch === '?') {
      regexSource += '[^/]';
      i++;
    } else {
      // Escape regex special characters.
      regexSource += ch.replace(/[.+^${}()|\\[\]\\\\]/g, '\\$&');
      i++;
    }
  }

  // Anchored patterns start from the root of the relative path.
  const prefix = isAnchored ? '^' : '(^|/)';
  // Allow the pattern to match a directory and everything inside it, or a file.
  const suffix = '(/.*)?$';

  return new RegExp(prefix + regexSource + suffix);
}

/**
 * Returns true when relPath (POSIX-normalised) matches any compiled pattern.
 */
function isIgnored(relPath: string, compiledPatterns: RegExp[]): boolean {
  return compiledPatterns.some((re) => re.test(relPath));
}

// ---------------------------------------------------------------------------
// scanFiles
// ---------------------------------------------------------------------------

/** Diagnostic counters exposed for logging/testing without changing the return type. */
export interface ScanStats {
  /** Code files collected. */
  total: number;
  /** Entries skipped due to EACCES. */
  permissionSkipped: number;
  /** Symlink targets already seen (loop detected). */
  symlinkLoopSkipped: number;
}

/**
 * Recursively scan rootDir and return relative paths to all code files,
 * respecting the provided ignore patterns.
 *
 * Guarantees:
 * - Symlink loops are detected via inode tracking and skipped without error.
 * - Permission errors (EACCES) on files/directories are caught and counted.
 * - Returned paths are always relative to rootDir with POSIX separators.
 * - `node_modules` and `.git` are skipped at any depth as a fast-path (they
 *   are never source files and can contain thousands of entries).
 *
 * @param rootDir        Absolute path to the directory root to scan.
 * @param ignorePatterns Gitignore-style pattern strings (from getIgnorePatterns).
 * @returns              Sorted list of relative file paths.
 */
export async function scanFiles(
  rootDir: string,
  ignorePatterns: string[],
): Promise<string[]> {
  const compiledPatterns = ignorePatterns.map(patternToRegex);
  const results: string[] = [];
  const scanStats: ScanStats = {
    total: 0,
    permissionSkipped: 0,
    symlinkLoopSkipped: 0,
  };

  // inode → boolean: tracks real directories (after symlink resolution) we
  // have entered to prevent infinite loops from circular symlinks.
  // Using number because fs.Stats.ino is a number (bigint only with BigInt flag).
  const visitedInodes = new Set<number>();

  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (err: unknown) {
      if (isPermissionError(err)) {
        scanStats.permissionSkipped++;
        return;
      }
      throw err;
    }

    for (const entry of entries) {
      // Fast-path: always skip well-known non-source directories.
      if (entry.name === 'node_modules' || entry.name === '.git') {
        continue;
      }

      const absPath = join(dir, entry.name);
      const relPath = getRelativePath(rootDir, absPath);

      // Evaluate ignore patterns on the relative path before any stat calls.
      if (isIgnored(relPath, compiledPatterns)) {
        continue;
      }

      // Stat the entry (lstat first — does not follow symlinks).
      let entryStat: Awaited<ReturnType<typeof lstat>>;
      try {
        entryStat = await lstat(absPath);
      } catch (err: unknown) {
        if (isPermissionError(err)) {
          scanStats.permissionSkipped++;
          continue;
        }
        throw err;
      }

      if (entryStat.isSymbolicLink()) {
        // Follow the symlink by stat-ing the resolved target.
        let targetStat: Awaited<ReturnType<typeof stat>>;
        try {
          targetStat = await stat(absPath); // follows symlinks
        } catch {
          // Broken symlink or permission denied on the target — skip silently.
          continue;
        }

        if (targetStat.isDirectory()) {
          if (visitedInodes.has(targetStat.ino)) {
            // This directory is already in the current walk chain — loop.
            scanStats.symlinkLoopSkipped++;
            continue;
          }
          visitedInodes.add(targetStat.ino);
          await walk(absPath);
          // Remove after returning so sibling subtrees can legitimately visit
          // the same target via a different symlink (not a loop in that case).
          visitedInodes.delete(targetStat.ino);
        } else if (targetStat.isFile() && isCodeFile(entry.name)) {
          scanStats.total++;
          results.push(relPath);
        }
        continue;
      }

      if (entryStat.isDirectory()) {
        if (visitedInodes.has(entryStat.ino)) {
          scanStats.symlinkLoopSkipped++;
          continue;
        }
        visitedInodes.add(entryStat.ino);
        await walk(absPath);
        visitedInodes.delete(entryStat.ino);
        continue;
      }

      if (entryStat.isFile() && isCodeFile(entry.name)) {
        scanStats.total++;
        results.push(relPath);
      }
    }
  }

  await walk(rootDir);

  // Return in a deterministic, sorted order.
  return results.sort();
}

// ---------------------------------------------------------------------------
// scanAllFiles
// ---------------------------------------------------------------------------

/**
 * Recursively scan rootDir and return relative paths to ALL files that should
 * be examined by the secret scanner (code files + config/env files).
 *
 * Key differences from `scanFiles`:
 * - Uses `isSecretScanFile` instead of `isCodeFile` — broader file set.
 * - `.env*` files are intentionally NOT filtered out even when the caller's
 *   ignorePatterns list contains `.env` entries from .gitignore, because
 *   secret scanning must inspect those files regardless of git tracking status.
 *   All other ignore patterns are still respected.
 *
 * All other guarantees from `scanFiles` apply:
 * - Symlink loops are detected via inode tracking and skipped without error.
 * - Permission errors (EACCES) on files/directories are caught and counted.
 * - `node_modules` and `.git` are skipped at any depth.
 *
 * NOTE: Unlike `scanFiles`, this function returns **absolute** paths so that
 * callers (e.g. RegexFallbackAnalyzer) can pass them directly to
 * `readFileSync` without an additional `join`.
 *
 * @param rootDir        Absolute path to the directory root to scan.
 * @param ignorePatterns Gitignore-style pattern strings (from getIgnorePatterns).
 * @returns              Sorted list of absolute file paths.
 */
export async function scanAllFiles(
  rootDir: string,
  ignorePatterns: string[],
): Promise<string[]> {
  // Strip any ignore patterns that would suppress .env* files so the secret
  // scanner always sees them.  Pattern strings that look like .env variants
  // are identified conservatively: a pattern matches if it equals `.env` or
  // starts with `.env` (covers `.env*`, `.env.*`, etc.).
  const filteredPatterns = ignorePatterns.filter((p) => {
    // Normalise: strip leading `/` and trailing `/` for comparison purposes.
    const normalised = p.replace(/^\//, '').replace(/\/$/, '');
    return !normalised.startsWith('.env');
  });

  const compiledPatterns = filteredPatterns.map(patternToRegex);
  const results: string[] = [];
  const scanStats: ScanStats = {
    total: 0,
    permissionSkipped: 0,
    symlinkLoopSkipped: 0,
  };

  const visitedInodes = new Set<number>();

  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (err: unknown) {
      if (isPermissionError(err)) {
        scanStats.permissionSkipped++;
        return;
      }
      throw err;
    }

    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git') {
        continue;
      }

      const absPath = join(dir, entry.name);
      const relPath = getRelativePath(rootDir, absPath);

      if (isIgnored(relPath, compiledPatterns)) {
        continue;
      }

      let entryStat: Awaited<ReturnType<typeof lstat>>;
      try {
        entryStat = await lstat(absPath);
      } catch (err: unknown) {
        if (isPermissionError(err)) {
          scanStats.permissionSkipped++;
          continue;
        }
        throw err;
      }

      if (entryStat.isSymbolicLink()) {
        let targetStat: Awaited<ReturnType<typeof stat>>;
        try {
          targetStat = await stat(absPath);
        } catch {
          continue;
        }

        if (targetStat.isDirectory()) {
          if (visitedInodes.has(targetStat.ino)) {
            scanStats.symlinkLoopSkipped++;
            continue;
          }
          visitedInodes.add(targetStat.ino);
          await walk(absPath);
          visitedInodes.delete(targetStat.ino);
        } else if (targetStat.isFile() && isSecretScanFile(entry.name)) {
          scanStats.total++;
          results.push(absPath);
        }
        continue;
      }

      if (entryStat.isDirectory()) {
        if (visitedInodes.has(entryStat.ino)) {
          scanStats.symlinkLoopSkipped++;
          continue;
        }
        visitedInodes.add(entryStat.ino);
        await walk(absPath);
        visitedInodes.delete(entryStat.ino);
        continue;
      }

      if (entryStat.isFile() && isSecretScanFile(entry.name)) {
        scanStats.total++;
        results.push(absPath);
      }
    }
  }

  await walk(rootDir);

  return results.sort();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isPermissionError(err: unknown): boolean {
  if (typeof err !== 'object' || err === null || !('code' in err)) {
    return false;
  }
  const code = (err as NodeJS.ErrnoException).code;
  // EACCES — standard Unix permission denied
  // EPERM  — macOS uses this for SIP-protected directories (e.g. TemporaryItems)
  return code === 'EACCES' || code === 'EPERM';
}
