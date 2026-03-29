// ============================================================
// CodeSentinel — Docker Security Analyzer
// Layer: static | Tool: docker-security
// ============================================================
//
// Strategy:
//   Glob rootDir recursively for Dockerfile* and docker-compose*.yml
//   files, then scan each line-by-line with a catalogue of regex
//   rules covering the most common Docker security mistakes:
//
//   Dockerfile checks:
//     - Running as root (no USER directive after the last FROM)
//     - Using latest tag or no tag in FROM
//     - COPY . . without .dockerignore present
//     - Unsafe install commands (apt-get, pip) missing hardening flags
//     - ADD used instead of COPY
//     - Disabled security features (--no-sandbox, --disable-web-security)
//
//   docker-compose checks:
//     - Hardcoded secrets in environment variable values
//     - Ports bound to 0.0.0.0 (all interfaces)
//     - Disabled security features in command/entrypoint fields
//
// All findings carry layer: 'static', tool: 'docker-security'.
// Files outside rootDir and inside node_modules / .git are skipped.
// ============================================================

import { readFile, readdir, access } from 'node:fs/promises';
import { join, basename, dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Directories that are always skipped when walking the tree. */
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.cache',
  'coverage',
  '__pycache__',
  '.venv',
  'vendor',
]);

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

/**
 * Walk rootDir recursively and return absolute paths of every file whose
 * basename matches the provided predicate.  Skips SKIP_DIRS unconditionally.
 */
async function findFiles(
  dir: string,
  predicate: (name: string) => boolean,
  results: string[] = [],
): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        await findFiles(join(dir, entry.name), predicate, results);
      }
    } else if (entry.isFile() && predicate(entry.name)) {
      results.push(join(dir, entry.name));
    }
  }

  return results;
}

/** Returns true if a .dockerignore file exists next to the given Dockerfile. */
async function hasDockerignore(dockerfilePath: string): Promise<boolean> {
  const dir = dirname(dockerfilePath);
  try {
    await access(join(dir, '.dockerignore'));
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Dockerfile analysis
// ---------------------------------------------------------------------------

/**
 * Scan a single Dockerfile and return all findings.
 *
 * The check for "running as root" is stateful: we track the last FROM
 * instruction seen, then after processing the entire file we emit a
 * finding if no USER directive was encountered after that FROM.
 */
async function analyzeDockerfile(filePath: string): Promise<Finding[]> {
  let source: string;
  try {
    source = await readFile(filePath, 'utf-8');
  } catch {
    return [];
  }

  const lines = source.split('\n');
  const findings: Finding[] = [];

  // State for root-user check
  let lastFromLine = -1;
  let hasUserDirective = false;

  // Check once whether .dockerignore exists (used for COPY . . check)
  const dockerignorePresent = await hasDockerignore(filePath);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const lineNumber = i + 1;

    // Skip comments and blank lines
    if (trimmed.startsWith('#') || trimmed.length === 0) {
      continue;
    }

    const upper = trimmed.toUpperCase();

    // ── FROM ──────────────────────────────────────────────────────────────

    if (/^FROM\s/i.test(trimmed)) {
      // Each FROM resets the USER state for the new build stage
      lastFromLine = lineNumber;
      hasUserDirective = false;

      // FROM image:latest or FROM image (no tag) — excluding FROM scratch
      // Pattern: FROM <image> with no colon, or FROM <image>:latest
      // Allow: FROM --platform=... image:tag forms
      const fromMatch = trimmed.match(
        /^FROM\s+(?:--\S+\s+)*(\S+)/i,
      );
      if (fromMatch) {
        const imageRef = fromMatch[1];
        // Skip scratch — it is a special keyword, not an image
        if (imageRef.toLowerCase() !== 'scratch') {
          const hasTag = imageRef.includes(':');
          const isLatest = hasTag && imageRef.toLowerCase().endsWith(':latest');
          if (!hasTag || isLatest) {
            findings.push({
              id: randomUUID(),
              layer: 'static',
              type: 'docker-latest-tag',
              severity: 'warning',
              confidence: 0.95,
              file: filePath,
              line: lineNumber,
              message: hasTag
                ? `FROM uses :latest tag — non-deterministic builds`
                : `FROM has no tag — defaults to :latest, non-deterministic builds`,
              tool: 'docker-security',
              suggestion:
                'Pin to a specific digest or version tag (e.g. node:20.11.0-alpine3.19) to ensure reproducible builds.',
            });
          }
        }
      }
      continue;
    }

    // ── USER ──────────────────────────────────────────────────────────────

    if (/^USER\s/i.test(trimmed)) {
      hasUserDirective = true;
      continue;
    }

    // ── ADD ──────────────────────────────────────────────────────────────

    if (/^ADD\s/i.test(trimmed)) {
      // ADD is safe for URLs and remote archives; flag only local copies
      // that could have used COPY instead.  We skip ADD <url> and ADD <git>.
      const addArgs = trimmed.slice(4).trim();
      const isUrl = /^https?:\/\//i.test(addArgs);
      if (!isUrl) {
        findings.push({
          id: randomUUID(),
          layer: 'static',
          type: 'docker-add-instead-of-copy',
          severity: 'info',
          confidence: 0.80,
          file: filePath,
          line: lineNumber,
          message:
            'ADD auto-extracts tar archives and fetches URLs — use COPY for simple file copies to avoid unexpected behaviour',
          tool: 'docker-security',
          suggestion:
            'Replace ADD with COPY unless you need automatic tar extraction or URL fetching.',
        });
      }
      continue;
    }

    // ── COPY . . ─────────────────────────────────────────────────────────

    if (/^COPY\s/i.test(trimmed)) {
      // Detect broad context: COPY . . or COPY . /app or COPY ./ /app
      if (/^COPY\s+\.\/?\s+/i.test(trimmed) && !dockerignorePresent) {
        findings.push({
          id: randomUUID(),
          layer: 'static',
          type: 'docker-broad-copy-context',
          severity: 'info',
          confidence: 0.75,
          file: filePath,
          line: lineNumber,
          message:
            'COPY . copies the entire build context without a .dockerignore — may include secrets, .env files, or large artifacts',
          tool: 'docker-security',
          suggestion:
            'Create a .dockerignore file to exclude .git, .env, node_modules, and other files that should not be in the image.',
        });
      }
      continue;
    }

    // ── RUN: unsafe apt-get ───────────────────────────────────────────────

    if (/^RUN\s/i.test(trimmed)) {
      // apt-get install without --no-install-recommends
      if (
        /apt-get\s+install\b/.test(trimmed) &&
        !/--no-install-recommends/.test(trimmed)
      ) {
        findings.push({
          id: randomUUID(),
          layer: 'static',
          type: 'docker-apt-no-recommends',
          severity: 'info',
          confidence: 0.70,
          file: filePath,
          line: lineNumber,
          message:
            'apt-get install without --no-install-recommends installs unnecessary packages, increasing attack surface and image size',
          tool: 'docker-security',
          suggestion:
            'Add --no-install-recommends to apt-get install and clean up with rm -rf /var/lib/apt/lists/* in the same RUN layer.',
        });
      }

      // pip install without --no-cache-dir
      if (
        /\bpip[23]?\s+install\b/.test(trimmed) &&
        !/--no-cache-dir/.test(trimmed)
      ) {
        findings.push({
          id: randomUUID(),
          layer: 'static',
          type: 'docker-pip-no-cache',
          severity: 'info',
          confidence: 0.70,
          file: filePath,
          line: lineNumber,
          message:
            'pip install without --no-cache-dir leaves build cache in the image layer, increasing image size unnecessarily',
          tool: 'docker-security',
          suggestion: 'Add --no-cache-dir to pip install.',
        });
      }

      // Disabled security features in RUN commands
      const securityFlag = detectDisabledSecurity(trimmed);
      if (securityFlag !== null) {
        findings.push({
          id: randomUUID(),
          layer: 'static',
          type: 'docker-disabled-security',
          severity: 'error',
          confidence: 0.95,
          file: filePath,
          line: lineNumber,
          message: `Disabled security feature: ${securityFlag} — disables browser/runtime sandboxing`,
          tool: 'docker-security',
          suggestion: securityFlagSuggestion(securityFlag),
        });
      }

      continue;
    }

    // ── ENV / CMD / ENTRYPOINT: disabled security features ────────────────

    const securityFlag = detectDisabledSecurity(trimmed);
    if (
      securityFlag !== null &&
      /^(?:ENV|CMD|ENTRYPOINT|ARG)\s/i.test(trimmed)
    ) {
      findings.push({
        id: randomUUID(),
        layer: 'static',
        type: 'docker-disabled-security',
        severity: 'error',
        confidence: 0.95,
        file: filePath,
        line: lineNumber,
        message: `Disabled security feature: ${securityFlag} — disables browser/runtime sandboxing`,
        tool: 'docker-security',
        suggestion: securityFlagSuggestion(securityFlag),
      });
    }
  }

  // ── Running as root ───────────────────────────────────────────────────────
  // Emit after the file is fully scanned so we know whether USER ever appeared.

  if (lastFromLine !== -1 && !hasUserDirective) {
    findings.push({
      id: randomUUID(),
      layer: 'static',
      type: 'docker-run-as-root',
      severity: 'warning',
      confidence: 0.90,
      file: filePath,
      line: lastFromLine,
      message:
        'No USER directive found — container will run as root, which escalates privilege if the container is compromised',
      tool: 'docker-security',
      suggestion:
        'Add a USER instruction after your last RUN/COPY/ADD step (e.g. RUN addgroup -S app && adduser -S app -G app && USER app).',
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// docker-compose analysis
// ---------------------------------------------------------------------------

/**
 * Regex for environment variable lines that contain a hardcoded secret value.
 *
 * Matches patterns like:
 *   - PASSWORD=mysecret
 *   - DB_PASSWORD: mysecret       (YAML block style)
 *   - SECRET_KEY=abc123
 *   - API_KEY=somethinglong
 *   - TOKEN=eyJhbGci...
 *
 * We deliberately require the value to be non-empty and not a variable
 * reference (${VAR}) to avoid flagging intentional env-var pass-throughs.
 */
const SECRET_ENV_RE =
  /(?:^|[\s"'])(?:[\w.]*[-_])?(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH[_-]?TOKEN|OAUTH[_-]?TOKEN|CLIENT[_-]?SECRET)(?:[\w]*)(?:\s*[:=]\s*)(?!(\$\{|"?\$\{|<|>|~))([^\s"'#]{3,})/i;

/**
 * Regex for ports bound to 0.0.0.0 — matches both quoted and unquoted forms:
 *   - "0.0.0.0:8080:8080"
 *   - 0.0.0.0:8080:8080
 */
const ALL_INTERFACES_PORT_RE = /(?:["']?)0\.0\.0\.0:\d+:\d+(?:["']?)/;

/**
 * Scan a single docker-compose file and return all findings.
 */
async function analyzeDockerCompose(filePath: string): Promise<Finding[]> {
  let source: string;
  try {
    source = await readFile(filePath, 'utf-8');
  } catch {
    return [];
  }

  const lines = source.split('\n');
  const findings: Finding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const lineNumber = i + 1;

    if (trimmed.startsWith('#') || trimmed.length === 0) {
      continue;
    }

    // ── Hardcoded secrets in environment values ────────────────────────────

    if (SECRET_ENV_RE.test(trimmed)) {
      // Extract the variable name for a clearer message
      const nameMatch = trimmed.match(
        /(?:[\w.]*[-_])?(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH[_-]?TOKEN|OAUTH[_-]?TOKEN|CLIENT[_-]?SECRET)(?:[\w]*)/i,
      );
      const varName = nameMatch ? nameMatch[0].toUpperCase() : 'secret variable';

      findings.push({
        id: randomUUID(),
        layer: 'static',
        type: 'docker-compose-secret-in-env',
        severity: 'warning',
        confidence: 0.85,
        file: filePath,
        line: lineNumber,
        message: `Hardcoded secret detected in environment variable: ${varName}`,
        tool: 'docker-security',
        suggestion:
          'Use Docker secrets (secrets: block), a .env file excluded from version control, or a secrets manager. Never commit credentials to source.',
      });
    }

    // ── Ports bound to all interfaces ─────────────────────────────────────

    if (ALL_INTERFACES_PORT_RE.test(trimmed)) {
      const portMatch = trimmed.match(/(\d+\.\d+\.\d+\.\d+:\d+:\d+)/);
      const portStr = portMatch ? portMatch[1] : '0.0.0.0:PORT:PORT';

      findings.push({
        id: randomUUID(),
        layer: 'static',
        type: 'docker-compose-exposed-port',
        severity: 'info',
        confidence: 0.80,
        file: filePath,
        line: lineNumber,
        message: `Port mapped to 0.0.0.0 (all interfaces): ${portStr} — exposes service to the entire network`,
        tool: 'docker-security',
        suggestion:
          "Bind to 127.0.0.1 for local-only services (e.g. 127.0.0.1:8080:8080). Only bind to 0.0.0.0 for services that must accept external connections.",
      });
    }

    // ── Disabled security features in command / entrypoint ────────────────

    const securityFlag = detectDisabledSecurity(trimmed);
    if (securityFlag !== null) {
      findings.push({
        id: randomUUID(),
        layer: 'static',
        type: 'docker-disabled-security',
        severity: 'error',
        confidence: 0.95,
        file: filePath,
        line: lineNumber,
        message: `Disabled security feature: ${securityFlag} — disables browser/runtime sandboxing`,
        tool: 'docker-security',
        suggestion: securityFlagSuggestion(securityFlag),
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/**
 * Detects disabled security flags in a line of text.
 * Returns the matched flag string, or null if none found.
 */
function detectDisabledSecurity(line: string): string | null {
  if (/--no-sandbox/.test(line)) return '--no-sandbox';
  if (/--disable-web-security/.test(line)) return '--disable-web-security';
  if (/--disable-setuid-sandbox/.test(line)) return '--disable-setuid-sandbox';
  return null;
}

function securityFlagSuggestion(flag: string): string {
  switch (flag) {
    case '--no-sandbox':
      return (
        'Run the container as a non-root user and use a proper seccomp/AppArmor profile instead of disabling the sandbox. ' +
        'If using Puppeteer/Chromium, configure the user namespace: docker run --cap-add=SYS_PTRACE.'
      );
    case '--disable-web-security':
      return (
        'Fix the underlying CORS configuration rather than disabling web security. ' +
        '--disable-web-security opens the browser to XSS and CSRF attacks and must never be used in production.'
      );
    case '--disable-setuid-sandbox':
      return (
        'Use user namespaces or a proper AppArmor/seccomp profile. ' +
        '--disable-setuid-sandbox bypasses OS-level process isolation.'
      );
    default:
      return 'Remove this flag and address the root cause rather than disabling security features.';
  }
}

// ---------------------------------------------------------------------------
// File name predicates
// ---------------------------------------------------------------------------

/** Returns true for files that should be scanned as Dockerfiles. */
function isDockerfile(name: string): boolean {
  // Matches: Dockerfile, Dockerfile.dev, Dockerfile.prod, Dockerfile.test, etc.
  // Also matches: dev.Dockerfile, etc.
  return /^Dockerfile(?:\.\S+)?$/i.test(name) || /\bDockerfile$/i.test(name);
}

/** Returns true for docker-compose YAML files. */
function isDockerCompose(name: string): boolean {
  return /^docker-compose(?:[.\-]\S+)?\.ya?ml$/i.test(name);
}

// ---------------------------------------------------------------------------
// Analyzer implementation
// ---------------------------------------------------------------------------

export class DockerSecurityAnalyzer implements Analyzer {
  readonly name = 'docker-security';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    if (!context.config.analyzers.static.security) {
      return [];
    }

    // Discover Docker-related files in rootDir.
    // We intentionally scan rootDir directly rather than filtering
    // context.files because Dockerfiles are not TypeScript/Python source
    // files and may not be in the scanned file list depending on config.
    const [dockerfiles, composeFiles] = await Promise.all([
      findFiles(context.rootDir, isDockerfile),
      findFiles(context.rootDir, isDockerCompose),
    ]);

    if (dockerfiles.length === 0 && composeFiles.length === 0) {
      return [];
    }

    // When incremental mode is active, restrict to changed Docker files only.
    const changedSet = context.changedFiles
      ? new Set(context.changedFiles)
      : null;

    const targetDockerfiles =
      changedSet !== null
        ? dockerfiles.filter((f) => changedSet.has(f))
        : dockerfiles;

    const targetComposeFiles =
      changedSet !== null
        ? composeFiles.filter((f) => changedSet.has(f))
        : composeFiles;

    // Run all file scans in parallel
    const allScans = [
      ...targetDockerfiles.map((f) => analyzeDockerfile(f)),
      ...targetComposeFiles.map((f) => analyzeDockerCompose(f)),
    ];

    const results = await Promise.allSettled(allScans);
    const findings: Finding[] = [];

    for (const result of results) {
      if (result.status === 'fulfilled') {
        findings.push(...result.value);
      }
      // Rejected scans are silently skipped — one unreadable file should not
      // abort the entire Docker security pass.
    }

    return findings;
  }
}
