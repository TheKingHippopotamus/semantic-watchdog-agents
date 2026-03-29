// ============================================================
// CodeSentinel — Config Staleness Analyzer
// Layer: static | Tool: config-staleness
// ============================================================
//
// Detects four categories of staleness in config files:
//
//   1. dead-config-reference   — paths / Python module names
//      referenced in config values that no longer exist on disk
//      (e.g. .mcp.json "-m mcp_server.server" → mcp_server/server.py
//      was renamed to golem_3dmcp/server.py)
//
//   2. hardcoded-localhost-url — localhost / 127.0.0.1 / 0.0.0.0
//      appearing in non-.env config files (should live in .env)
//
//   3. hardcoded-port          — numeric port literals in config
//      files; flagged at info level so developers know to
//      externalise them
//
//   4. duplicate-config-key    — the same environment variable or
//      top-level key defined in multiple config files
//      (e.g. DATABASE_URL in both .env and docker-compose.yml)
//
// Scanned targets (relative to rootDir):
//   *.json, .mcp.json, tsconfig.json, package.json  (root + .github/ + .vscode/)
//   *.yaml, *.yml  (root + .github/ + docker-compose*.yml)
//   *.toml  (root)
//   .env  (root — read only for duplicate-key detection, not URL checks)
//
// All findings are layer: 'static', tool: 'config-staleness'.
// ============================================================

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative, dirname, basename } from 'node:path';
import { createHash } from 'node:crypto';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Glob-style suffixes considered config files and their scan directories. */
const CONFIG_GLOB_SPECS: Array<{ dir: string | null; exts: string[] }> = [
  // Root-level configs
  { dir: null, exts: ['.json', '.yaml', '.yml', '.toml', '.ini', '.env'] },
  // CI / GitHub configs
  { dir: '.github', exts: ['.json', '.yaml', '.yml'] },
  // VS Code workspace settings
  { dir: '.vscode', exts: ['.json'] },
];

/** Specific filenames always scanned regardless of extension rules. */
const ALWAYS_SCAN_NAMES = new Set([
  '.mcp.json',
  'tsconfig.json',
  'package.json',
  'package-lock.json',
  '.env',
  '.env.local',
  '.env.production',
  '.env.development',
]);

/** Directories that always produce docker-compose-style files. */
const DOCKER_COMPOSE_PATTERN = /^docker-compose.*\.(ya?ml)$/;

/**
 * Regex to detect localhost / loopback / wildcard bind addresses.
 * Intentionally broad — we want to catch http://localhost:3000,
 * "host": "127.0.0.1", host=0.0.0.0, etc.
 */
const LOCALHOST_RE =
  /\b(?:https?:\/\/)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?(?:\/[^\s"',]*)?\b/i;

/**
 * Regex to extract a standalone port number in config context.
 * Matches values like "3000", port: 8080, PORT=5432.
 * Avoids matching version strings (1.2.3) or years (2024).
 */
const PORT_VALUE_RE =
  /(?:^|["'\s,:{=])(\d{2,5})(?:["'\s,}]|$)/g;

/** Valid port range. */
const PORT_MIN = 80;
const PORT_MAX = 65535;

/** Keys / patterns in JSON / TOML / YAML that typically hold port numbers. */
const PORT_KEY_RE = /\bport\b/i;

/** Python dotted module reference: two or more dot-separated identifiers. */
const PYTHON_MODULE_RE = /^([a-zA-Z_]\w*)(\.[a-zA-Z_]\w*)+$/;

/**
 * Regex to find string values that look like file paths:
 *   - starts with / or ./ or ../
 *   - or contains at least one / or \ surrounded by non-space chars
 */
const FILE_PATH_RE = /^(?:\.{1,2}\/|\/|\w:\\)|\S+[/\\]\S+/;

/** Suffixes to skip for URL/port checks (binary or irrelevant). */
const SKIP_URL_CHECK_SUFFIXES = new Set(['.env', '.env.local', '.env.production', '.env.development']);

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

function makeId(type: string, subject: string): string {
  const raw = `${type}:${subject}`;
  return `csa-${createHash('sha1').update(raw).digest('hex').slice(0, 12)}`;
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/**
 * Return the list of config file absolute paths to scan for a given rootDir.
 * - Applies CONFIG_GLOB_SPECS per directory.
 * - Picks up docker-compose*.yml at root.
 * - Adds ALWAYS_SCAN_NAMES if present.
 */
function collectConfigFiles(rootDir: string): string[] {
  const seen = new Set<string>();
  const results: string[] = [];

  function add(absPath: string): void {
    if (!seen.has(absPath) && existsSync(absPath)) {
      seen.add(absPath);
      results.push(absPath);
    }
  }

  // Always-scan names at root.
  for (const name of ALWAYS_SCAN_NAMES) {
    add(join(rootDir, name));
  }

  // Extension-based scan per directory spec.
  for (const spec of CONFIG_GLOB_SPECS) {
    const dir = spec.dir ? join(rootDir, spec.dir) : rootDir;

    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }

    for (const entry of entries) {
      const absEntry = join(dir, entry);
      const ext = entry.slice(entry.lastIndexOf('.'));

      if (spec.exts.includes(ext)) {
        add(absEntry);
      }

      // docker-compose*.yml anywhere in root directory.
      if (spec.dir === null && DOCKER_COMPOSE_PATTERN.test(entry)) {
        add(absEntry);
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Simple value extraction helpers
// ---------------------------------------------------------------------------

/**
 * Flatten all string leaves out of a parsed JSON value tree.
 * Returns an array of { value, path } where path is a dot-notation key trace.
 */
function flattenJsonStrings(
  node: unknown,
  path: string,
  acc: Array<{ value: string; path: string }>,
): void {
  if (typeof node === 'string') {
    acc.push({ value: node, path });
    return;
  }
  if (typeof node === 'number') {
    acc.push({ value: String(node), path });
    return;
  }
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      flattenJsonStrings(node[i], `${path}[${i}]`, acc);
    }
    return;
  }
  if (node !== null && typeof node === 'object') {
    for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
      flattenJsonStrings(val, path ? `${path}.${key}` : key, acc);
    }
  }
}

/**
 * Naive line-by-line extraction for YAML / TOML / INI files.
 * Returns an array of { value: string, lineNumber: number, key: string }.
 *
 * This is intentionally not a full parser — it handles the 90% case of
 * "key: value" or "key = value" single-line entries well enough for
 * staleness detection without pulling in heavy parser dependencies.
 */
interface LineValue {
  value: string;
  lineNumber: number;
  key: string;
}

function extractLineValues(content: string): LineValue[] {
  const results: LineValue[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comments and blank lines.
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) {
      continue;
    }

    // YAML: "key: value" or "key: 'value'" or 'key: "value"'
    const yamlMatch = trimmed.match(/^([\w.-]+)\s*:\s*['"]?([^'"#\n]+?)['"]?\s*(?:#.*)?$/);
    if (yamlMatch) {
      results.push({ key: yamlMatch[1], value: yamlMatch[2].trim(), lineNumber: i + 1 });
      continue;
    }

    // TOML / INI / dotenv: "key = value"
    const eqMatch = trimmed.match(/^([\w.-]+)\s*=\s*['"]?([^'"#\n]+?)['"]?\s*(?:#.*)?$/);
    if (eqMatch) {
      results.push({ key: eqMatch[1], value: eqMatch[2].trim(), lineNumber: i + 1 });
    }
  }

  return results;
}

/**
 * Find the approximate line number of a string occurrence within raw content.
 * Returns 1-based line number, or undefined if not found.
 */
function findLineNumber(content: string, search: string): number | undefined {
  const idx = content.indexOf(search);
  if (idx === -1) return undefined;
  return content.slice(0, idx).split('\n').length;
}

// ---------------------------------------------------------------------------
// Python module path resolution
// ---------------------------------------------------------------------------

/**
 * Given a dotted Python module string like "mcp_server.server",
 * return candidate filesystem paths to check:
 *   - rootDir/mcp_server/server.py
 *   - rootDir/mcp_server/server/__init__.py
 *   - rootDir/mcp_server/__init__.py  (package-only reference)
 */
function pythonModuleCandidates(rootDir: string, module: string): string[] {
  const parts = module.split('.');
  const candidates: string[] = [];

  // Full path as .py file.
  candidates.push(join(rootDir, ...parts) + '.py');

  // Full path as package (__init__.py).
  candidates.push(join(rootDir, ...parts, '__init__.py'));

  // Package root only (first segment).
  if (parts.length > 1) {
    candidates.push(join(rootDir, parts[0], '__init__.py'));
  }

  return candidates;
}

/**
 * Return true if at least one of the candidate paths exists.
 */
function pythonModuleExists(rootDir: string, module: string): boolean {
  return pythonModuleCandidates(rootDir, module).some(existsSync);
}

// ---------------------------------------------------------------------------
// Pass 1 — Dead config references
// ---------------------------------------------------------------------------

/**
 * Scan all collected config files for values that look like file paths or
 * Python module references that no longer exist on disk.
 *
 * Special handling for "-m module.name" in JSON arrays (mcp-style configs).
 */
function detectDeadReferences(
  configFiles: string[],
  rootDir: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const filePath of configFiles) {
    const ext = basename(filePath).includes('.')
      ? filePath.slice(filePath.lastIndexOf('.'))
      : '';

    let content: string;
    try {
      content = readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const relFile = relative(rootDir, filePath);

    if (ext === '.json') {
      let parsed: unknown;
      try {
        parsed = JSON.parse(content);
      } catch {
        continue;
      }

      const leaves: Array<{ value: string; path: string }> = [];
      flattenJsonStrings(parsed, '', leaves);

      // Detect "-m module.name" argument pattern (Python -m invocation).
      // Look for arrays where one element is "-m" and the next is a dotted module.
      detectPythonMArgs(parsed, filePath, relFile, content, rootDir, findings);

      for (const { value, path } of leaves) {
        // Skip the "-m" element itself.
        if (value === '-m') continue;

        // Python module reference: check if the element that came after "-m" was this value.
        // Already handled above via detectPythonMArgs — skip to avoid double-reporting.
        if (PYTHON_MODULE_RE.test(value) && isPythonModuleArg(parsed, value)) {
          continue;
        }

        // File path reference.
        if (FILE_PATH_RE.test(value) && !value.startsWith('http') && !value.startsWith('${')) {
          // Resolve relative to rootDir.
          const candidate = value.startsWith('/') ? value : join(rootDir, value);
          if (!existsSync(candidate)) {
            const line = findLineNumber(content, value);
            findings.push({
              id: makeId('dead-config-reference', `${filePath}:${value}`),
              layer: 'static',
              type: 'dead-config-reference',
              severity: 'warning',
              confidence: 0.75,
              file: relFile,
              line,
              message: `Config value "${value}" at "${path}" looks like a path but does not exist on disk`,
              tool: 'config-staleness',
              suggestion: `Verify the path is correct relative to the project root, or remove the stale reference.`,
              meta: { configPath: path, missingValue: value },
            });
          }
        }
      }
    } else {
      // YAML / TOML / INI — line-by-line extraction.
      const lineValues = extractLineValues(content);

      for (const { value, lineNumber, key } of lineValues) {
        if (FILE_PATH_RE.test(value) && !value.startsWith('http') && !value.startsWith('${')) {
          const candidate = value.startsWith('/') ? value : join(rootDir, value);
          if (!existsSync(candidate)) {
            findings.push({
              id: makeId('dead-config-reference', `${filePath}:${lineNumber}:${value}`),
              layer: 'static',
              type: 'dead-config-reference',
              severity: 'warning',
              confidence: 0.75,
              file: relFile,
              line: lineNumber,
              message: `Config key "${key}" value "${value}" looks like a path but does not exist on disk`,
              tool: 'config-staleness',
              suggestion: `Verify the path is correct relative to the project root, or remove the stale reference.`,
              meta: { key, missingValue: value },
            });
          }
        }
      }
    }
  }

  return findings;
}

/**
 * Walk a parsed JSON object recursively looking for arrays where an element
 * is "-m" and the next element is a dotted Python module name.
 * Emits a finding if the module does not resolve to a file on disk.
 */
function detectPythonMArgs(
  node: unknown,
  filePath: string,
  relFile: string,
  content: string,
  rootDir: string,
  findings: Finding[],
): void {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length - 1; i++) {
      if (node[i] === '-m' && typeof node[i + 1] === 'string') {
        const moduleName = node[i + 1] as string;
        if (PYTHON_MODULE_RE.test(moduleName) && !pythonModuleExists(rootDir, moduleName)) {
          const line = findLineNumber(content, moduleName);
          findings.push({
            id: makeId('dead-config-reference', `${filePath}:python-module:${moduleName}`),
            layer: 'static',
            type: 'dead-config-reference',
            severity: 'error',
            confidence: 0.92,
            file: relFile,
            line,
            message: `Python module reference "-m ${moduleName}" does not resolve to any file under the project root`,
            tool: 'config-staleness',
            suggestion: `Check if the module was renamed or moved. Candidates checked: ${pythonModuleCandidates(rootDir, moduleName).map((p) => relative(rootDir, p)).join(', ')}`,
            meta: { module: moduleName, candidates: pythonModuleCandidates(rootDir, moduleName).map((p) => relative(rootDir, p)) },
          });
        }
      }
    }
    for (const element of node) {
      detectPythonMArgs(element, filePath, relFile, content, rootDir, findings);
    }
    return;
  }

  if (node !== null && typeof node === 'object') {
    for (const val of Object.values(node as Record<string, unknown>)) {
      detectPythonMArgs(val, filePath, relFile, content, rootDir, findings);
    }
  }
}

/**
 * Return true if the given value appears immediately after a "-m" element
 * anywhere in a JSON tree (to avoid double-reporting it as a file path).
 */
function isPythonModuleArg(node: unknown, value: string): boolean {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length - 1; i++) {
      if (node[i] === '-m' && node[i + 1] === value) return true;
    }
    return node.some((el) => isPythonModuleArg(el, value));
  }
  if (node !== null && typeof node === 'object') {
    return Object.values(node as Record<string, unknown>).some((v) =>
      isPythonModuleArg(v, value),
    );
  }
  return false;
}

// ---------------------------------------------------------------------------
// Pass 2 — Hardcoded localhost URLs
// ---------------------------------------------------------------------------

/**
 * Scan JSON and YAML/TOML config files (NOT .env files) for localhost / 127.0.0.1
 * / 0.0.0.0 values that should be externalised to environment variables.
 */
function detectLocalhostUrls(
  configFiles: string[],
  rootDir: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const filePath of configFiles) {
    const name = basename(filePath);

    // .env files intentionally hold localhost addresses — skip.
    if (SKIP_URL_CHECK_SUFFIXES.has(name) || name.startsWith('.env')) {
      continue;
    }

    let content: string;
    try {
      content = readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const relFile = relative(rootDir, filePath);
    const ext = name.includes('.') ? name.slice(name.lastIndexOf('.')) : '';

    if (ext === '.json') {
      let parsed: unknown;
      try {
        parsed = JSON.parse(content);
      } catch {
        continue;
      }

      const leaves: Array<{ value: string; path: string }> = [];
      flattenJsonStrings(parsed, '', leaves);

      for (const { value, path } of leaves) {
        if (typeof value !== 'string') continue;
        if (!LOCALHOST_RE.test(value)) continue;

        const line = findLineNumber(content, value);
        findings.push({
          id: makeId('hardcoded-localhost-url', `${filePath}:${path}`),
          layer: 'static',
          type: 'hardcoded-localhost-url',
          severity: 'warning',
          confidence: 0.80,
          file: relFile,
          line,
          message: `Hardcoded localhost address "${value}" found at "${path}" in config file — consider using an environment variable`,
          tool: 'config-staleness',
          suggestion: `Move this value to .env and reference it as an environment variable (e.g. \${HOST} or process.env.HOST).`,
          meta: { configPath: path, url: value },
        });
      }
    } else {
      // YAML / TOML / INI.
      const lineValues = extractLineValues(content);

      for (const { value, lineNumber, key } of lineValues) {
        if (!LOCALHOST_RE.test(value)) continue;

        findings.push({
          id: makeId('hardcoded-localhost-url', `${filePath}:${lineNumber}`),
          layer: 'static',
          type: 'hardcoded-localhost-url',
          severity: 'warning',
          confidence: 0.80,
          file: relFile,
          line: lineNumber,
          message: `Hardcoded localhost address "${value}" in key "${key}" — consider using an environment variable`,
          tool: 'config-staleness',
          suggestion: `Move this value to .env and reference it as an environment variable.`,
          meta: { key, url: value },
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Pass 3 — Hardcoded port numbers
// ---------------------------------------------------------------------------

/**
 * Flag numeric port literals in config files at info level.
 * Only reports on keys that contain the word "port" or values that appear
 * as standalone integers in the valid port range — reducing noise from
 * version numbers, years, etc.
 */
function detectHardcodedPorts(
  configFiles: string[],
  rootDir: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const filePath of configFiles) {
    const name = basename(filePath);

    // .env files are the right place for port values — don't flag them.
    if (name.startsWith('.env')) continue;

    // package.json / tsconfig.json / package-lock.json — ports are very
    // unlikely and false-positive rate is high; skip.
    if (
      name === 'package.json' ||
      name === 'package-lock.json' ||
      name === 'tsconfig.json'
    ) {
      continue;
    }

    let content: string;
    try {
      content = readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const relFile = relative(rootDir, filePath);
    const ext = name.includes('.') ? name.slice(name.lastIndexOf('.')) : '';

    if (ext === '.json') {
      let parsed: unknown;
      try {
        parsed = JSON.parse(content);
      } catch {
        continue;
      }

      const leaves: Array<{ value: string; path: string }> = [];
      flattenJsonStrings(parsed, '', leaves);

      for (const { value, path } of leaves) {
        const lastKey = path.split('.').pop() ?? '';
        if (!PORT_KEY_RE.test(lastKey)) continue;

        const num = Number(value);
        if (!Number.isInteger(num) || num < PORT_MIN || num > PORT_MAX) continue;

        const line = findLineNumber(content, value);
        findings.push({
          id: makeId('hardcoded-port', `${filePath}:${path}`),
          layer: 'static',
          type: 'hardcoded-port',
          severity: 'info',
          confidence: 0.70,
          file: relFile,
          line,
          message: `Hardcoded port ${value} at "${path}" — consider externalising to an environment variable`,
          tool: 'config-staleness',
          suggestion: `Replace with an environment variable reference (e.g. \${PORT} or process.env.PORT).`,
          meta: { configPath: path, port: num },
        });
      }
    } else {
      const lineValues = extractLineValues(content);

      for (const { value, lineNumber, key } of lineValues) {
        if (!PORT_KEY_RE.test(key)) continue;

        const num = Number(value);
        if (!Number.isInteger(num) || num < PORT_MIN || num > PORT_MAX) continue;

        findings.push({
          id: makeId('hardcoded-port', `${filePath}:${lineNumber}`),
          layer: 'static',
          type: 'hardcoded-port',
          severity: 'info',
          confidence: 0.70,
          file: relFile,
          line: lineNumber,
          message: `Hardcoded port ${value} for key "${key}" — consider externalising to an environment variable`,
          tool: 'config-staleness',
          suggestion: `Replace with an environment variable reference.`,
          meta: { key, port: num },
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Pass 4 — Duplicate config keys across files
// ---------------------------------------------------------------------------

/**
 * Collect environment variable / top-level key names from each config file,
 * then flag any key that appears in more than one file.
 *
 * Sources:
 *   .env*         → all VAR=value lines
 *   docker-compose*.yml → environment: block keys
 *   *.json        → top-level keys only (too noisy to go deeper)
 *   *.yaml/*.yml  → top-level keys only
 *   *.toml        → top-level keys only
 */
function detectDuplicateKeys(
  configFiles: string[],
  rootDir: string,
): Finding[] {
  // Map from normalised key name → array of { file, lineNumber }
  const keyMap = new Map<string, Array<{ file: string; line: number }>>();

  for (const filePath of configFiles) {
    const name = basename(filePath);
    const relFile = relative(rootDir, filePath);

    let content: string;
    try {
      content = readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const ext = name.includes('.') ? name.slice(name.lastIndexOf('.')) : '';

    if (name.startsWith('.env')) {
      // .env files: VAR=value lines.
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const m = trimmed.match(/^([A-Z0-9_]+)\s*=/);
        if (m) {
          const key = m[1];
          if (!keyMap.has(key)) keyMap.set(key, []);
          keyMap.get(key)!.push({ file: relFile, line: i + 1 });
        }
      }
    } else if (ext === '.json') {
      let parsed: unknown;
      try {
        parsed = JSON.parse(content);
      } catch {
        continue;
      }
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const key of Object.keys(parsed as Record<string, unknown>)) {
          const normKey = key.toUpperCase();
          const line = findLineNumber(content, `"${key}"`) ?? 1;
          if (!keyMap.has(normKey)) keyMap.set(normKey, []);
          keyMap.get(normKey)!.push({ file: relFile, line });
        }
      }
    } else {
      // YAML / TOML / docker-compose — use line-value extractor for top-level.
      const lineValues = extractLineValues(content);
      // Only capture keys that look like environment variable names (ALL_CAPS)
      // or are from an "environment:" block in docker-compose.
      for (const { key, lineNumber } of lineValues) {
        if (!/^[A-Z][A-Z0-9_]*$/.test(key)) continue;
        if (!keyMap.has(key)) keyMap.set(key, []);
        keyMap.get(key)!.push({ file: relFile, line: lineNumber });
      }
    }
  }

  const findings: Finding[] = [];

  for (const [key, occurrences] of keyMap) {
    if (occurrences.length < 2) continue;

    // Deduplicate by file — only report once per key if same file defines it
    // multiple times (e.g. commented vs active line).
    const uniqueFiles = [...new Map(occurrences.map((o) => [o.file, o])).values()];
    if (uniqueFiles.length < 2) continue;

    const fileList = uniqueFiles.map((o) => o.file).join(', ');

    for (const occurrence of uniqueFiles) {
      findings.push({
        id: makeId('duplicate-config-key', `${key}:${occurrence.file}`),
        layer: 'static',
        type: 'duplicate-config-key',
        severity: 'warning',
        confidence: 0.85,
        file: occurrence.file,
        line: occurrence.line,
        message: `Config key "${key}" is defined in multiple files: ${fileList}`,
        tool: 'config-staleness',
        suggestion: `Choose a single source of truth for "${key}". Typically .env should be the canonical location for environment-specific values.`,
        related: uniqueFiles.filter((o) => o.file !== occurrence.file).map((o) => o.file),
        meta: { key, definedIn: uniqueFiles.map((o) => o.file) },
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

export class ConfigStalenessAnalyzer implements Analyzer {
  readonly name = 'config-staleness';
  readonly layer = 'static' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { rootDir } = context;

    const configFiles = collectConfigFiles(rootDir);

    if (configFiles.length === 0) {
      return [];
    }

    // All four passes are independent — run in parallel.
    const [deadRefs, localhostUrls, ports, dupeKeys] = await Promise.all([
      Promise.resolve(detectDeadReferences(configFiles, rootDir)),
      Promise.resolve(detectLocalhostUrls(configFiles, rootDir)),
      Promise.resolve(detectHardcodedPorts(configFiles, rootDir)),
      Promise.resolve(detectDuplicateKeys(configFiles, rootDir)),
    ]);

    return [...deadRefs, ...localhostUrls, ...ports, ...dupeKeys];
  }
}
