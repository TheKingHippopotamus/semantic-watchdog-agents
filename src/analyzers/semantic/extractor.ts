// ============================================================
// CodeSentinel — Function Extractor
//
// Parses source files via ast-grep and extracts function-level
// units (declarations, methods, arrow functions) as structured
// ExtractedFunction objects ready for embedding.
//
// Language support:
//   Native (ast-grep built-in):  TypeScript, TSX, JavaScript
//   Regex fallback:              Python, Go, Rust, Java, C, C++
//   Unknown extension:           Whole-file synthetic function
// ============================================================

import { extname, basename, dirname } from 'node:path';
import { parse, Lang } from '@ast-grep/napi';
import type { ExtractedFunction } from '../../types.js';

// ---------------------------------------------------------------------------
// Language detection
// ---------------------------------------------------------------------------

type RegexLang = 'python' | 'go' | 'rust' | 'java' | 'c' | 'cpp';

type LangDetection =
  | { kind: 'native'; lang: Lang }
  | { kind: 'regex';  langKey: RegexLang }
  | { kind: 'unknown' };

const EXT_MAP: Record<string, LangDetection> = {
  '.ts':   { kind: 'native', lang: Lang.TypeScript },
  '.tsx':  { kind: 'native', lang: Lang.Tsx },
  '.js':   { kind: 'native', lang: Lang.JavaScript },
  '.mjs':  { kind: 'native', lang: Lang.JavaScript },
  '.cjs':  { kind: 'native', lang: Lang.JavaScript },
  '.jsx':  { kind: 'native', lang: Lang.JavaScript },
  '.py':   { kind: 'regex',  langKey: 'python' },
  '.go':   { kind: 'regex',  langKey: 'go' },
  '.rs':   { kind: 'regex',  langKey: 'rust' },
  '.java': { kind: 'regex',  langKey: 'java' },
  '.c':    { kind: 'regex',  langKey: 'c' },
  '.h':    { kind: 'regex',  langKey: 'c' },
  '.cc':   { kind: 'regex',  langKey: 'cpp' },
  '.cpp':  { kind: 'regex',  langKey: 'cpp' },
  '.cxx':  { kind: 'regex',  langKey: 'cpp' },
  '.hpp':  { kind: 'regex',  langKey: 'cpp' },
};

function detectLanguage(filePath: string): LangDetection {
  const ext = extname(filePath).toLowerCase();
  return EXT_MAP[ext] ?? { kind: 'unknown' };
}

// ---------------------------------------------------------------------------
// File-level noise filters
// ---------------------------------------------------------------------------

/**
 * Returns true when the file should be skipped entirely.
 * These file categories produce meaningless embeddings:
 *   - TypeScript declaration files (.d.ts) — no runtime logic
 *   - Files under 10 lines — barrel re-exports, trivial config stubs
 *   - Test files (*.test.ts, *.spec.ts, *.test.js, *.spec.js) — avoid comparing
 *     test code against production code for duplication
 *   - Files that only contain type/interface declarations and no function bodies
 */
function shouldSkipFile(filePath: string, source: string): boolean {
  const file = basename(filePath);

  // .d.ts — ambient type declarations
  if (file.endsWith('.d.ts')) return true;

  // Test files
  if (/\.(test|spec)\.[jt]sx?$/.test(file)) return true;

  // Trivially short files (barrel exports, empty placeholders, re-export stubs)
  const lineCount = source.split('\n').length;
  if (lineCount < 10) return true;

  // Files with only type/interface/enum exports and no function bodies.
  // Heuristic: if there are zero opening braces outside of type positions,
  // or every brace is preceded by a type/interface/enum keyword, it's type-only.
  const stripped = source
    .replace(/\/\/.*$/gm, '')            // strip line comments
    .replace(/\/\*[\s\S]*?\*\//g, '');   // strip block comments

  // Count `{` that are part of a function/method/class body vs. type-only braces.
  // A reliable discriminator: presence of `=>`, `function`, `class … {`, `() {` etc.
  const hasFunctionBody =
    /(?:function\s+\w+|=>\s*\{|\)\s*:\s*\w[^;{(]*\s*\{|=\s*\{[\s\S]{20,}?\})/
      .test(stripped);

  const hasOnlyTypeExports =
    /^\s*export\s+(?:type|interface|enum)\s+\w+/m.test(stripped) &&
    !hasFunctionBody;

  if (hasOnlyTypeExports) return true;

  return false;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Extract function-level units from a source file.
 *
 * Returns an empty array for files that would only produce noise (type
 * declaration files, test files, trivially short files, pure-type files).
 *
 * For unsupported languages with real content, returns a single whole-file
 * synthetic function (name='<whole-file>', body='') so downstream consumers
 * can detect and filter it via the empty body.
 */
export function extractFunctions(filePath: string, source: string): ExtractedFunction[] {
  // Hard skip — these categories contribute only noise to semantic analysis
  if (shouldSkipFile(filePath, source)) return [];

  const detection = detectLanguage(filePath);

  if (detection.kind === 'unknown') {
    return [wholeFileFunction(filePath, source)];
  }

  if (detection.kind === 'regex') {
    return extractWithRegex(filePath, source, detection.langKey);
  }

  // Native ast-grep extraction
  try {
    return extractWithAstGrep(filePath, source, detection.lang);
  } catch {
    // AST parse failure (syntax error, binary incompatibility) — degrade gracefully.
    return [wholeFileFunction(filePath, source)];
  }
}

// ---------------------------------------------------------------------------
// ast-grep native extraction (TypeScript / TSX / JavaScript)
// ---------------------------------------------------------------------------

type AstNode = ReturnType<ReturnType<typeof parse>['root']>;

function extractWithAstGrep(
  filePath: string,
  source: string,
  lang: Lang,
): ExtractedFunction[] {
  const root = parse(lang, source).root();
  const results: ExtractedFunction[] = [];

  // Collect import module sources for context
  const imports = collectImports(root);

  // 1. Function declarations (function foo() {}) and function expressions
  //    assigned to variables (const foo = function() {})
  for (const node of root.findAll({
    rule: {
      any: [
        { kind: 'function_declaration' },
        { kind: 'function_expression' },
        { kind: 'generator_function_declaration' },
        { kind: 'generator_function' },
      ],
    },
  })) {
    const fn = buildFromFunctionNode(node, filePath, imports, lang);
    if (fn !== null) results.push(fn);
  }

  // 2. Method definitions inside classes (methods, getters, setters)
  for (const node of root.findAll({
    rule: { kind: 'method_definition' },
  })) {
    const fn = buildFromMethodNode(node, filePath, imports, lang);
    if (fn !== null) results.push(fn);
  }

  // 3. Arrow functions assigned to named variables/exports
  for (const node of root.findAll({
    rule: { kind: 'arrow_function' },
  })) {
    const fn = buildFromArrowNode(node, filePath, imports, lang);
    if (fn !== null) results.push(fn);
  }

  // Deduplicate by startLine (overlapping matches from nested scopes)
  const deduped = deduplicateByStartLine(results);

  // Filter trivial functions (getters/setters/one-liners, super()-only constructors)
  return deduped.filter(fn => !isTrivialFunction(fn));
}

// ---------------------------------------------------------------------------
// Node builders
// ---------------------------------------------------------------------------

/**
 * Builds an ExtractedFunction from a function_declaration / function_expression
 * / generator variant node.
 */
function buildFromFunctionNode(
  node: AstNode,
  filePath: string,
  imports: string[],
  lang: Lang,
): ExtractedFunction | null {
  let name = node.field('name')?.text() ?? '';

  if (!name) {
    // function expression in a variable declarator: const foo = function() {}
    const parent = node.parent();
    if (parent?.kind() === 'variable_declarator') {
      name = parent.field('name')?.text() ?? '';
    }
  }

  if (!name) name = '<anonymous>';

  const range = node.range();
  // ast-grep ranges are 0-indexed; convert to 1-indexed for consistency
  const startLine = range.start.line + 1;
  const endLine = range.end.line + 1;

  return {
    name,
    filePath,
    startLine,
    endLine,
    params: extractParams(node),
    returnType: extractReturnType(node, lang),
    imports,
    exports: isExported(node),
    body: node.text(),
    description: '',
  };
}

/**
 * Builds an ExtractedFunction from a method_definition node.
 */
function buildFromMethodNode(
  node: AstNode,
  filePath: string,
  imports: string[],
  lang: Lang,
): ExtractedFunction | null {
  const name = node.field('name')?.text() ?? '<anonymous>';

  const range = node.range();
  const startLine = range.start.line + 1;
  const endLine = range.end.line + 1;

  return {
    name,
    filePath,
    startLine,
    endLine,
    params: extractParams(node),
    returnType: extractReturnType(node, lang),
    imports,
    exports: isExported(node),
    body: node.text(),
    description: '',
  };
}

/**
 * Builds an ExtractedFunction from an arrow_function node.
 * Only returns a function if the arrow is assigned to a named identifier
 * (variable declarator or export). Anonymous inline arrows are skipped.
 */
function buildFromArrowNode(
  node: AstNode,
  filePath: string,
  imports: string[],
  lang: Lang,
): ExtractedFunction | null {
  const parent = node.parent();
  if (!parent) return null;

  // const foo = () => {} — parent is variable_declarator
  if (parent.kind() !== 'variable_declarator') return null;

  const name = parent.field('name')?.text();
  if (!name) return null;

  const range = node.range();
  const startLine = range.start.line + 1;
  const endLine = range.end.line + 1;

  return {
    name,
    filePath,
    startLine,
    endLine,
    params: extractParams(node),
    returnType: extractReturnType(node, lang),
    imports,
    exports: isExported(node),
    body: node.text(),
    description: '',
  };
}

// ---------------------------------------------------------------------------
// AST helpers
// ---------------------------------------------------------------------------

/**
 * Extracts parameter names from a function/arrow/method node.
 *
 * Handles the following patterns:
 *   - Simple identifier:      foo
 *   - Typed (TS):             foo: string   → foo
 *   - Default value:          foo = 'bar'   → foo
 *   - Rest:                   ...args       → args
 *   - Destructured:           { a, b }      → kept as-is
 *   - Optional (TS):          foo?          → foo
 */
function extractParams(node: AstNode): string[] {
  const paramsNode = node.field('parameters');
  if (!paramsNode) return [];

  return paramsNode
    .children()
    .filter(c => c.isNamed() && c.kind() !== ',')
    .map(c => {
      const kind = c.kind();

      // required_parameter / optional_parameter (TypeScript) have a `pattern` field
      const patternNode = c.field('pattern');
      if (patternNode) {
        // Strip anything after a colon (type annotation)
        return patternNode.text().replace(/\?$/, '').split(':')[0].trim();
      }

      // identifier — direct param name
      if (kind === 'identifier') {
        return c.text().split(':')[0].trim();
      }

      // rest_pattern: ...args → args
      if (kind === 'rest_pattern') {
        const inner = c.children().find(ch => ch.kind() === 'identifier');
        return inner?.text() ?? c.text().replace(/^\.\.\./, '').split(':')[0].trim();
      }

      // assignment_pattern: foo = default → foo
      if (kind === 'assignment_pattern') {
        return c.field('left')?.text().split(':')[0].trim() ?? c.text();
      }

      // Fallback: use raw text, strip type annotation
      return c.text().replace(/\?$/, '').split(':')[0].trim();
    })
    .filter(p => p.length > 0 && p !== ')' && p !== '(');
}

/**
 * Extracts the return type annotation from a TypeScript function node.
 * Returns undefined for JavaScript (no annotations) and when absent.
 */
function extractReturnType(node: AstNode, lang: Lang): string | undefined {
  if (lang !== Lang.TypeScript && lang !== Lang.Tsx) return undefined;

  const returnTypeNode = node.field('return_type');
  if (!returnTypeNode) return undefined;

  // The `return_type` field text includes the leading `: ` — strip it
  return returnTypeNode.text().replace(/^:\s*/, '').trim();
}

/**
 * Determines if a function/method is exported.
 * Handles:
 *   export function foo()          — export_statement wraps function
 *   export default function foo()  — export_statement wraps function
 *   export const foo = () => {}    — export_statement wraps variable declaration
 *   class methods — not exported (controlled by class visibility, not JS export)
 */
function isExported(node: AstNode): boolean {
  let current = node.parent();
  let depth = 0;

  while (current !== null && current !== undefined && depth < 5) {
    const k = current.kind();

    if (k === 'export_statement') return true;

    // Stop if we enter a nested block or class body — no longer top-level
    if (k === 'statement_block' || k === 'class_body' || k === 'program') {
      return false;
    }

    current = current.parent();
    depth++;
  }

  return false;
}

/**
 * Collects all import module source strings from the file root.
 * Example: import { parse } from 'node:path'  → 'node:path'
 */
function collectImports(root: AstNode): string[] {
  const importNodes = root.findAll({ rule: { kind: 'import_declaration' } });
  const sources: string[] = [];

  for (const node of importNodes) {
    const sourceNode = node.field('source');
    if (sourceNode) {
      // source text includes surrounding quotes — strip them
      const raw = sourceNode.text().replace(/^['"`]|['"`]$/g, '');
      if (raw) sources.push(raw);
    }
  }

  return [...new Set(sources)];
}

/**
 * Removes ExtractedFunctions that share the same startLine.
 * Keeps the entry with the longer body (more complete extraction).
 */
function deduplicateByStartLine(fns: ExtractedFunction[]): ExtractedFunction[] {
  const seen = new Map<number, ExtractedFunction>();

  for (const fn of fns) {
    const existing = seen.get(fn.startLine);
    if (!existing || (fn.body ?? '').length > (existing.body ?? '').length) {
      seen.set(fn.startLine, fn);
    }
  }

  return [...seen.values()].sort((a, b) => a.startLine - b.startLine);
}

/**
 * Returns true for functions that are too trivial to produce a meaningful
 * embedding and should be excluded from semantic analysis:
 *
 *   - Body length < 3 lines: getters, setters, one-liners like `return this.x`
 *   - Constructors whose body is only `super(...)` calls or simple field
 *     assignments (`this.x = x`) — no real logic
 */
function isTrivialFunction(fn: ExtractedFunction): boolean {
  const body = fn.body ?? '';
  if (!body) return false;  // already synthetic — handled elsewhere

  const lines = body.split('\n').filter(l => l.trim().length > 0);
  // Fewer than 3 non-empty lines means signature + at most 1 statement — trivial
  if (lines.length < 3) return true;

  // Constructor triviality check: only super() calls and this.x = y assignments
  if (fn.name === 'constructor') {
    const bodyOnly = body
      .replace(/^[^{]*\{/, '')   // strip up to opening brace
      .replace(/\}\s*$/, '')      // strip closing brace
      .trim();

    const statements = bodyOnly
      .split(/;|\n/)
      .map(s => s.trim())
      .filter(s => s.length > 0);

    const isTrivialStatement = (s: string): boolean =>
      /^super\s*\(/.test(s) ||
      /^this\.\w+\s*=\s*\w+$/.test(s) ||
      /^this\.\w+\s*=\s*this\.\w+$/.test(s);

    if (statements.every(isTrivialStatement)) return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Regex-based extraction (Python, Go, Rust, Java, C, C++)
//
// @ast-grep/lang-* WASM binaries are not bundled in this project.
// These regex extractors handle the common declaration patterns reliably.
// ---------------------------------------------------------------------------

interface RegexExtractor {
  /** Matches function/method signatures (must have a capturing group for name). */
  fn: RegExp;
  /** Group index for the function name inside `fn`. */
  nameGroup: number;
  /** Matches import/include/use statements. */
  imports: RegExp;
  /** Import capture group index. */
  importGroup: number;
  /** Test whether the matched signature is exported/public. */
  isExported: (match: string) => boolean;
}

const REGEX_EXTRACTORS: Record<RegexLang, RegexExtractor> = {
  python: {
    fn: /^[ \t]*(?:async\s+)?def\s+(\w+)\s*\(/gm,
    nameGroup: 1,
    imports: /^(?:import|from)\s+([\w.]+)/gm,
    importGroup: 1,
    isExported: (m) => !m.includes('    ') && !m.includes('\t'),  // top-level (no indent)
  },
  go: {
    // func (recv Type) FunctionName(params) returnType
    // func FunctionName(params) returnType
    fn: /^func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s+)?([A-Za-z_]\w*)\s*[(<[]/gm,
    nameGroup: 1,
    imports: /^\s+"([\w./\-]+)"/gm,
    importGroup: 1,
    isExported: (m) => /func\s+[A-Z]/.test(m),  // exported = starts with uppercase
  },
  rust: {
    fn: /^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)\s*[<(]/gm,
    nameGroup: 1,
    imports: /^use\s+([\w:{}, *]+);/gm,
    importGroup: 1,
    isExported: (m) => /\bpub\b/.test(m),
  },
  java: {
    // Matches: [modifiers] ReturnType methodName(
    // The tricky part: capture last word before `(` as the name
    fn: /^[ \t]*(?:(?:public|private|protected|static|final|abstract|synchronized|native)\s+){0,4}(?:\w+(?:<[^>]+>)?\s+)+?(\w+)\s*\(/gm,
    nameGroup: 1,
    imports: /^import\s+(?:static\s+)?([\w.]+);/gm,
    importGroup: 1,
    isExported: (m) => /\bpublic\b/.test(m),
  },
  c: {
    // Avoids matching control flow keywords; requires opening brace (not declaration-only)
    fn: /^(?![ \t]*(?:if|else|for|while|switch|do|return|case|break|continue)\b)(?:static\s+|extern\s+|inline\s+)?(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:long\s+){0,2}(?:\w+)\s*\*?\s*(\w+)\s*\([^;]{0,200}?\)\s*(?:\{|$)/gm,
    nameGroup: 1,
    imports: /^#include\s+[<"]([\w./]+)[>"]/gm,
    importGroup: 1,
    isExported: (m) => !/\bstatic\b/.test(m),
  },
  cpp: {
    fn: /^(?![ \t]*(?:if|else|for|while|switch|do|return|case|break|continue)\b)(?:(?:static|inline|virtual|explicit|constexpr|override|final)\s+)*(?:const\s+)?(?:[\w:*&<>, ]+\s+)?(?:\w+::)*(\w+)\s*\([^;]{0,200}?\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:\{|$)/gm,
    nameGroup: 1,
    imports: /^#include\s+[<"]([\w./]+)[>"]/gm,
    importGroup: 1,
    isExported: (m) => !/\bstatic\b/.test(m),
  },
};

/** Identifiers that the C/C++/Java regexes may incorrectly capture as function names. */
const FALSE_POSITIVE_NAMES = new Set([
  'if', 'else', 'for', 'while', 'switch', 'catch', 'return', 'do', 'try',
  'class', 'struct', 'enum', 'namespace', 'template', 'new', 'delete',
  'void', 'int', 'char', 'float', 'double', 'long', 'short', 'unsigned',
  'signed', 'const', 'static', 'extern', 'inline', 'auto', 'register',
]);

function extractWithRegex(
  filePath: string,
  source: string,
  lang: RegexLang,
): ExtractedFunction[] {
  // Python gets a dedicated enriched extractor — generic regex produces descriptions
  // that are too similar across files (all generic `def` lines) and causes CodeBERT
  // to score unrelated functions at 99%+ similarity.
  if (lang === 'python') {
    return extractPythonFunctions(filePath, source);
  }

  const extractor = REGEX_EXTRACTORS[lang];
  const lines = source.split('\n');
  const results: ExtractedFunction[] = [];

  // Collect imports
  const imports: string[] = [];
  const importRegex = new RegExp(extractor.imports.source, extractor.imports.flags);
  let importMatch: RegExpExecArray | null;
  while ((importMatch = importRegex.exec(source)) !== null) {
    const val = importMatch[extractor.importGroup];
    if (val) imports.push(val);
  }

  // Extract functions
  const fnRegex = new RegExp(extractor.fn.source, extractor.fn.flags);
  let match: RegExpExecArray | null;

  while ((match = fnRegex.exec(source)) !== null) {
    const name = match[extractor.nameGroup];
    if (!name || FALSE_POSITIVE_NAMES.has(name)) continue;

    const startLine = offsetToLine(source, match.index);
    const endLine = findFunctionEnd(lines, startLine - 1, lang);
    const body = lines.slice(startLine - 1, endLine).join('\n');

    results.push({
      name,
      filePath,
      startLine,
      endLine,
      params: extractParamsFromSignatureText(match[0]),
      returnType: undefined,  // Regex cannot reliably extract typed return annotations
      imports,
      exports: extractor.isExported(match[0]),
      body,
      description: '',
    });
  }

  // Dedup by start line (regex can produce overlapping matches on multiline patterns)
  const deduped = deduplicateByStartLine(results);

  return deduped.length > 0 ? deduped : [wholeFileFunction(filePath, source)];
}

// ---------------------------------------------------------------------------
// Python-specific enriched extractor
//
// The generic regex path produces descriptions like "function connect(self)"
// for every DB adapter, making CodeBERT score them at 99%+ similarity even
// across completely different implementations.  This extractor pulls the full
// def signature (including type annotations), docstring, decorators, and class
// context so the embedding captures actual semantic content.
// ---------------------------------------------------------------------------

/**
 * Extracts file-level import module names from Python source.
 * Handles both `import foo` and `from foo import bar` forms.
 */
function collectPythonImports(source: string): string[] {
  const imports: string[] = [];
  const re = /^(?:from\s+([\w.]+)\s+import|import\s+([\w.,\s]+))/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    const mod = (m[1] ?? m[2] ?? '').trim().split(/\s*,\s*/)[0].split('.')[0];
    if (mod) imports.push(mod);
  }
  return [...new Set(imports)].slice(0, 10);
}

/**
 * For a given `def` line (0-indexed), scan upward to find any decorator lines
 * (lines starting with `@` at the same or greater indent level than the def).
 * Returns decorator strings without the leading `@`.
 */
function collectPythonDecorators(lines: string[], defIdx: number): string[] {
  const defIndent = lines[defIdx].match(/^(\s*)/)?.[1].length ?? 0;
  const decorators: string[] = [];

  for (let i = defIdx - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (line === '' || line.startsWith('#')) continue;  // skip blanks / comments
    const lineIndent = lines[i].match(/^(\s*)/)?.[1].length ?? 0;
    if (lineIndent === defIndent && line.startsWith('@')) {
      // Strip `@` and take only the decorator name (before any `(`)
      decorators.unshift(line.replace(/^@/, '').split('(')[0].trim());
    } else {
      break;  // first non-decorator, non-blank line ends the decorator block
    }
  }

  return decorators;
}

/**
 * Scans backward from `defIdx` to find the enclosing `class` name, if any.
 * Looks for a `class Foo:` line with strictly less indentation.
 */
function findPythonClassName(lines: string[], defIdx: number): string | undefined {
  const defIndent = lines[defIdx].match(/^(\s*)/)?.[1].length ?? 0;
  if (defIndent === 0) return undefined;  // top-level function, not a method

  for (let i = defIdx - 1; i >= 0; i--) {
    const line = lines[i];
    if (line.trim() === '' || line.trim().startsWith('#')) continue;
    const lineIndent = line.match(/^(\s*)/)?.[1].length ?? 0;
    if (lineIndent < defIndent) {
      const classMatch = line.match(/^\s*class\s+(\w+)/);
      if (classMatch) return classMatch[1];
      // Some other block (function, if, etc.) — still the enclosing scope
      // but not a class, keep searching upward
    }
  }

  return undefined;
}

/**
 * Extracts the docstring immediately following a `def` line.
 * Handles both triple-double-quote and triple-single-quote variants,
 * single-line and multi-line forms.  Returns the raw docstring content
 * (without the triple quotes) trimmed to at most 300 characters.
 */
function extractPythonDocstring(lines: string[], defIdx: number, blockEndIdx: number): string | undefined {
  // Scan from the line after `def` for the opening triple-quote
  let openLine = -1;
  let quoteChar = '';

  for (let i = defIdx + 1; i <= blockEndIdx && i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed === '') continue;
    if (trimmed.startsWith('"""') || trimmed.startsWith("'''")) {
      openLine = i;
      quoteChar = trimmed.startsWith('"""') ? '"""' : "'''";
      break;
    }
    // First non-blank, non-triple-quote line means no docstring
    break;
  }

  if (openLine === -1) return undefined;

  const openTrimmed = lines[openLine].trim();
  // Single-line docstring: """Some text."""
  const singleLine = openTrimmed.slice(3);
  const closeIdx = singleLine.indexOf(quoteChar);
  if (closeIdx !== -1) {
    return singleLine.slice(0, closeIdx).trim().slice(0, 300) || undefined;
  }

  // Multi-line docstring: collect until closing triple-quote
  const docLines: string[] = [singleLine.trim()];
  for (let i = openLine + 1; i <= blockEndIdx && i < lines.length; i++) {
    const line = lines[i];
    const closeMatch = line.indexOf(quoteChar);
    if (closeMatch !== -1) {
      const tail = line.slice(0, closeMatch).trim();
      if (tail) docLines.push(tail);
      break;
    }
    docLines.push(line.trim());
  }

  return docLines.filter(Boolean).join(' ').trim().slice(0, 300) || undefined;
}

/**
 * Extracts the full `def` signature line(s) for a Python function.
 * Handles multi-line signatures (when params span multiple lines with `\`
 * continuation or open parenthesis).  Returns the normalized single-line text.
 */
function extractPythonSignature(lines: string[], defIdx: number): string {
  let sig = lines[defIdx].trim();
  // If the param list doesn't close on the def line, gather continuation lines
  let depth = (sig.match(/\(/g) ?? []).length - (sig.match(/\)/g) ?? []).length;
  let i = defIdx + 1;
  while (depth > 0 && i < lines.length) {
    const cont = lines[i].trim();
    sig += ' ' + cont;
    depth += (cont.match(/\(/g) ?? []).length - (cont.match(/\)/g) ?? []).length;
    i++;
  }
  // Normalize: collapse internal whitespace
  return sig.replace(/\s+/g, ' ').trim();
}

/**
 * Returns true when a Python `__init__` body contains only `self.x = y`
 * assignments (and no meaningful logic).  These constructors are trivial
 * data-transfer objects and produce near-identical embeddings.
 */
function isTrivialPythonInit(body: string): boolean {
  const bodyLines = body.split('\n').slice(1);  // skip the def line itself
  const meaningful = bodyLines.filter(l => {
    const t = l.trim();
    return t && !t.startsWith('#') && t !== 'pass';
  });
  if (meaningful.length === 0) return true;

  // Every meaningful line must be a self.x = ... assignment or super().__init__ call
  return meaningful.every(l => {
    const t = l.trim();
    return (
      /^self\.\w+\s*=\s*.+$/.test(t) ||
      /^super\(\)\.__init__\(/.test(t) ||
      /^super\([\w,\s]*\)\.__init__\(/.test(t)
    );
  });
}

/**
 * Returns true when a dunder method body is shorter than 5 non-blank lines.
 * Short dunders like `__repr__`, `__str__`, `__len__`, `__bool__` produce
 * near-identical embeddings and clutter the duplication report.
 */
function isTrivialPythonDunder(name: string, body: string): boolean {
  if (!name.startsWith('__') || !name.endsWith('__')) return false;
  // __init__ has its own check; everything else uses the line count heuristic
  if (name === '__init__') return false;
  const nonBlankLines = body.split('\n').filter(l => l.trim().length > 0);
  return nonBlankLines.length < 5;
}

/**
 * Full Python function extractor.  For each `def` found:
 *   1. Resolves the enclosing class (if any)
 *   2. Collects decorators
 *   3. Extracts the full signature with type annotations
 *   4. Extracts the docstring
 *   5. Builds a rich `description` field that makes the embedding meaningful
 *   6. Filters trivial constructors and short dunder methods
 */
function extractPythonFunctions(filePath: string, source: string): ExtractedFunction[] {
  const lines = source.split('\n');
  const fileImports = collectPythonImports(source);
  const results: ExtractedFunction[] = [];

  // Match every `def` (sync and async), including nested ones
  const defRe = /^[ \t]*(?:async\s+)?def\s+(\w+)\s*\(/gm;
  let match: RegExpExecArray | null;

  while ((match = defRe.exec(source)) !== null) {
    const name = match[1];
    if (!name) continue;

    const startLine = offsetToLine(source, match.index);  // 1-indexed
    const defIdx = startLine - 1;                          // 0-indexed

    const endLine = findPythonBlockEnd(lines, defIdx);     // 1-indexed exclusive end
    const body = lines.slice(defIdx, endLine).join('\n');

    // --- Trivial function filters ---
    if (name === '__init__' && isTrivialPythonInit(body)) continue;
    if (isTrivialPythonDunder(name, body)) continue;

    // --- Context extraction ---
    const className = findPythonClassName(lines, defIdx);
    const decorators = collectPythonDecorators(lines, defIdx);
    const signature = extractPythonSignature(lines, defIdx);
    const docstring = extractPythonDocstring(lines, defIdx, endLine - 1);
    const isTopLevel = !className;

    // --- Params: extract from signature for the description field ---
    const params = extractParamsFromSignatureText(signature);

    // --- Build rich description ---
    const descParts: string[] = [];

    if (className) {
      descParts.push(`Method ${name} of class ${className}`);
    } else {
      const isAsync = lines[defIdx].trim().startsWith('async ');
      descParts.push(`${isAsync ? 'Async function' : 'Function'} ${name}`);
    }

    if (decorators.length > 0) {
      descParts.push(`decorated with ${decorators.join(', ')}`);
    }

    if (docstring) {
      descParts.push(`Docstring: ${docstring}`);
    }

    if (params.length > 0) {
      // Exclude `self` and `cls` — they are noise in the embedding
      const meaningfulParams = params.filter(p => p !== 'self' && p !== 'cls');
      if (meaningfulParams.length > 0) {
        descParts.push(`Parameters: ${meaningfulParams.join(', ')}`);
      }
    }

    // Return type annotation from signature (text after ` -> ` before `:`)
    const returnTypeMatch = signature.match(/->\s*([^:]+)\s*:/);
    if (returnTypeMatch) {
      descParts.push(`Returns: ${returnTypeMatch[1].trim()}`);
    }

    if (fileImports.length > 0) {
      descParts.push(`Imports: ${fileImports.join(', ')}`);
    }

    const description = descParts.join('. ');

    results.push({
      name,
      filePath,
      startLine,
      endLine,
      params,
      returnType: returnTypeMatch?.[1]?.trim(),
      imports: fileImports,
      exports: isTopLevel && !name.startsWith('_'),
      body,
      description,
    });
  }

  // Deduplicate by start line (nested defs can overlap)
  const deduped = deduplicateByStartLine(results);

  return deduped.length > 0 ? deduped : [wholeFileFunction(filePath, source)];
}

/** Converts a byte offset in `source` to a 1-indexed line number. */
function offsetToLine(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset; i++) {
    if (source[i] === '\n') line++;
  }
  return line;
}

/**
 * Heuristically finds the last line of a function body.
 * Brace-delimited languages: track { } depth.
 * Python: use indentation change to detect block end.
 */
function findFunctionEnd(lines: string[], startIdx: number, lang: RegexLang): number {
  if (lang === 'python') {
    return findPythonBlockEnd(lines, startIdx);
  }
  return findBraceBlockEnd(lines, startIdx);
}

function findBraceBlockEnd(lines: string[], startIdx: number): number {
  let depth = 0;
  let foundOpen = false;

  for (let i = startIdx; i < lines.length; i++) {
    // Strip string literals and comments (simplified) to avoid counting braces in them
    const stripped = lines[i]
      .replace(/"[^"\\]*"|'[^'\\]*'/g, '""')  // simple string stripping
      .replace(/\/\/.*$/, '');                  // line comment stripping

    for (const ch of stripped) {
      if (ch === '{') { depth++; foundOpen = true; }
      else if (ch === '}') { depth--; }
    }

    if (foundOpen && depth === 0) {
      return i + 1;  // 1-indexed
    }
  }

  // Fallback: cap at 50 lines from start or end of file
  return Math.min(startIdx + 50, lines.length);
}

function findPythonBlockEnd(lines: string[], startIdx: number): number {
  const defLine = lines[startIdx] ?? '';
  const baseIndent = defLine.match(/^(\s*)/)?.[1].length ?? 0;

  for (let i = startIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '' || line.trim().startsWith('#')) continue;
    const indent = line.match(/^(\s*)/)?.[1].length ?? 0;
    if (indent <= baseIndent) {
      return i;  // Line i is the first line outside the block (1-indexed: line i)
    }
  }

  return lines.length;
}

/**
 * Extracts parameter names from a raw function signature text fragment.
 * Handles both typed and untyped params across languages.
 */
function extractParamsFromSignatureText(signature: string): string[] {
  const parenOpen = signature.indexOf('(');
  if (parenOpen === -1) return [];

  // Grab what's between the first ( and its matching )
  let depth = 0;
  let paramEnd = -1;
  for (let i = parenOpen; i < signature.length; i++) {
    if (signature[i] === '(') depth++;
    else if (signature[i] === ')') {
      depth--;
      if (depth === 0) { paramEnd = i; break; }
    }
  }

  const inner = signature.slice(parenOpen + 1, paramEnd >= 0 ? paramEnd : undefined);
  if (!inner.trim()) return [];

  return inner
    .split(',')
    .map(p => {
      // Each segment: strip leading type keyword, take last word token as name
      const clean = p
        .trim()
        .replace(/^(?:const|mut|final|readonly|@\w+\s+)+/, '')  // modifiers/annotations
        .replace(/\.\.\./g, '');                                  // rest operator

      // TypeScript/Java: `Type name` or `name: Type` — take the identifier
      const tokens = clean.split(/[\s:=<>[\](){}*&?]+/).filter(Boolean);
      return tokens[tokens.length - 1] ?? '';
    })
    .filter(p => p.length > 0 && !/^\d/.test(p) && !FALSE_POSITIVE_NAMES.has(p));
}

// ---------------------------------------------------------------------------
// Whole-file fallback
// ---------------------------------------------------------------------------

/**
 * Builds a synthetic whole-file ExtractedFunction for files where no real
 * function-level units could be extracted.
 *
 * Consumers can detect this sentinel via:
 *   fn.name === '<whole-file>' && fn.body === ''
 *
 * The description is enriched with file-path context and any top-level names
 * found via lightweight regex so the resulting embedding is not a random blob
 * of text but carries actual semantic signal.
 */
function wholeFileFunction(filePath: string, source: string): ExtractedFunction {
  const lineCount = source.split('\n').length;

  // ---- Enrich description with structural names --------------------------------

  // Directory name carries semantic context (e.g. "parsers", "validators")
  const dirName = basename(dirname(filePath));
  const fileName = basename(filePath);

  // Named exports: `export { Foo, bar }` or `export const/function/class Foo`
  const exportNames: string[] = [];
  for (const m of source.matchAll(/export\s+(?:default\s+)?(?:const|function|class|type|interface|enum)\s+(\w+)/g)) {
    exportNames.push(m[1]);
  }
  // Re-export style: export { Foo, Bar }
  for (const m of source.matchAll(/export\s*\{([^}]+)\}/g)) {
    for (const part of m[1].split(',')) {
      const name = part.replace(/\s+as\s+\w+/, '').trim();
      if (name && /^\w+$/.test(name)) exportNames.push(name);
    }
  }

  // Class names
  const classNames: string[] = [];
  for (const m of source.matchAll(/\bclass\s+(\w+)/g)) {
    classNames.push(m[1]);
  }

  // Import module sources (first 5 — enough for semantic context)
  const importSources: string[] = [];
  for (const m of source.matchAll(/from\s+['"`]([\w@./\-]+)['"`]/g)) {
    importSources.push(m[1]);
  }

  const parts: string[] = [`File: ${dirName}/${fileName}`];
  if (exportNames.length > 0) parts.push(`exports: ${[...new Set(exportNames)].slice(0, 10).join(', ')}`);
  if (classNames.length > 0) parts.push(`classes: ${[...new Set(classNames)].slice(0, 5).join(', ')}`);
  if (importSources.length > 0) parts.push(`imports: ${[...new Set(importSources)].slice(0, 5).join(', ')}`);

  return {
    name: '<whole-file>',
    filePath,
    startLine: 1,
    endLine: lineCount,
    params: [],
    returnType: undefined,
    imports: importSources,
    exports: exportNames.length > 0,
    // Empty body signals synthetic — downstream can filter via `fn.name === '<whole-file>'`
    body: '',
    description: parts.join(' | '),
  };
}
