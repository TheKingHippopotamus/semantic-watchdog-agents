// ============================================================
// CodeSentinel — Function Textifier
//
// Converts an ExtractedFunction into a concise natural-language
// description suitable for a code embedding model.
//
// Strategy follows the Qdrant/HuggingFace semantic code search
// cookbook: split identifiers into constituent words, then
// assemble a prose sentence that captures function intent,
// parameter types, return type, and context (exports, imports).
//
// The output is intentionally kept under 200 words so that
// sentence-transformer models with a 512-token limit are never
// truncated on a single function description.
// ============================================================

import type { ExtractedFunction } from '../../types.js';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Converts a code function into a natural-language description for embedding.
 *
 * Example:
 *   async validateUserToken(token: string): Promise<boolean>
 *   → "Async function validate user token that takes token string parameter
 *      and returns promise boolean. Imports from jsonwebtoken. Exported."
 */
export function textify(fn: ExtractedFunction): string {
  const parts: string[] = [];

  // 1. Async / generator prefix detected from body.
  // body is optional (absent on cache-loaded entries — SEC-06); fall back to
  // empty string so the regex tests are simply false when body is unavailable.
  const bodyText = fn.body ?? '';
  const isAsync = /^\s*async\s/.test(bodyText) || /\basync\b/.test(fn.name);
  const isGenerator = /^\s*function\s*\*/.test(bodyText) || bodyText.startsWith('*');

  if (fn.name === '<whole-file>') {
    return buildWholeFileDescription(fn);
  }

  // 2. Function type phrase
  const prefix = buildPrefix(isAsync, isGenerator);
  const nameWords = splitIdentifier(fn.name).join(' ');
  parts.push(`${prefix} ${nameWords}`);

  // 3. Parameters
  if (fn.params.length > 0) {
    const paramPhrase = buildParamPhrase(fn.params);
    parts.push(`that takes ${paramPhrase}`);
  } else {
    parts.push('with no parameters');
  }

  // 4. Return type
  if (fn.returnType) {
    const retPhrase = buildReturnPhrase(fn.returnType);
    parts.push(`and returns ${retPhrase}`);
  }

  // 5. Import context (limit to 3 most relevant)
  const relevantImports = selectRelevantImports(fn.imports, fn.name, fn.params);
  if (relevantImports.length > 0) {
    const importPhrase = relevantImports
      .map(imp => lastSegment(imp))
      .join(', ');
    parts.push(`Imports from ${importPhrase}.`);
  }

  // 6. Export status
  if (fn.exports) {
    parts.push('Exported.');
  }

  const description = parts.join(' ').trim();

  // Guard: truncate to ~200 words if somehow oversized
  return truncateToWordLimit(description, 200);
}

/**
 * Splits camelCase, PascalCase, snake_case, and SCREAMING_SNAKE identifiers
 * into constituent lowercase words.
 *
 * Examples:
 *   validateUserToken  → ['validate', 'user', 'token']
 *   HTTPSClient        → ['https', 'client']
 *   parse_json_body    → ['parse', 'json', 'body']
 *   MAX_RETRY_COUNT    → ['max', 'retry', 'count']
 *   getHTTPResponse    → ['get', 'http', 'response']
 */
export function splitIdentifier(name: string): string[] {
  if (!name || name === '<anonymous>' || name === '<whole-file>') {
    return [];
  }

  // Step 1: Replace all underscores and hyphens with spaces (handles snake_case)
  let result = name.replace(/[_-]+/g, ' ');

  // Step 2: Insert space before a capital letter that follows a lowercase letter
  //         e.g. validateUser → validate User
  result = result.replace(/([a-z])([A-Z])/g, '$1 $2');

  // Step 3: Insert space before a capital letter that is followed by lowercase,
  //         but preceded by consecutive uppercase letters (handles acronyms like HTTPSClient → HTTPS Client)
  result = result.replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2');

  // Step 4: Split on whitespace, lowercase all tokens, remove empty/numeric-only tokens
  return result
    .split(/\s+/)
    .map(t => t.toLowerCase())
    .filter(t => t.length > 0 && !/^\d+$/.test(t));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildPrefix(isAsync: boolean, isGenerator: boolean): string {
  if (isAsync && isGenerator) return 'Async generator function';
  if (isAsync) return 'Async function';
  if (isGenerator) return 'Generator function';
  return 'Function';
}

/**
 * Builds a readable parameter phrase from a list of parameter names.
 * Handles type annotations embedded in the param string (strips them).
 *
 * Input:  ['userId', 'options', 'callback']
 * Output: 'user id, options, and callback parameters'
 */
function buildParamPhrase(params: string[]): string {
  const phrases = params.map(p => {
    // Strip type annotations if they slipped through (e.g. "token:string")
    const name = p.split(/[:\s]/)[0];
    const words = splitIdentifier(name);
    return words.length > 0 ? words.join(' ') : name;
  });

  if (phrases.length === 1) {
    return `${phrases[0]} parameter`;
  }

  if (phrases.length === 2) {
    return `${phrases[0]} and ${phrases[1]} parameters`;
  }

  const last = phrases[phrases.length - 1];
  const rest = phrases.slice(0, -1).join(', ');
  return `${rest}, and ${last} parameters`;
}

/**
 * Converts a TypeScript return type annotation into prose.
 * Strips generic brackets and Promise wrappers for clarity.
 *
 * Examples:
 *   Promise<boolean>     → 'promise boolean'
 *   string[]             → 'string array'
 *   Record<string, any>  → 'record'
 *   void                 → 'nothing'
 */
function buildReturnPhrase(returnType: string): string {
  let rt = returnType.trim();

  // Handle void/never specially
  if (rt === 'void' || rt === 'never') return 'nothing';
  if (rt === 'never') return 'never';

  // Unwrap Promise<X> → "promise X"
  const promiseMatch = rt.match(/^Promise<(.+)>$/i);
  if (promiseMatch) {
    const inner = buildReturnPhrase(promiseMatch[1]);
    return `promise ${inner}`;
  }

  // Handle array type T[] or Array<T>
  if (rt.endsWith('[]')) {
    const inner = buildReturnPhrase(rt.slice(0, -2));
    return `${inner} array`;
  }

  const arrayMatch = rt.match(/^Array<(.+)>$/i);
  if (arrayMatch) {
    const inner = buildReturnPhrase(arrayMatch[1]);
    return `${inner} array`;
  }

  // Strip remaining generic parameters — just keep the base type name
  rt = rt.replace(/<[^>]*>/g, '').trim();

  // Split the base type identifier into words
  const words = splitIdentifier(rt);
  return words.length > 0 ? words.join(' ') : rt.toLowerCase();
}

/**
 * Selects up to 3 most relevant imports for a function.
 * Relevance: imports whose last segment shares tokens with the function name
 * or parameter names score higher. Node built-ins (node:*) are deprioritized.
 */
function selectRelevantImports(
  imports: string[],
  fnName: string,
  params: string[],
): string[] {
  if (imports.length === 0) return [];
  if (imports.length <= 3) return imports;

  const fnTokens = new Set([
    ...splitIdentifier(fnName),
    ...params.flatMap(p => splitIdentifier(p.split(/[:\s]/)[0])),
  ]);

  const scored = imports.map(imp => {
    const seg = lastSegment(imp).toLowerCase();
    const segTokens = splitIdentifier(seg);
    const overlap = segTokens.filter(t => fnTokens.has(t)).length;
    const isBuiltin = imp.startsWith('node:') || imp.startsWith('./') || imp.startsWith('../');
    return { imp, score: overlap - (isBuiltin ? 0.5 : 0) };
  });

  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, 3).map(s => s.imp);
}

/**
 * Returns the last path/module segment of an import string.
 * Examples:
 *   'node:crypto'    → 'crypto'
 *   './utils/parse'  → 'parse'
 *   'jsonwebtoken'   → 'jsonwebtoken'
 */
function lastSegment(imp: string): string {
  return imp.split(/[:/]/).filter(Boolean).pop() ?? imp;
}

/**
 * Generates a description for whole-file synthetic functions.
 */
function buildWholeFileDescription(fn: ExtractedFunction): string {
  const lineCount = fn.endLine - fn.startLine + 1;
  const importPhrase = fn.imports.length > 0
    ? ` Imports from ${fn.imports.slice(0, 3).map(lastSegment).join(', ')}.`
    : '';
  return `Source file with ${lineCount} lines.${importPhrase}`;
}

/**
 * Truncates a description to a maximum number of words.
 * Appends an ellipsis if truncated.
 */
function truncateToWordLimit(text: string, maxWords: number): string {
  const words = text.split(/\s+/);
  if (words.length <= maxWords) return text;
  return words.slice(0, maxWords).join(' ') + '...';
}
