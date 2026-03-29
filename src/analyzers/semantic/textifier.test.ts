import { describe, it, expect } from 'vitest';
import { splitIdentifier, textify } from './textifier.js';
import type { ExtractedFunction } from '../../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFunction(overrides: Partial<ExtractedFunction> = {}): ExtractedFunction {
  return {
    name: 'myFunction',
    filePath: '/src/example.ts',
    startLine: 1,
    endLine: 10,
    params: [],
    returnType: undefined,
    imports: [],
    exports: false,
    body: 'function myFunction() {}',
    description: '',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// splitIdentifier
// ---------------------------------------------------------------------------

describe('splitIdentifier', () => {
  it('splits camelCase into lowercase words', () => {
    expect(splitIdentifier('camelCase')).toEqual(['camel', 'case']);
  });

  it('splits PascalCase into lowercase words', () => {
    expect(splitIdentifier('PascalCase')).toEqual(['pascal', 'case']);
  });

  it('splits snake_case into lowercase words', () => {
    expect(splitIdentifier('snake_case')).toEqual(['snake', 'case']);
  });

  it('splits SCREAMING_SNAKE into lowercase words', () => {
    expect(splitIdentifier('SCREAMING_SNAKE')).toEqual(['screaming', 'snake']);
  });

  it('splits kebab-case into lowercase words', () => {
    expect(splitIdentifier('kebab-case')).toEqual(['kebab', 'case']);
  });

  it('splits consecutive uppercase acronym followed by a word (HTTPSClient)', () => {
    expect(splitIdentifier('HTTPSClient')).toEqual(['https', 'client']);
  });

  it('splits mixed camel+acronym (getHTTPResponse)', () => {
    expect(splitIdentifier('getHTTPResponse')).toEqual(['get', 'http', 'response']);
  });

  it('splits leading acronym followed by word (XMLParser)', () => {
    expect(splitIdentifier('XMLParser')).toEqual(['xml', 'parser']);
  });

  it('returns a single-element array for a single-character name', () => {
    expect(splitIdentifier('a')).toEqual(['a']);
  });

  it('returns an empty array for an empty string', () => {
    expect(splitIdentifier('')).toEqual([]);
  });

  it('returns an empty array for the special <anonymous> token', () => {
    expect(splitIdentifier('<anonymous>')).toEqual([]);
  });

  it('returns an empty array for the special <whole-file> token', () => {
    expect(splitIdentifier('<whole-file>')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// textify
// ---------------------------------------------------------------------------

describe('textify', () => {
  describe('standard function with rich metadata', () => {
    const fn = makeFunction({
      name: 'validateUserToken',
      params: ['token: string'],
      returnType: 'Promise<boolean>',
      imports: ['jsonwebtoken'],
      exports: true,
      body: 'function validateUserToken(token) {}',
    });

    it('contains the split words from the function name', () => {
      const result = textify(fn);
      expect(result.toLowerCase()).toContain('validate');
      expect(result.toLowerCase()).toContain('user');
      expect(result.toLowerCase()).toContain('token');
    });

    it('contains the unwrapped return type words', () => {
      const result = textify(fn);
      expect(result.toLowerCase()).toContain('promise');
      expect(result.toLowerCase()).toContain('boolean');
    });

    it('contains the import module name', () => {
      const result = textify(fn);
      expect(result.toLowerCase()).toContain('jsonwebtoken');
    });

    it('contains the exported marker', () => {
      const result = textify(fn);
      expect(result.toLowerCase()).toContain('exported');
    });

    it('is under 200 words', () => {
      const wordCount = textify(fn).split(/\s+/).length;
      expect(wordCount).toBeLessThanOrEqual(200);
    });
  });

  describe('minimal empty function', () => {
    const fn = makeFunction({
      name: 'noop',
      params: [],
      returnType: undefined,
      imports: [],
      exports: false,
      body: 'function noop() {}',
    });

    it('produces a non-empty string', () => {
      expect(textify(fn).trim().length).toBeGreaterThan(0);
    });

    it('mentions no parameters', () => {
      const result = textify(fn).toLowerCase();
      expect(result).toContain('no parameters');
    });

    it('does not mention Exported when exports is false', () => {
      const result = textify(fn);
      expect(result).not.toContain('Exported');
    });

    it('does not mention Imports when imports is empty', () => {
      const result = textify(fn);
      expect(result).not.toContain('Imports');
    });

    it('is under 200 words', () => {
      const wordCount = textify(fn).split(/\s+/).length;
      expect(wordCount).toBeLessThanOrEqual(200);
    });
  });

  describe('async function', () => {
    const fn = makeFunction({
      name: 'fetchUserProfile',
      params: ['userId: string'],
      returnType: 'Promise<User>',
      imports: [],
      exports: false,
      body: 'async function fetchUserProfile(userId) {}',
    });

    it('is prefixed with "Async function"', () => {
      expect(textify(fn)).toMatch(/^Async function/);
    });

    it('includes split words from the name', () => {
      const result = textify(fn).toLowerCase();
      expect(result).toContain('fetch');
      expect(result).toContain('user');
      expect(result).toContain('profile');
    });

    it('is under 200 words', () => {
      const wordCount = textify(fn).split(/\s+/).length;
      expect(wordCount).toBeLessThanOrEqual(200);
    });
  });

  describe('generator function', () => {
    const fn = makeFunction({
      name: 'generateIds',
      params: [],
      returnType: 'Generator<number>',
      imports: [],
      exports: false,
      body: 'function* generateIds() {}',
    });

    it('is prefixed with "Generator function"', () => {
      expect(textify(fn)).toMatch(/^Generator function/);
    });
  });

  describe('whole-file synthetic function', () => {
    const fn = makeFunction({
      name: '<whole-file>',
      startLine: 1,
      endLine: 50,
      imports: ['node:fs', 'lodash'],
      body: '',
    });

    it('describes the file with its line count', () => {
      const result = textify(fn);
      expect(result).toContain('50');
      expect(result.toLowerCase()).toContain('source file');
    });
  });

  describe('output word-count guarantee across varied inputs', () => {
    const cases: Array<Partial<ExtractedFunction>> = [
      { name: 'a', params: [], body: 'function a() {}' },
      {
        name: 'reallyLongFunctionNameThatSplitsIntoManyWords',
        params: ['paramOne: string', 'paramTwo: number', 'paramThree: boolean'],
        returnType: 'Record<string, unknown>',
        imports: ['lodash', 'axios', 'express', 'jsonwebtoken', 'bcrypt'],
        exports: true,
        body: 'function reallyLongFunctionNameThatSplitsIntoManyWords() {}',
      },
    ];

    cases.forEach((overrides, idx) => {
      it(`case ${idx + 1} is under 200 words`, () => {
        const fn = makeFunction(overrides);
        const wordCount = textify(fn).split(/\s+/).length;
        expect(wordCount).toBeLessThanOrEqual(200);
      });
    });
  });

  describe('return type edge cases', () => {
    it('describes void return type as nothing', () => {
      const fn = makeFunction({ name: 'cleanup', returnType: 'void', body: 'function cleanup() {}' });
      expect(textify(fn).toLowerCase()).toContain('nothing');
    });

    it('describes array return type with "array" suffix', () => {
      const fn = makeFunction({ name: 'listItems', returnType: 'string[]', body: 'function listItems() {}' });
      expect(textify(fn).toLowerCase()).toContain('string array');
    });

    it('handles nested Promise wrapping', () => {
      const fn = makeFunction({
        name: 'fetchAll',
        returnType: 'Promise<string[]>',
        body: 'function fetchAll() {}',
      });
      const result = textify(fn).toLowerCase();
      expect(result).toContain('promise');
      expect(result).toContain('string array');
    });
  });
});
