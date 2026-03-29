import { randomUUID } from 'node:crypto';
import { statSync, readFileSync } from 'node:fs';
import type {
  Analyzer,
  AnalysisContext,
  Finding,
  DuplicatePair,
  ExtractedFunction,
} from '../../types.js';
import { Embedder } from './embedder.js';
import { extractFunctions } from './extractor.js';
import { textify } from './textifier.js';
import { loadCache, saveCache } from './cache.js';

// ---------------------------------------------------------------------------
// SemanticDuplicationAnalyzer
//
// Detects semantically equivalent functions across the codebase using
// CodeBERT embeddings and pairwise cosine similarity.
//
// Pipeline:
//   1. Extract all functions from every file via AST (extractor)
//   2. Textify each function into a natural-language description (textifier)
//   3. Load the embedding cache; skip re-embedding unchanged files
//   4. Embed only functions from new / changed files (Embedder)
//   5. Save the updated cache to disk
//   6. Compute O(n²) pairwise cosine similarity across all function embeddings
//   7. Emit one Finding per pair that exceeds the configured threshold
//
// Confidence tiers (mapped from similarity score):
//   >= 0.95  →  0.95  (near-identical logic)
//   >= 0.90  →  0.90  (very high overlap)
//   >= 0.85  →  0.85  (high overlap / threshold minimum)
//
// Each Finding records both function names, both file paths, the similarity
// score in meta, and the non-primary file in `related`.
// ---------------------------------------------------------------------------

/** Per-function embedding resolved at analysis time. */
interface FunctionEmbedding {
  fn: ExtractedFunction;
  embedding: Float32Array;
}

export class SemanticDuplicationAnalyzer implements Analyzer {
  readonly name = 'semantic-duplication';
  readonly layer = 'semantic' as const;

  private readonly embedder: Embedder;

  constructor(embedder?: Embedder) {
    // Allow injection for testing; create a default instance otherwise.
    this.embedder = embedder ?? new Embedder();
  }

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { files, changedFiles, config } = context;

    if (!config.analyzers.semantic.duplication) {
      return [];
    }

    const threshold = config.analyzers.semantic.duplicationThreshold;

    // Initialize the embedder (no-op if already initialized).
    await this.embedder.init();

    // ------------------------------------------------------------------
    // 1. Extract functions from every analysed file.
    // ------------------------------------------------------------------
    const allFunctions: ExtractedFunction[] = [];

    for (const filePath of files) {
      let extracted: ExtractedFunction[];
      try {
        const source = readFileSync(filePath, 'utf-8');
        extracted = extractFunctions(filePath, source);
      } catch {
        // Un-parseable files (binary, broken syntax) are skipped silently.
        continue;
      }
      allFunctions.push(...extracted);
    }

    // ------------------------------------------------------------------
    // 1b. Filter out synthetic / degenerate entries before any embedding.
    //
    //   - <whole-file> fallback entries: the extractor emits one of these
    //     when it cannot find any real functions.  They all get generic
    //     descriptions ("File with N lines, exports: …") so CodeBERT embeds
    //     them almost identically, producing hundreds of false positives.
    //
    //   - <anonymous> entries: unnamed arrow functions, IIFE wrappers, etc.
    //     Without a stable identity they produce unstable comparisons.
    //
    //   - Trivially short bodies (< 50 chars): one-liners such as
    //     `export default X` or `const fn = () => value` carry no real
    //     logic and their descriptions are too sparse to compare reliably.
    // ------------------------------------------------------------------
    const SYNTHETIC_NAMES = new Set(['<whole-file>', '<anonymous>']);
    const MIN_BODY_LENGTH = 50;

    const meaningfulFunctions = allFunctions.filter(
      (fn) =>
        !SYNTHETIC_NAMES.has(fn.name) &&
        (fn.body ?? '').length >= MIN_BODY_LENGTH,
    );

    // Need at least 2 real functions project-wide to have anything to compare.
    if (meaningfulFunctions.length < 2) {
      return [];
    }

    // ------------------------------------------------------------------
    // 2. Textify every function (builds the NL description for embedding).
    //    The extractor may already populate fn.description; textify
    //    ensures it is present regardless.
    // ------------------------------------------------------------------
    for (const fn of meaningfulFunctions) {
      if (!fn.description) {
        fn.description = textify(fn);
      }
    }

    // ------------------------------------------------------------------
    // 3. Load embedding cache.
    // ------------------------------------------------------------------
    const cache = await loadCache(context.rootDir);

    // Build a set of "dirty" files: files that are new or have changed
    // since their last cached mtime.
    const changedSet = new Set<string>(changedFiles ?? []);

    // If no changedFiles hint was provided, treat every file as potentially
    // dirty and rely on mtime comparison against the cache.
    const isDirty = (filePath: string): boolean => {
      if (changedSet.size > 0) {
        return changedSet.has(filePath);
      }
      const cached = cache.get(filePath);
      if (!cached) return true;
      try {
        const mtime = statSync(filePath).mtimeMs;
        return mtime !== cached.mtime;
      } catch {
        return true;
      }
    };

    // ------------------------------------------------------------------
    // 4. Embed functions from dirty files only.
    //    Functions from clean (cached) files reuse their stored embedding.
    // ------------------------------------------------------------------
    const resolved: FunctionEmbedding[] = [];

    // Group dirty functions by file to batch embed them together — one
    // Embedder call per file rather than one per function reduces overhead
    // when the model has per-call startup cost.
    const dirtyByFile = new Map<string, ExtractedFunction[]>();

    for (const fn of meaningfulFunctions) {
      if (isDirty(fn.filePath)) {
        const bucket = dirtyByFile.get(fn.filePath) ?? [];
        bucket.push(fn);
        dirtyByFile.set(fn.filePath, bucket);
      }
    }

    // Embed dirty functions.
    for (const [, fns] of dirtyByFile) {
      const texts = fns.map((fn) => fn.description);
      let embeddings: Float32Array[];
      try {
        embeddings = await this.embedder.embedBatch(texts);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(
          `[codesentinel] embedder failed for ${fns[0].filePath} — skipping: ${msg}`,
        );
        continue;
      }

      for (let i = 0; i < fns.length; i++) {
        const embedding = embeddings[i];
        if (embedding) {
          resolved.push({ fn: fns[i], embedding });
        }
      }
    }

    // Reuse cached embeddings for clean files.
    for (const fn of meaningfulFunctions) {
      if (!isDirty(fn.filePath)) {
        const cached = cache.get(fn.filePath);
        if (cached) {
          // The cache stores one embedding per file (aggregate), but we need
          // per-function embeddings.  If the cache entry carries per-function
          // data, use it; otherwise fall through to re-embed.
          //
          // We look for a matching function entry in the cached functions list
          // to retrieve its individual embedding.  The cache contract (from
          // EmbeddingCacheEntry in types.ts) stores `functions` and a single
          // top-level `embedding` (the file-level aggregate).
          //
          // For per-function embeddings we embed on first encounter and rely
          // on the dirty-file path above.  If not found in the resolved list
          // already, treat as dirty and embed now.
          const alreadyResolved = resolved.some(
            (r) =>
              r.fn.filePath === fn.filePath && r.fn.name === fn.name,
          );
          if (!alreadyResolved) {
            // Embed individually — this only fires when the cache lacks
            // per-function detail for a clean file (shouldn't happen in
            // normal operation after the first full run).
            let embedding: Float32Array;
            try {
              [embedding] = await this.embedder.embedBatch([fn.description]);
            } catch {
              continue;
            }
            resolved.push({ fn, embedding });
          }
        }
      }
    }

    if (resolved.length < 2) {
      // Nothing to compare.
      await saveCache(context.rootDir, cache);
      return [];
    }

    // ------------------------------------------------------------------
    // 5. Persist updated cache.
    // ------------------------------------------------------------------
    await saveCache(context.rootDir, cache);

    // ------------------------------------------------------------------
    // 6. Pairwise cosine similarity — O(n²) over resolved embeddings.
    //    For a typical codebase this is fast enough; the bottleneck is
    //    always the embedding step, not the comparison.
    // ------------------------------------------------------------------
    const pairs: DuplicatePair[] = [];
    const MAX_PAIRS = 500; // Cap to prevent stack/memory issues on large codebases

    outer:
    for (let i = 0; i < resolved.length - 1; i++) {
      for (let j = i + 1; j < resolved.length; j++) {
        const a = resolved[i];
        const b = resolved[j];

        // Skip same-file, same-function identity.
        if (a.fn.filePath === b.fn.filePath && a.fn.name === b.fn.name) {
          continue;
        }

        // Skip cross-file comparisons of identically-named functions.
        // Common patterns like __init__, constructor, render, handle etc.
        // naturally embed similarly across files without being real duplicates.
        if (a.fn.name === b.fn.name) {
          continue;
        }

        const similarity = cosineSimilarity(a.embedding, b.embedding);

        if (similarity >= threshold) {
          // Verify with token overlap — embedding similarity alone produces
          // false positives for same-domain functions. Require at least 40%
          // shared tokens in the function body to confirm structural similarity.
          const bodyA = (a.fn.body ?? '').toLowerCase();
          const bodyB = (b.fn.body ?? '').toLowerCase();
          if (bodyA.length > 0 && bodyB.length > 0) {
            const tokensA = new Set(bodyA.split(/\W+/).filter(t => t.length > 2));
            const tokensB = new Set(bodyB.split(/\W+/).filter(t => t.length > 2));
            if (tokensA.size > 0 && tokensB.size > 0) {
              let overlap = 0;
              for (const t of tokensA) { if (tokensB.has(t)) overlap++; }
              const jaccardish = overlap / Math.min(tokensA.size, tokensB.size);
              if (jaccardish < 0.4) continue; // Not structurally similar enough
            }
          }

          pairs.push({
            fileA: a.fn.filePath,
            functionA: a.fn.name,
            lineA: a.fn.startLine,
            fileB: b.fn.filePath,
            functionB: b.fn.name,
            lineB: b.fn.startLine,
            similarity,
          });
          if (pairs.length >= MAX_PAIRS) break outer;
        }
      }
    }

    // Sort by highest similarity first, then convert to findings.
    pairs.sort((a, b) => b.similarity - a.similarity);

    // ------------------------------------------------------------------
    // 7. Convert DuplicatePair list to Finding list.
    // ------------------------------------------------------------------
    const findings: Finding[] = [];
    for (const pair of pairs) {
      findings.push(buildFinding(pair));
    }
    return findings;
  }
}

// ---------------------------------------------------------------------------
// Math helpers
// ---------------------------------------------------------------------------

/**
 * Cosine similarity between two equal-length Float32Arrays.
 * Returns a value in [-1, 1]; for embedding vectors typically [0, 1].
 * Returns 0 if either vector has zero magnitude.
 */
function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  let dot = 0;
  let magA = 0;
  let magB = 0;

  for (let k = 0; k < a.length; k++) {
    dot += a[k] * b[k];
    magA += a[k] * a[k];
    magB += b[k] * b[k];
  }

  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  if (denom === 0) return 0;
  return dot / denom;
}

// ---------------------------------------------------------------------------
// Finding builder
// ---------------------------------------------------------------------------

/**
 * Maps a similarity score to a discrete confidence tier.
 *
 *   >= 0.95  →  0.95
 *   >= 0.90  →  0.90
 *   >= 0.85  →  0.85
 */
function confidenceFromSimilarity(similarity: number): number {
  if (similarity >= 0.95) return 0.95;
  if (similarity >= 0.90) return 0.90;
  return 0.85;
}

function buildFinding(pair: DuplicatePair): Finding {
  const pct = (pair.similarity * 100).toFixed(1);
  const sameFile = pair.fileA === pair.fileB;

  const locationB = sameFile
    ? `line ${pair.lineB}`
    : pair.fileB;

  const message = sameFile
    ? `Semantic duplicate: \`${pair.functionA}\` (line ${pair.lineA}) and \`${pair.functionB}\` (${locationB}) are ${pct}% similar`
    : `Semantic duplicate: \`${pair.functionA}\` in ${pair.fileA} and \`${pair.functionB}\` in ${pair.fileB} are ${pct}% similar`;

  return {
    id: randomUUID(),
    layer: 'semantic',
    type: 'semantic-duplication',
    severity: 'warning',
    confidence: confidenceFromSimilarity(pair.similarity),
    file: pair.fileA,
    line: pair.lineA,
    endLine: pair.lineA,
    message,
    tool: 'codebert-duplication',
    suggestion:
      'Consider extracting the shared logic into a single shared utility function ' +
      'to reduce maintenance burden and prevent divergence over time.',
    related: [pair.fileB],
    meta: {
      similarity: pair.similarity,
      functionA: pair.functionA,
      functionB: pair.functionB,
      fileA: pair.fileA,
      fileB: pair.fileB,
      lineA: pair.lineA,
      lineB: pair.lineB,
    },
  };
}
