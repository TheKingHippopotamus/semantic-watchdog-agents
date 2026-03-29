// ============================================================
// CodeSentinel — Intent Recovery Module
// Layer: semantic | Tool: codebert-intent
// ============================================================
//
// Runs AFTER static dead-code analysis.  For each orphan file identified
// by the static layer (files that are unreachable from any entry point and
// have no importers), this module:
//
//   1. Embeds the orphan file via CodeBERT (whole-file summary).
//   2. Embeds (or reuses) all non-orphan files in the corpus.
//   3. Finds K=5 nearest neighbours among non-orphan files by cosine
//      similarity.
//   4. Groups nearest neighbours by directory to identify the most likely
//      integration point.
//   5. Emits one Finding per orphan with a human-readable message:
//        "Orphan file X is semantically similar to [Y, Z]. It may belong
//         in the same module or should be wired into [nearest entry point]."
//
// Orphan files are injected via:
//   - context.meta.orphanFiles (string[]) — set by the pipeline orchestrator
//     before running semantic analysis (preferred, stateless), OR
//   - analyzer.setOrphans(paths) — explicit setter for manual pipeline control
//
// Confidence range: 0.70–0.80 (suggestion, not assertion).
// ============================================================

import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { basename, dirname, extname, relative } from 'node:path';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';
import { Embedder } from './embedder.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Number of nearest neighbours to retrieve per orphan. */
const K_NEAREST = 5;

/** Confidence for an orphan whose top-1 similarity is 1.0 (identical). */
const CONFIDENCE_HIGH = 0.80;

/** Confidence floor for an orphan with similarity 0.0. */
const CONFIDENCE_LOW = 0.70;

/** Maximum source bytes read per file when building the NL summary. */
const MAX_READ_BYTES = 8_000;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface FileEmbedding {
  filePath: string;
  embedding: Float32Array;
}

interface NearestNeighbour {
  filePath: string;
  similarity: number;
}

// ---------------------------------------------------------------------------
// Exported analyzer
// ---------------------------------------------------------------------------

export class IntentAnalyzer implements Analyzer {
  readonly name = 'intent-recovery';
  readonly layer = 'semantic' as const;

  private readonly embedder: Embedder;

  /**
   * Orphan file paths injected from outside (typically by the static
   * dead-code analyzer which identifies unreachable files first).
   *
   * Populated via setOrphans() or via context.meta.orphanFiles at analysis
   * time.  context.meta takes precedence when both are set.
   */
  private injectedOrphans: string[] = [];

  constructor(embedder?: Embedder) {
    this.embedder = embedder ?? new Embedder();
  }

  /**
   * Inject orphan file paths from the static dead-code analysis stage.
   *
   * Call this before analyze() when orchestrating the pipeline manually.
   * context.meta.orphanFiles is preferred when using the standard pipeline
   * because it keeps the interface stateless.
   */
  setOrphans(paths: string[]): void {
    this.injectedOrphans = [...paths];
  }

  /**
   * Implements the Analyzer interface.
   *
   * Reads orphan paths from context.meta.orphanFiles (preferred) or from the
   * list injected via setOrphans().  For each orphan, finds K=5 nearest
   * neighbours among non-orphan corpus files and emits an intent-recovery
   * Finding.
   */
  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { files, config, rootDir } = context;

    if (!config.analyzers.semantic.intentRecovery) {
      return [];
    }

    // ── Resolve orphan list ──────────────────────────────────────────────────
    const orphanPaths = resolveOrphans(context, this.injectedOrphans);

    if (orphanPaths.length === 0) {
      return [];
    }

    // Guard against stale orphan paths that are not in the current file list.
    const fileSet = new Set(files);
    const validOrphans = orphanPaths.filter((p) => fileSet.has(p));

    if (validOrphans.length === 0) {
      return [];
    }

    // Non-orphan files form the corpus we search for nearest neighbours.
    const orphanSet = new Set(validOrphans);
    const nonOrphanFiles = files.filter((f) => !orphanSet.has(f));

    if (nonOrphanFiles.length === 0) {
      // Entire codebase is orphaned — no neighbours to suggest.
      return [];
    }

    // ── Initialise embedder ──────────────────────────────────────────────────
    try {
      await this.embedder.init();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[codesentinel/intent] embedder failed — skipping intent recovery: ${msg}`);
      return [];
    }

    // ── Embed non-orphan corpus ──────────────────────────────────────────────
    const nonOrphanEmbeddings = await embedFilesAsync(nonOrphanFiles, this.embedder);

    if (nonOrphanEmbeddings.length === 0) {
      return [];
    }

    // ── Process each orphan ──────────────────────────────────────────────────
    const findings: Finding[] = [];

    for (const orphanPath of validOrphans) {
      let orphanEmbedding: Float32Array;
      try {
        const text = await buildFileSummaryText(orphanPath);
        const vec = await this.embedder.embed(text);
        if (!vec || vec.length === 0) continue;
        orphanEmbedding = vec;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(`[codesentinel/intent] failed to embed ${orphanPath} — skipping: ${msg}`);
        continue;
      }

      // K nearest neighbours from the non-orphan corpus.
      const neighbours = findKNearest(orphanEmbedding, nonOrphanEmbeddings, K_NEAREST);
      if (neighbours.length === 0) continue;

      findings.push(buildFinding(orphanPath, neighbours, rootDir));
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// Orphan resolver
// ---------------------------------------------------------------------------

/**
 * Resolve the list of orphan files from the analysis context or the injected
 * list set via setOrphans().
 *
 * Priority:
 *   1. context.meta.orphanFiles  (passed through the standard pipeline)
 *   2. injectedOrphans           (set via setOrphans() before analyze())
 */
function resolveOrphans(context: AnalysisContext, injectedOrphans: string[]): string[] {
  // AnalysisContext does not formally declare a meta field, but pipeline
  // orchestrators may attach one at runtime.  We access it via a safe cast
  // rather than touching the shared type definition.
  const ctx = context as AnalysisContext & { meta?: Record<string, unknown> };
  const meta = ctx.meta;

  if (meta && Array.isArray(meta['orphanFiles'])) {
    const fromMeta = (meta['orphanFiles'] as unknown[]).filter(
      (v): v is string => typeof v === 'string',
    );
    if (fromMeta.length > 0) return fromMeta;
  }

  return injectedOrphans;
}

// ---------------------------------------------------------------------------
// Embedding helpers
// ---------------------------------------------------------------------------

/**
 * Embed a list of files by building NL summaries first, then batch-embedding.
 *
 * Files that fail to summarise or embed are silently skipped — a partial
 * corpus is better than aborting the entire analysis.
 */
async function embedFilesAsync(
  filePaths: string[],
  embedder: Embedder,
): Promise<FileEmbedding[]> {
  const summaries: { filePath: string; text: string }[] = [];

  for (const filePath of filePaths) {
    try {
      const text = await buildFileSummaryText(filePath);
      summaries.push({ filePath, text });
    } catch {
      continue;
    }
  }

  if (summaries.length === 0) return [];

  let embeddings: Float32Array[];
  try {
    embeddings = await embedder.embedBatch(summaries.map((s) => s.text));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[codesentinel/intent] batch embed failed: ${msg}`);
    return [];
  }

  const results: FileEmbedding[] = [];
  for (let i = 0; i < summaries.length; i++) {
    const embedding = embeddings[i];
    if (embedding && embedding.length > 0) {
      results.push({ filePath: summaries[i].filePath, embedding });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// K-nearest neighbour search
// ---------------------------------------------------------------------------

/**
 * Find the K nearest neighbours to `query` from `corpus` by cosine similarity.
 *
 * Runs a linear scan — O(n × d).  For corpus sizes typical in a single
 * codebase (hundreds to a few thousand files) this is faster than the
 * overhead of building a FAISS/HNSW index.
 *
 * @returns Up to K neighbours sorted by descending similarity.
 */
function findKNearest(
  query: Float32Array,
  corpus: FileEmbedding[],
  k: number,
): NearestNeighbour[] {
  const scored: NearestNeighbour[] = corpus.map(({ filePath, embedding }) => ({
    filePath,
    similarity: cosineSimilarity(query, embedding),
  }));

  scored.sort((a, b) => b.similarity - a.similarity);
  return scored.slice(0, k);
}

// ---------------------------------------------------------------------------
// Finding builder
// ---------------------------------------------------------------------------

/**
 * Build a Finding for an orphan file given its K nearest neighbours.
 *
 * Message format:
 *   "Orphan file X is semantically similar to [Y, Z]. It may belong in the
 *    same module or should be wired into [nearest entry point]."
 */
function buildFinding(
  orphanPath: string,
  neighbours: NearestNeighbour[],
  rootDir: string,
): Finding {
  const orphanRel = relative(rootDir, orphanPath);
  const topSimilarity = neighbours[0]?.similarity ?? 0;
  const confidence = scoreConfidence(topSimilarity);

  // Identify the integration directory: the directory that appears most often
  // among the K nearest neighbours (plurality vote, tie-broken alphabetically).
  const dirVotes = new Map<string, number>();
  for (const { filePath } of neighbours) {
    const dir = dirname(relative(rootDir, filePath));
    dirVotes.set(dir, (dirVotes.get(dir) ?? 0) + 1);
  }

  let nearestEntryDir = '.';
  let maxVotes = 0;
  for (const [dir, votes] of dirVotes) {
    if (votes > maxVotes || (votes === maxVotes && dir < nearestEntryDir)) {
      maxVotes = votes;
      nearestEntryDir = dir;
    }
  }

  // Short list of neighbours for the message (name + similarity %).
  const neighbourNames = neighbours
    .slice(0, 3)
    .map(({ filePath, similarity }) => {
      const rel = relative(rootDir, filePath);
      const pct = (similarity * 100).toFixed(0);
      return `${rel} (${pct}%)`;
    })
    .join(', ');

  const message =
    `Orphan file \`${orphanRel}\` is semantically similar to [${neighbourNames}]. ` +
    `It may belong in the same module or should be wired into \`${nearestEntryDir}\`.`;

  return {
    id: randomUUID(),
    layer: 'semantic',
    type: 'orphan-intent-recovery',
    severity: 'info',
    confidence,
    file: orphanPath,
    message,
    tool: 'codebert-intent',
    suggestion:
      `Consider moving \`${orphanRel}\` into \`${nearestEntryDir}\` and importing it ` +
      `from one of its semantic neighbours: ` +
      `[${neighbours.slice(0, 3).map((n) => relative(rootDir, n.filePath)).join(', ')}]. ` +
      `Alternatively, if this file is intentionally standalone, add it as an entry ` +
      `point or delete it if the functionality is already covered elsewhere.`,
    related: neighbours.map((n) => n.filePath),
    meta: {
      orphanFile: orphanPath,
      nearestNeighbours: neighbours.map((n) => ({
        filePath: n.filePath,
        similarity: n.similarity,
      })),
      nearestEntryDir,
      topSimilarity,
    },
  };
}

// ---------------------------------------------------------------------------
// Confidence scoring
// ---------------------------------------------------------------------------

/**
 * Map the top-1 cosine similarity (0–1) onto confidence ∈ [0.70, 0.80].
 *
 * A high similarity (the orphan is near-identical to a corpus file)
 * → confidence 0.80 (we are confident it belongs there).
 * A low similarity (weakly related) → confidence 0.70 (it's a suggestion).
 */
function scoreConfidence(topSimilarity: number): number {
  const sim = Math.max(0, Math.min(1, topSimilarity));
  return CONFIDENCE_LOW + (CONFIDENCE_HIGH - CONFIDENCE_LOW) * sim;
}

// ---------------------------------------------------------------------------
// File summary builder
// ---------------------------------------------------------------------------

/**
 * Build a natural-language whole-file description suitable for embedding.
 *
 * Uses the same lightweight regex-based extractor as drift.ts — no dependency
 * on extractor.ts or textifier.ts (which may not yet exist).
 */
async function buildFileSummaryText(filePath: string): Promise<string> {
  const name = basename(filePath, extname(filePath));
  const lang = extname(filePath).replace('.', '').toUpperCase() || 'UNKNOWN';

  let source = '';
  try {
    const raw = await readFile(filePath, 'utf-8');
    source = raw.length > MAX_READ_BYTES ? raw.slice(0, MAX_READ_BYTES) : raw;
  } catch {
    return `File: ${name}. Language: ${lang}.`;
  }

  const parts: string[] = [`File: ${name}.`, `Language: ${lang}.`];

  const exports = extractExportedNames(source);
  if (exports.length > 0) parts.push(`Exports: ${exports.slice(0, 10).join(', ')}.`);

  const fns = extractFunctionNames(source);
  if (fns.length > 0) parts.push(`Functions: ${fns.slice(0, 10).join(', ')}.`);

  const classes = extractClassNames(source);
  if (classes.length > 0) parts.push(`Classes: ${classes.slice(0, 5).join(', ')}.`);

  const imports = extractImportedModules(source);
  if (imports.length > 0) parts.push(`Imports: ${imports.slice(0, 8).join(', ')}.`);

  const comment = extractLeadingComment(source);
  if (comment.length > 0) parts.push(`Description: ${comment.slice(0, 200)}.`);

  return parts.join(' ');
}

// ---------------------------------------------------------------------------
// Lightweight source-code heuristic extractors (regex, language-agnostic)
// ---------------------------------------------------------------------------

function extractExportedNames(source: string): string[] {
  const names: string[] = [];
  const tsRe =
    /export\s+(?:default\s+)?(?:const|function|class|type|interface|enum|abstract\s+class)\s+([A-Za-z_$][\w$]*)/g;
  let m: RegExpExecArray | null;
  while ((m = tsRe.exec(source)) !== null) names.push(m[1]);
  const pyRe = /^(?:def|class)\s+([A-Za-z][A-Za-z0-9_]*)/gm;
  while ((m = pyRe.exec(source)) !== null) {
    if (!m[1].startsWith('_')) names.push(m[1]);
  }
  return [...new Set(names)];
}

function extractFunctionNames(source: string): string[] {
  const names: string[] = [];
  const patterns: RegExp[] = [
    /function\s+([A-Za-z_$][\w$]*)\s*\(/g,
    /const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\(/g,
    /def\s+([A-Za-z_][\w]*)\s*\(/g,
    /func\s+(?:\([^)]+\)\s+)?([A-Za-z_][\w]*)\s*\(/g,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null) names.push(m[1]);
  }
  return [...new Set(names)];
}

function extractClassNames(source: string): string[] {
  const names: string[] = [];
  const re = /class\s+([A-Za-z_$][\w$]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) names.push(m[1]);
  return [...new Set(names)];
}

function extractImportedModules(source: string): string[] {
  const mods: string[] = [];
  const esRe = /from\s+['"]([^'"]+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = esRe.exec(source)) !== null) {
    const seg = m[1].split('/').pop() ?? m[1];
    mods.push(seg.replace(/\.[^.]+$/, ''));
  }
  const pyRe = /^(?:import|from)\s+([\w.]+)/gm;
  while ((m = pyRe.exec(source)) !== null) mods.push(m[1].split('.')[0]);
  return [...new Set(mods)].filter(Boolean);
}

function extractLeadingComment(source: string): string {
  const trimmed = source.trimStart();
  if (trimmed.startsWith('/*')) {
    const end = trimmed.indexOf('*/');
    if (end !== -1) {
      return trimmed.slice(2, end).replace(/^\s*\*+\s?/gm, '').replace(/\n+/g, ' ').trim();
    }
  }
  const lineRe = /^(?:\/\/|#)\s?(.*)/;
  const commentLines: string[] = [];
  for (const line of trimmed.split('\n')) {
    const match = lineRe.exec(line.trimStart());
    if (match) commentLines.push(match[1]);
    else break;
  }
  return commentLines.join(' ').trim();
}

// ---------------------------------------------------------------------------
// Math helpers
// ---------------------------------------------------------------------------

/**
 * Cosine similarity between two Float32Arrays.
 *
 * Both inputs are assumed to be L2-normalised (Embedder guarantees this), so
 * this is effectively a dot product.  The full formula is computed to guard
 * against any vector that loses unit length.
 */
function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  if (a.length !== b.length || a.length === 0) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? 0 : Math.max(-1, Math.min(1, dot / denom));
}
