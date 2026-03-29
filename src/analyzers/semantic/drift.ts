// ============================================================
// CodeSentinel — Structural Drift Detector
// Layer: semantic | Tool: codebert-drift
// ============================================================
//
// Detects files that have semantically drifted away from the directory they
// belong in.  A file "drifts" when its embedding clusters with files from a
// different directory than the one it currently lives in.
//
// Pipeline:
//   1. Read each source file and build a natural-language whole-file summary
//      (not function-level — one description per file).
//   2. Batch-embed all summaries via CodeBERT (file-level embeddings).
//   3. Cluster the embedding vectors using Lloyd's k-means with k-means++
//      initialisation.  K = clamp(floor(√n), 2, MAX_K).
//   4. For every cluster, determine its "dominant directory" — the directory
//      that the plurality of cluster members live in.
//   5. Flag any file whose cluster's dominant directory differs from the
//      file's actual parent directory.
//
// Confidence range: 0.75–0.85 (clustering is heuristic; the result is a
// suggestion, not a structural assertion).
//
// Example: file in src/utils/ clusters with src/auth/ files →
//   DriftFinding with suggestedDir: src/auth in the suggestion field.
// ============================================================

import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { basename, dirname, extname, join, relative } from 'node:path';
import type { Analyzer, AnalysisContext, Finding, DriftFinding } from '../../types.js';
import { Embedder } from './embedder.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Skip drift analysis if fewer than this many files are present. */
const MIN_FILES_FOR_DRIFT = 4;

/** Upper bound on the number of k-means clusters. */
const MAX_K = 20;

/** Maximum Lloyd's algorithm iterations per k-means run. */
const KMEANS_MAX_ITER = 100;

/**
 * Number of independent k-means restarts.
 * The run with the lowest inertia (Σ squared cosine distances) is kept.
 */
const KMEANS_RUNS = 3;

/** Confidence for a file very close to its cluster centroid (distance ≈ 0). */
const CONFIDENCE_HIGH = 0.85;

/** Confidence for a file far from its cluster centroid (distance ≈ 1). */
const CONFIDENCE_LOW = 0.75;

/** Maximum source bytes read per file when building the NL summary. */
const MAX_READ_BYTES = 8_000;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface FileSummary {
  filePath: string;
  /** Relative path from rootDir (POSIX separators). */
  relPath: string;
  /** Relative directory from rootDir (e.g. "src/auth"). Empty string for root. */
  dirPath: string;
  /** Top-level directory label used for cluster majority voting. */
  dirLabel: string;
  /** Natural-language text fed to the embedder. */
  summary: string;
}

interface ClusterAssignment {
  summary: FileSummary;
  clusterId: number;
  /** Cosine distance to the assigned centroid (1 − similarity). */
  distanceToCentroid: number;
}

interface DominantDir {
  dirLabel: string;
  dirPath: string;
  voteCount: number;
}

// ---------------------------------------------------------------------------
// Exported analyzer
// ---------------------------------------------------------------------------

export class DriftAnalyzer implements Analyzer {
  readonly name = 'drift';
  readonly layer = 'semantic' as const;

  private readonly embedder: Embedder;

  constructor(embedder?: Embedder) {
    this.embedder = embedder ?? new Embedder();
  }

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const { files, config, rootDir } = context;

    if (!config.analyzers.semantic.drift) {
      return [];
    }

    // ── 1. Build whole-file NL summaries ─────────────────────────────────────
    // Each summary encodes the file's API surface (exports, functions, classes,
    // imports, leading docstring) — not its implementation and not its
    // directory, so the embedding reflects semantic content only.
    const summaries = await buildFileSummaries(files, rootDir);

    if (summaries.length < MIN_FILES_FOR_DRIFT) {
      return [];
    }

    // ── 2. Embed all summaries one at a time ─────────────────────────────────
    // The @huggingface/transformers feature-extraction pipeline with
    // pooling:'mean' returns shape [1, hidden] per call, not [batch, seq, hidden]
    // when called with a batch array. Embedding per-item avoids the shape mismatch.
    let embeddings: Float32Array[];
    try {
      await this.embedder.init();
      const summaryTexts = summaries.map((s) => s.summary);
      embeddings = await this.embedder.embedBatch(summaryTexts);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[codesentinel/drift] embedder failed — skipping drift analysis: ${msg}`);
      return [];
    }

    if (embeddings.length !== summaries.length) {
      console.warn(
        `[codesentinel/drift] embedding/summary count mismatch ` +
          `(${embeddings.length} vs ${summaries.length}) — skipping`,
      );
      return [];
    }

    // ── 3. K-means clustering ────────────────────────────────────────────────
    // K grows sub-linearly with corpus size: K = clamp(floor(√n), 2, MAX_K).
    // K must never exceed the number of files — kMeans++ cannot pick more
    // unique seed centroids than there are data points.
    const k = Math.max(2, Math.min(MAX_K, Math.min(summaries.length, Math.floor(Math.sqrt(summaries.length)))));
    const labels = kMeans(embeddings, k, KMEANS_MAX_ITER, KMEANS_RUNS);

    // ── 4. Assign files to clusters with distance-to-centroid ────────────────
    const centroids = computeCentroids(embeddings, labels, k);
    const assignments: ClusterAssignment[] = summaries.map((summary, idx) => {
      const centroid = centroids[labels[idx]];
      const sim = cosineSimilarity(embeddings[idx], centroid);
      return { summary, clusterId: labels[idx], distanceToCentroid: 1 - sim };
    });

    // ── 5. Determine dominant directory per cluster ──────────────────────────
    const dominantDirByCluster = computeDominantDirs(assignments, k);

    // ── 6. Flag drifted files ────────────────────────────────────────────────
    const findings: Finding[] = [];

    for (const assignment of assignments) {
      const { summary, clusterId, distanceToCentroid } = assignment;
      const dominant = dominantDirByCluster[clusterId];

      if (!dominant) continue;

      // A file has drifted when it lives in a different directory than the one
      // that dominates its embedding cluster.
      // Example: src/utils/jwtHelper.ts whose cluster is dominated by src/auth/
      if (summary.dirLabel === dominant.dirLabel) continue;

      const confidence = scoreConfidence(distanceToCentroid);
      if (confidence < config.confidenceThreshold) continue;

      // Collect the closest cluster peers as supporting evidence.
      const clusterPeers = assignments
        .filter((a) => a.clusterId === clusterId && a.summary.filePath !== summary.filePath)
        .sort((a, b) => a.distanceToCentroid - b.distanceToCentroid)
        .slice(0, 5)
        .map((a) => a.summary.filePath);

      // suggestedDir is the absolute path to the dominant directory so callers
      // can use it directly in shell commands, IDE "move" actions, etc.
      const suggestedAbsDir = join(rootDir, dominant.dirPath);

      const driftFinding: DriftFinding = {
        file: summary.filePath,
        currentDir: summary.dirPath || '.',
        suggestedDir: dominant.dirPath,
        nearestCluster: clusterPeers,
        confidence,
      };

      const peerNames = clusterPeers
        .slice(0, 3)
        .map((p) => relative(rootDir, p))
        .join(', ');

      findings.push({
        id: randomUUID(),
        layer: 'semantic',
        type: 'structural-drift',
        severity: 'info',
        confidence,
        file: summary.filePath,
        message:
          `Structural drift: \`${relative(rootDir, summary.filePath)}\` lives in ` +
          `\`${summary.dirPath || '.'}\` but clusters with \`${dominant.dirPath}\` files` +
          (peerNames ? ` (e.g. ${peerNames})` : '') +
          `. Consider moving it to \`${dominant.dirPath}\`.`,
        tool: 'codebert-drift',
        suggestion:
          `Suggested directory: ${suggestedAbsDir}. ` +
          `Nearest cluster: [${clusterPeers.map((p) => relative(rootDir, p)).join(', ')}].`,
        related: clusterPeers,
        meta: {
          driftFinding,
          clusterId,
          distanceToCentroid,
          dominantDirLabel: dominant.dirLabel,
          currentDir: summary.dirPath || '.',
          suggestedDir: dominant.dirPath,
        },
      });
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// File summary builder
// ---------------------------------------------------------------------------

/**
 * Build a FileSummary for each file.  Files that cannot be read are silently
 * skipped — the clustering will still run on whatever is readable.
 */
async function buildFileSummaries(
  files: string[],
  rootDir: string,
): Promise<FileSummary[]> {
  const results: FileSummary[] = [];

  for (const filePath of files) {
    try {
      const relPath = relative(rootDir, filePath).replace(/\\/g, '/');
      const dirRaw = dirname(relPath);
      const dirPath = dirRaw === '.' ? '' : dirRaw;
      const dirLabel = dirPath.split('/')[0] ?? '';
      const summary = await buildFileSummaryText(filePath);
      results.push({ filePath, relPath, dirPath, dirLabel, summary });
    } catch {
      continue;
    }
  }

  return results;
}

/**
 * Build a natural-language whole-file description suitable for embedding.
 *
 * The description encodes the file's API surface and stated purpose, not its
 * implementation details.  Directory context is intentionally excluded so
 * that the embedding reflects semantic content rather than location — if we
 * included "src/auth" in the summary, the clustering would just reproduce the
 * existing directory structure, defeating the purpose.
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
// K-means clustering (Lloyd's algorithm with k-means++ initialisation)
// ---------------------------------------------------------------------------

/**
 * Run k-means on an array of unit-normalised embedding vectors.
 *
 * @param vectors   All embedding vectors — must be the same dimension.
 * @param k         Number of clusters.
 * @param maxIter   Maximum Lloyd's iterations per run.
 * @param runs      Independent restarts; the run with lowest inertia wins.
 * @returns         Cluster labels (0 … k-1) for each input vector.
 */
function kMeans(
  vectors: Float32Array[],
  k: number,
  maxIter: number,
  runs: number,
): number[] {
  const n = vectors.length;

  // Safety: k cannot exceed the number of data points.
  // kMeans++ cannot pick more unique seeds than there are vectors.
  const effectiveK = Math.min(k, n);

  let bestLabels: number[] = new Array<number>(n).fill(0);
  let bestInertia = Infinity;

  if (n === 0 || effectiveK === 0) return bestLabels;

  const dims = vectors[0].length;

  for (let run = 0; run < runs; run++) {
    const centroids = kMeansPlusPlusInit(vectors, effectiveK);
    const labels: number[] = new Array<number>(n).fill(0);

    for (let iter = 0; iter < maxIter; iter++) {
      // Assignment step: assign each vector to its nearest centroid.
      let changed = false;
      for (let i = 0; i < n; i++) {
        const nearest = nearestCentroidIdx(vectors[i], centroids);
        if (nearest !== labels[i]) {
          labels[i] = nearest;
          changed = true;
        }
      }
      if (!changed) break; // Converged.

      // Update step: recompute centroids as L2-normalised means of members.
      // Pass current centroids so empty clusters can retain their position.
      const updated = recomputeCentroids(vectors, labels, effectiveK, dims, centroids);
      for (let c = 0; c < effectiveK; c++) centroids[c] = updated[c];
    }

    // Inertia = Σ (1 − cosine_similarity)² across all assignments.
    let inertia = 0;
    for (let i = 0; i < n; i++) {
      const sim = cosineSimilarity(vectors[i], centroids[labels[i]]);
      inertia += (1 - sim) * (1 - sim);
    }

    if (inertia < bestInertia) {
      bestInertia = inertia;
      bestLabels = [...labels];
    }
  }

  return bestLabels;
}

/**
 * K-means++ initialisation.
 *
 * Selects initial centroids with probability proportional to squared cosine
 * distance from the nearest already-chosen centroid.  This spreads seeds
 * across the embedding space for faster, more stable convergence.
 *
 * Time: O(k × n × d) — acceptable for the hundreds-to-thousands file range
 * typical of a codebase.
 */
function kMeansPlusPlusInit(vectors: Float32Array[], k: number): Float32Array[] {
  const n = vectors.length;
  const centroids: Float32Array[] = [];

  // First centroid: uniform random.
  centroids.push(copyVec(vectors[Math.floor(Math.random() * n)]));

  for (let c = 1; c < k; c++) {
    const distances = new Float64Array(n);
    let totalDist = 0;

    for (let i = 0; i < n; i++) {
      let minDist = Infinity;
      for (const centroid of centroids) {
        const sim = cosineSimilarity(vectors[i], centroid);
        const d = (1 - sim) * (1 - sim);
        if (d < minDist) minDist = d;
      }
      distances[i] = minDist;
      totalDist += minDist;
    }

    if (totalDist === 0) {
      // All points coincide; fall back to uniform random.
      centroids.push(copyVec(vectors[Math.floor(Math.random() * n)]));
      continue;
    }

    // Sample proportional to squared distance.
    const threshold = Math.random() * totalDist;
    let cumulative = 0;
    let chosen = n - 1;
    for (let i = 0; i < n; i++) {
      cumulative += distances[i];
      if (cumulative >= threshold) {
        chosen = i;
        break;
      }
    }
    centroids.push(copyVec(vectors[chosen]));
  }

  return centroids;
}

/** Index of the centroid with the highest cosine similarity to `vec`. */
function nearestCentroidIdx(vec: Float32Array, centroids: Float32Array[]): number {
  let bestIdx = 0;
  let bestSim = -Infinity;
  for (let c = 0; c < centroids.length; c++) {
    const sim = cosineSimilarity(vec, centroids[c]);
    if (sim > bestSim) {
      bestSim = sim;
      bestIdx = c;
    }
  }
  return bestIdx;
}

/**
 * Recompute k centroids as the L2-normalised mean of member vectors.
 *
 * @param prevCentroids  The centroids from the previous iteration, used to
 *                       retain position for any cluster that lost all members.
 *                       Empty clusters retain their previous centroid to avoid
 *                       zero-vector centroids that would corrupt cosine maths.
 */
function recomputeCentroids(
  vectors: Float32Array[],
  labels: number[],
  k: number,
  dims: number,
  prevCentroids?: Float32Array[],
): Float32Array[] {
  const sums: Float32Array[] = Array.from({ length: k }, () => new Float32Array(dims));
  const counts: number[] = new Array<number>(k).fill(0);

  for (let i = 0; i < vectors.length; i++) {
    const c = labels[i];
    counts[c]++;
    for (let d = 0; d < dims; d++) sums[c][d] += vectors[i][d];
  }

  return sums.map((sum, c) => {
    if (counts[c] === 0) {
      // Empty cluster: keep the previous centroid so it does not collapse to
      // a zero vector (which would make cosineSimilarity return 0 for all
      // members and corrupt subsequent assignment and inertia calculations).
      return prevCentroids?.[c] ?? sum;
    }
    for (let d = 0; d < sum.length; d++) sum[d] /= counts[c];
    return l2Normalize(sum);
  });
}

/**
 * Compute the final centroid array from a converged label assignment.
 * Delegates to recomputeCentroids — called once after k-means finishes.
 */
function computeCentroids(
  vectors: Float32Array[],
  labels: number[],
  k: number,
): Float32Array[] {
  if (vectors.length === 0) return [];
  return recomputeCentroids(vectors, labels, k, vectors[0].length);
}

// ---------------------------------------------------------------------------
// Dominant-directory computation
// ---------------------------------------------------------------------------

/**
 * For each cluster, identify the directory that the plurality of member files
 * live in.  Ties are broken by lexicographically smaller directory path so
 * the result is deterministic across runs.
 *
 * Returns an array of length k; entries for empty clusters are null.
 */
function computeDominantDirs(
  assignments: ClusterAssignment[],
  k: number,
): (DominantDir | null)[] {
  const result: (DominantDir | null)[] = new Array(k).fill(null);

  for (let c = 0; c < k; c++) {
    const members = assignments.filter((a) => a.clusterId === c);
    if (members.length === 0) continue;

    const votes = new Map<string, { dirLabel: string; dirPath: string; count: number }>();
    for (const member of members) {
      const key = member.summary.dirPath || '.';
      const existing = votes.get(key);
      if (existing) {
        existing.count++;
      } else {
        votes.set(key, {
          dirLabel: member.summary.dirLabel || '.',
          dirPath: member.summary.dirPath || '.',
          count: 1,
        });
      }
    }

    let winner: DominantDir = { dirLabel: '.', dirPath: '.', voteCount: 0 };
    for (const [, entry] of votes) {
      if (
        entry.count > winner.voteCount ||
        (entry.count === winner.voteCount && entry.dirPath < winner.dirPath)
      ) {
        winner = {
          dirLabel: entry.dirLabel,
          dirPath: entry.dirPath,
          voteCount: entry.count,
        };
      }
    }
    result[c] = winner;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Confidence scoring
// ---------------------------------------------------------------------------

/**
 * Map cosine distance-to-centroid onto confidence ∈ [0.75, 0.85].
 *
 * Files close to their centroid (distance ≈ 0) are firmly in the cluster
 * → confidence 0.85.  Outliers (distance ≈ 1) may have been assigned
 * heuristically → confidence 0.75.
 */
function scoreConfidence(distanceToCentroid: number): number {
  const d = Math.max(0, Math.min(1, distanceToCentroid));
  return CONFIDENCE_LOW + (CONFIDENCE_HIGH - CONFIDENCE_LOW) * (1 - d);
}

// ---------------------------------------------------------------------------
// Math helpers
// ---------------------------------------------------------------------------

/**
 * Cosine similarity between two Float32Arrays.
 *
 * Both inputs are assumed to be L2-normalised (Embedder guarantees this), so
 * this is effectively a dot product.  The full formula is computed to guard
 * against centroids that lose unit length after averaging.
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

/** L2-normalise a Float32Array in place and return it. */
function l2Normalize(vec: Float32Array): Float32Array {
  let norm = 0;
  for (let i = 0; i < vec.length; i++) norm += vec[i] * vec[i];
  norm = Math.sqrt(norm);
  if (norm === 0) return vec;
  for (let i = 0; i < vec.length; i++) vec[i] /= norm;
  return vec;
}

function copyVec(src: Float32Array): Float32Array {
  return new Float32Array(src);
}
