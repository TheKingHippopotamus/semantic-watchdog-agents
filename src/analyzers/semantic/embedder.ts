import type { DuplicatePair } from '../../types.js';

// ---------------------------------------------------------------------------
// Embedder
//
// Wraps the @huggingface/transformers feature-extraction pipeline to produce
// normalized float32 sentence/code embeddings from an ONNX CodeBERT model.
//
// Lifecycle:
//   const embedder = new Embedder();
//   await embedder.init();          // downloads model on first run (~125 MB)
//   const vec = await embedder.embed('function foo() {}');
//
// Mean pooling is applied over the token dimension of the last hidden state,
// and the result is L2-normalised to a unit vector so cosine similarity can
// be computed as a plain dot product.
// ---------------------------------------------------------------------------

// @huggingface/transformers ships its own type declarations.
// We import via a type-safe wrapper so the dynamic pipeline call below
// remains fully typed.
import { pipeline } from '@huggingface/transformers';

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/** Raw tensor-like shape returned by the feature-extraction pipeline. */
interface PipelineTensor {
  /** Flat underlying data in row-major order. */
  data: Float32Array | number[];
  /** Shape: [batch, sequence_length, hidden_size] */
  dims: number[];
  /** Converts to a nested JS array. */
  tolist(): number[][][];
}

/** The object returned for each item by the feature-extraction pipeline. */
type PipelineOutput = PipelineTensor | PipelineTensor[];

/** Minimal pipeline callable signature we rely on. */
type FeatureExtractionPipeline = (
  input: string | string[],
  options?: Record<string, unknown>,
) => Promise<PipelineOutput | PipelineOutput[]>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// SEC-01: Model ID is hardcoded — never user-configurable.
// A crafted .sentinelrc.json pointing to a malicious HuggingFace repo
// could load arbitrary ONNX weights into the process.
const CODEBERT_MODEL_ID = 'onnx-community/codebert-base-ONNX' as const;
const DEFAULT_BATCH_SIZE = 16;

// ---------------------------------------------------------------------------
// Embedder
// ---------------------------------------------------------------------------

export class Embedder {
  private readonly modelId: string = CODEBERT_MODEL_ID;
  private pipe: FeatureExtractionPipeline | null = null;

  constructor(_modelId?: string) {
    // SEC-01: Ignore any external model ID. Always use the pinned model.
    this.modelId = CODEBERT_MODEL_ID;
  }

  // -------------------------------------------------------------------------
  // init
  // -------------------------------------------------------------------------

  /**
   * Load the feature-extraction pipeline.
   *
   * On first run the model weights are downloaded from the HuggingFace hub
   * (~125 MB for codebert-base-ONNX) and cached in the local HF cache
   * directory (`~/.cache/huggingface/hub`). Subsequent calls resolve
   * immediately from disk.
   *
   * A progress callback is registered so the user can see download activity
   * rather than staring at a silent prompt.
   */
  async init(): Promise<void> {
    if (this.pipe !== null) {
      return;
    }

    console.log(`[Embedder] Loading model: ${this.modelId}`);
    console.log('[Embedder] First run will download weights (~125 MB) — subsequent runs use the local cache.');

    let lastReported = -1;

    this.pipe = (await pipeline('feature-extraction', this.modelId, {
      progress_callback: (progress: { status: string; name?: string; progress?: number }) => {
        if (progress.status === 'downloading' && typeof progress.progress === 'number') {
          const pct = Math.floor(progress.progress);
          // Report every 10 percentage points to avoid log spam.
          if (pct >= lastReported + 10) {
            lastReported = pct;
            const bar = buildProgressBar(pct);
            process.stdout.write(`\r[Embedder] Downloading ${progress.name ?? 'weights'} ${bar} ${pct}%`);
          }
        } else if (progress.status === 'ready') {
          if (lastReported >= 0) {
            // Clear the progress line.
            process.stdout.write('\n');
          }
          console.log('[Embedder] Model ready.');
        }
      },
    })) as unknown as FeatureExtractionPipeline;

    console.log(`[Embedder] Pipeline initialized.`);
  }

  // -------------------------------------------------------------------------
  // embed
  // -------------------------------------------------------------------------

  /**
   * Embed a single text string.
   *
   * Returns a normalized Float32Array of length equal to the model's hidden
   * size (768 for codebert-base). The vector has unit L2 norm, making cosine
   * similarity equivalent to dot product.
   *
   * @throws if `init()` has not been called.
   */
  async embed(text: string): Promise<Float32Array> {
    this.assertReady();

    const raw = await this.pipe!(text, { pooling: 'mean', normalize: false });
    return meanPoolAndNormalize(raw as PipelineOutput);
  }

  // -------------------------------------------------------------------------
  // embedBatch
  // -------------------------------------------------------------------------

  /**
   * Embed an array of texts in mini-batches.
   *
   * @param texts      Texts to embed.
   * @param batchSize  Number of texts per inference call (default 16).
   *                   Tune down on machines with limited RAM.
   * @returns Array of normalized Float32Arrays in the same order as `texts`.
   *
   * @throws if `init()` has not been called.
   */
  async embedBatch(
    texts: string[],
    batchSize: number = DEFAULT_BATCH_SIZE,
  ): Promise<Float32Array[]> {
    this.assertReady();

    if (texts.length === 0) {
      return [];
    }

    const results: Float32Array[] = new Array(texts.length);
    const totalBatches = Math.ceil(texts.length / batchSize);

    for (let batchIdx = 0; batchIdx < totalBatches; batchIdx++) {
      const start = batchIdx * batchSize;
      const end = Math.min(start + batchSize, texts.length);
      const slice = texts.slice(start, end);

      const pct = Math.round(((batchIdx + 1) / totalBatches) * 100);
      process.stdout.write(
        `\r[Embedder] Embedding batch ${batchIdx + 1}/${totalBatches} (${pct}%) — items ${start + 1}–${end} of ${texts.length}`,
      );

      // Embed items individually to avoid batch tensor shape issues.
      // The pipeline with pooling:'mean' returns [1, hidden] per item —
      // batching behavior varies across @huggingface/transformers versions.
      for (let i = 0; i < slice.length; i++) {
        const raw = await this.pipe!(slice[i], { pooling: 'mean', normalize: false });
        const vec = meanPoolAndNormalize(raw as PipelineOutput);
        results[start + i] = vec;
      }
    }

    // Clear progress line.
    process.stdout.write('\n');
    console.log(`[Embedder] Embedded ${texts.length} texts.`);

    return results;
  }

  // -------------------------------------------------------------------------
  // cosineSimilarity
  // -------------------------------------------------------------------------

  /**
   * Cosine similarity between two unit-normalized vectors.
   *
   * Because both vectors are L2-normalised by `embed` / `embedBatch`, this
   * is a plain dot product — O(d), no sqrt required.
   *
   * @returns Value in [-1, 1]. Returns 0 if either vector has zero length.
   */
  cosineSimilarity(a: Float32Array, b: Float32Array): number {
    if (a.length !== b.length) {
      throw new RangeError(
        `cosineSimilarity: vector length mismatch (${a.length} vs ${b.length})`,
      );
    }

    let dot = 0;
    for (let i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
    }

    // Both vectors are unit-normalised so the norms are 1.0; the dot product
    // IS the cosine similarity. Clamp to [-1, 1] to guard against floating
    // point drift.
    return Math.max(-1, Math.min(1, dot));
  }

  // -------------------------------------------------------------------------
  // findDuplicates
  // -------------------------------------------------------------------------

  /**
   * Pairwise duplicate detection across a set of pre-computed embeddings.
   *
   * Runs an O(n²) comparison — suitable for the hundreds-to-low-thousands
   * range typical of a single codebase. For very large corpora a FAISS/HNSW
   * index would be appropriate, but that's a later optimisation.
   *
   * @param embeddings  Array of `{ id, vector }` objects.
   *                    The `id` must be formatted as `"<filePath>::<functionName>::<startLine>"`
   *                    so this method can decompose it into the DuplicatePair fields.
   * @param threshold   Cosine similarity cutoff in (0, 1]. Pairs at or above
   *                    this value are returned. Typical useful range: 0.85–0.95.
   * @returns Deduplicated array of DuplicatePair, sorted descending by similarity.
   */
  findDuplicates(
    embeddings: { id: string; vector: Float32Array }[],
    threshold: number,
  ): DuplicatePair[] {
    if (threshold <= 0 || threshold > 1) {
      throw new RangeError(`findDuplicates: threshold must be in (0, 1], got ${threshold}`);
    }

    const pairs: DuplicatePair[] = [];

    for (let i = 0; i < embeddings.length - 1; i++) {
      for (let j = i + 1; j < embeddings.length; j++) {
        const similarity = this.cosineSimilarity(embeddings[i].vector, embeddings[j].vector);

        if (similarity >= threshold) {
          const a = parseEmbeddingId(embeddings[i].id);
          const b = parseEmbeddingId(embeddings[j].id);

          pairs.push({
            fileA: a.filePath,
            functionA: a.functionName,
            lineA: a.startLine,
            fileB: b.filePath,
            functionB: b.functionName,
            lineB: b.startLine,
            similarity,
          });
        }
      }
    }

    // Sort most-similar first so callers can truncate by rank.
    pairs.sort((x, y) => y.similarity - x.similarity);

    return pairs;
  }

  // -------------------------------------------------------------------------
  // dispose
  // -------------------------------------------------------------------------

  /**
   * Release the ONNX session and null the pipeline reference.
   *
   * Call this after all embedding work is done and before the process exits.
   * Without an explicit dispose the ONNX Runtime background threads can still
   * be running when Node.js begins its cleanup phase, triggering a mutex
   * destructor race on macOS that aborts with:
   *   "mutex lock failed: Invalid argument"
   *
   * The pipeline object returned by @huggingface/transformers may expose a
   * `dispose()` method on newer versions — we call it when present. Nulling
   * the reference ensures the GC cannot trigger the destructor at an
   * unpredictable point later in the shutdown sequence.
   */
  dispose(): void {
    if (this.pipe !== null) {
      const p = this.pipe as unknown as { dispose?: () => void };
      if (typeof p.dispose === 'function') {
        try {
          p.dispose();
        } catch {
          // Swallow — we are shutting down regardless.
        }
      }
      this.pipe = null;
    }
  }

  // -------------------------------------------------------------------------
  // Private
  // -------------------------------------------------------------------------

  private assertReady(): void {
    if (this.pipe === null) {
      throw new Error(
        'Embedder has not been initialised. Call `await embedder.init()` before embedding.',
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Module-private helpers
// ---------------------------------------------------------------------------

/**
 * Mean-pool the token dimension of a feature-extraction tensor, then
 * L2-normalise the result to a unit vector.
 *
 * The pipeline output for a single string is a tensor of shape
 * [1, seq_len, hidden_size]. We average across seq_len (dim 1) and return
 * the resulting [hidden_size] vector as a Float32Array.
 */
function meanPoolAndNormalize(raw: PipelineOutput): Float32Array {
  const tensor = asSingleTensor(raw);
  const [, seqLen, hiddenSize] = resolveDims(tensor);

  const pooled = new Float32Array(hiddenSize);
  const flat = toFloat32Array(tensor.data);

  // Sum across the sequence dimension.
  for (let s = 0; s < seqLen; s++) {
    const offset = s * hiddenSize;
    for (let h = 0; h < hiddenSize; h++) {
      pooled[h] += flat[offset + h];
    }
  }

  // Divide by sequence length.
  for (let h = 0; h < hiddenSize; h++) {
    pooled[h] /= seqLen;
  }

  return l2Normalize(pooled);
}

/**
 * Extract per-item vectors from a batch pipeline output.
 *
 * Handles two layouts:
 *   1. Single batched tensor [batchSize, seq_len, hidden_size]
 *   2. Array of per-item tensors, each [1, seq_len, hidden_size]
 */
function extractBatchVectors(
  raw: PipelineOutput | PipelineOutput[],
  expectedCount: number,
): Float32Array[] {
  // Case 1: single tensor with batch dimension that matches expected count.
  if (!Array.isArray(raw) && hasDims(raw)) {
    const tensor = raw as PipelineTensor;
    const dims = resolveDims(tensor);
    const [batchSize, seqLen, hiddenSize] = dims;

    if (batchSize === expectedCount && batchSize > 1) {
      const flat = toFloat32Array(tensor.data);
      const result: Float32Array[] = [];

      for (let b = 0; b < batchSize; b++) {
        const pooled = new Float32Array(hiddenSize);
        for (let s = 0; s < seqLen; s++) {
          const offset = (b * seqLen + s) * hiddenSize;
          for (let h = 0; h < hiddenSize; h++) {
            pooled[h] += flat[offset + h];
          }
        }
        for (let h = 0; h < hiddenSize; h++) {
          pooled[h] /= seqLen;
        }
        result.push(l2Normalize(pooled));
      }

      return result;
    }

    // Pipeline returned a single tensor (batch=1) for multiple inputs.
    // This happens when @huggingface/transformers pools per-item.
    // Fall through to per-item processing.
  }

  // Case 2: array of per-item outputs, OR single tensor to be treated as one item.
  const items = (Array.isArray(raw) ? raw : [raw]) as PipelineOutput[];

  return items.map((item) => meanPoolAndNormalize(item));
}

/** L2-normalise a Float32Array in place, returning the same array. */
function l2Normalize(vec: Float32Array): Float32Array {
  let norm = 0;
  for (let i = 0; i < vec.length; i++) {
    norm += vec[i] * vec[i];
  }
  norm = Math.sqrt(norm);

  if (norm === 0) {
    // Zero vector — return as-is (cosine similarity will be 0 against anything).
    return vec;
  }

  for (let i = 0; i < vec.length; i++) {
    vec[i] /= norm;
  }

  return vec;
}

/**
 * Unwrap a potentially array-wrapped single tensor.
 * The pipeline sometimes wraps the result in a length-1 array.
 */
function asSingleTensor(raw: PipelineOutput): PipelineTensor {
  if (Array.isArray(raw)) {
    if (raw.length !== 1) {
      throw new Error(
        `asSingleTensor: expected 1 tensor, got ${raw.length}. Use extractBatchVectors for batch outputs.`,
      );
    }
    return raw[0] as PipelineTensor;
  }
  return raw as PipelineTensor;
}

/** Resolve dims from a tensor, normalising [seq, hidden] → [1, seq, hidden]. */
function resolveDims(tensor: PipelineTensor): [number, number, number] {
  const d = tensor.dims;
  if (d.length === 3) return [d[0], d[1], d[2]];
  if (d.length === 2) return [1, d[0], d[1]];
  throw new Error(`Unexpected tensor dims: [${d.join(', ')}]`);
}

/** Type guard: does the value look like a PipelineTensor? */
function hasDims(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    'dims' in value &&
    Array.isArray((value as PipelineTensor).dims)
  );
}

/** Coerce tensor.data to Float32Array regardless of whether it arrived as a
 *  plain number[] (in some environments transformers.js returns number[]). */
function toFloat32Array(data: Float32Array | number[]): Float32Array {
  if (data instanceof Float32Array) return data;
  return new Float32Array(data);
}

// ---------------------------------------------------------------------------
// Embedding ID codec
// ---------------------------------------------------------------------------

/**
 * Embedding IDs encode three pieces of metadata in a single string so that
 * findDuplicates can reconstruct DuplicatePair without keeping a parallel
 * metadata array.
 *
 * Format:  "<filePath>::<functionName>::<startLine>"
 *
 * Callers are responsible for constructing IDs in this format. The separator
 * "::" is chosen because it cannot appear in a posix file path or a valid
 * JS/TS identifier.
 */
interface EmbeddingMeta {
  filePath: string;
  functionName: string;
  startLine: number;
}

function parseEmbeddingId(id: string): EmbeddingMeta {
  const parts = id.split('::');
  if (parts.length < 3) {
    throw new Error(
      `parseEmbeddingId: invalid ID format "${id}". Expected "<filePath>::<functionName>::<startLine>"`,
    );
  }
  // Allow "::" in file paths by only splitting at the last two delimiters.
  const startLine = parseInt(parts[parts.length - 1], 10);
  const functionName = parts[parts.length - 2];
  const filePath = parts.slice(0, parts.length - 2).join('::');

  if (isNaN(startLine)) {
    throw new Error(
      `parseEmbeddingId: startLine is not a number in ID "${id}"`,
    );
  }

  return { filePath, functionName, startLine };
}

// ---------------------------------------------------------------------------
// Progress bar utility
// ---------------------------------------------------------------------------

function buildProgressBar(pct: number, width = 20): string {
  const filled = Math.round((pct / 100) * width);
  const empty = width - filled;
  return `[${'#'.repeat(filled)}${'.'.repeat(empty)}]`;
}
