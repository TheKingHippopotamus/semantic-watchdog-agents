import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import os from 'node:os';
import type { EmbeddingCacheEntry } from '../../types.js';

// ---------------------------------------------------------------------------
// CodeSentinel — Embedding Cache
//
// Persists file embeddings to disk so re-analysis can skip unchanged files.
//
// Cache layout on disk:
//
//   ~/.cache/codesentinel/<sha256-of-rootDir>/
//   ├── meta.json          — serializable index of all cached entries
//   └── embeddings.bin     — concatenated Float32Array binary data
//
// Binary format (embeddings.bin):
//
//   [ entry0_length_uint32 | entry0_float32s | entry1_length_uint32 | ... ]
//
//   Each entry starts with a 4-byte little-endian uint32 indicating the
//   number of Float32 elements that follow for that entry.  Entries are
//   stored in the same order as the `meta.json` entries array so the reader
//   can reconstruct the full Map without storing byte offsets in meta.json.
//
// Corruption handling:
//   Any I/O or parse error during load causes the entire cache directory to
//   be deleted so it can be rebuilt from scratch on the next run.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Serialisable form of a single cache entry stored in meta.json.
 * The Float32Array embedding is stored separately in embeddings.bin.
 */
interface MetaEntry {
  filePath: string;
  mtime: number;
  functionCount: number;
  /** Inline-serialised ExtractedFunction array (JSON-safe). */
  functions: EmbeddingCacheEntry['functions'];
}

/** Top-level structure of meta.json. */
interface MetaFile {
  version: number;
  entries: MetaEntry[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CACHE_VERSION = 1;
const CACHE_BASE_DIR = join(os.homedir(), '.cache', 'codesentinel');
const META_FILENAME = 'meta.json';
const EMBEDDINGS_FILENAME = 'embeddings.bin';

// Bytes per Float32 element.
const FLOAT32_BYTES = 4;
// Bytes used to store the uint32 element-count prefix for each embedding.
const LENGTH_PREFIX_BYTES = 4;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Returns the absolute path to the cache directory for the given project root.
 *
 * The directory is named with the SHA-256 hash of the absolute `rootDir` path
 * so that distinct projects never share cache state.
 */
export function getCacheDir(rootDir: string): string {
  const hash = createHash('sha256').update(rootDir).digest('hex');
  return join(CACHE_BASE_DIR, hash);
}

/**
 * Loads all cached embeddings for the given project root.
 *
 * Returns an empty Map when no cache exists yet.  Deletes and returns an empty
 * Map when the cache is present but corrupt or versioned differently.
 */
export async function loadCache(
  rootDir: string,
): Promise<Map<string, EmbeddingCacheEntry>> {
  const cacheDir = getCacheDir(rootDir);
  const metaPath = join(cacheDir, META_FILENAME);
  const embeddingsPath = join(cacheDir, EMBEDDINGS_FILENAME);

  try {
    const [metaRaw, embeddingsBuf] = await Promise.all([
      readFile(metaPath, 'utf-8'),
      readFile(embeddingsPath),
    ]);

    const meta: MetaFile = JSON.parse(metaRaw);

    if (meta.version !== CACHE_VERSION) {
      // Version mismatch — treat as stale and rebuild.
      await clearCache(rootDir);
      return new Map();
    }

    const embeddings = parseEmbeddingsBinary(embeddingsBuf, meta.entries.length);

    const result = new Map<string, EmbeddingCacheEntry>();

    for (let i = 0; i < meta.entries.length; i++) {
      const entry = meta.entries[i];
      result.set(entry.filePath, {
        filePath: entry.filePath,
        mtime: entry.mtime,
        embedding: embeddings[i],
        functions: entry.functions,
      });
    }

    return result;
  } catch (err: unknown) {
    // No cache yet — silently return empty.
    if (isNodeError(err) && err.code === 'ENOENT') {
      return new Map();
    }

    // Corruption or unexpected error — nuke and rebuild.
    console.warn(
      `[codesentinel] embedding cache is corrupt, clearing: ${errorMessage(err)}`,
    );
    await clearCache(rootDir);
    return new Map();
  }
}

/**
 * Persists all entries in `entries` to the on-disk cache for `rootDir`.
 *
 * Creates the cache directory if it does not yet exist.  Overwrites any
 * existing meta.json and embeddings.bin atomically (write to temp names then
 * rename is not needed here — the worst outcome of a crash mid-write is a
 * corrupt cache that `loadCache` will detect and clear).
 */
export async function saveCache(
  rootDir: string,
  entries: Map<string, EmbeddingCacheEntry>,
): Promise<void> {
  const cacheDir = getCacheDir(rootDir);

  await mkdir(cacheDir, { recursive: true });

  const entriesArray = Array.from(entries.values());

  const metaEntries: MetaEntry[] = entriesArray.map((e) => ({
    filePath: e.filePath,
    mtime: e.mtime,
    functionCount: e.functions.length,
    // Strip function bodies before caching — SEC-06
    // Bodies contain full source text that would persist on disk beyond the
    // lifetime of the project. The in-memory cache retains bodies for the
    // current session; only the serialised form is sanitised.
    functions: e.functions.map(({ body, ...rest }) => rest),
  }));

  const meta: MetaFile = {
    version: CACHE_VERSION,
    entries: metaEntries,
  };

  const embeddingsBuf = buildEmbeddingsBinary(entriesArray.map((e) => e.embedding));

  await Promise.all([
    writeFile(join(cacheDir, META_FILENAME), JSON.stringify(meta), 'utf-8'),
    writeFile(join(cacheDir, EMBEDDINGS_FILENAME), embeddingsBuf),
  ]);
}

/**
 * Returns the subset of `currentFiles` that need re-embedding.
 *
 * A file needs re-embedding when:
 * - It is not present in the cache (new file).
 * - Its recorded mtime differs from the current mtime (modified file).
 *
 * Files that are in the cache but absent from `currentFiles` are considered
 * deleted; they are not returned here — callers should prune the cache by
 * rebuilding it with only the entries for files that still exist.
 */
export function getStaleFiles(
  cache: Map<string, EmbeddingCacheEntry>,
  currentFiles: { path: string; mtime: number }[],
): string[] {
  const stale: string[] = [];

  for (const { path, mtime } of currentFiles) {
    const cached = cache.get(path);
    if (cached === undefined || cached.mtime !== mtime) {
      stale.push(path);
    }
  }

  return stale;
}

/**
 * Deletes the entire cache directory for the given project root.
 *
 * Safe to call when the directory does not yet exist.
 */
export async function clearCache(rootDir: string): Promise<void> {
  const cacheDir = getCacheDir(rootDir);
  try {
    await rm(cacheDir, { recursive: true, force: true });
  } catch (err: unknown) {
    // If the directory was never created, rm with force should already handle
    // ENOENT silently.  Anything else is worth surfacing.
    if (!isNodeError(err) || err.code !== 'ENOENT') {
      throw err;
    }
  }
}

// ---------------------------------------------------------------------------
// Binary serialisation helpers
// ---------------------------------------------------------------------------

/**
 * Packs an ordered array of Float32Arrays into a single Buffer.
 *
 * Format per embedding:
 *   [uint32 elementCount (4 bytes LE)] [float32 * elementCount (4 bytes each LE)]
 */
function buildEmbeddingsBinary(embeddings: Float32Array[]): Buffer {
  const totalBytes = embeddings.reduce(
    (sum, e) => sum + LENGTH_PREFIX_BYTES + e.length * FLOAT32_BYTES,
    0,
  );

  const buf = Buffer.allocUnsafe(totalBytes);
  let offset = 0;

  for (const embedding of embeddings) {
    buf.writeUInt32LE(embedding.length, offset);
    offset += LENGTH_PREFIX_BYTES;

    // Copy the Float32Array's underlying bytes directly.
    const srcBytes = Buffer.from(
      embedding.buffer,
      embedding.byteOffset,
      embedding.byteLength,
    );
    srcBytes.copy(buf, offset);
    offset += embedding.byteLength;
  }

  return buf;
}

/**
 * Parses a Buffer written by `buildEmbeddingsBinary` and returns an array of
 * `count` Float32Arrays in the same order they were written.
 *
 * Throws a descriptive Error if the buffer is truncated or the entry count
 * does not match, so callers can treat the cache as corrupt.
 */
function parseEmbeddingsBinary(buf: Buffer, count: number): Float32Array[] {
  const result: Float32Array[] = [];
  let offset = 0;

  for (let i = 0; i < count; i++) {
    if (offset + LENGTH_PREFIX_BYTES > buf.length) {
      throw new Error(
        `embeddings.bin truncated at entry ${i}: expected length prefix at byte ${offset}, ` +
          `buffer length is ${buf.length}`,
      );
    }

    const elementCount = buf.readUInt32LE(offset);
    offset += LENGTH_PREFIX_BYTES;

    const byteLength = elementCount * FLOAT32_BYTES;

    if (offset + byteLength > buf.length) {
      throw new Error(
        `embeddings.bin truncated at entry ${i}: expected ${byteLength} bytes of float data ` +
          `at offset ${offset}, buffer length is ${buf.length}`,
      );
    }

    // Slice without copying — the ArrayBuffer is owned by Node's Buffer so
    // this is valid for the lifetime of the calling function.
    const embedding = new Float32Array(
      buf.buffer,
      buf.byteOffset + offset,
      elementCount,
    );

    // Copy into a fresh ArrayBuffer so the entry is independent of the source
    // Buffer and safe to hold in memory after the Buffer is GC'd.
    result.push(new Float32Array(embedding));
    offset += byteLength;
  }

  if (result.length !== count) {
    throw new Error(
      `embeddings.bin entry count mismatch: expected ${count}, parsed ${result.length}`,
    );
  }

  return result;
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/** Narrows an unknown error to a Node.js system error with a `code` property. */
function isNodeError(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && 'code' in err;
}

/** Extracts a string message from any thrown value. */
function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// Re-export stat so callers can get mtime without a separate import when
// building the currentFiles array for getStaleFiles.
export { stat as fsStat };
