// ============================================================
// CodeSentinel — File Watcher
// ============================================================

import { watch, type FSWatcher } from 'chokidar';
import { relative } from 'node:path';
import type { FileChangeEvent, OrchestratorLike, SentinelConfig } from './types.js';

export class Watcher {
  private readonly config: SentinelConfig;
  private readonly orchestrator: OrchestratorLike;
  private watcher: FSWatcher | null = null;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private pendingEvents: Map<string, FileChangeEvent> = new Map();

  constructor(config: SentinelConfig, orchestrator: OrchestratorLike) {
    this.config = config;
    this.orchestrator = orchestrator;
  }

  start(): void {
    if (this.watcher !== null) {
      throw new Error('Watcher is already running. Call stop() before starting again.');
    }

    const ignored = this.buildIgnorePatterns();

    this.watcher = watch(this.config.rootDir, {
      ignored,
      persistent: true,
      ignoreInitial: true,
      awaitWriteFinish: {
        stabilityThreshold: 50,
        pollInterval: 10,
      },
    });

    this.watcher
      .on('add', (filePath: string) => this.handleEvent('add', filePath))
      .on('change', (filePath: string) => this.handleEvent('change', filePath))
      .on('unlink', (filePath: string) => this.handleEvent('unlink', filePath))
      .on('error', (err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`[CodeSentinel] Watcher error: ${message}`);
      });

    if (this.config.output.verbose) {
      console.log(`[CodeSentinel] Watching ${this.config.rootDir} (debounce: ${this.config.watch.debounceMs}ms)`);
    }
  }

  stop(): void {
    if (this.debounceTimer !== null) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }

    if (this.watcher !== null) {
      void this.watcher.close();
      this.watcher = null;
    }

    this.pendingEvents.clear();

    if (this.config.output.verbose) {
      console.log('[CodeSentinel] Watcher stopped.');
    }
  }

  private handleEvent(type: FileChangeEvent['type'], filePath: string): void {
    if (this.config.output.verbose) {
      const rel = relative(this.config.rootDir, filePath);
      console.log(`[CodeSentinel] ${type}: ${rel}`);
    }

    // Deduplicate by path — later event type wins (e.g. change overwrites add)
    this.pendingEvents.set(filePath, {
      type,
      path: filePath,
      timestamp: Date.now(),
    });

    // Reset the debounce window on every new event
    if (this.debounceTimer !== null) {
      clearTimeout(this.debounceTimer);
    }

    this.debounceTimer = setTimeout(() => {
      this.flush();
    }, this.config.watch.debounceMs);
  }

  private flush(): void {
    this.debounceTimer = null;

    if (this.pendingEvents.size === 0) {
      return;
    }

    const batch = Array.from(this.pendingEvents.values());
    this.pendingEvents.clear();

    if (this.config.output.verbose) {
      console.log(`[CodeSentinel] Flushing ${batch.length} change(s) to orchestrator.`);
    }

    void this.orchestrator.runOnChanges(batch);
  }

  /**
   * Build the ignore list for chokidar.
   * Converts the plain-string patterns from config into regex-safe patterns
   * that match both directory names and file paths.
   */
  private buildIgnorePatterns(): (string | RegExp)[] {
    const patterns: (string | RegExp)[] = [
      /node_modules/,
      /\.git/,
    ];

    for (const entry of this.config.ignore) {
      // Skip duplicates already covered above
      if (entry === 'node_modules' || entry === '.git') {
        continue;
      }
      // If the entry looks like a glob or contains path separators, pass it through;
      // otherwise wrap it so it matches anywhere in the path.
      if (entry.includes('/') || entry.includes('*')) {
        patterns.push(entry);
      } else {
        // Match directory segment or filename anywhere in path
        patterns.push(new RegExp(`(^|[/\\\\])${escapeRegex(entry)}([/\\\\]|$)`));
      }
    }

    return patterns;
  }
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
