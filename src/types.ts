// ============================================================
// CodeSentinel — Shared Types
// ============================================================

/** Analyzer layer classification */
export type AnalyzerLayer = 'static' | 'secrets' | 'semantic';

/** Finding severity levels */
export type Severity = 'error' | 'warning' | 'info';

/** Unified finding — every analyzer outputs this */
export interface Finding {
  id: string;
  layer: AnalyzerLayer;
  type: string;
  severity: Severity;
  confidence: number;
  file: string;
  line?: number;
  endLine?: number;
  message: string;
  tool: string;
  suggestion?: string;
  related?: string[];
  meta?: Record<string, unknown>;
}

/** Analyzer interface — all analyzers implement this */
export interface Analyzer {
  name: string;
  layer: AnalyzerLayer;
  analyze(context: AnalysisContext): Promise<Finding[]>;
}

/** Context passed to every analyzer */
export interface AnalysisContext {
  rootDir: string;
  files: string[];
  changedFiles?: string[];
  config: SentinelConfig;
}

/** Global configuration */
export interface SentinelConfig {
  rootDir: string;
  confidenceThreshold: number;
  ignore: string[];
  analyzers: {
    static: {
      enabled: boolean;
      deadCode: boolean;
      circularDeps: boolean;
      dependencies: boolean;
      security: boolean;
      complexity: boolean;
      complexityThreshold: number;
      testCoverage: boolean;
      crossProjectDuplication: boolean;
    };
    secrets: {
      enabled: boolean;
      useGitleaks: boolean;
      regexFallback: boolean;
    };
    semantic: {
      enabled: boolean;
      model: string;
      duplication: boolean;
      duplicationThreshold: number;
      drift: boolean;
      intentRecovery: boolean;
    };
  };
  watch: {
    enabled: boolean;
    debounceMs: number;
  };
  output: {
    format: 'terminal' | 'json' | 'sarif' | 'agent';
    verbose: boolean;
  };
}

/** Reporter interface */
export interface Reporter {
  name: string;
  report(findings: Finding[], config: SentinelConfig): Promise<void>;
}

/** File change event from watcher */
export interface FileChangeEvent {
  type: 'add' | 'change' | 'unlink';
  path: string;
  timestamp: number;
}

/** Embedding cache entry */
export interface EmbeddingCacheEntry {
  filePath: string;
  mtime: number;
  embedding: Float32Array;
  functions: ExtractedFunction[];
}

/** Extracted function from AST */
export interface ExtractedFunction {
  name: string;
  filePath: string;
  startLine: number;
  endLine: number;
  params: string[];
  returnType?: string;
  imports: string[];
  exports: boolean;
  body?: string;  // Not persisted to disk cache (SEC-06) — absent on cache-loaded entries
  description: string;  // textified NL description
}

/** Semantic duplicate pair */
export interface DuplicatePair {
  fileA: string;
  functionA: string;
  lineA: number;
  fileB: string;
  functionB: string;
  lineB: number;
  similarity: number;
}

/** Structural drift finding */
export interface DriftFinding {
  file: string;
  currentDir: string;
  suggestedDir: string;
  nearestCluster: string[];
  confidence: number;
}

/**
 * Minimal interface that the Watcher requires from the Orchestrator.
 * The concrete Orchestrator class must satisfy this contract.
 */
export interface OrchestratorLike {
  /**
   * Re-run analysis on a specific set of changed files and emit findings.
   * Called by the Watcher each time a debounced batch of events fires.
   */
  runOnChanges(events: FileChangeEvent[]): Promise<void>;
}
