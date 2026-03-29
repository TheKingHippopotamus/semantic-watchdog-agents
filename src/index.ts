// ============================================================
// CodeSentinel — Public API Entry Point
// ============================================================
//
// Re-exports everything a downstream consumer needs.
// No logic lives here — this is purely a barrel file.
//
// Usage:
//   import { Orchestrator, loadConfig } from 'codesentinel';
// ============================================================

// ── Types ────────────────────────────────────────────────────────────────────
export type {
  AnalyzerLayer,
  Severity,
  Finding,
  Analyzer,
  AnalysisContext,
  SentinelConfig,
  Reporter,
  FileChangeEvent,
  EmbeddingCacheEntry,
  ExtractedFunction,
  DuplicatePair,
  DriftFinding,
  OrchestratorLike,
} from './types.js';

// ── Core ─────────────────────────────────────────────────────────────────────
export { Orchestrator } from './orchestrator.js';
export { loadConfig } from './config.js';
export { Watcher } from './watcher.js';

// ── Static analyzers ─────────────────────────────────────────────────────────
export { DependencyAnalyzer } from './analyzers/static/dependencies.js';
export { MadgeCircularAnalyzer } from './analyzers/static/circular.js';
export { DeadCodeAnalyzer } from './analyzers/static/dead-code.js';
export { SecurityAnalyzer } from './analyzers/static/security.js';
export { AstPatternAnalyzer } from './analyzers/static/ast-patterns.js';
export { ComplexityAnalyzer } from './analyzers/static/complexity.js';

// ── Secrets analyzers ────────────────────────────────────────────────────────
export { GitleaksAnalyzer } from './analyzers/secrets/gitleaks.js';
export { RegexFallbackAnalyzer } from './analyzers/secrets/fallback.js';

// ── Semantic analyzers ───────────────────────────────────────────────────────
export { SemanticDuplicationAnalyzer } from './analyzers/semantic/duplication.js';
export { DriftAnalyzer } from './analyzers/semantic/drift.js';
export { IntentAnalyzer } from './analyzers/semantic/intent.js';
export { Embedder } from './analyzers/semantic/embedder.js';

// ── Reporters ────────────────────────────────────────────────────────────────
export { TerminalReporter } from './reporter/terminal.js';
export { JsonReporter } from './reporter/json.js';
export { SarifReporter } from './reporter/sarif.js';
export { AgentReporter } from './reporter/agent.js';
