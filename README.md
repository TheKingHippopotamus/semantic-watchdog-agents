# CodeSentinel

Continuous code watchdog — static analysis, secret scanning, and local AI-powered duplicate detection in a single CLI.

---

## Why this exists

Multi-agent development produces disconnected modules, duplicate logic, dead files, and leaked secrets faster than any human reviewer can catch. Standard linters check style. Code review checks logic. Neither checks whether two agents independently built the same thing, whether a module has drifted semantically away from where it lives in the directory structure, or whether a token was hardcoded three files deep.

CodeSentinel runs three analysis layers on every scan or file change and surfaces findings above a configurable confidence threshold — before they compound.

---

## What it does

```
┌─────────────────────────────────────────────────┐
│                  CodeSentinel CLI                │
│            (Node.js — npm distributable)         │
├─────────────────────────────────────────────────┤
│                                                  │
│  ┌─── TRIGGER ──────────────────────────────┐   │
│  │  chokidar v4 — file watcher              │   │
│  │  Triggers on: add, change, unlink        │   │
│  │  Respects: .gitignore, .sentinelignore   │   │
│  └──────────────┬───────────────────────────┘   │
│                 │                                │
│  ┌──────────────▼───────────────────────────┐   │
│  │         ORCHESTRATOR                      │   │
│  │  Routes change events to analyzers        │   │
│  │  Collects findings                        │   │
│  │  Applies confidence gate (≥ 0.90)         │   │
│  │  Reports to developer / agent             │   │
│  └──────────────┬───────────────────────────┘   │
│                 │                                │
│  ┌──────────────▼───────────────────────────┐   │
│  │         ANALYZER LAYERS                   │   │
│  │                                           │   │
│  │  Layer 1: STATIC (deterministic, fast)    │   │
│  │  ├── dependency-cruiser  (orphans, arch)  │   │
│  │  ├── madge               (circular deps)  │   │
│  │  ├── knip                (dead files)     │   │
│  │  ├── eslint-plugin-security (patterns)    │   │
│  │  ├── ast-grep            (AST matching)   │   │
│  │  └── typhonjs-escomplex  (complexity)     │   │
│  │                                           │   │
│  │  Layer 2: SECRETS (regex + entropy)       │   │
│  │  ├── gitleaks            (150+ patterns)  │   │
│  │  └── regex fallback      (top-20 formats) │   │
│  │                                           │   │
│  │  Layer 3: SEMANTIC (runs locally)         │   │
│  │  ├── CodeBERT ONNX       (125MB, MIT)     │   │
│  │  ├── cosine similarity   (duplication)    │   │
│  │  ├── cluster analysis    (struct. drift)  │   │
│  │  └── nearest-neighbor    (intent recovery)│   │
│  │                                           │   │
│  └───────────────────────────────────────────┘   │
│                                                  │
│  ┌───────────────────────────────────────────┐   │
│  │         REPORTER                          │   │
│  │  terminal / json / sarif / agent          │   │
│  └───────────────────────────────────────────┘   │
│                                                  │
└─────────────────────────────────────────────────┘
```

### Layer 1 — Static

| What it detects | Tool | Confidence |
|---|---|---|
| Dead files (no importers) | knip | 1.0 |
| Unused exports | knip | 1.0 |
| Circular dependencies | madge | 1.0 |
| Architecture violations | dependency-cruiser | 1.0 |
| Orphan modules | dependency-cruiser | 1.0 |
| Security anti-patterns | ast-grep + eslint-plugin-security | 0.85–0.95 |
| Cyclomatic complexity spikes | typhonjs-escomplex | 1.0 |

### Layer 2 — Secrets

Runs gitleaks (150+ regex patterns + entropy scoring) when the binary is available, falls back to a built-in JS regex pass covering the top-20 formats (AWS, GitHub, Stripe, OpenAI, etc.) when it is not.

### Layer 3 — Semantic

Loads `onnx-community/codebert-base-ONNX` (125MB, INT8 quantized, MIT license) via `@huggingface/transformers`. The model runs fully local via ONNX Runtime — no API calls, no cloud.

| What it detects | How |
|---|---|
| Semantic duplication (Type-3/4) | Embed functions, compute cosine similarity |
| Structural drift | Cluster file embeddings, compare to directory layout |
| Intent recovery for orphans | Static finds the orphan; semantic finds its nearest semantic neighbors |
| Redundant agent work | High embedding similarity + low import overlap |

Backed by BigCloneBench (F1 = 0.928 for Type-4 clones, Feng et al. 2020 EMNLP). Embeddings are cached per-project in `~/.cache/codesentinel/<project-hash>/` and recomputed only for changed files.

---

## Quick start

```bash
# One-shot scan of the current directory
npx codesentinel scan

# Scan and output JSON for piping to agents
npx codesentinel scan --format json

# Watch mode — re-analyzes on every file change
npx codesentinel watch
```

First run downloads the CodeBERT model (~125MB) to `~/.cache/huggingface/`. Subsequent runs use the local cache.

---

## Installation

### npm

```bash
# Global install
npm install -g codesentinel

# Or run directly without installing
npx codesentinel scan
```

### Docker

```bash
docker pull codesentinel/codesentinel
```

The Docker image bundles the CodeBERT model and gitleaks binary — no downloads after pull.

---

## CLI reference

All options are global and apply to both `scan` and `watch`.

```
Usage: codesentinel [options] [command]

Commands:
  scan [dir]         Run a one-shot analysis of a directory (default)
  watch [dir]        Watch a directory and re-analyse on file changes
  clear-cache [dir]  Clear the embedding cache for a directory

Options:
  --threshold <n>    Confidence threshold, 0–1 (default: 0.9)
  --format <type>    Output format: terminal | json | sarif | agent (default: terminal)
  --verbose          Show all findings including below-threshold
  --no-semantic      Skip semantic analysis (faster, no model load)
  --no-secrets       Skip secret scanning
  --no-static        Skip static analysis
  -V, --version      Print version
  -h, --help         Print help
```

`scan` and `watch` both accept an optional `[dir]` argument. When omitted they default to the current working directory.

Exit codes: `0` for clean or warnings only, `1` for error-severity findings or scan failure.

---

## Output formats

### terminal (default)

Color-coded, ranked by severity. Designed for developer terminals.

```
[ERROR]   src/auth/token.ts:14   SECRETS   confidence 0.97
  Hardcoded secret: possible AWS access key
  tool: gitleaks

[WARNING] src/utils/format.ts    STATIC    confidence 1.00
  Dead file — 0 importers
  tool: knip

[WARNING] src/payments/charge.ts SEMANTIC  confidence 0.91
  Semantic duplicate of src/billing/process.ts:makeCharge (similarity 0.93)
  tool: codebert
```

### json

Machine-readable array of `Finding` objects. Pipe to any consumer.

```bash
codesentinel scan --format json | jq '.[] | select(.severity == "error")'
```

```json
[
  {
    "id": "SEC-001",
    "layer": "secrets",
    "type": "hardcoded-secret",
    "severity": "error",
    "confidence": 0.97,
    "file": "src/auth/token.ts",
    "line": 14,
    "message": "Hardcoded secret: possible AWS access key",
    "tool": "gitleaks",
    "suggestion": "Move to environment variable or secrets manager"
  }
]
```

### sarif

Standard SARIF 2.1.0 format for IDE and CI integration. Works with VS Code's built-in SARIF viewer and GitHub Code Scanning.

```bash
codesentinel scan --format sarif > results.sarif
```

### agent

Structured plain text optimized for LLM context windows. Findings are grouped by layer and formatted as a numbered list with file paths, line numbers, and suggestions — ready to paste into an agent prompt.

```bash
codesentinel scan --format agent | claude "review these findings and prioritize fixes"
```

---

## Configuration

### .sentinelrc.json

Place in project root. Merged deeply over defaults — only specify what you want to override.

```json
{
  "confidenceThreshold": 0.9,
  "analyzers": {
    "static": {
      "enabled": true,
      "deadCode": true,
      "circularDeps": true,
      "dependencies": true,
      "security": true,
      "complexity": true,
      "complexityThreshold": 20
    },
    "secrets": {
      "enabled": true,
      "useGitleaks": true,
      "regexFallback": true
    },
    "semantic": {
      "enabled": true,
      "model": "onnx-community/codebert-base-ONNX",
      "duplication": true,
      "duplicationThreshold": 0.85,
      "drift": true,
      "intentRecovery": true
    }
  },
  "watch": {
    "debounceMs": 300
  },
  "output": {
    "format": "terminal",
    "verbose": false
  }
}
```

### .sentinelignore

Gitignore-style pattern file. Added on top of the built-in ignore list (`node_modules`, `.git`, `dist`, `build`, `coverage`, `.next`, `__pycache__`, `.venv`, `vendor`).

```
# .sentinelignore
generated/
*.pb.ts
__fixtures__/
```

---

## Confidence model

Every finding carries a `confidence` score (0–1). The default gate is `>= 0.90`.

| Layer | Finding type | Confidence |
|---|---|---|
| Static | Dead file, circular dep, unused export | 1.0 — deterministic |
| Static | Architecture violation | 1.0 — deterministic (user rules) |
| Static | Complexity spike | 1.0 — deterministic |
| Static | Security anti-pattern | 0.85–0.95 |
| Secrets | Known pattern match (gitleaks) | 0.90–0.99 |
| Secrets | High-entropy string only | 0.70–0.85 |
| Semantic | Duplicate, similarity > 0.95 | 0.90+ |
| Semantic | Duplicate, similarity 0.85–0.95 | 0.70–0.89 |
| Semantic | Structural drift | 0.75–0.85 |
| Semantic | Intent recovery suggestion | 0.60–0.80 |

Gate behavior:

- `confidence >= threshold` — displayed as a finding (default: `>= 0.90`)
- `confidence 0.70–0.89` — shown with `--verbose` or `--threshold 0.7`
- `confidence < 0.70` — suppressed (available with `--verbose --threshold 0`)

---

## Privacy

Your code never leaves your machine. The AI model runs locally via ONNX Runtime. No API keys, no cloud, no telemetry.

The CodeBERT model is downloaded once from HuggingFace Hub on first run and cached at `~/.cache/huggingface/`. After that, every scan runs fully offline.

---

## Requirements

- Node.js >= 18
- `gitleaks` binary — optional; if absent, built-in regex patterns cover common secret formats. Install via [gitleaks releases](https://github.com/gitleaks/gitleaks/releases) or `brew install gitleaks`.

---

## Docker

The Docker image includes everything: compiled CLI, CodeBERT model (pre-downloaded), and gitleaks binary. No internet access required after pull.

```bash
# One-shot scan — mount your project directory
docker run --rm -v $(pwd):/project codesentinel/codesentinel scan

# JSON output for agent consumption
docker run --rm -v $(pwd):/project codesentinel/codesentinel scan --format json

# Watch mode
docker run --rm -it -v $(pwd):/project codesentinel/codesentinel watch

# Scan a specific subdirectory
docker run --rm -v /path/to/repo:/project codesentinel/codesentinel scan /project/src
```

Your code is mounted read-only at `/project`. The container writes nothing to the mount.

---

## What this is not

- **Not a linter.** ESLint and Prettier handle formatting and style. CodeSentinel handles structural and semantic problems.
- **Not a test runner.** It does not execute code. It analyzes code statically and semantically.
- **Not an LLM.** The embedded model is a 125MB encoder that produces vectors. It computes similarity scores — math, not generation. It does not generate text, chat, or hallucinate.
- **Not a replacement for code review.** It is an early-warning system that catches what humans and agents miss at scale.

---

## License

MIT
