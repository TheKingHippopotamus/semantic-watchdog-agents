# CodeSentinel — Continuous Code Watchdog
# Revised Plan (Evidence-Based)

**Version:** 2.0
**Date:** 2026-03-27
**Status:** Research complete, pre-implementation

---

## WHAT CHANGED FROM V1

V1 described a semantic search CLI ("ask a question, get ranked files").
The actual vision is bigger: a **continuous code watchdog** that triggers on every change, detects problems across multiple dimensions, and reports findings to the developer or to AI agents (Claude).

The research proved:
- Embeddings are the right tool for **some** tasks (duplication, drift, intent recovery)
- Static analysis is the right tool for **other** tasks (dead code, secrets, security patterns)
- A single model doing everything is not viable — a **multi-layer architecture** composing free tools + one AI model is the evidence-backed approach

---

## ARCHITECTURE

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
│  │  Receives change events                   │   │
│  │  Routes to relevant analyzers             │   │
│  │  Collects findings                        │   │
│  │  Applies confidence gate (≥90%)           │   │
│  │  Reports to developer / agents            │   │
│  └──────────────┬───────────────────────────┘   │
│                 │                                │
│  ┌──────────────▼───────────────────────────┐   │
│  │         ANALYZER LAYERS                   │   │
│  │                                           │   │
│  │  Layer 1: STATIC (deterministic, fast)    │   │
│  │  ├── dependency-cruiser  (npm, API)       │   │
│  │  ├── madge               (npm, API)       │   │
│  │  ├── knip                (npm, JSON CLI)  │   │
│  │  ├── eslint + security   (npm, API)       │   │
│  │  ├── ast-grep            (npm, napi)      │   │
│  │  └── typhonjs-escomplex  (npm, API)       │   │
│  │                                           │   │
│  │  Layer 2: SECRETS (regex + entropy)       │   │
│  │  ├── gitleaks            (binary, JSON)   │   │
│  │  └── detect-secrets      (pypi, API)      │   │
│  │                                           │   │
│  │  Layer 3: SEMANTIC (AI model)             │   │
│  │  ├── Code embeddings     (ONNX, ~125MB)   │   │
│  │  ├── Cosine similarity   (duplication)    │   │
│  │  ├── Cluster analysis    (structural drift)│  │
│  │  └── Nearest-neighbor    (intent recovery)│   │
│  │                                           │   │
│  └───────────────────────────────────────────┘   │
│                                                  │
│  ┌───────────────────────────────────────────┐   │
│  │         REPORTER                          │   │
│  │  ├── Terminal (color-coded, ranked)        │   │
│  │  ├── JSON    (for piping to agents)        │   │
│  │  ├── SARIF   (IDE integration)             │   │
│  │  └── Agent   (structured output for Claude)│   │
│  └───────────────────────────────────────────┘   │
│                                                  │
└─────────────────────────────────────────────────┘
```

---

## WHAT EACH LAYER DETECTS (with evidence)

### Layer 1: Static Analysis

| Detection | Tool | How | Confidence |
|-----------|------|-----|------------|
| Dead files (no importers) | knip | Import graph traversal | 100% deterministic |
| Unused exports | knip | Export/import cross-ref | 100% deterministic |
| Circular dependencies | madge (API) | Dependency graph cycles | 100% deterministic |
| Architecture violations | dependency-cruiser (API) | User-defined rules | 100% deterministic |
| Orphan modules | dependency-cruiser (API) | Unreachable from entry | 100% deterministic |
| Security anti-patterns | ast-grep (napi) + eslint-plugin-security | AST pattern matching | High (known patterns) |
| Code complexity spikes | typhonjs-escomplex (API) | Cyclomatic complexity | 100% deterministic |

**Evidence:** These are solved problems. knip has 3M weekly downloads. dependency-cruiser is the standard for JS/TS architecture enforcement. All have programmatic APIs except knip (JSON CLI).

### Layer 2: Secret Detection

| Detection | Tool | How | Confidence |
|-----------|------|-----|------------|
| API keys, tokens | gitleaks (binary) | 150+ regex patterns + entropy | High (~95%+) |
| Hardcoded passwords | gitleaks | Pattern + context | High |
| PII in code/comments | detect-secrets (pypi) | Plugin architecture | Moderate-High |

**Evidence:** Secret formats are structured (AKIA..., ghp_..., sk_live_...). Regex + entropy is near-perfect for known patterns. ML adds ~5-10% marginal improvement (CredSweeper benchmark). Rule-based is sufficient.

**Distribution note:** gitleaks is a Go binary (~10MB). Options:
- Bundle platform-specific binary in npm package (like esbuild does)
- Ship as optional: `npx codesentinel --install-secrets`
- Docker image bundles everything

### Layer 3: Semantic Analysis (the AI layer)

| Detection | How | Evidence |
|-----------|-----|----------|
| Semantic code duplication (Type-3/4) | Embed functions → cosine similarity | CodeBERT F1=0.928 on BigCloneBench Type-4 (Feng et al. 2020, EMNLP) |
| Structural drift | Embed files → cluster → compare clusters to folder structure | Proven in software architecture recovery literature (ICSME, MSR) |
| Intent recovery for orphans | Static finds orphan → embeddings find nearest semantic neighbors | Qdrant cookbook pattern (HuggingFace) |
| Redundant agent work | Two files with high embedding similarity + low import overlap | Logical extension of clone detection |

**Model choice:**

| Model | ONNX Size | Quality | Transformers.js? | License |
|-------|-----------|---------|-------------------|---------|
| `onnx-community/codebert-base-ONNX` | 125MB (INT8) | F1=0.928 Type-4 clones | Yes (standard RoBERTa) | MIT |
| `onnx-community/CodeBERTa-small-v1-ONNX` | 84MB (INT8) | Lower (MLM, not contrastive) | Yes | MIT |
| `jinaai/jina-embeddings-v2-base-code` | 162MB (quantized) | Best (contrastive-trained on 150M code pairs) | Risk (custom arch) | Apache-2.0 |

**Recommendation:** Start with `onnx-community/codebert-base-ONNX` (125MB, MIT, guaranteed Transformers.js compatibility). Upgrade to Jina code if needed after field testing.

**Why not MiniLM:** 0.801 MRR on NL→code search is decent, but for duplication detection (code→code similarity), code-trained models are proven (F1=0.928 vs estimated ~0.5-0.6). The 45MB size difference doesn't justify the quality gap.

---

## FREE TOOL STACK — FULL INVENTORY

### Core (npm — ships with the CLI)

| Package | Purpose | API Type | Size |
|---------|---------|----------|------|
| `@huggingface/transformers` | ONNX model inference | Programmatic | ~2MB (model downloaded separately) |
| `dependency-cruiser` | Import graph, architecture rules, orphans | Programmatic API | ~2.5MB |
| `madge` | Circular dependencies, orphan detection | Programmatic API | ~1MB |
| `@ast-grep/napi` | AST pattern matching, custom security rules | Programmatic napi | ~5MB |
| `eslint` + `eslint-plugin-security` | JS/TS security patterns | Programmatic API | ~10MB |
| `typhonjs-escomplex` | Cyclomatic complexity, maintainability | Programmatic API | ~1MB |
| `chokidar` | File watching | Programmatic API | ~50KB |

### CLI-composed (JSON output, spawned as child process)

| Package | Purpose | Install | Size |
|---------|---------|---------|------|
| `knip` | Dead files, unused exports, unused deps | npm (peer) | ~5MB |
| `gitleaks` | Secret detection | Binary (platform-specific) | ~10MB |
| `semgrep` | Advanced SAST rules (optional) | pypi or binary | ~100MB |

### Optional Python layer (if user has Python)

| Package | Purpose | Install | Size |
|---------|---------|---------|------|
| `vulture` | Python dead code | pip | ~100KB |
| `radon` | Python complexity metrics | pip | ~200KB |
| `bandit` | Python security | pip | ~500KB |
| `detect-secrets` | Secret detection (alternative) | pip | ~1MB |

---

## DISTRIBUTION STRATEGY

### Option A: npm-first (recommended for v1)

```bash
npm install -g codesentinel
# or
npx codesentinel
```

**What ships in npm package:**
- Orchestrator + all Layer 1 tools (pure npm deps)
- Embedding model auto-downloads on first run (~125MB to ~/.cache/)
- Layer 2 (gitleaks) bundled as optional platform binary

**Total npm install size:** ~25MB (without model)
**First run download:** ~125MB (model, one-time)

### Option B: Docker (batteries-included)

```bash
docker pull codesentinel/codesentinel
# or
podman pull codesentinel/codesentinel
```

**What ships in image:**
- Everything from Option A
- Pre-downloaded model
- gitleaks binary
- semgrep + Python tools (vulture, radon, bandit)
- No internet needed after pull

**Image size estimate:** ~500MB (alpine-based, multi-stage build)

**Usage:**
```bash
# Watch mode — mount project dir, stream findings
docker run -v $(pwd):/project codesentinel/codesentinel watch

# One-shot scan
docker run -v $(pwd):/project codesentinel/codesentinel scan

# Output JSON for agent consumption
docker run -v $(pwd):/project codesentinel/codesentinel scan --json
```

### Option C: pypi (Python-native alternative)

```bash
pip install codesentinel
```

Wraps the same logic but uses Python ecosystem natively (vulture, radon, bandit, detect-secrets, credsweeper). Uses `onnxruntime` (Python) instead of Transformers.js. Same ONNX model.

**Why both npm and pypi:** Different developer ecosystems. JS devs won't install Python. Python devs won't install Node. The model and logic are the same — only the runtime wrapper differs.

### Option D: Standalone binary (future)

Use `pkg` (npm→binary) or `bun build --compile` to produce a single executable. Zero runtime dependencies.

---

## PHASE PLAN (REVISED)

### Phase 0 — Proof of Concept (validate the AI layer)
**Duration:** 2-3 days
**Goal:** Prove CodeBERT embeddings detect semantic duplication in real projects

**Tasks:**
1. Single Node.js script: load `onnx-community/codebert-base-ONNX` via `@huggingface/transformers`
2. Parse a real project with `@ast-grep/napi` — extract all functions
3. Embed each function, compute pairwise cosine similarity
4. Display pairs with similarity > 0.85
5. **Decision gate:** Do the flagged pairs represent actual semantic duplication?
   - YES → proceed
   - NO → try textification (convert code to NL descriptions before embedding)
   - STILL NO → try `jinaai/jina-embeddings-v2-base-code` (162MB, contrastive-trained)

**Why this is Phase 0:** If the AI layer doesn't work, the rest is just a wrapper around existing tools (still useful, but not differentiated). Validate the hard part first.

### Phase 1 — Static Layer MVP
**Duration:** 3-4 days
**Dependency:** None (parallel with Phase 0)
**Goal:** Wire up free tools into a single scan command

**Tasks:**
1. CLI skeleton: `codesentinel scan [dir]`
2. Integrate dependency-cruiser (orphans, circular deps, architecture violations)
3. Integrate madge (circular deps visualization)
4. Integrate knip via JSON (dead files, unused exports)
5. Integrate eslint-plugin-security (JS/TS security patterns)
6. Integrate typhonjs-escomplex (complexity thresholds)
7. Unified finding format:
   ```json
   {
     "id": "DEAD-FILE-001",
     "layer": "static",
     "type": "dead-file",
     "severity": "warning",
     "confidence": 1.0,
     "file": "src/old-utils.ts",
     "message": "File has zero importers",
     "tool": "knip",
     "suggestion": null
   }
   ```
8. Confidence gate: only display findings with confidence ≥ threshold (default 0.9)

### Phase 2 — Secret Layer
**Duration:** 1-2 days
**Dependency:** Phase 1 (needs finding format)

**Tasks:**
1. Bundle gitleaks binary (platform-specific optional dep, like esbuild model)
2. Run gitleaks on scan, parse JSON output
3. Map findings to unified format
4. Fallback: if gitleaks not available, use regex-based JS implementation for top-20 secret patterns (AWS, GitHub, Stripe, etc.)

### Phase 3 — Semantic Layer (AI)
**Duration:** 3-4 days
**Dependency:** Phase 0 (validation passed)

**Tasks:**
1. Function extraction pipeline: ast-grep → extract functions across JS/TS/Python/Go
2. Textification: function signature + name + imports → natural language description
3. Embedding pipeline: batch-embed all functions on first scan
4. Cache: store embeddings + file mtimes in `~/.cache/codesentinel/<project-hash>/`
5. Duplication detection: flag function pairs with cosine similarity > threshold
6. Structural drift: cluster file embeddings, compare to directory structure
7. Intent recovery: when static layer finds an orphan, semantic layer finds its nearest neighbors and suggests where to connect it

### Phase 4 — Watch Mode
**Duration:** 2 days
**Dependency:** Phases 1-3

**Tasks:**
1. chokidar file watcher with debouncing (300ms)
2. On change: re-run only affected analyzers
   - File added → knip (is it connected?), semantic (embed + check for duplicates)
   - File modified → security scan, complexity check, re-embed
   - File deleted → update import graph, remove from embedding cache
3. Incremental embedding: only re-embed changed files (mtime comparison)
4. Terminal output: live-updating dashboard or log stream

### Phase 5 — Agent Integration
**Duration:** 2 days
**Dependency:** Phase 4

**Tasks:**
1. `--json` output mode for machine consumption
2. `--agent` output mode: structured findings formatted for Claude/LLM context
3. Pipe-friendly: `codesentinel scan --json | claude "review these findings"`
4. SARIF output for IDE integration (VS Code problem matcher)
5. Webhook/stdout streaming for integration with agent orchestrators

### Phase 6 — Hardening + Distribution
**Duration:** 3 days
**Dependency:** Phase 5

**Tasks:**
1. Error handling: graceful degradation if optional tools missing
2. Cross-platform testing: macOS arm64, Linux x64, Windows x64
3. npm package configuration + publish
4. Docker image: multi-stage build, alpine base, all tools pre-installed
5. pypi wrapper (if demand exists)
6. GitHub Actions CI: test matrix

---

## CONFIDENCE MODEL

Every finding has a confidence score. The ≥90% gate is enforced by default.

| Layer | Finding Type | Confidence Basis |
|-------|-------------|------------------|
| Static | Dead file | 1.0 — deterministic (import graph) |
| Static | Circular dep | 1.0 — deterministic |
| Static | Unused export | 1.0 — deterministic |
| Static | Architecture violation | 1.0 — deterministic (user-defined rules) |
| Static | Security anti-pattern | 0.85-0.95 — pattern match quality varies |
| Static | Complexity spike | 1.0 — deterministic (threshold-based) |
| Secret | Known pattern match | 0.90-0.99 — based on regex specificity + entropy score |
| Secret | High-entropy string | 0.70-0.85 — entropy alone has false positives |
| Semantic | Duplicate (similarity > 0.95) | 0.90+ — backed by BigCloneBench F1=0.928 |
| Semantic | Duplicate (similarity 0.85-0.95) | 0.70-0.89 — "possible duplicate, review" |
| Semantic | Structural drift | 0.75-0.85 — clustering is heuristic |
| Semantic | Intent recovery | 0.60-0.80 — suggestion only, never auto-action |

**Gate logic:**
- `confidence >= 0.90` → Display as finding (default)
- `confidence 0.70-0.89` → Display only with `--verbose` or `--threshold 0.7`
- `confidence < 0.70` → Suppressed (available in `--debug`)

---

## WHAT THIS IS NOT

- **Not a linter.** ESLint/Prettier handle formatting and style. CodeSentinel handles structural and semantic problems.
- **Not a test runner.** It doesn't execute code. It analyzes code statically + semantically.
- **Not an LLM.** The embedded model is a 125MB encoder that produces vectors. It doesn't generate text, chat, or hallucinate. It computes similarity scores — math, not magic.
- **Not a replacement for code review.** It's an early warning system that catches what humans and agents miss at scale.

---

## COMPETITIVE LANDSCAPE

| Tool | What it does | What CodeSentinel adds |
|------|-------------|----------------------|
| knip | Dead files, unused exports | We compose knip + add semantic analysis |
| SonarQube | SAST + code quality | Cloud-dependent, heavy. We're local-first, zero-config |
| Semgrep | Pattern-based security | We compose semgrep + add semantic duplication |
| jscpd | Textual code duplication | Type-1/2 only. We detect Type-3/4 (semantic) |
| CodeClimate | Code quality dashboard | Cloud SaaS. We're local CLI |
| Codacy | Automated code review | Cloud SaaS. We're local CLI |

**Unique differentiator:** No existing tool combines static analysis + semantic AI for duplication/drift detection in a local, zero-config CLI. The multi-agent development use case (detecting disconnected/redundant agent work) is unserved.

---

## DEPENDENCY MAP (REVISED)

```
Phase 0 (AI Validation) ─────────────────┐
                                          │
Phase 1 (Static Layer) ──┐               │
                          │               │
Phase 2 (Secrets) ────────┤               │
                          │               │
                          ▼               ▼
                    Phase 3 (Semantic Layer)
                          │
                          ▼
                    Phase 4 (Watch Mode)
                          │
                          ▼
                    Phase 5 (Agent Integration)
                          │
                          ▼
                    Phase 6 (Hardening + Distribution)
```

Phases 0 and 1 run in parallel. Phase 0 validates the AI bet. Phase 1 delivers value even if Phase 0 fails (you'd still have the best-composed static analysis CLI).

---

## TOTAL EFFORT

| Phase | Duration | Parallel? |
|-------|----------|-----------|
| Phase 0 — AI Validation | 2-3 days | Yes (with Phase 1) |
| Phase 1 — Static Layer MVP | 3-4 days | Yes (with Phase 0) |
| Phase 2 — Secret Layer | 1-2 days | After Phase 1 |
| Phase 3 — Semantic Layer | 3-4 days | After Phase 0 |
| Phase 4 — Watch Mode | 2 days | After 1+3 |
| Phase 5 — Agent Integration | 2 days | After Phase 4 |
| Phase 6 — Hardening | 3 days | After Phase 5 |
| **TOTAL** | **~12-14 days** | With parallelization: **~10 days** |

---

## RISK REGISTER (REVISED)

| Risk | Impact | Mitigation | Evidence |
|------|--------|------------|----------|
| CodeBERT embeddings don't catch real duplicates | Semantic layer is useless | Phase 0 validation before investing. Fallback: Jina code model (contrastive-trained) | BigCloneBench F1=0.928 suggests it will work |
| Too many tools = too slow for watch mode | Bad UX | Profile each tool. Cache aggressively. Only run affected analyzers per change | dependency-cruiser: <2s on 1000-file projects |
| gitleaks binary distribution is messy | npm install fails on some platforms | Optional dep with JS regex fallback. Docker image as alternative | esbuild successfully ships platform binaries via npm |
| ONNX model too large for npm | Package bloat | Model downloaded on first run (like @huggingface/transformers pattern) | MiniLM does this today: 23MB auto-download |
| Users don't have Node 20+ | Can't use chokidar v4 | Support Node 18 with chokidar v3 fallback or use @parcel/watcher | Check engine requirements |
| False positives annoy users | Tool gets ignored | 90% confidence gate. Conservative thresholds. Easy suppress per-finding | Confidence model designed for this |

---

## SUCCESS CRITERIA

- [ ] `npx codesentinel scan` produces useful findings on a real 500+ file project
- [ ] Zero false positives at default threshold (90% confidence)
- [ ] Semantic layer catches at least one duplication that jscpd/textual tools miss
- [ ] Watch mode reacts to changes in <3 seconds
- [ ] Full scan completes in <30 seconds (first run) / <5 seconds (cached)
- [ ] Works on macOS, Linux, Windows
- [ ] Zero configuration required (sensible defaults)
- [ ] Zero network calls after model download
- [ ] Agent-consumable output (JSON/structured) works with Claude
- [ ] Published on npm with `npx codesentinel` support

---

## RESEARCH SOURCES

All architectural decisions are backed by:

**Embedding models:**
- Feng et al. 2020 — CodeBERT (EMNLP)
- Guo et al. 2021 — GraphCodeBERT (ICLR)
- Guo et al. 2022 — UniXcoder (ACL)
- Singh benchmark — MiniLM vs code models on CodeSearchNet

**Duplication detection:**
- Svajlenko & Roy 2014 — BigCloneBench (ICSME)
- Wang et al. 2023 — CodeT5+ (EMNLP)
- Lu et al. 2021 — CodeXGLUE (NeurIPS)

**Security:**
- Fu & Tantithamthavorn 2022 — LineVul
- Zhou et al. 2019 — Devign dataset
- Chakraborty et al. 2021 — ReVeal dataset

**Architecture:**
- HuggingFace/Qdrant Cookbook — Code Search with Vector Embeddings
- CoIR benchmark (ACL 2025)
- SearchBySnippet (arxiv 2305.11625)
