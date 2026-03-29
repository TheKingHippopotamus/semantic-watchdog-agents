# =============================================================================
# CodeSentinel — Production Dockerfile
# Multi-stage build: builder (compile TypeScript) → runtime (minimal image)
# =============================================================================

# ── Gitleaks version pin ──────────────────────────────────────────────────────
ARG GITLEAKS_VERSION=8.30.1

# =============================================================================
# Stage 1 — Build
# Compiles TypeScript to dist/. Output is copied into the runtime stage.
# =============================================================================
FROM node:22-alpine AS builder

WORKDIR /build

# Install dependencies first (layer cache: only invalidated when lock file changes)
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts

# Copy TypeScript config then source
COPY tsconfig.json ./
COPY src/ ./src/

# Compile
RUN npm run build

# =============================================================================
# Stage 2 — Runtime
# Lean image: only compiled JS, production node_modules, and the gitleaks binary.
# =============================================================================
FROM node:22-alpine AS runtime

LABEL maintainer="CodeSentinel <https://github.com/codesentinel>" \
      org.opencontainers.image.description="Continuous code watchdog — static analysis + semantic AI for dead code, duplication, drift, and secrets" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.source="https://github.com/codesentinel/codesentinel"

# Build-time argument — platform token injected by Docker BuildKit (buildx).
# Values: "linux/amd64" or "linux/arm64"
ARG TARGETPLATFORM
ARG GITLEAKS_VERSION

WORKDIR /app

# ── System dependencies ───────────────────────────────────────────────────────
# curl + tar: download/unpack gitleaks  |  git: needed by some static analysers
RUN apk add --no-cache curl tar git

# ── Gitleaks binary ───────────────────────────────────────────────────────────
# Download the correct pre-built binary for the target platform.
# Gitleaks release naming: linux_x64 for amd64, linux_arm64 for arm64.
RUN set -eux; \
    case "${TARGETPLATFORM}" in \
      "linux/arm64") ARCH="arm64" ;; \
      *)             ARCH="x64"  ;; \
    esac; \
    curl -fsSL \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH}.tar.gz" \
      -o /tmp/gitleaks.tar.gz; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    rm /tmp/gitleaks.tar.gz; \
    chmod +x /usr/local/bin/gitleaks; \
    gitleaks version

# ── Application files ─────────────────────────────────────────────────────────
# Copy compiled output and production node_modules from the builder stage.
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/node_modules ./node_modules
COPY package.json ./

# ── Pre-download CodeBERT ONNX model ─────────────────────────────────────────
# Bake the model into the image so the first `codesentinel scan` command
# does not require network access. The HuggingFace transformers library
# honours the HF_HOME environment variable for its cache location.
#
# We run a tiny inline Node script that initialises the feature-extraction
# pipeline — this triggers the same download path used by the embedder at
# runtime, populating the cache at /root/.cache/huggingface/.
ENV HF_HOME=/root/.cache/huggingface

RUN node --input-type=module <<'EOF'
import { pipeline } from '@huggingface/transformers';

console.log('[docker-build] Pre-downloading onnx-community/codebert-base-ONNX ...');

await pipeline('feature-extraction', 'onnx-community/codebert-base-ONNX', {
  progress_callback: (p) => {
    if (p.status === 'downloading' && typeof p.progress === 'number') {
      const pct = Math.floor(p.progress);
      process.stdout.write(`\r  ${p.name ?? 'weights'} ${pct}%`);
    } else if (p.status === 'ready') {
      process.stdout.write('\n');
    }
  },
});

console.log('[docker-build] Model cached successfully.');
EOF

# ── Mount point for user code ─────────────────────────────────────────────────
VOLUME /project

# ── Runtime configuration ─────────────────────────────────────────────────────
# NODE_ENV: suppress development-only warnings in dependencies.
# HF_HOME already set above — restate for runtime clarity.
ENV NODE_ENV=production \
    HF_HOME=/root/.cache/huggingface

ENTRYPOINT ["node", "dist/cli.js"]
CMD ["scan", "/project"]
