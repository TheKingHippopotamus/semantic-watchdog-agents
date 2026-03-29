import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { SentinelConfig } from './types.js';

const DEFAULT_CONFIG: SentinelConfig = {
  rootDir: process.cwd(),
  confidenceThreshold: 0.9,
  ignore: [
    'node_modules', '.git', 'dist', 'build', 'coverage',
    '.next', '.nuxt', '.output', '__pycache__', '.venv',
    'vendor', '.agent-office'
  ],
  analyzers: {
    static: {
      enabled: true,
      deadCode: true,
      circularDeps: true,
      dependencies: true,
      security: true,
      complexity: true,
      complexityThreshold: 20,
      testCoverage: true,
      crossProjectDuplication: true,
    },
    secrets: {
      enabled: true,
      useGitleaks: true,
      regexFallback: true,
    },
    semantic: {
      enabled: true,
      model: 'onnx-community/codebert-base-ONNX',
      duplication: true,
      duplicationThreshold: 0.97,
      drift: true,
      intentRecovery: true,
    },
  },
  watch: {
    enabled: false,
    debounceMs: 300,
  },
  output: {
    format: 'terminal',
    verbose: false,
  },
};

export function loadConfig(rootDir: string): SentinelConfig {
  const config = { ...DEFAULT_CONFIG, rootDir };

  const configPaths = [
    join(rootDir, '.sentinelrc.json'),
    join(rootDir, '.sentinelrc'),
  ];

  for (const configPath of configPaths) {
    if (existsSync(configPath)) {
      const userConfig = JSON.parse(readFileSync(configPath, 'utf-8'));
      const result = deepMerge(config, userConfig) as unknown as SentinelConfig;
      // SEC-05: never allow config to redirect scanning to arbitrary paths
      result.rootDir = rootDir;
      return result;
    }
  }

  // Load .sentinelignore if exists
  const ignorePath = join(rootDir, '.sentinelignore');
  if (existsSync(ignorePath)) {
    const ignoreLines = readFileSync(ignorePath, 'utf-8')
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
    config.ignore = [...config.ignore, ...ignoreLines];
  }

  return config;
}

function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (
      source[key] && typeof source[key] === 'object' && !Array.isArray(source[key]) &&
      target[key] && typeof target[key] === 'object' && !Array.isArray(target[key])
    ) {
      result[key] = deepMerge(target[key] as Record<string, unknown>, source[key] as Record<string, unknown>);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}
