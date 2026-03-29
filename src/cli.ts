#!/usr/bin/env node
// ============================================================
// CodeSentinel — CLI Entry Point
// ============================================================

// Suppress the ONNX Runtime mutex destructor crash on macOS.
// The C++ runtime sometimes fires "mutex lock failed: Invalid argument"
// during process teardown when ONNX background threads are still live.
// This is not a real error — the scan has already completed successfully.
process.on('uncaughtException', (err) => {
  if (err && typeof err === 'object' && 'message' in err &&
      String((err as Error).message).includes('mutex')) {
    // Swallow the ONNX mutex crash silently — scan already finished.
    process.exit(0);
  }
  console.error(err);
  process.exit(1);
});

import { resolve } from 'node:path';
import { rmSync, existsSync } from 'node:fs';
import { Command, Option } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { loadConfig } from './config.js';
import { Orchestrator } from './orchestrator.js';
import { Watcher } from './watcher.js';
import type { SentinelConfig, Finding } from './types.js';

// ── CLI version pulled from package.json (Node16 resolveJsonModule) ──────────
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { version } = require('../package.json') as { version: string };

// ── Global option types ───────────────────────────────────────────────────────
interface GlobalOptions {
  threshold?: string;
  format?: string;
  verbose?: boolean;
  semantic?: boolean;
  secrets?: boolean;
  static?: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function resolveDir(dir: string | undefined): string {
  return resolve(dir ?? process.cwd());
}

/**
 * Load config from disk then overlay CLI flag overrides.
 */
function buildConfig(rootDir: string, opts: GlobalOptions): SentinelConfig {
  const config = loadConfig(rootDir);

  if (opts.threshold !== undefined) {
    const parsed = parseFloat(opts.threshold);
    if (isNaN(parsed) || parsed < 0 || parsed > 1) {
      console.error(chalk.red('--threshold must be a number between 0 and 1'));
      process.exit(1);
    }
    config.confidenceThreshold = parsed;
  }

  if (opts.format !== undefined) {
    const allowed = ['terminal', 'json', 'sarif', 'agent'] as const;
    if (!allowed.includes(opts.format as (typeof allowed)[number])) {
      console.error(chalk.red(`--format must be one of: ${allowed.join(', ')}`));
      process.exit(1);
    }
    config.output.format = opts.format as SentinelConfig['output']['format'];
  }

  if (opts.verbose) {
    config.output.verbose = true;
  }

  // --no-semantic / --no-secrets / --no-static disable the respective analyzers.
  // Commander maps --no-<flag> to opts.<flag> = false.
  if (opts.semantic === false) {
    config.analyzers.semantic.enabled = false;
  }
  if (opts.secrets === false) {
    config.analyzers.secrets.enabled = false;
  }
  if (opts.static === false) {
    config.analyzers.static.enabled = false;
  }

  return config;
}

function getGlobalOpts(cmd: Command): GlobalOptions {
  // Walk up to root command to collect inherited global options
  let root: Command = cmd;
  while (root.parent !== null) {
    root = root.parent;
  }
  return root.opts<GlobalOptions>();
}

// ── Program definition ────────────────────────────────────────────────────────

const program = new Command();

program
  .name('codesentinel')
  .description('Continuous code watchdog — static, secrets, and semantic analysis')
  .version(version)
  // Global options (inherited by all subcommands via .opts() on root)
  .addOption(
    new Option('--threshold <n>', 'confidence threshold (0–1)').default('0.9')
  )
  .addOption(
    new Option('--format <type>', 'output format').choices(['terminal', 'json', 'sarif', 'agent']).default('terminal')
  )
  .option('--verbose', 'show all findings including below-threshold', false)
  .option('--no-semantic', 'skip semantic analysis (faster)')
  .option('--no-secrets', 'skip secret scanning')
  .option('--no-static', 'skip static analysis');

// ── scan ──────────────────────────────────────────────────────────────────────

program
  .command('scan [dir]', { isDefault: true })
  .description('Run a one-shot analysis of a directory')
  .action(async (dir: string | undefined, _opts: Record<string, unknown>, cmd: Command) => {
    const rootDir = resolveDir(dir);
    const config = buildConfig(rootDir, getGlobalOpts(cmd));

    const orchestrator = new Orchestrator(config);

    const spinner = ora({
      text: `Scanning ${rootDir} …`,
      color: 'cyan',
    }).start();

    try {
      const findings = await orchestrator.runFullScan();
      spinner.stop();

      await orchestrator.report(findings);

      const hasErrors = findings.some(
        (f: Finding) => f.severity === 'error' && f.confidence >= config.confidenceThreshold
      );

      // Force exit to prevent the ONNX Runtime mutex destructor race on macOS.
      // When the semantic layer is active, ONNX background threads may still be
      // winding down during Node.js's cleanup phase, causing an abort trap.
      // The Embedder.dispose() call in the orchestrator is the primary fix;
      // this exit is the safety net that bypasses the GC-triggered destructor
      // entirely for the common one-shot scan case.
      process.exit(hasErrors ? 1 : 0);
    } catch (err) {
      spinner.fail('Scan failed');
      console.error(chalk.red((err instanceof Error ? err.message : String(err))));
      process.exit(1);
    }
  });

// ── watch ─────────────────────────────────────────────────────────────────────

program
  .command('watch [dir]')
  .description('Watch a directory and re-analyse on file changes')
  .action(async (dir: string | undefined, _opts: Record<string, unknown>, cmd: Command) => {
    const rootDir = resolveDir(dir);
    const config = buildConfig(rootDir, getGlobalOpts(cmd));
    config.watch.enabled = true;

    const orchestrator = new Orchestrator(config);
    const watcher = new Watcher(config, orchestrator);

    console.log(chalk.cyan(`[CodeSentinel] Starting watcher on ${rootDir}`));
    console.log(chalk.dim('Press Ctrl+C to stop.\n'));

    // Run an initial full scan before entering watch mode
    const spinner = ora({ text: 'Initial scan …', color: 'cyan' }).start();
    try {
      const findings = await orchestrator.runFullScan();
      spinner.stop();
      await orchestrator.report(findings);
    } catch (err) {
      spinner.fail('Initial scan failed');
      console.error(chalk.red((err instanceof Error ? err.message : String(err))));
      // Don't exit — keep watching even if the first scan fails
    }

    watcher.start();

    // Graceful shutdown
    const shutdown = (): void => {
      console.log(chalk.dim('\n[CodeSentinel] Shutting down…'));
      watcher.stop();
      process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  });

// ── clear-cache ───────────────────────────────────────────────────────────────

program
  .command('clear-cache [dir]')
  .description('Clear the embedding cache for a directory')
  .action(async (dir: string | undefined, _opts: Record<string, unknown>, cmd: Command) => {
    const rootDir = resolveDir(dir);
    const config = buildConfig(rootDir, getGlobalOpts(cmd));
    const orchestrator = new Orchestrator(config);
    const cachePath = orchestrator.getCachePath();

    if (!existsSync(cachePath)) {
      console.log(chalk.yellow(`No cache found at ${cachePath}`));
      return;
    }

    try {
      rmSync(cachePath, { recursive: true, force: true });
      console.log(chalk.green(`Cache cleared: ${cachePath}`));
    } catch (err) {
      console.error(chalk.red(`Failed to clear cache: ${err instanceof Error ? err.message : String(err)}`));
      process.exit(1);
    }
  });

// ── Parse ─────────────────────────────────────────────────────────────────────

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(chalk.red(err instanceof Error ? err.message : String(err)));
  process.exit(1);
});
