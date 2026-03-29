// ============================================================
// CodeSentinel — Gitleaks Secret Detection Adapter
// ============================================================

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';

const execFileAsync = promisify(execFile);

// ── Gitleaks JSON output schema ──────────────────────────────────────────────

/**
 * A single finding emitted by `gitleaks detect --report-format json`.
 * Fields are PascalCase as gitleaks serialises them.
 */
interface GitleaksRawFinding {
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  File: string;
  SymlinkFile: string;
  Commit: string;
  Entropy: number;
  Author: string;
  Email: string;
  Date: string;
  Message: string;
  Tags: string[] | null;
  RuleID: string;
  Fingerprint: string;
}

// ── Rule classification helpers ──────────────────────────────────────────────

/**
 * Known gitleaks rule IDs whose pattern matches a specific credential format
 * (not merely entropy-based). Used to assign confidence 0.95.
 *
 * This list covers the rules shipped with gitleaks v8 default config.
 * See: https://github.com/gitleaks/gitleaks/blob/main/config/gitleaks.toml
 */
const PATTERN_BASED_RULE_IDS = new Set([
  'aws-access-token',
  'aws-secret-access-key',
  'github-pat',
  'github-fine-grained-pat',
  'github-oauth',
  'github-app-token',
  'github-refresh-token',
  'gitlab-pat',
  'gitlab-ptt',
  'gitlab-rrt',
  'slack-bot-token',
  'slack-app-level-token',
  'slack-legacy-token',
  'slack-user-token',
  'slack-webhook-url',
  'slack-config-access-token',
  'slack-config-refresh-token',
  'stripe-access-token',
  'stripe-publishable-token',
  'twilio-api-key',
  'sendgrid-api-token',
  'mailchimp-api-key',
  'mailgun-private-api-token',
  'mailgun-pub-key',
  'mailgun-signing-key',
  'npm-access-token',
  'pypi-upload-token',
  'rubygems-api-token',
  'heroku-api-key',
  'digitalocean-pat',
  'digitalocean-access-token',
  'dropbox-api-secret',
  'dropbox-short-lived-api-token',
  'dropbox-long-lived-api-token',
  'twitch-api-token',
  'twitter-api-key',
  'twitter-api-secret',
  'twitter-access-token',
  'twitter-access-secret',
  'facebook-access-token',
  'facebook-page-access-token',
  'linkedin-access-token',
  'linkedin-client-id',
  'linkedin-client-secret',
  'google-api-key',
  'google-cloud-service-account',
  'gcp-api-key',
  'datadog-api-key',
  'datadog-app-key',
  'newrelic-user-api-key',
  'newrelic-user-api-id',
  'newrelic-ingest-browser-api-key',
  'okta-access-token',
  'auth0-access-token',
  'vault-service-token',
  'vault-batch-token',
  'hashicorp-tf-api-token',
  'jwt',
  'jwt-base64',
  'ssh-dsa-private-key',
  'ssh-ec-private-key',
  'ssh-rsa-private-key',
  'ssh-openssh-private-key',
  'pgp-private-key',
  'pkcs8-private-key',
  'secret-value-in-dsn',
  'generic-api-key',
  'generic-secret',
  'private-key',
  'password-in-url',
]);

/**
 * Maps a gitleaks RuleID to a human-readable secret type label used in the
 * Finding message. Falls back to a formatted version of the rule ID itself.
 */
const RULE_LABEL_MAP: Record<string, string> = {
  'aws-access-token': 'AWS Access Key',
  'aws-secret-access-key': 'AWS Secret Access Key',
  'github-pat': 'GitHub Personal Access Token',
  'github-fine-grained-pat': 'GitHub Fine-Grained Token',
  'github-oauth': 'GitHub OAuth Token',
  'github-app-token': 'GitHub App Token',
  'github-refresh-token': 'GitHub Refresh Token',
  'gitlab-pat': 'GitLab Personal Access Token',
  'gitlab-ptt': 'GitLab Pipeline Trigger Token',
  'gitlab-rrt': 'GitLab Runner Registration Token',
  'slack-bot-token': 'Slack Bot Token',
  'slack-app-level-token': 'Slack App-Level Token',
  'slack-legacy-token': 'Slack Legacy Token',
  'slack-user-token': 'Slack User Token',
  'slack-webhook-url': 'Slack Webhook URL',
  'slack-config-access-token': 'Slack Config Access Token',
  'slack-config-refresh-token': 'Slack Config Refresh Token',
  'stripe-access-token': 'Stripe Access Key',
  'stripe-publishable-token': 'Stripe Publishable Key',
  'twilio-api-key': 'Twilio API Key',
  'sendgrid-api-token': 'SendGrid API Key',
  'mailchimp-api-key': 'Mailchimp API Key',
  'mailgun-private-api-token': 'Mailgun Private API Token',
  'mailgun-pub-key': 'Mailgun Public Key',
  'mailgun-signing-key': 'Mailgun Signing Key',
  'npm-access-token': 'npm Access Token',
  'pypi-upload-token': 'PyPI Upload Token',
  'rubygems-api-token': 'RubyGems API Token',
  'heroku-api-key': 'Heroku API Key',
  'digitalocean-pat': 'DigitalOcean Personal Access Token',
  'digitalocean-access-token': 'DigitalOcean Access Token',
  'dropbox-api-secret': 'Dropbox API Secret',
  'dropbox-short-lived-api-token': 'Dropbox Short-Lived Token',
  'dropbox-long-lived-api-token': 'Dropbox Long-Lived Token',
  'twitch-api-token': 'Twitch API Token',
  'twitter-api-key': 'Twitter API Key',
  'twitter-api-secret': 'Twitter API Secret',
  'twitter-access-token': 'Twitter Access Token',
  'twitter-access-secret': 'Twitter Access Secret',
  'facebook-access-token': 'Facebook Access Token',
  'facebook-page-access-token': 'Facebook Page Access Token',
  'linkedin-access-token': 'LinkedIn Access Token',
  'linkedin-client-id': 'LinkedIn Client ID',
  'linkedin-client-secret': 'LinkedIn Client Secret',
  'google-api-key': 'Google API Key',
  'google-cloud-service-account': 'Google Cloud Service Account',
  'gcp-api-key': 'GCP API Key',
  'datadog-api-key': 'Datadog API Key',
  'datadog-app-key': 'Datadog Application Key',
  'newrelic-user-api-key': 'New Relic User API Key',
  'newrelic-user-api-id': 'New Relic User API ID',
  'newrelic-ingest-browser-api-key': 'New Relic Browser API Key',
  'okta-access-token': 'Okta Access Token',
  'auth0-access-token': 'Auth0 Access Token',
  'vault-service-token': 'HashiCorp Vault Service Token',
  'vault-batch-token': 'HashiCorp Vault Batch Token',
  'hashicorp-tf-api-token': 'HashiCorp Terraform API Token',
  'jwt': 'JSON Web Token',
  'jwt-base64': 'JSON Web Token (Base64)',
  'ssh-dsa-private-key': 'SSH DSA Private Key',
  'ssh-ec-private-key': 'SSH EC Private Key',
  'ssh-rsa-private-key': 'SSH RSA Private Key',
  'ssh-openssh-private-key': 'SSH OpenSSH Private Key',
  'pgp-private-key': 'PGP Private Key',
  'pkcs8-private-key': 'PKCS#8 Private Key',
  'private-key': 'Private Key',
  'password-in-url': 'Password in URL',
  'generic-api-key': 'Generic API Key',
  'generic-secret': 'Generic Secret',
  'secret-value-in-dsn': 'Secret Value in DSN',
};

/**
 * Converts a kebab-case rule ID to a human-readable title when no explicit
 * mapping exists (e.g. "my-custom-rule" → "My Custom Rule").
 */
function ruleIdToLabel(ruleId: string): string {
  return ruleId
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

function getLabelForRule(ruleId: string): string {
  return RULE_LABEL_MAP[ruleId.toLowerCase()] ?? ruleIdToLabel(ruleId);
}

/**
 * A finding is entropy-based when gitleaks reports a non-zero Entropy value
 * AND the rule is not in our explicit pattern-match registry.
 */
function isEntropyBased(raw: GitleaksRawFinding): boolean {
  return raw.Entropy > 0 && !PATTERN_BASED_RULE_IDS.has(raw.RuleID.toLowerCase());
}

// ── Binary availability ──────────────────────────────────────────────────────

/**
 * Resolves to the absolute path of the gitleaks binary, or null when it is
 * not available. Uses `which` on POSIX; gracefully handles Windows.
 */
async function resolveGitleaksBinary(): Promise<string | null> {
  const command = process.platform === 'win32' ? 'where' : 'which';
  try {
    const { stdout } = await execFileAsync(command, ['gitleaks']);
    const resolved = stdout.trim().split('\n')[0].trim();
    return resolved.length > 0 ? resolved : null;
  } catch {
    return null;
  }
}

// ── Mapping ──────────────────────────────────────────────────────────────────

function mapToFinding(raw: GitleaksRawFinding): Finding {
  const entropyBased = isEntropyBased(raw);
  const confidence = entropyBased ? 0.85 : 0.95;
  const secretType = getLabelForRule(raw.RuleID);

  // Severity: confirmed pattern match → error; entropy guess → warning
  const severity = entropyBased ? 'warning' : 'error';

  const message = entropyBased
    ? `Possible secret detected (${secretType}) — high-entropy value`
    : `${secretType} detected in source`;

  const suggestion = entropyBased
    ? `Verify this is not a real credential. If so, rotate immediately and use a secrets manager.`
    : `Rotate this credential immediately. Store secrets in a secrets manager (e.g. Vault, AWS Secrets Manager) and reference via environment variables.`;

  // Redact the matched secret value to prevent full credentials from
  // appearing in JSON/agent output. Only the first 4 characters are
  // preserved so the finding remains useful for triage without leaking
  // the actual secret.
  const redactedMatch = raw.Match ? raw.Match.substring(0, 4) + '...' : undefined;

  const meta: Record<string, unknown> = {
    ruleId: raw.RuleID,
    fingerprint: raw.Fingerprint,
    entropy: raw.Entropy,
    match: redactedMatch,
  };

  // Only include commit details when gitleaks ran against git history
  if (raw.Commit) {
    meta['commit'] = raw.Commit;
    meta['author'] = raw.Author;
    meta['date'] = raw.Date;
  }

  if (raw.Tags && raw.Tags.length > 0) {
    meta['tags'] = raw.Tags;
  }

  return {
    id: randomUUID(),
    layer: 'secrets',
    type: raw.RuleID,
    severity,
    confidence,
    file: raw.File || raw.SymlinkFile,
    line: raw.StartLine > 0 ? raw.StartLine : undefined,
    endLine: raw.EndLine > raw.StartLine ? raw.EndLine : undefined,
    message,
    tool: 'gitleaks',
    suggestion,
    meta,
  };
}

// ── Analyzer implementation ──────────────────────────────────────────────────

export class GitleaksAnalyzer implements Analyzer {
  readonly name = 'gitleaks';
  readonly layer = 'secrets' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    if (!context.config.analyzers.secrets.useGitleaks) {
      return [];
    }

    const binary = await resolveGitleaksBinary();
    if (binary === null) {
      // Graceful degradation: caller (fallback.ts) handles the no-binary case
      return [];
    }

    return this.runGitleaks(binary, context.rootDir);
  }

  /**
   * Spawns the gitleaks binary against `sourceDir` and returns parsed
   * findings. Exits 1 when leaks are found (which is expected behaviour) so
   * we treat that exit code as a normal result, not an error.
   */
  private async runGitleaks(binary: string, sourceDir: string): Promise<Finding[]> {
    const args = [
      'detect',
      '--source', sourceDir,
      '--report-format', 'json',
      '--report-path', '/dev/stdout',
      '--no-git',
      '--exit-code', '0',   // always exit 0 so execFile does not throw
    ];

    let stdout: string;

    try {
      const result = await execFileAsync(binary, args, {
        maxBuffer: 64 * 1024 * 1024,  // 64 MB — large mono-repos produce large reports
      });
      stdout = result.stdout;
    } catch (err: unknown) {
      // execFile rejects on non-zero exit or spawn error. With --exit-code 0
      // this only fires on a real spawn failure (binary not executable, etc.).
      const message = err instanceof Error ? err.message : String(err);
      // Return empty rather than surfacing a noisy error — the binary check
      // above already confirmed the path exists, so this is a transient issue.
      process.stderr.write(`[codesentinel/gitleaks] spawn error: ${message}\n`);
      return [];
    }

    return this.parseOutput(stdout);
  }

  /**
   * Parses gitleaks JSON output. Handles three cases:
   *  - Valid array of findings
   *  - `null` literal (no findings, gitleaks quirk on some versions)
   *  - Empty / non-JSON output
   */
  private parseOutput(stdout: string): Finding[] {
    const trimmed = stdout.trim();
    if (!trimmed || trimmed === 'null') {
      return [];
    }

    let raw: unknown;
    try {
      raw = JSON.parse(trimmed);
    } catch {
      // Gitleaks may emit non-JSON warnings to stdout in edge cases
      process.stderr.write(`[codesentinel/gitleaks] failed to parse output: ${trimmed.slice(0, 200)}\n`);
      return [];
    }

    if (!Array.isArray(raw)) {
      return [];
    }

    const findings: Finding[] = [];

    for (const item of raw) {
      if (!isGitleaksRawFinding(item)) {
        continue;
      }
      findings.push(mapToFinding(item));
    }

    return findings;
  }
}

// ── Type guard ───────────────────────────────────────────────────────────────

function isGitleaksRawFinding(value: unknown): value is GitleaksRawFinding {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v['RuleID'] === 'string' &&
    typeof v['File'] === 'string' &&
    typeof v['Description'] === 'string' &&
    typeof v['StartLine'] === 'number'
  );
}
