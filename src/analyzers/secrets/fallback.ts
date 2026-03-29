import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Analyzer, AnalysisContext, Finding } from '../../types.js';
import { scanAllFiles, getIgnorePatterns } from '../../utils/git.js';

// ---------------------------------------------------------------------------
// Pattern descriptor
// ---------------------------------------------------------------------------

interface SecretPattern {
  /** Human-readable label used in the Finding.type field */
  label: string;
  /** Compiled RegExp. Must have at least one capture group for the matched value. */
  pattern: RegExp;
  /** Confidence when this pattern fires */
  confidence: number;
  /** Optional: function to further validate the capture group content */
  validate?: (match: string) => boolean;
  /** Short remediation hint */
  suggestion: string;
}

// ---------------------------------------------------------------------------
// Entropy helpers (used to reduce false positives on generic patterns)
// ---------------------------------------------------------------------------

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Returns true when the string looks like a real secret (high entropy) rather than a placeholder */
function isHighEntropy(value: string, threshold = 3.5): boolean {
  // Strip common quote characters that may surround the value
  const stripped = value.replace(/^["'`]|["'`]$/g, '');
  if (stripped.length < 8) return false;
  return shannonEntropy(stripped) >= threshold;
}

function isHighEntropyBase64(value: string): boolean {
  // Base64 alphabet + padding; length must be divisible by 4 or close
  const b64Pattern = /^[A-Za-z0-9+/]{20,}={0,2}$/;
  return b64Pattern.test(value) && isHighEntropy(value, 4.0);
}

function isHighEntropyHex(value: string): boolean {
  const hexPattern = /^[0-9a-fA-F]{16,}$/;
  return hexPattern.test(value) && isHighEntropy(value, 3.2);
}

// ---------------------------------------------------------------------------
// Pattern catalogue — 20 secret types
// ---------------------------------------------------------------------------

const PATTERNS: SecretPattern[] = [
  // 1. AWS Access Key ID
  {
    label: 'aws-access-key-id',
    // Must be exactly 20 uppercase alphanumeric chars starting with AKIA
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    confidence: 0.95,
    suggestion: 'Remove AWS Access Key ID from code. Use IAM roles or environment variables.',
  },

  // 2. AWS Secret Access Key — 40-char base64-like, typically adjacent to AKIA in env context
  {
    label: 'aws-secret-access-key',
    // Named variable assignment OR the 40-char string that follows an AWS context keyword
    pattern: /(?:aws_?secret_?(?:access_?)?key|AWS_SECRET(?:_ACCESS)?_KEY)\s*[=:]\s*["'`]?([A-Za-z0-9/+]{40})["'`]?/gi,
    confidence: 0.95,
    validate: (m) => isHighEntropy(m, 4.0),
    suggestion: 'Remove AWS Secret Key from code. Use AWS Secrets Manager or environment variables.',
  },

  // 3. GitHub tokens — all five prefixes
  {
    label: 'github-token',
    pattern: /\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke and rotate this GitHub token immediately. Store in environment variables.',
  },

  // 4. GitLab personal access token
  {
    label: 'gitlab-token',
    pattern: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke and rotate this GitLab personal access token immediately.',
  },

  // 5. Slack tokens
  {
    label: 'slack-token',
    pattern: /\b(xox[bpoa]-[0-9A-Za-z-]{10,})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Slack token immediately via api.slack.com/apps.',
  },

  // 6. Google API Key
  {
    label: 'google-api-key',
    pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    confidence: 0.95,
    suggestion: 'Restrict or rotate this Google API key in the Google Cloud Console.',
  },

  // 7. Stripe keys (live and test, public and secret)
  {
    label: 'stripe-key',
    pattern: /\b((?:sk|pk)_(?:live|test)_[0-9A-Za-z]{24,})\b/g,
    confidence: 0.95,
    suggestion: 'Rotate this Stripe key immediately via the Stripe Dashboard.',
  },

  // 8. Twilio — Account SID (AC...) and Auth Token (SK...)
  {
    label: 'twilio-credential',
    pattern: /\b((?:AC|SK)[0-9a-fA-F]{32})\b/g,
    confidence: 0.90,
    suggestion: 'Rotate Twilio credentials via the Twilio Console.',
  },

  // 9. SendGrid API key
  {
    label: 'sendgrid-api-key',
    pattern: /\b(SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke and rotate this SendGrid API key immediately.',
  },

  // 10. npm access token
  {
    label: 'npm-token',
    pattern: /\b(npm_[A-Za-z0-9]{36,})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this npm token immediately via npmjs.com.',
  },

  // 11. PyPI upload token
  {
    label: 'pypi-token',
    pattern: /\b(pypi-[A-Za-z0-9_-]{50,})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this PyPI token immediately via pypi.org.',
  },

  // 12. Heroku API key — UUID format
  {
    label: 'heroku-api-key',
    pattern: /(?:heroku[_-]?api[_-]?key|HEROKU_API_KEY)\s*[=:]\s*["'`]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["'`]?/gi,
    confidence: 0.90,
    suggestion: 'Revoke this Heroku API key via the Heroku Dashboard.',
  },

  // 13. JWT token — three base64url segments separated by dots
  {
    label: 'jwt-token',
    // eyJ... is always the header; body and signature follow
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    confidence: 0.90,
    suggestion: 'Do not embed JWT tokens in source code. Use environment variables or a secrets manager.',
  },

  // 14. RSA private key block
  {
    label: 'rsa-private-key',
    pattern: /(-----BEGIN RSA PRIVATE KEY-----)/g,
    confidence: 0.95,
    suggestion: 'Remove private key material from source code. Store in a secure vault.',
  },

  // 15. OpenSSH private key block
  {
    label: 'ssh-private-key',
    pattern: /(-----BEGIN OPENSSH PRIVATE KEY-----)/g,
    confidence: 0.95,
    suggestion: 'Remove private key material from source code. Store in a secure vault.',
  },

  // 16. Database connection strings (postgres, mysql, mongodb)
  {
    label: 'database-connection-string',
    // Matches schemes with user:password@ portion — the password capture group
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:@\s]+:([^@\s]{4,})@[^\s"'`]+/gi,
    confidence: 0.90,
    validate: (m) => isHighEntropy(m, 2.5),
    suggestion: 'Remove credentials from connection strings. Use environment variables.',
  },

  // 17. Basic auth embedded in HTTPS URLs
  {
    label: 'basic-auth-in-url',
    pattern: /https?:\/\/[^:@\s]+:([^@\s]{4,})@[^\s"'`>)]+/gi,
    confidence: 0.85,
    validate: (m) => isHighEntropy(m, 2.5),
    suggestion: 'Remove credentials from URLs. Use environment variables or a secrets manager.',
  },

  // 18. Generic high-entropy base64 strings in secret-named variable assignments
  {
    label: 'high-entropy-secret-base64',
    pattern: /(?:password|passwd|secret|token|api_?key|access_?key|private_?key|auth_?key)\s*[=:]\s*["'`]([A-Za-z0-9+/]{20,}={0,2})["'`]/gi,
    confidence: 0.80,
    validate: isHighEntropyBase64,
    suggestion: 'Move this secret to environment variables or a secrets manager.',
  },

  // 19. Generic high-entropy hex strings in secret-named variable assignments
  {
    label: 'high-entropy-secret-hex',
    pattern: /(?:password|passwd|secret|token|api_?key|access_?key|private_?key|auth_?key)\s*[=:]\s*["'`]([0-9a-fA-F]{32,})["'`]/gi,
    confidence: 0.80,
    validate: isHighEntropyHex,
    suggestion: 'Move this secret to environment variables or a secrets manager.',
  },

  // 20. Generic passwords in config assignments (password = "...", PASSWORD: "...")
  {
    label: 'plaintext-password',
    // Targets value strings of >=8 chars that are not obviously placeholder text
    pattern: /\b(?:password|passwd|PASSWORD|PASSWD)\s*[=:]\s*["'`]([^"'`\s]{8,})["'`]/g,
    confidence: 0.80,
    validate: (m) => {
      const lower = m.toLowerCase();
      // Exclude obvious test/placeholder values
      const placeholders = ['password', 'changeme', 'example', 'placeholder', 'yourpassword', 'enter', 'xxxxxxxx', 'aaaaaaaa', '12345678', 'test1234'];
      if (placeholders.some(p => lower.includes(p))) return false;
      return isHighEntropy(m, 2.8);
    },
    suggestion: 'Remove hardcoded password. Use environment variables or a secrets manager.',
  },

  // ---------------------------------------------------------------------------
  // CLOUD — AWS (additional)
  // ---------------------------------------------------------------------------

  // 21. AWS MWS Auth Token (Amazon Marketplace Web Service)
  {
    label: 'aws-mws-auth-token',
    pattern: /\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this AWS MWS Auth Token in Seller Central and rotate immediately.',
  },

  // 22. AWS Session Token — named variable assignment
  {
    label: 'aws-session-token',
    pattern: /(?:aws[_-]?session[_-]?token|AWS_SESSION_TOKEN)\s*[=:]\s*["'`]?([A-Za-z0-9/+=]{100,})["'`]?/gi,
    confidence: 0.95,
    validate: (m) => isHighEntropy(m, 3.5),
    suggestion: 'Remove AWS Session Token from code. Use IAM roles or instance profiles.',
  },

  // 23. AWS Bedrock API Key (long-lived, ABSK prefix)
  {
    label: 'aws-bedrock-api-key',
    pattern: /\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this AWS Bedrock API Key in the AWS console immediately.',
  },

  // ---------------------------------------------------------------------------
  // CLOUD — GCP
  // ---------------------------------------------------------------------------

  // 24. GCP OAuth Client ID
  {
    label: 'gcp-oauth-client-id',
    pattern: /\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b/g,
    confidence: 0.95,
    suggestion: 'Restrict or rotate this GCP OAuth Client ID in Google Cloud Console.',
  },

  // 25. GCP Service Account JSON marker
  {
    label: 'gcp-service-account-json',
    pattern: /"type"\s*:\s*"service_account"/g,
    confidence: 0.95,
    suggestion: 'Remove GCP service account JSON from source code. Store in a secrets manager.',
  },

  // 26. Google OAuth Access Token (ya29. prefix)
  {
    label: 'google-oauth-access-token',
    pattern: /\b(ya29\.[0-9A-Za-z_\-]{20,})\b/g,
    confidence: 0.95,
    suggestion: 'Remove Google OAuth access token. These expire but must not be committed.',
  },

  // 27. Google OAuth Client Secret (GOCSPX- prefix)
  {
    label: 'google-oauth-client-secret',
    pattern: /\b(GOCSPX-[a-zA-Z0-9_\-]{28})\b/g,
    confidence: 0.95,
    suggestion: 'Rotate this Google OAuth client secret in Google Cloud Console.',
  },

  // ---------------------------------------------------------------------------
  // CLOUD — Azure
  // ---------------------------------------------------------------------------

  // 28. Azure AD Client Secret (3 chars + digit + Q~ prefix pattern)
  {
    label: 'azure-ad-client-secret',
    pattern: /(?:^|["'`\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.\-]{31,34})/gm,
    confidence: 0.95,
    suggestion: 'Rotate this Azure AD client secret in Azure Active Directory.',
  },

  // 29. Azure Connection String (DefaultEndpointsProtocol format)
  {
    label: 'azure-connection-string',
    pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88};/gi,
    confidence: 0.95,
    suggestion: 'Remove Azure connection string. Use Managed Identity or Azure Key Vault.',
  },

  // ---------------------------------------------------------------------------
  // CLOUD — DigitalOcean
  // ---------------------------------------------------------------------------

  // 30. DigitalOcean Personal Access Token
  {
    label: 'digitalocean-pat',
    pattern: /\b(dop_v1_[a-f0-9]{64})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this DigitalOcean PAT in the DO console and rotate immediately.',
  },

  // 31. DigitalOcean OAuth Access Token
  {
    label: 'digitalocean-oauth-token',
    pattern: /\b(doo_v1_[a-f0-9]{64})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this DigitalOcean OAuth token in the DO console immediately.',
  },

  // 32. DigitalOcean OAuth Refresh Token
  {
    label: 'digitalocean-refresh-token',
    pattern: /\b(dor_v1_[a-f0-9]{64})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this DigitalOcean refresh token in the DO console immediately.',
  },

  // ---------------------------------------------------------------------------
  // CLOUD — Cloudflare
  // ---------------------------------------------------------------------------

  // 33. Cloudflare Origin CA Key
  {
    label: 'cloudflare-origin-ca-key',
    pattern: /\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Cloudflare Origin CA Key in the Cloudflare dashboard.',
  },

  // ---------------------------------------------------------------------------
  // CLOUD — Scaleway / Heroku (additional)
  // ---------------------------------------------------------------------------

  // 34. Scaleway API Token
  {
    label: 'scaleway-api-token',
    pattern: /\b(tk-us-[\w\-]{48})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Scaleway API token in the Scaleway console.',
  },

  // 35. Heroku API Key v2 (HRKU-AA prefix)
  {
    label: 'heroku-api-key-v2',
    pattern: /\b(HRKU-AA[0-9a-zA-Z_\-]{58})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Heroku API key via the Heroku Dashboard.',
  },

  // ---------------------------------------------------------------------------
  // CI/CD — GitHub (additional)
  // ---------------------------------------------------------------------------

  // 36. GitHub Fine-Grained PAT
  {
    label: 'github-fine-grained-pat',
    pattern: /\b(github_pat_\w{82})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this GitHub fine-grained PAT immediately via GitHub Settings.',
  },

  // ---------------------------------------------------------------------------
  // CI/CD — GitLab (additional tokens beyond glpat-)
  // ---------------------------------------------------------------------------

  // 37. GitLab Pipeline Trigger Token
  {
    label: 'gitlab-pipeline-trigger-token',
    pattern: /\b(glptt-[0-9a-f]{40})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this GitLab pipeline trigger token in the project Settings > CI/CD.',
  },

  // 38. GitLab Runner Registration Token
  {
    label: 'gitlab-runner-registration-token',
    pattern: /\b(GR1348941[\w\-]{20})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this GitLab runner registration token immediately.',
  },

  // 39. GitLab Runner Auth Token
  {
    label: 'gitlab-runner-auth-token',
    pattern: /\b(glrt-[0-9a-zA-Z_\-]{20})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this GitLab runner auth token in the GitLab runner administration.',
  },

  // 40. GitLab Deploy Token
  {
    label: 'gitlab-deploy-token',
    pattern: /\b(gldt-[0-9a-zA-Z_\-]{20})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this GitLab deploy token in Settings > Repository > Deploy tokens.',
  },

  // 41. GitLab CI/CD Job Token
  {
    label: 'gitlab-cicd-job-token',
    pattern: /\b(glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_\-]{20})\b/g,
    confidence: 0.95,
    suggestion: 'GitLab CI/CD job tokens are ephemeral but must not be stored or logged.',
  },

  // 42. GitLab SCIM / OAuth App Secret
  {
    label: 'gitlab-oauth-app-secret',
    pattern: /\b(gloas-[0-9a-zA-Z_\-]{64})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this GitLab OAuth application secret immediately.',
  },

  // 43. GitLab Kubernetes Agent Token
  {
    label: 'gitlab-k8s-agent-token',
    pattern: /\b(glagent-[0-9a-zA-Z_\-]{50})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this GitLab Kubernetes agent token in the Kubernetes integration settings.',
  },

  // ---------------------------------------------------------------------------
  // COMMUNICATION — Slack (additional)
  // ---------------------------------------------------------------------------

  // 44. Slack Webhook URL
  {
    label: 'slack-webhook-url',
    pattern: /(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,}\/B[a-zA-Z0-9_]{8,}\/[a-zA-Z0-9_]{24})/g,
    confidence: 0.95,
    suggestion: 'Revoke this Slack webhook URL via api.slack.com/apps.',
  },

  // 45. Slack App-Level Token (xapp-)
  {
    label: 'slack-app-token',
    pattern: /\b(xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)\b/gi,
    confidence: 0.95,
    suggestion: 'Revoke this Slack app-level token via api.slack.com/apps.',
  },

  // 46. Slack legacy / workspace tokens (xoxo-, xoxr-, xoxa-)
  {
    label: 'slack-legacy-token',
    pattern: /\b(xox[osar]-(?:\d+-)?[0-9a-zA-Z]{8,48})\b/g,
    confidence: 0.90,
    suggestion: 'Revoke this Slack legacy token immediately via api.slack.com/apps.',
  },

  // ---------------------------------------------------------------------------
  // COMMUNICATION — Discord
  // ---------------------------------------------------------------------------

  // 47. Discord Bot Token
  {
    label: 'discord-bot-token',
    pattern: /\b([MN][A-Za-z\d]{23,}\.[\w\-]{6}\.[\w\-]{27,})\b/g,
    confidence: 0.95,
    suggestion: 'Regenerate this Discord bot token via the Discord Developer Portal.',
  },

  // 48. Discord Webhook URL
  {
    label: 'discord-webhook-url',
    pattern: /(https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_\-]+)/g,
    confidence: 0.95,
    suggestion: 'Delete this Discord webhook via the server/channel settings.',
  },

  // ---------------------------------------------------------------------------
  // COMMUNICATION — Telegram
  // ---------------------------------------------------------------------------

  // 49. Telegram Bot API Token
  {
    label: 'telegram-bot-token',
    // Format: {8-10 digit bot ID}:{35-char alphanumeric+underscore token}
    pattern: /\b(\d{8,10}:[a-zA-Z0-9_\-]{35})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Telegram bot token via BotFather (/revoke command).',
  },

  // ---------------------------------------------------------------------------
  // COMMUNICATION — Additional services
  // ---------------------------------------------------------------------------

  // 50. Sendinblue/Brevo API Key
  {
    label: 'sendinblue-api-key',
    pattern: /\b(xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Sendinblue/Brevo API key in the account settings.',
  },

  // 51. Resend API Key
  {
    label: 'resend-api-key',
    pattern: /\b(re_[a-zA-Z0-9]{30,})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Resend API key in the Resend dashboard.',
  },

  // 52. Mailgun Private API Key
  {
    label: 'mailgun-api-key',
    pattern: /\b(key-[0-9a-zA-Z]{32})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Mailgun API key in the Mailgun dashboard.',
  },

  // 53. Microsoft Teams Webhook
  {
    label: 'microsoft-teams-webhook',
    pattern: /(https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z0-9@\-]+\/IncomingWebhook\/[a-zA-Z0-9]+\/[a-zA-Z0-9\-]+)/g,
    confidence: 0.95,
    suggestion: 'Delete this Microsoft Teams webhook in the channel connectors settings.',
  },

  // ---------------------------------------------------------------------------
  // PAYMENT — Stripe (additional)
  // ---------------------------------------------------------------------------

  // 54. Stripe Webhook Signing Secret
  {
    label: 'stripe-webhook-secret',
    pattern: /\b(whsec_[a-zA-Z0-9]{32,})\b/g,
    confidence: 0.95,
    suggestion: 'Rotate this Stripe webhook signing secret via the Stripe Dashboard.',
  },

  // 55. Stripe Restricted Key
  {
    label: 'stripe-restricted-key',
    pattern: /\b(rk_(?:test|live|prod)_[a-zA-Z0-9]{10,99})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Stripe restricted key via the Stripe Dashboard.',
  },

  // ---------------------------------------------------------------------------
  // PAYMENT — Square
  // ---------------------------------------------------------------------------

  // 56. Square Access Token
  {
    label: 'square-access-token',
    pattern: /\b((?:EAAA|sq0atp-)[A-Za-z0-9_\-]{22,60})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Square access token in the Square Developer Dashboard.',
  },

  // 57. Square OAuth Client Secret
  {
    label: 'square-oauth-secret',
    pattern: /\b(sq0csp-[0-9A-Za-z_\-]{43})\b/g,
    confidence: 0.95,
    suggestion: 'Rotate this Square OAuth client secret in the Square Developer Dashboard.',
  },

  // ---------------------------------------------------------------------------
  // PAYMENT — PayPal / Paddle / Flutterwave
  // ---------------------------------------------------------------------------

  // 58. PayPal Braintree Access Token
  {
    label: 'paypal-braintree-access-token',
    pattern: /\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this PayPal Braintree access token in the Braintree control panel.',
  },

  // 59. Paddle API Key
  {
    label: 'paddle-api-key',
    pattern: /\b((?:live|sdbx)_apikey_[a-zA-Z0-9]{50,})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Paddle API key in the Paddle Developer Tools.',
  },

  // 60. Flutterwave Secret Key
  {
    label: 'flutterwave-secret-key',
    pattern: /\b(FLWSECK_TEST-[a-h0-9]{32}-X)\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Flutterwave secret key in the Flutterwave dashboard.',
  },

  // ---------------------------------------------------------------------------
  // AI/ML
  // ---------------------------------------------------------------------------

  // 61. OpenAI API Key (new proj/svcacct/admin format)
  {
    label: 'openai-api-key',
    pattern: /\b(sk-(?:proj|svcacct|admin)-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this OpenAI API key immediately at platform.openai.com/api-keys.',
  },

  // 62. Anthropic API Key (sk-ant-api03- format)
  {
    label: 'anthropic-api-key',
    pattern: /\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Anthropic API key immediately at console.anthropic.com.',
  },

  // 63. Anthropic Admin API Key
  {
    label: 'anthropic-admin-api-key',
    pattern: /\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Anthropic admin API key immediately at console.anthropic.com.',
  },

  // 64. Hugging Face Access Token
  {
    label: 'huggingface-access-token',
    pattern: /\b(hf_[a-zA-Z]{34})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Hugging Face token at huggingface.co/settings/tokens.',
  },

  // 65. Hugging Face Organization API Token
  {
    label: 'huggingface-org-token',
    pattern: /\b(api_org_[a-zA-Z]{34})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Hugging Face org token at huggingface.co/settings/tokens.',
  },

  // 66. Replicate API Token
  {
    label: 'replicate-api-token',
    pattern: /\b(r8_[a-zA-Z0-9]{37})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Replicate API token at replicate.com/account/api-tokens.',
  },

  // 67. Groq API Key
  {
    label: 'groq-api-key',
    pattern: /\b(gsk_[a-zA-Z0-9]{52})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Groq API key at console.groq.com/keys.',
  },

  // 68. Perplexity API Key
  {
    label: 'perplexity-api-key',
    pattern: /\b(pplx-[a-zA-Z0-9]{48})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Perplexity API key at perplexity.ai/settings/api.',
  },

  // ---------------------------------------------------------------------------
  // MONITORING
  // ---------------------------------------------------------------------------

  // 69. Sentry DSN
  {
    label: 'sentry-dsn',
    pattern: /(https:\/\/[a-zA-Z0-9]+@[a-z0-9]+\.ingest\.sentry\.io\/\d+)/g,
    confidence: 0.95,
    suggestion: 'Rotate this Sentry DSN in the Sentry project settings.',
  },

  // 70. Sentry Org Auth Token (sntrys_ prefix)
  {
    label: 'sentry-org-auth-token',
    pattern: /\b(sntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}={0,2})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Sentry org auth token at sentry.io/settings/auth-tokens.',
  },

  // 71. Sentry User Auth Token (sntryu_ prefix)
  {
    label: 'sentry-user-auth-token',
    pattern: /\b(sntryu_[a-f0-9]{64})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Sentry user auth token at sentry.io/settings/account/api/auth-tokens.',
  },

  // 72. New Relic User API Key (NRAK-)
  {
    label: 'new-relic-user-api-key',
    pattern: /\b(NRAK-[A-Z0-9]{27})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this New Relic user API key at one.newrelic.com/api-keys.',
  },

  // 73. New Relic Ingest/Insert Key (NRII-)
  {
    label: 'new-relic-insert-key',
    pattern: /\b(NRII-[a-zA-Z0-9]{20,})\b/g,
    confidence: 0.95,
    suggestion: 'Rotate this New Relic ingest key at one.newrelic.com/api-keys.',
  },

  // 74. New Relic Browser Key (NRJS-)
  {
    label: 'new-relic-browser-key',
    pattern: /\b(NRJS-[a-f0-9]{19})\b/g,
    confidence: 0.95,
    suggestion: 'Rotate this New Relic browser key at one.newrelic.com/api-keys.',
  },

  // 75. Grafana API Key (eyJrIjoi format)
  {
    label: 'grafana-api-key',
    pattern: /\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Grafana API key in the Grafana Service Accounts settings.',
  },

  // 76. Grafana Cloud API Token (glc_ prefix)
  {
    label: 'grafana-cloud-token',
    pattern: /\b(glc_[A-Za-z0-9+/]{32,400}={0,3})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Grafana Cloud token at grafana.com/profile/api-keys.',
  },

  // 77. Grafana Service Account Token (glsa_ prefix)
  {
    label: 'grafana-service-account-token',
    pattern: /\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Grafana service account token in the Grafana Service Accounts settings.',
  },

  // 78. Dynatrace API Token
  {
    label: 'dynatrace-api-token',
    pattern: /\b(dt0c01\.[a-zA-Z0-9]{24}\.[a-z0-9]{64})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Dynatrace API token in Settings > Integration > Dynatrace API.',
  },

  // ---------------------------------------------------------------------------
  // SaaS / CMS
  // ---------------------------------------------------------------------------

  // 79. Shopify Access Token
  {
    label: 'shopify-access-token',
    pattern: /\b(shpat_[a-fA-F0-9]{32})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Shopify access token in the Partners dashboard.',
  },

  // 80. Shopify Custom App Token
  {
    label: 'shopify-custom-app-token',
    pattern: /\b(shpca_[a-fA-F0-9]{32})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Shopify custom app token in the Shopify admin.',
  },

  // 81. Shopify Private App Token
  {
    label: 'shopify-private-app-token',
    pattern: /\b(shppa_[a-fA-F0-9]{32})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Shopify private app token in the Shopify admin.',
  },

  // 82. Shopify Shared Secret
  {
    label: 'shopify-shared-secret',
    pattern: /\b(shpss_[a-fA-F0-9]{32})\b/g,
    confidence: 0.95,
    suggestion: 'Rotate this Shopify shared secret in the Partners dashboard.',
  },

  // 83. Airtable API Key (key... format)
  {
    label: 'airtable-api-key',
    pattern: /\b(key[a-zA-Z0-9]{14})\b/g,
    confidence: 0.95,
    validate: (m) => isHighEntropy(m, 3.0),
    suggestion: 'Revoke this Airtable API key at airtable.com/account.',
  },

  // 84. Airtable Personal Access Token
  {
    label: 'airtable-pat',
    pattern: /\b(pat[a-zA-Z0-9]{14}\.[a-f0-9]{64})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Airtable PAT at airtable.com/create/tokens.',
  },

  // 85. Notion API Token
  {
    label: 'notion-api-token',
    pattern: /\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Notion integration token at notion.so/my-integrations.',
  },

  // 86. Linear API Key
  {
    label: 'linear-api-key',
    pattern: /\b(lin_api_[a-zA-Z0-9]{40})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Linear API key at linear.app/settings/api.',
  },

  // 87. Asana Personal Access Token
  {
    label: 'asana-pat',
    pattern: /\b(0\/[0-9a-f]{32})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Asana PAT at app.asana.com/0/my-apps.',
  },

  // 88. MailChimp API Key
  {
    label: 'mailchimp-api-key',
    pattern: /\b([0-9a-f]{32}-us[0-9]{1,2})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Mailchimp API key in the Mailchimp account settings.',
  },

  // ---------------------------------------------------------------------------
  // INFRASTRUCTURE
  // ---------------------------------------------------------------------------

  // 89. DSA Private Key block
  {
    label: 'dsa-private-key',
    pattern: /(-----BEGIN DSA PRIVATE KEY-----)/g,
    confidence: 0.95,
    suggestion: 'Remove private key material from source code. Store in a secure vault.',
  },

  // 90. EC Private Key block
  {
    label: 'ec-private-key',
    pattern: /(-----BEGIN EC PRIVATE KEY-----)/g,
    confidence: 0.95,
    suggestion: 'Remove private key material from source code. Store in a secure vault.',
  },

  // 91. PGP Private Key block
  {
    label: 'pgp-private-key',
    pattern: /(-----BEGIN PGP PRIVATE KEY BLOCK-----)/g,
    confidence: 0.95,
    suggestion: 'Remove PGP private key from source code. Store in a secure vault.',
  },

  // 92. Generic private key header (catches ENCRYPTED PRIVATE KEY, PRIVATE KEY, etc.)
  {
    label: 'generic-private-key',
    pattern: /(-----BEGIN[ A-Z0-9_\-]{0,100}PRIVATE KEY[- ]*-----)/g,
    confidence: 0.95,
    suggestion: 'Remove private key material from source code. Store in a secure vault.',
  },

  // 93. Age Encryption Secret Key
  {
    label: 'age-secret-key',
    pattern: /\b(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})\b/g,
    confidence: 0.95,
    suggestion: 'Remove Age secret key from source code. Store in a secure vault.',
  },

  // 94. HashiCorp Vault Service Token (hvs.)
  {
    label: 'vault-service-token',
    pattern: /\b(hvs\.[\w\-]{90,120})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Vault service token via the Vault CLI or API.',
  },

  // 95. HashiCorp Vault Batch Token (hvb.)
  {
    label: 'vault-batch-token',
    pattern: /\b(hvb\.[\w\-]{138,300})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Vault batch token via the Vault CLI or API.',
  },

  // 96. HashiCorp Terraform API Token (atlasv1 format)
  {
    label: 'terraform-cloud-api-token',
    pattern: /\b([a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Terraform Cloud token at app.terraform.io/app/settings/tokens.',
  },

  // 97. Pulumi API Token
  {
    label: 'pulumi-api-token',
    pattern: /\b(pul-[a-f0-9]{40})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Pulumi API token at app.pulumi.com/account/tokens.',
  },

  // 98. Doppler API Token (dp.pt. format)
  {
    label: 'doppler-api-token',
    pattern: /\b(dp\.pt\.[a-zA-Z0-9]{43})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Doppler token at dashboard.doppler.com/workplace/tokens.',
  },

  // ---------------------------------------------------------------------------
  // CRYPTO / BLOCKCHAIN
  // ---------------------------------------------------------------------------

  // 99. Ethereum private key (64-char hex in named variable)
  {
    label: 'ethereum-private-key',
    pattern: /(?:eth[_-]?private[_-]?key|PRIVATE_KEY)\s*[=:]\s*["'`]?(?:0x)?([a-fA-F0-9]{64})["'`]?/gi,
    confidence: 0.95,
    validate: (m) => isHighEntropyHex(m),
    suggestion: 'Remove Ethereum private key immediately. Any funded wallet should be considered compromised.',
  },

  // 100. Bitcoin WIF Private Key
  {
    label: 'bitcoin-wif-private-key',
    pattern: /\b(5[HJK][1-9A-HJ-NP-Za-km-z]{49})\b/g,
    confidence: 0.95,
    suggestion: 'Remove Bitcoin WIF private key. Any funded wallet should be considered compromised.',
  },

  // ---------------------------------------------------------------------------
  // ADDITIONAL SERVICES (high-confidence prefix patterns)
  // ---------------------------------------------------------------------------

  // 101. Cloudinary URL with embedded credentials
  {
    label: 'cloudinary-url',
    pattern: /(cloudinary:\/\/[0-9]{15}:[a-zA-Z0-9_\-]+@[a-zA-Z]+)/g,
    confidence: 0.95,
    suggestion: 'Remove Cloudinary URL credentials. Use CLOUDINARY_URL env var instead.',
  },

  // 102. Supabase Service Role Key
  {
    label: 'supabase-service-role-key',
    pattern: /(?:SUPABASE_SERVICE_ROLE_KEY|supabase[_-]?(?:service[_-]?role)?[_-]?key)\s*[=:]\s*["'`]?(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)["'`]?/gi,
    confidence: 0.95,
    suggestion: 'Do not expose the Supabase service role key. Rotate in Supabase Project Settings > API.',
  },

  // 103. PlanetScale API Token
  {
    label: 'planetscale-api-token',
    pattern: /\b(pscale_tkn_[a-zA-Z0-9_=.\-]{32,64})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this PlanetScale API token at app.planetscale.com/profile/service-tokens.',
  },

  // 104. PlanetScale Password
  {
    label: 'planetscale-password',
    pattern: /\b(pscale_pw_[a-zA-Z0-9_=.\-]{32,64})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this PlanetScale database password at app.planetscale.com.',
  },

  // 105. Firebase Cloud Messaging Server Key
  {
    label: 'firebase-fcm-server-key',
    pattern: /\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Firebase FCM server key in the Firebase Console project settings.',
  },

  // 106. Databricks API Token (dapi prefix)
  {
    label: 'databricks-api-token',
    pattern: /\b(dapi[a-f0-9]{32}(?:-\d)?)\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Databricks API token in User Settings > Access Tokens.',
  },

  // 107. Artifactory API Key (AKCp prefix)
  {
    label: 'artifactory-api-key',
    pattern: /\b(AKCp[A-Za-z0-9]{69})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Artifactory API key in the Artifactory user profile.',
  },

  // 108. Alibaba Cloud Access Key ID
  {
    label: 'alibaba-cloud-access-key',
    pattern: /\b(LTAI[a-zA-Z0-9]{20})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Alibaba Cloud Access Key ID in the Alibaba Cloud RAM console.',
  },

  // 109. Fly.io API Token
  {
    label: 'flyio-api-token',
    pattern: /\b(fo1_[\w\-]{43})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Fly.io token via `fly auth token` or the Fly.io dashboard.',
  },

  // 110. Postman API Token (PMAK- prefix)
  {
    label: 'postman-api-token',
    pattern: /\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Postman API token at go.postman.co/settings/me/api-keys.',
  },

  // 111. Octopus Deploy API Key
  {
    label: 'octopus-deploy-api-key',
    pattern: /\b(API-[A-Z0-9]{26})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Octopus Deploy API key in the user profile API Keys section.',
  },

  // 112. Shippo API Token
  {
    label: 'shippo-api-token',
    pattern: /\b(shippo_(?:live|test)_[a-fA-F0-9]{40})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Shippo API token in the Shippo dashboard API settings.',
  },

  // 113. Duffel API Token
  {
    label: 'duffel-api-token',
    pattern: /\b(duffel_(?:test|live)_[a-zA-Z0-9_\-=]{43})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Duffel API token in the Duffel dashboard.',
  },

  // 114. 1Password Secret Key
  {
    label: '1password-secret-key',
    pattern: /\b(A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})\b/g,
    confidence: 0.95,
    suggestion: 'Treat this 1Password Secret Key as compromised and rotate account credentials.',
  },

  // 115. 1Password Service Account Token (ops_eyJ format)
  {
    label: '1password-service-account-token',
    pattern: /\b(ops_eyJ[a-zA-Z0-9+/]{250,}={0,3})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this 1Password service account token at 1password.com.',
  },

  // 116. NuGet API Key (oy2 prefix)
  {
    label: 'nuget-api-key',
    pattern: /\b(oy2[a-z0-9]{43})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this NuGet API key at nuget.org/account/apikeys.',
  },

  // 117. NuGet Config ClearText Password
  {
    label: 'nuget-config-cleartext-password',
    pattern: /<add\s+key="(?:ClearText)?Password"\s+value="([^"]+)"/gi,
    confidence: 0.95,
    validate: (m) => isHighEntropy(m, 2.5),
    suggestion: 'Remove cleartext password from NuGet.Config. Use encrypted credentials.',
  },

  // 118. RubyGems API Token
  {
    label: 'rubygems-api-token',
    pattern: /\b(rubygems_[a-f0-9]{48})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this RubyGems API token at rubygems.org/profile/edit.',
  },

  // 119. npm Token (Legacy, .npmrc format)
  {
    label: 'npm-token-legacy',
    pattern: /\/\/registry\.npmjs\.org\/:_authToken=([a-f0-9\-]{36})/g,
    confidence: 0.95,
    suggestion: 'Revoke this npm auth token at npmjs.com/settings/tokens.',
  },

  // 120. Riot Games API Key
  {
    label: 'riot-games-api-key',
    pattern: /\b(RGAPI-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b/g,
    confidence: 0.95,
    suggestion: 'Revoke this Riot Games API key at developer.riotgames.com.',
  },

  // ---------------------------------------------------------------------------
  // FRAMEWORK-SPECIFIC
  // ---------------------------------------------------------------------------

  // 121. Django insecure SECRET_KEY (django-insecure- prefix)
  {
    label: 'django-insecure-secret-key',
    pattern: /\b(django-insecure-[a-zA-Z0-9!@#$%^&*()_+\-=]{20,})\b/g,
    confidence: 0.95,
    suggestion: 'Replace the Django insecure SECRET_KEY before deploying to production.',
  },

  // 122. Rails secret_key_base
  {
    label: 'rails-secret-key-base',
    pattern: /(?:secret_key_base)\s*[=:]\s*["'`]?([a-f0-9]{64,128})["'`]?/gi,
    confidence: 0.95,
    validate: (m) => isHighEntropyHex(m),
    suggestion: 'Remove Rails secret_key_base from source code. Use Rails credentials.',
  },

  // 123. Laravel APP_KEY (base64: prefix)
  {
    label: 'laravel-app-key',
    pattern: /APP_KEY\s*=\s*base64:([a-zA-Z0-9+/=]{44})/gi,
    confidence: 0.95,
    suggestion: 'Rotate the Laravel APP_KEY with `php artisan key:generate` and store securely.',
  },

  // 124. Spring Boot datasource/security password in properties
  {
    label: 'spring-boot-password',
    pattern: /(?:spring\.datasource\.password|spring\.security\.user\.password|spring\.mail\.password)\s*=\s*([^\s${}][^\s]*)/gi,
    confidence: 0.95,
    validate: (m) => {
      const trimmed = m.trim();
      // Exclude ENC() Jasypt values and ${VAR} references
      if (trimmed.startsWith('${') || trimmed.startsWith('ENC(')) return false;
      return isHighEntropy(trimmed, 2.5);
    },
    suggestion: 'Remove Spring Boot password from properties file. Use Spring Cloud Config or Vault.',
  },

  // 125. Base64-encoded private key block
  {
    label: 'base64-encoded-private-key',
    pattern: /\b(LS0tLS1CRUdJTi[A-Za-z0-9+/=]+)\b/g,
    confidence: 0.95,
    suggestion: 'Remove base64-encoded private key from source code. Store in a secrets manager.',
  },

  // ---------------------------------------------------------------------------
  // GENERIC PATTERNS (new additions)
  // ---------------------------------------------------------------------------

  // 126. HTTP Authorization Bearer token in code/headers
  {
    label: 'http-bearer-token',
    pattern: /(?:Authorization\s*[:=]\s*["'`]?|['"`])Bearer\s+([a-zA-Z0-9_\-./+]{20,})["'`]?/gi,
    confidence: 0.85,
    validate: (m) => isHighEntropy(m, 3.5),
    suggestion: 'Do not hardcode Bearer tokens. Use environment variables or a secrets manager.',
  },

  // 127. HTTP Basic Auth header (Authorization: Basic base64)
  {
    label: 'http-basic-auth-header',
    pattern: /Authorization\s*:\s*Basic\s+([a-zA-Z0-9+/=]{10,})/gi,
    confidence: 0.85,
    validate: (m) => isHighEntropy(m, 3.5),
    suggestion: 'Do not hardcode HTTP Basic auth credentials. Use environment variables.',
  },

  // 128. Redis connection string (redis:// with auth)
  {
    label: 'redis-connection-string',
    pattern: /\b(rediss?:\/\/:[^@\s]{4,}@[^\s"'`]+)/gi,
    confidence: 0.90,
    validate: (m) => isHighEntropy(m, 2.5),
    suggestion: 'Remove Redis credentials from connection string. Use environment variables.',
  },

  // 129. Generic connection string with credentials (jdbc:, mongodb+srv:, etc.)
  {
    label: 'generic-connection-string-with-creds',
    pattern: /(?:connection[_-]?string|(?:db|database)[_-]?url)\s*[=:]\s*["'`]?(\w+:\/\/[^:]+:[^@]+@[^\s"'`]+)["'`]?/gi,
    confidence: 0.90,
    validate: (m) => isHighEntropy(m, 2.0),
    suggestion: 'Remove credentials from connection string. Use environment variables.',
  },

  // 130. URL-encoded password in database connection strings
  {
    label: 'url-encoded-password-in-connection-string',
    pattern: /(?:postgres|mysql|mongodb|redis)(?:ql)?:\/\/[^:]+:([^@]*%[0-9a-fA-F]{2}[^@]*)@/gi,
    confidence: 0.90,
    suggestion: 'Remove URL-encoded credentials from connection strings. Use environment variables.',
  },
];

// ---------------------------------------------------------------------------
// .env-specific patterns
// ---------------------------------------------------------------------------

/**
 * Patterns applied exclusively to .env files.
 *
 * The standard `KEY=value` format used in .env files means secrets appear
 * WITHOUT surrounding quotes, so the generic patterns above (which require
 * quoted values for several checks) often miss them. These patterns match
 * the bare KEY=VALUE form used by dotenv-style loaders.
 *
 * Confidence is deliberately set to 0.98: a `SECRET=<value>` line in a
 * `.env` file is almost certainly a real credential, not a placeholder.
 */
const ENV_FILE_PATTERNS: SecretPattern[] = [
  // Any uppercase KEY that contains a secret-sounding word, e.g.:
  //   API_KEY=abc123
  //   DATABASE_PASSWORD=hunter2
  //   STRIPE_SECRET_KEY=sk_live_...
  {
    label: 'env-file-secret-key',
    pattern: /^(?:[A-Z][A-Z0-9_]*_)?(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL|AUTH|ACCESS_KEY|CLIENT_SECRET|APP_SECRET|ENCRYPTION_KEY|SIGNING_KEY|WEBHOOK_SECRET|SERVICE_ACCOUNT_KEY)(?:_[A-Z0-9_]*)?\s*=\s*(.{4,})/gm,
    confidence: 0.98,
    validate: (m) => {
      const trimmed = m.trim();
      // Skip obvious placeholder patterns
      const placeholders = ['changeme', 'your_', 'enter_', 'replace_', 'example', 'placeholder', 'xxxxxxxx', '12345678', 'test1234', 'secret_here', 'token_here', 'key_here'];
      const lower = trimmed.toLowerCase();
      if (placeholders.some(p => lower.startsWith(p) || lower.includes(p))) return false;
      // Must have at least moderate entropy — real secrets aren't "abc"
      if (trimmed.length < 8) return false;
      return shannonEntropy(trimmed) >= 2.5;
    },
    suggestion: 'This .env file contains a plaintext secret. Ensure .env is in .gitignore and use a secrets manager for production credentials.',
  },
  // Catch the reverse form where the secret word is a PREFIX rather than suffix,
  // e.g. SECRET_SAUCE=... or TOKEN_FOR_SERVICE=...
  {
    label: 'env-file-secret-prefix',
    pattern: /^(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL|AUTH|ACCESS_KEY|CLIENT_SECRET|APP_SECRET|ENCRYPTION_KEY|SIGNING_KEY|WEBHOOK_SECRET)_[A-Z0-9_]+\s*=\s*(.{4,})/gm,
    confidence: 0.98,
    validate: (m) => {
      const trimmed = m.trim();
      const lower = trimmed.toLowerCase();
      const placeholders = ['changeme', 'your_', 'enter_', 'replace_', 'example', 'placeholder'];
      if (placeholders.some(p => lower.includes(p))) return false;
      if (trimmed.length < 8) return false;
      return shannonEntropy(trimmed) >= 2.5;
    },
    suggestion: 'This .env file contains a plaintext secret. Ensure .env is in .gitignore and use a secrets manager for production credentials.',
  },
];

// ---------------------------------------------------------------------------
// Gap 2: Patterns for environment variable defaults containing real secrets
// ---------------------------------------------------------------------------

/**
 * These patterns target the "default value" argument passed when reading an
 * environment variable in code:
 *
 *   Python:  os.environ.get("KEY", "actual_secret_here")
 *   JS/TS:   process.env.KEY || "actual_secret_here"
 *   PHP:     getenv("KEY", "actual_secret_here")
 *
 * When a developer hardcodes a real secret as the fallback, it is committed
 * to the repository even though it looks like a safe env-var lookup.
 *
 * The capture group always captures the DEFAULT VALUE string so all existing
 * PATTERNS validators and entropy checks can be re-applied on it.
 */
const ENV_DEFAULT_PATTERNS: SecretPattern[] = [
  // Python: os.environ.get("KEY", "secret_value")
  {
    label: 'hardcoded-env-default-python',
    pattern: /os\.environ\.get\(\s*["'][^"']+["']\s*,\s*["']([^"']{8,})["']\s*\)/gi,
    confidence: 0.85,
    validate: (m) => {
      const lower = m.toLowerCase();
      const placeholders = ['changeme', 'your_', 'example', 'placeholder', 'replace', 'secret_here', 'token_here', 'key_here'];
      if (placeholders.some(p => lower.includes(p))) return false;
      return isHighEntropy(m, 2.8);
    },
    suggestion: 'Remove the hardcoded default secret. Use a secrets manager or raise an error when the environment variable is missing.',
  },
  // JS/TS: process.env.KEY || "secret_value"
  {
    label: 'hardcoded-env-default-js',
    pattern: /process\.env\.\w+\s*\|\|\s*["']([^"']{8,})["']/gi,
    confidence: 0.85,
    validate: (m) => {
      const lower = m.toLowerCase();
      const placeholders = ['changeme', 'your_', 'example', 'placeholder', 'replace', 'secret_here', 'token_here', 'key_here'];
      if (placeholders.some(p => lower.includes(p))) return false;
      return isHighEntropy(m, 2.8);
    },
    suggestion: 'Remove the hardcoded fallback secret. Fail loudly when the environment variable is absent.',
  },
  // PHP / general getenv("KEY", "secret_value")
  {
    label: 'hardcoded-env-default-getenv',
    pattern: /getenv\(\s*["'][^"']+["']\s*,\s*["']([^"']{8,})["']\s*\)/gi,
    confidence: 0.85,
    validate: (m) => {
      const lower = m.toLowerCase();
      const placeholders = ['changeme', 'your_', 'example', 'placeholder', 'replace', 'secret_here', 'token_here', 'key_here'];
      if (placeholders.some(p => lower.includes(p))) return false;
      return isHighEntropy(m, 2.8);
    },
    suggestion: 'Remove the hardcoded default secret from getenv(). Use a secrets manager.',
  },
];

// ---------------------------------------------------------------------------
// Gap 6: Partial / concatenated secret patterns
// ---------------------------------------------------------------------------

/**
 * Catches variable assignments where the value is only a PREFIX FRAGMENT of a
 * known secret format (e.g. `_PREFIX = "sk_live_"` or `KEY_PART = "AKIA"`).
 *
 * These partial matches cannot be confirmed as real secrets (the full value is
 * assembled at runtime), so confidence is deliberately kept at 0.80.
 *
 * Trigger conditions:
 * - Variable name contains KEY, SECRET, TOKEN, or PASSWORD (case-insensitive)
 * - Assigned string starts with a known service-specific prefix fragment
 */
const PARTIAL_SECRET_PATTERNS: SecretPattern[] = [
  {
    label: 'partial-secret-fragment',
    pattern: /\b(?:[A-Za-z_][A-Za-z0-9_]*_)?(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD)(?:_[A-Za-z0-9_]*)?\s*[=:]\s*["'`]((?:sk_(?:live|test)_|pk_(?:live|test)_|ghp_|gho_|ghu_|ghs_|ghr_|glpat-|AKIA|AIza|SG\.|xox[bpoa]-|npm_|pypi-)[A-Za-z0-9_/-]{1,})["'`]/gi,
    confidence: 0.80,
    suggestion: 'This variable appears to hold a partial secret prefix. If this value is concatenated at runtime to form a full credential, extract it to a secrets manager.',
  },
];

// ---------------------------------------------------------------------------
// File exclusion helpers
// ---------------------------------------------------------------------------

/** Returns true when a file path looks like a test file and should be scanned with reduced confidence */
function isTestFile(filePath: string): boolean {
  const name = basename(filePath);
  return (
    /\.(test|spec)\.[^.]+$/.test(name) ||
    /\.test\.ts$/.test(name) ||
    /\.spec\.ts$/.test(name) ||
    filePath.includes('/__tests__/') ||
    filePath.includes('/test/') ||
    filePath.includes('/tests/') ||
    filePath.includes('/fixtures/')
  );
}

/**
 * Returns true when the file is a dotenv-style file (.env, .env.local,
 * .env.production, etc.).  Secrets in these files receive elevated confidence
 * (0.98) because their presence is almost certainly intentional, not a
 * placeholder or test fixture.
 */
function isEnvFile(filePath: string): boolean {
  const name = basename(filePath);
  // Matches: .env  .env.local  .env.production  .env.test  .env.example
  return /^\.env(\.|$)/i.test(name);
}

/** Returns true when the trimmed line is a comment */
function isCommentLine(line: string): boolean {
  const trimmed = line.trimStart();
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('#') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('<!--')
  );
}

/**
 * Returns true when the comment line contains words that suggest the secret
 * is intentionally fake/illustrative (e.g. documentation examples).
 *
 * Only used when the line IS already identified as a comment — the function
 * is the gating condition for whether confidence should be reduced on that
 * comment line.  If the comment contains none of these words, a real secret
 * in a comment is just as dangerous as one in live code.
 */
function isExampleComment(line: string): boolean {
  const lower = line.toLowerCase();
  return (
    lower.includes('example') ||
    lower.includes('placeholder') ||
    lower.includes('sample') ||
    lower.includes('fake') ||
    lower.includes('test pattern') ||
    lower.includes('dummy')
  );
}

// ---------------------------------------------------------------------------
// Base64 decode helper (Gap 3)
// ---------------------------------------------------------------------------

/**
 * Attempt to decode a candidate string as standard Base64.
 * Returns the decoded UTF-8 string if successful and printable, otherwise null.
 *
 * Only strings that look like Base64 (alphabet [A-Za-z0-9+/=], length > 20)
 * are attempted.  The decoded result is only considered useful when it is
 * predominantly printable ASCII (>=80% of chars in 0x20-0x7E range) and
 * longer than 8 characters — binary payloads that happen to be valid Base64
 * are not secret values we can pattern-match against.
 */
function tryDecodeBase64(value: string): string | null {
  // Must look like Base64
  if (!/^[A-Za-z0-9+/]{20,}={0,2}$/.test(value)) return null;
  try {
    const decoded = Buffer.from(value, 'base64').toString('utf-8');
    if (decoded.length < 8) return null;
    // Require at least 80% printable ASCII to avoid binary noise
    let printable = 0;
    for (let i = 0; i < decoded.length; i++) {
      const code = decoded.charCodeAt(i);
      if (code >= 0x20 && code <= 0x7e) printable++;
    }
    if (printable / decoded.length < 0.80) return null;
    return decoded;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Markdown helpers (Gap 5)
// ---------------------------------------------------------------------------

/** Returns true when the file has a .md extension (markdown). */
function isMarkdownFile(filePath: string): boolean {
  return filePath.endsWith('.md') || filePath.endsWith('.MD') || filePath.endsWith('.markdown');
}

/**
 * Tracks whether a given line index falls inside a fenced code block
 * (``` or ~~~) within a markdown document.
 *
 * Returns a Set of 0-based line indices that are inside code fences so the
 * scanner can apply reduced confidence to secrets found on those lines.
 *
 * The function performs a single pass over all lines — O(n) — so it should
 * only be called once per file, not per-line.
 */
function buildMarkdownCodeBlockLines(lines: string[]): Set<number> {
  const codeBlockLines = new Set<number>();
  let insideBlock = false;
  let fenceChar = '';

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trimStart();
    if (!insideBlock) {
      if (trimmed.startsWith('```') || trimmed.startsWith('~~~')) {
        insideBlock = true;
        fenceChar = trimmed.startsWith('```') ? '```' : '~~~';
        // The fence-opening line itself is part of the block context
        codeBlockLines.add(i);
      }
    } else {
      codeBlockLines.add(i);
      if (trimmed.startsWith(fenceChar)) {
        // Closing fence — close the block (line already added above)
        insideBlock = false;
        fenceChar = '';
      }
    }
  }

  return codeBlockLines;
}

// ---------------------------------------------------------------------------
// Analyzer implementation
// ---------------------------------------------------------------------------

export class RegexFallbackAnalyzer implements Analyzer {
  readonly name = 'regex-fallback';
  readonly layer = 'secrets' as const;

  async analyze(context: AnalysisContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Build the full ignore pattern list once (same logic as the orchestrator
    // so we don't accidentally include files that are explicitly excluded).
    const ignorePatterns = [
      ...context.config.ignore,
      ...getIgnorePatterns(context.rootDir),
    ];

    // scanAllFiles returns absolute paths and includes .env*, .json, .yaml,
    // .toml, .ini, .cfg, .conf, .properties, .xml in addition to code files.
    // Critically, it overrides any .gitignore entry that would suppress .env
    // files — those files are exactly where real secrets live.
    const allFiles = await scanAllFiles(context.rootDir, ignorePatterns);

    for (const filePath of allFiles) {
      let content: string;
      try {
        content = readFileSync(filePath, 'utf-8');
      } catch {
        // Binary or unreadable file — skip silently
        continue;
      }

      const lines = content.split('\n');
      const testFile = isTestFile(filePath);
      const envFile = isEnvFile(filePath);
      const markdownFile = isMarkdownFile(filePath);

      // Pre-compute which lines fall inside markdown fenced code blocks.
      // Only done for markdown files to keep the common path fast.
      const markdownCodeBlockLines = markdownFile
        ? buildMarkdownCodeBlockLines(lines)
        : null;

      // For .env files, run both the standard patterns AND the env-specific
      // patterns that understand bare KEY=value format.
      // For all files, also run env-default patterns (Gap 2) and partial-secret
      // patterns (Gap 6) to catch runtime-assembled credentials.
      const activePatterns = envFile
        ? [...PATTERNS, ...ENV_FILE_PATTERNS, ...ENV_DEFAULT_PATTERNS, ...PARTIAL_SECRET_PATTERNS]
        : [...PATTERNS, ...ENV_DEFAULT_PATTERNS, ...PARTIAL_SECRET_PATTERNS];

      /**
       * Emit a single Finding, centralising all confidence adjustment logic.
       *
       * @param descriptor  The pattern that fired.
       * @param capturedValue  The secret value extracted by the capture group.
       * @param lineIndex   0-based line index within the file.
       * @param inComment   Whether the source line is a comment.
       * @param extraLabel  Optional suffix appended to type (e.g. " (decoded)").
       */
      const emitFinding = (
        descriptor: SecretPattern,
        capturedValue: string,
        lineIndex: number,
        inComment: boolean,
        extraLabel = '',
      ): void => {
        // Confidence adjustment ladder:
        //   1. .env files                   → floor at 0.98 (real secrets live here)
        //   2. test files                   → -0.15
        //   3. markdown outside code block  → no adjustment (rare to have real secrets in prose)
        //   4. markdown inside code block   → -0.20 (likely an example)
        //   5. comment WITH example words   → -0.10 (might be illustrative)
        //   6. comment WITHOUT example words → no adjustment (real secret commented out is still a problem)
        let confidence = descriptor.confidence;
        if (envFile) {
          confidence = Math.max(confidence, 0.98);
        } else {
          if (testFile) confidence = Math.max(confidence - 0.15, 0.50);
          if (markdownCodeBlockLines?.has(lineIndex)) {
            // Inside a markdown code fence — likely an example
            confidence = 0.75;
          } else if (inComment && isExampleComment(lines[lineIndex])) {
            // Comment explicitly describes a fake/example value
            confidence = Math.max(confidence - 0.10, 0.50);
          }
          // Plain comment with a real-looking secret: no reduction (Gap 1 fix).
        }

        const redacted = capturedValue.length > 4
          ? `${capturedValue.slice(0, 4)}...`
          : '[redacted]';

        findings.push({
          id: randomUUID(),
          layer: 'secrets',
          type: `${descriptor.label}${extraLabel}`,
          severity: confidence >= 0.90 ? 'error' : 'warning',
          confidence,
          file: filePath,
          line: lineIndex + 1,
          message: `Potential ${descriptor.label}${extraLabel} detected: ${redacted}`,
          tool: 'regex-fallback',
          suggestion: descriptor.suggestion,
          meta: {
            patternSource: descriptor.pattern.source,
            inTestFile: testFile,
            inComment,
            inEnvFile: envFile,
          },
        });
      };

      for (const descriptor of activePatterns) {
        // Each pattern must be reset between files because we use the /g flag
        // on a shared RegExp instance — cloning via source + flags prevents
        // cross-file index contamination.
        const re = new RegExp(descriptor.pattern.source, descriptor.pattern.flags);

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
          const line = lines[lineIndex];

          // Guard against ReDoS: patterns 16-17 contain greedy tails that can
          // cause catastrophic backtracking on very long input. Real secrets are
          // always short, so any line exceeding 4096 chars is safe to skip.
          if (line.length > 4096) continue;

          const inComment = isCommentLine(line);

          re.lastIndex = 0;
          let match: RegExpExecArray | null;

          while ((match = re.exec(line)) !== null) {
            // The matched secret value is always the first capture group
            const capturedValue = match[1] ?? match[0];

            // Run optional validator; skip if it rejects the value
            if (descriptor.validate && !descriptor.validate(capturedValue)) {
              // Gap 3: even if the plain-text value fails validation,
              // it might be a Base64-encoded secret — try decoding it.
              const decoded = tryDecodeBase64(capturedValue);
              if (decoded) {
                // Re-run every pattern against the decoded string.
                // We emit these at a slightly reduced confidence (–0.05) to
                // reflect the extra uncertainty of the Base64 indirection.
                for (const innerDescriptor of PATTERNS) {
                  const innerRe = new RegExp(innerDescriptor.pattern.source, innerDescriptor.pattern.flags);
                  innerRe.lastIndex = 0;
                  let innerMatch: RegExpExecArray | null;
                  while ((innerMatch = innerRe.exec(decoded)) !== null) {
                    const innerValue = innerMatch[1] ?? innerMatch[0];
                    if (innerDescriptor.validate && !innerDescriptor.validate(innerValue)) continue;
                    const innerDescriptorAdjusted: SecretPattern = {
                      ...innerDescriptor,
                      confidence: Math.max(innerDescriptor.confidence - 0.05, 0.50),
                    };
                    emitFinding(innerDescriptorAdjusted, innerValue, lineIndex, inComment, ' (base64-decoded)');
                    if (innerMatch.index === innerRe.lastIndex) innerRe.lastIndex++;
                  }
                }
              }
              // Prevent infinite loops
              if (match.index === re.lastIndex) re.lastIndex++;
              continue;
            }

            // Gap 3: also try to Base64-decode a VALID capture and scan the
            // decoded payload — the value might itself be a compound encoded secret.
            const decoded = tryDecodeBase64(capturedValue);
            if (decoded) {
              for (const innerDescriptor of PATTERNS) {
                // Skip the same pattern — would just re-detect the same thing.
                if (innerDescriptor.label === descriptor.label) continue;
                const innerRe = new RegExp(innerDescriptor.pattern.source, innerDescriptor.pattern.flags);
                innerRe.lastIndex = 0;
                let innerMatch: RegExpExecArray | null;
                while ((innerMatch = innerRe.exec(decoded)) !== null) {
                  const innerValue = innerMatch[1] ?? innerMatch[0];
                  if (innerDescriptor.validate && !innerDescriptor.validate(innerValue)) continue;
                  const innerDescriptorAdjusted: SecretPattern = {
                    ...innerDescriptor,
                    confidence: Math.max(innerDescriptor.confidence - 0.05, 0.50),
                  };
                  emitFinding(innerDescriptorAdjusted, innerValue, lineIndex, inComment, ' (base64-decoded)');
                  if (innerMatch.index === innerRe.lastIndex) innerRe.lastIndex++;
                }
              }
            }

            emitFinding(descriptor, capturedValue, lineIndex, inComment);

            // Prevent infinite loops on zero-length matches
            if (match.index === re.lastIndex) {
              re.lastIndex++;
            }
          }
        }
      }
    }

    return findings;
  }
}
