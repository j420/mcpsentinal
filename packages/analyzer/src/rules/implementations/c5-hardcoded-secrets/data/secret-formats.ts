/**
 * C5 — Hardcoded Secrets: structural credential-format specifications.
 *
 * Lives under `data/` so the no-static-patterns guard skips it. Each
 * spec is a TYPED RECORD describing an opaque credential format: the
 * literal prefix string, the expected post-prefix character set, and
 * the post-prefix length window.
 *
 * The consumer (gather.ts) iterates string literals, checks each for
 * a spec prefix, then validates the remainder against the charset and
 * length. NO REGEX — plain `String.prototype.startsWith` + a typed
 * charset check. This is deliberately portable to new formats without
 * engineering complex anchored regex patterns.
 *
 * Adding a new credential format: add an entry here. Every new format
 * MUST document a known issuer, an observed minimum length, and the
 * charset. Formats without real-world precedent do NOT belong in this
 * table — the C5 CHARTER obsolescence clause hinges on the list being
 * a curated registry of real credentials, not speculative shapes.
 */

/** Named character-class presets — the spec validator checks each character against the named class. */
export type CharsetName =
  | "hex-lower"
  | "hex-any"
  | "alphanumeric"
  | "alphanumeric-upper"
  | "alphanumeric-underscore"
  | "base64url";

export interface SecretFormatSpec {
  /** Short identifier — surfaces into evidence observed/rationale. */
  readonly id: string;
  /** Human issuer name. */
  readonly issuer: string;
  /** Literal prefix on the token (matched by startsWith). */
  readonly prefix: string;
  /**
   * Inclusive length window for the segment AFTER the prefix.
   * min > 0 — no empty suffixes. max is informational, not enforced
   * beyond warning on very long matches that may be a false positive.
   */
  readonly minSuffix: number;
  readonly maxSuffix: number;
  /** Charset the suffix is expected to use. */
  readonly charset: CharsetName;
  /** Severity confidence hint — prefixes issued by a known service get a higher score. */
  readonly precedenceTier: "highest" | "high" | "medium";
  /** Whether `.` is permitted inside the suffix (for segmented tokens like SG.<22>.<43>, eyJ...). */
  readonly allowDot: boolean;
  /** Whether `-` is permitted inside the suffix (for sk-ant-xxx-style tokens). */
  readonly allowDash: boolean;
}

/**
 * 14 concrete credential formats. Each entry is backed by the issuer's
 * published token shape (see CHARTER threat_refs). The list is a
 * curated registry — don't add speculative shapes.
 */
export const KNOWN_SECRET_FORMATS: readonly SecretFormatSpec[] = [
  {
    id: "openai-api-key",
    issuer: "OpenAI",
    prefix: "sk-",
    minSuffix: 20,
    maxSuffix: 80,
    charset: "alphanumeric",
    precedenceTier: "highest",
    allowDot: false,
    allowDash: true,
  },
  {
    id: "anthropic-api-key",
    issuer: "Anthropic",
    prefix: "sk-ant-",
    minSuffix: 20,
    maxSuffix: 120,
    charset: "alphanumeric",
    precedenceTier: "highest",
    allowDot: false,
    allowDash: true,
  },
  {
    id: "github-pat-classic",
    issuer: "GitHub",
    prefix: "ghp_",
    minSuffix: 36,
    maxSuffix: 40,
    charset: "alphanumeric",
    precedenceTier: "highest",
    allowDot: false,
    allowDash: false,
  },
  {
    id: "github-oauth-token",
    issuer: "GitHub",
    prefix: "gho_",
    minSuffix: 36,
    maxSuffix: 40,
    charset: "alphanumeric",
    precedenceTier: "highest",
    allowDot: false,
    allowDash: false,
  },
  {
    id: "aws-access-key-permanent",
    issuer: "AWS",
    prefix: "AKIA",
    minSuffix: 16,
    maxSuffix: 16,
    charset: "alphanumeric-upper",
    precedenceTier: "highest",
    allowDot: false,
    allowDash: false,
  },
  {
    id: "aws-access-key-temporary",
    issuer: "AWS",
    prefix: "ASIA",
    minSuffix: 16,
    maxSuffix: 16,
    charset: "alphanumeric-upper",
    precedenceTier: "highest",
    allowDot: false,
    allowDash: false,
  },
  {
    id: "slack-bot-token",
    issuer: "Slack",
    prefix: "xoxb-",
    minSuffix: 20,
    maxSuffix: 90,
    charset: "alphanumeric",
    precedenceTier: "highest",
    allowDot: false,
    allowDash: true,
  },
  {
    id: "slack-user-token",
    issuer: "Slack",
    prefix: "xoxp-",
    minSuffix: 20,
    maxSuffix: 90,
    charset: "alphanumeric",
    precedenceTier: "highest",
    allowDot: false,
    allowDash: true,
  },
  {
    id: "stripe-live-secret",
    issuer: "Stripe",
    prefix: "sk_live_",
    minSuffix: 24,
    maxSuffix: 64,
    charset: "alphanumeric",
    precedenceTier: "highest",
    allowDot: false,
    allowDash: false,
  },
  {
    id: "sendgrid-api-key",
    issuer: "SendGrid",
    prefix: "SG.",
    minSuffix: 50,
    maxSuffix: 80,
    charset: "base64url",
    precedenceTier: "highest",
    allowDot: true,
    allowDash: true,
  },
  {
    id: "google-api-key",
    issuer: "Google",
    prefix: "AIza",
    minSuffix: 35,
    maxSuffix: 40,
    charset: "alphanumeric-underscore",
    precedenceTier: "highest",
    allowDot: false,
    allowDash: true,
  },
  {
    id: "databricks-token",
    issuer: "Databricks",
    prefix: "dapi",
    minSuffix: 32,
    maxSuffix: 32,
    charset: "hex-lower",
    precedenceTier: "high",
    allowDot: false,
    allowDash: false,
  },
  {
    id: "npm-access-token",
    issuer: "npm",
    prefix: "npm_",
    minSuffix: 36,
    maxSuffix: 40,
    charset: "alphanumeric",
    precedenceTier: "highest",
    allowDot: false,
    allowDash: false,
  },
  {
    id: "jwt-token",
    issuer: "JWT-compact-serialisation",
    prefix: "eyJ",
    minSuffix: 30,
    maxSuffix: 2000,
    charset: "base64url",
    precedenceTier: "high",
    allowDot: true,
    allowDash: true,
  },
];

/** PEM header prefix — matched as a substring anywhere in the source code, not a string literal. */
export const PEM_PRIVATE_KEY_HEADER = "-----BEGIN";

/** Suffixes after BEGIN that indicate a private key header. */
export const PEM_PRIVATE_KEY_VARIANTS: readonly string[] = [
  " RSA PRIVATE KEY-----",
  " EC PRIVATE KEY-----",
  " DSA PRIVATE KEY-----",
  " OPENSSH PRIVATE KEY-----",
  " PRIVATE KEY-----",
];

/** Placeholder markers — if the suffix OR the surrounding line contains one, skip. */
export const PLACEHOLDER_MARKERS: readonly string[] = [
  "REPLACE",
  "PLACEHOLDER",
  "xxxxx",
  "XXXXX",
  "<insert",
  "your_",
  "_here",
  "example",
  "sample",
  "dummy",
  "fake",
  "test-key",
  "changeme",
];

/** Filenames whose shape marks them as example / template files. */
export const EXAMPLE_FILENAME_MARKERS: readonly string[] = [
  ".env.example",
  ".env.sample",
  ".env.template",
  ".env.dist",
  "example.env",
];

/**
 * Charset validator — returns true if every character in `suffix` belongs to
 * the named charset (plus an allow-list for `.` and `-` driven by the spec).
 */
export function suffixMatchesCharset(
  suffix: string,
  charset: CharsetName,
  allowDot: boolean,
  allowDash: boolean,
): boolean {
  for (let i = 0; i < suffix.length; i++) {
    const ch = suffix.charCodeAt(i);
    const c = suffix[i];
    if (allowDot && c === ".") continue;
    if (allowDash && c === "-") continue;
    switch (charset) {
      case "hex-lower":
        if (!((ch >= 48 && ch <= 57) || (ch >= 97 && ch <= 102))) return false;
        break;
      case "hex-any":
        if (
          !(
            (ch >= 48 && ch <= 57) ||
            (ch >= 97 && ch <= 102) ||
            (ch >= 65 && ch <= 70)
          )
        )
          return false;
        break;
      case "alphanumeric":
        if (
          !(
            (ch >= 48 && ch <= 57) ||
            (ch >= 97 && ch <= 122) ||
            (ch >= 65 && ch <= 90)
          )
        )
          return false;
        break;
      case "alphanumeric-upper":
        if (!((ch >= 48 && ch <= 57) || (ch >= 65 && ch <= 90))) return false;
        break;
      case "alphanumeric-underscore":
        if (
          !(
            (ch >= 48 && ch <= 57) ||
            (ch >= 97 && ch <= 122) ||
            (ch >= 65 && ch <= 90) ||
            c === "_"
          )
        )
          return false;
        break;
      case "base64url":
        if (
          !(
            (ch >= 48 && ch <= 57) ||
            (ch >= 97 && ch <= 122) ||
            (ch >= 65 && ch <= 90) ||
            c === "_" ||
            c === "-"
          )
        )
          return false;
        break;
    }
  }
  return true;
}

/** Identifier names a generic assignment check cares about (credential-shaped identifiers). */
export const CREDENTIAL_IDENTIFIER_NAMES: readonly string[] = [
  "api_key",
  "apikey",
  "secret",
  "secret_key",
  "auth_token",
  "authToken",
  "access_token",
  "accessToken",
  "private_key",
  "privateKey",
  "password",
  "passwd",
  "token",
];

/** File suffixes that indicate a test fixture — longer than 5, must live here. */
export const TEST_FILE_SUFFIXES: readonly string[] = [
  ".test.ts",
  ".test.js",
  ".spec.ts",
  ".spec.js",
  ".test.py",
  ".spec.py",
];
