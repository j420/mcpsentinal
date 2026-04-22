/**
 * L9 — CI/CD Secret Exfiltration: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 * Consumed by gather.ts for the secret-name heuristic, bulk-env-dump
 * recognition, and the exfil-sink classification that distinguishes
 * "credential-theft channel" from "generic network call".
 *
 * Zero regex; every matcher is `String.prototype.includes()` only.
 */

// ─── Secret-name markers ──────────────────────────────────────────────────

/**
 * Secret-bearing identifier fragments. L9 fires ONLY when the env read
 * name contains at least one of these tokens. A generic env→network
 * flow (e.g. reading process.env.NODE_ENV) must NOT fire L9.
 *
 * Each entry is a case-insensitive substring the heuristic matches with
 * `toUpperCase().includes(token)`.
 */
export interface SecretNameMarker {
  readonly token: string;
  readonly kind: "provider" | "credential-class";
  readonly example: string;
}

export const L9_SECRET_NAME_MARKERS: readonly SecretNameMarker[] = [
  { token: "TOKEN", kind: "credential-class", example: "GITHUB_TOKEN, NPM_TOKEN" },
  { token: "SECRET", kind: "credential-class", example: "AWS_SECRET_ACCESS_KEY" },
  { token: "PASSWORD", kind: "credential-class", example: "DB_PASSWORD" },
  { token: "CREDENTIAL", kind: "credential-class", example: "GCP_CREDENTIALS" },
  { token: "API_KEY", kind: "credential-class", example: "OPENAI_API_KEY" },
  { token: "APIKEY", kind: "credential-class", example: "STRIPE_APIKEY" },
  { token: "PRIVATE_KEY", kind: "credential-class", example: "SIGNING_PRIVATE_KEY" },
  { token: "PRIVKEY", kind: "credential-class", example: "SSH_PRIVKEY" },
  { token: "AUTH", kind: "credential-class", example: "AUTH_HEADER" },
  { token: "BEARER", kind: "credential-class", example: "BEARER_TOKEN" },
  { token: "NPM_", kind: "provider", example: "NPM_AUTH_IDENT" },
  { token: "GITHUB_", kind: "provider", example: "GITHUB_PAT" },
  { token: "AWS_", kind: "provider", example: "AWS_ACCESS_KEY_ID" },
  { token: "GCP_", kind: "provider", example: "GCP_SERVICE_ACCOUNT" },
  { token: "AZURE_", kind: "provider", example: "AZURE_CLIENT_SECRET" },
  { token: "STRIPE_", kind: "provider", example: "STRIPE_SECRET_KEY" },
  { token: "SLACK_", kind: "provider", example: "SLACK_BOT_TOKEN" },
  { token: "ANTHROPIC_", kind: "provider", example: "ANTHROPIC_API_KEY" },
  { token: "OPENAI_", kind: "provider", example: "OPENAI_API_KEY" },
];

// ─── Bulk env-dump shapes ─────────────────────────────────────────────────

/**
 * Bulk-env-dump shapes — canonical expressions where the attacker
 * serialises the entire environment in one call. The gather step flags
 * these even when no specific secret marker is present.
 */
export interface BulkEnvDumpShape {
  /** Function whose receiver is the whole env. */
  readonly callee: string;
  /** Argument expression text (full env access). */
  readonly envArg: string;
  readonly ecosystem: "node" | "python";
  readonly description: string;
}

export const L9_BULK_ENV_DUMP_SHAPES: readonly BulkEnvDumpShape[] = [
  { callee: "JSON.stringify", envArg: "process.env", ecosystem: "node",
    description: "Whole-env JSON dump — exposes every CI secret" },
  { callee: "Object.keys", envArg: "process.env", ecosystem: "node",
    description: "Key enumeration of CI environment" },
  { callee: "Object.entries", envArg: "process.env", ecosystem: "node",
    description: "Entry enumeration of CI environment" },
  { callee: "Object.values", envArg: "process.env", ecosystem: "node",
    description: "Value enumeration of CI environment" },
  { callee: "dict", envArg: "os.environ", ecosystem: "python",
    description: "Python whole-env dict copy" },
  { callee: "json.dumps", envArg: "os.environ", ecosystem: "python",
    description: "Python whole-env JSON dump" },
];

// ─── Exfil sink taxonomy ─────────────────────────────────────────────────

/**
 * Calls whose presence with a secret-bearing argument indicates an
 * exfiltration channel. Each entry carries a severity class (critical
 * for network / artifact, high for log-only) and a human rationale.
 *
 * The AST walker matches on `receiver.method` / `method` / `object.func`
 * shapes; every entry specifies which shape it intends.
 */
export interface ExfilSink {
  /** Name as it appears in the call expression. */
  readonly name: string;
  /** How the name appears in the AST. */
  readonly shape:
    | "bare-function"      // fetch(...), eval(...)
    | "member-call"        // logger.info(...), res.send(...)
    | "qualified-function"; // console.log(...), dns.resolve(...)
  /** Classification of the sink for severity + evidence-chain type. */
  readonly channel: "network" | "dns" | "log" | "artifact";
  readonly severity: "critical" | "high";
  readonly rationale: string;
}

export const L9_EXFIL_SINKS: readonly ExfilSink[] = [
  { name: "fetch", shape: "bare-function", channel: "network", severity: "critical",
    rationale: "HTTP fetch — secret leaves the CI trust boundary via HTTP" },
  { name: "axios", shape: "bare-function", channel: "network", severity: "critical",
    rationale: "axios HTTP client — secret exfiltrated over HTTP" },
  { name: "got", shape: "bare-function", channel: "network", severity: "critical",
    rationale: "got HTTP client — secret exfiltrated over HTTP" },
  { name: "request", shape: "bare-function", channel: "network", severity: "critical",
    rationale: "legacy request() HTTP — secret exfiltrated over HTTP" },
  { name: "http.request", shape: "qualified-function", channel: "network", severity: "critical",
    rationale: "node http.request — low-level HTTP exfil primitive" },
  { name: "https.request", shape: "qualified-function", channel: "network", severity: "critical",
    rationale: "node https.request — TLS HTTP exfil primitive" },
  { name: "dns.resolve", shape: "qualified-function", channel: "dns", severity: "critical",
    rationale: "DNS exfil bypasses HTTP firewalls — encodes data in subdomains" },
  { name: "dns.lookup", shape: "qualified-function", channel: "dns", severity: "critical",
    rationale: "DNS exfil via lookup — same channel as dns.resolve" },
  { name: "console.log", shape: "qualified-function", channel: "log", severity: "high",
    rationale: "console.log — secret persists in CI run history / workflow logs" },
  { name: "console.error", shape: "qualified-function", channel: "log", severity: "high",
    rationale: "console.error — stderr captured by CI as part of build logs" },
  { name: "console.warn", shape: "qualified-function", channel: "log", severity: "high",
    rationale: "console.warn — captured by CI logs" },
  { name: "console.info", shape: "qualified-function", channel: "log", severity: "high",
    rationale: "console.info — captured by CI logs" },
  { name: "print", shape: "bare-function", channel: "log", severity: "high",
    rationale: "Python print — stdout captured by CI logs" },
  { name: "fs.writeFile", shape: "qualified-function", channel: "artifact", severity: "critical",
    rationale: "fs.writeFile — env dumped to an artifact subsequently uploaded" },
  { name: "fs.writeFileSync", shape: "qualified-function", channel: "artifact", severity: "critical",
    rationale: "fs.writeFileSync — env dumped to an artifact file" },
  { name: "fs.appendFile", shape: "qualified-function", channel: "artifact", severity: "critical",
    rationale: "fs.appendFile — env written into a persistent file" },
  { name: "fs.appendFileSync", shape: "qualified-function", channel: "artifact", severity: "critical",
    rationale: "fs.appendFileSync — env written into a persistent file" },
];

// ─── Charter-audited masking primitives ──────────────────────────────────

/**
 * Charter-audited masking / redaction primitives. If a call to one of
 * these is observed in the ENCLOSING SCOPE of the exfil call with the
 * secret as an argument, severity drops to informational.
 */
export interface MaskingPrimitive {
  readonly name: string;
  readonly shape: "bare-function" | "qualified-function";
  readonly description: string;
}

export const L9_MASKING_PRIMITIVES: readonly MaskingPrimitive[] = [
  { name: "addMask", shape: "bare-function",
    description: "GitHub Actions toolkit addMask() — registers the value as a CI-masked secret" },
  { name: "core.setSecret", shape: "qualified-function",
    description: "@actions/core setSecret() — canonical GitHub Actions masking call" },
  { name: "maskSecret", shape: "bare-function",
    description: "Project-local masking helper (charter-audited on name only)" },
  { name: "redactSecret", shape: "bare-function",
    description: "Project-local redaction helper (charter-audited on name only)" },
];
