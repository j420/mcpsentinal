/**
 * L13 — Build Credential File Theft: rule-specific config data.
 *
 * Lives under `data/` (guard-skipped). Consumed by gather.ts.
 */

/**
 * Substrings that identify a credential file by path. The gather
 * function inspects every fs file-read call argument text and the text
 * of Dockerfile COPY instructions for these substrings.
 */
export const CREDENTIAL_FILE_SUBSTRINGS: ReadonlySet<string> = new Set([
  ".npmrc",
  ".pypirc",
  "pip.conf",
  ".docker/config.json",
  ".ssh/id_",
  ".ssh/authorized_keys",
  ".aws/credentials",
  ".aws/config",
  ".config/gh/hosts.yml",
  "credentials.json",
  "keyfile.json",
  ".env",
  ".env.local",
  ".env.production",
]);

/**
 * Sink categories reported by the lightweight taint analyser that
 * indicate the credential bytes reach a network egress.
 */
export const L13_LIGHTWEIGHT_NETWORK_SINK_CATEGORIES: readonly string[] = [
  "url_request",
  "command_execution", // curl/wget subprocess exec counts as network egress
] as const;

/**
 * AST-taint analyser sink categories for the same classification. The
 * AST analyser's url-egress category is called `ssrf` (historical
 * naming — the detection pattern is identical to network-send).
 */
export const L13_AST_NETWORK_SINK_CATEGORIES: readonly string[] = [
  "ssrf",
  "command_execution",
] as const;

/**
 * Charter-audited sanitisers for L13 — there are effectively none.
 * A "sanitiser" would be a redaction function that strips the
 * credential before it reaches the sink; we don't enumerate names
 * because no canonical library exists. The empty set means every
 * flow is reported as unmitigated.
 */
export const L13_CHARTER_SANITISERS: ReadonlySet<string> = new Set();

/**
 * AST-taint source categories we accept as "file read". The AST
 * analyser tags readFileSync/readFile/open results as
 * `function_return`; the shape of the call is what carries the
 * credential semantic. Keeping the list short lets gather.ts decide.
 */
export const L13_AST_FILE_READ_SOURCE_CATEGORIES: readonly string[] = [
  "function_return",
] as const;

/** Dockerfile instructions that copy local files into the image. */
export const DOCKERFILE_COPY_TOKENS: readonly string[] = [
  "COPY ",
  "ADD ",
] as const;
