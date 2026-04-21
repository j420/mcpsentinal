/**
 * N7 — Typed vocabularies for progress-token detection.
 */

export type ProgressTokenRole =
  | "token-target"
  | "user-source"
  | "predictable-source"
  | "crypto-generator";

/** Identifier-name fragments that indicate a progress-correlation field. */
export const PROGRESS_TOKEN_IDENTIFIERS: Record<string, ProgressTokenRole> = {
  progresstoken: "token-target",
  progress_token: "token-target",
  progressid: "token-target",
  progress_id: "token-target",
  progresskey: "token-target",
};

/**
 * RHS roots that indicate the right-hand side carries user input. Matched
 * against the head of the expression text.
 */
export const USER_SOURCE_ROOTS: Record<string, ProgressTokenRole> = {
  req: "user-source",
  request: "user-source",
  params: "user-source",
  body: "user-source",
  query: "user-source",
  args: "user-source",
  input: "user-source",
  ctx: "user-source",
};

/** Expression fragments that indicate a predictable but server-local source. */
export const PREDICTABLE_SOURCE_TOKENS: Record<string, ProgressTokenRole> = {
  "Date.now": "predictable-source",
  "performance.now": "predictable-source",
  indexOf: "predictable-source",
  getTime: "predictable-source",
  increment_operator: "predictable-source",
  length_access: "predictable-source",
};

/** Crypto generators — presence in the scope inverts the finding. */
export const CRYPTO_GENERATORS: Record<string, ProgressTokenRole> = {
  "crypto.randomUUID": "crypto-generator",
  "crypto.randomBytes": "crypto-generator",
  "crypto.getRandomValues": "crypto-generator",
  randomUUID: "crypto-generator",
  nanoid: "crypto-generator",
  uuid: "crypto-generator",
  cuid: "crypto-generator",
};
