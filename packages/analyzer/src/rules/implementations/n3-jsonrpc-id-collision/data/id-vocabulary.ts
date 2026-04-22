/**
 * N3 — Typed vocabularies for JSON-RPC request id collision detection.
 *
 * Every entry is a typed record with a semantic role.
 */

export type IdVocabularyRole =
  | "id-target"
  | "counter-expression"
  | "timestamp-source"
  | "crypto-generator";

/**
 * Identifier names plausibly holding a JSON-RPC request id. Matched against
 * the left-hand side of assignment/initialisation AST nodes.
 */
export const REQUEST_ID_IDENTIFIERS: Record<string, IdVocabularyRole> = {
  requestid: "id-target",
  request_id: "id-target",
  rpcid: "id-target",
  rpc_id: "id-target",
  messageid: "id-target",
  jsonrpcid: "id-target",
  correlationid: "id-target",
};

/** Generators that produce unpredictable ids. Presence inverts the finding. */
export const CRYPTO_GENERATORS: Record<string, IdVocabularyRole> = {
  "crypto.randomUUID": "crypto-generator",
  "crypto.randomBytes": "crypto-generator",
  "crypto.getRandomValues": "crypto-generator",
  randomUUID: "crypto-generator",
  uuidv4: "crypto-generator",
  nanoid: "crypto-generator",
  cuid: "crypto-generator",
  ulid: "crypto-generator",
};

/**
 * Expression fragments that indicate a timestamp-monotonic id source.
 * Checked against the RHS text of an id-target assignment.
 */
export const TIMESTAMP_SOURCES: Record<string, IdVocabularyRole> = {
  "Date.now": "timestamp-source",
  "performance.now": "timestamp-source",
  "process.hrtime": "timestamp-source",
  "new Date": "timestamp-source",
  getTime: "timestamp-source",
};
