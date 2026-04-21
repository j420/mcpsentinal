/**
 * N1 — Typed vocabularies for JSON-RPC batch detection.
 *
 * Every vocabulary is a structured record, not a free-form string array.
 * Each entry carries the semantic role its identifier plays in the AST check
 * so the gather step can make structural decisions, not lexical ones.
 */

/** Role an identifier plays in request-shaped iteration detection. */
export type BatchIdentifierRole =
  | "batch-array" // a parameter/variable plausibly holding a JSON-RPC batch
  | "iteration-method" // a method call that walks an array (forEach/map/reduce)
  | "isarray-target" // a variable inspected by Array.isArray at a guard
  | "limit-vocabulary" // names/patterns that indicate an explicit size bound
  | "throttle-vocabulary"; // names/patterns that indicate flow control

/**
 * Identifier names a JSON-RPC handler plausibly uses to refer to a batch-shaped
 * value. Matched against expression text produced by the TypeScript compiler API.
 */
export const BATCH_IDENTIFIERS: Record<string, BatchIdentifierRole> = {
  req: "isarray-target",
  request: "isarray-target",
  body: "isarray-target",
  message: "isarray-target",
  data: "isarray-target",
  batch: "batch-array",
  payload: "isarray-target",
  requests: "batch-array",
  messages: "batch-array",
};

/** Array-walking methods that execute N calls for a batch of length N. */
export const ITERATION_METHODS: Record<string, BatchIdentifierRole> = {
  forEach: "iteration-method",
  map: "iteration-method",
  reduce: "iteration-method",
};

/**
 * Vocabulary indicating an explicit size bound exists in the enclosing scope.
 * Presence of ANY of these invalidates the finding — the server has a limit.
 */
export const LIMIT_VOCABULARY: Record<string, BatchIdentifierRole> = {
  length_comparison: "limit-vocabulary", // `.length` followed by < > <= >= or ===
  max: "limit-vocabulary",
  maxbatch: "limit-vocabulary",
  maxsize: "limit-vocabulary",
  maxlength: "limit-vocabulary",
  maxcount: "limit-vocabulary",
  maxrequests: "limit-vocabulary",
  limit: "limit-vocabulary",
  slice: "limit-vocabulary",
};

/** Vocabulary for rate-limiting / throttling primitives. */
export const THROTTLE_VOCABULARY: Record<string, BatchIdentifierRole> = {
  throttle: "throttle-vocabulary",
  debounce: "throttle-vocabulary",
  ratelimit: "throttle-vocabulary",
  rate_limit: "throttle-vocabulary",
  bulkhead: "throttle-vocabulary",
};
