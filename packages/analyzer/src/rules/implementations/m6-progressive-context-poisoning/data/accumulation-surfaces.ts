/**
 * M6 — Vocabulary for accumulation-without-bounds detection.
 *
 * Typed Readonly<Record> of accumulation verbs and context-shaped
 * identifier roots. Zero regex literals. Per-entry arrays are capped at
 * 5.
 */

export interface AccumulationVerb {
  readonly verb: string;
  readonly kind: "append" | "push" | "insert" | "persist" | "index";
  readonly label: string;
}

/**
 * Accumulation verbs — the call / method name the scanner looks for on
 * a context-shaped target. Case-insensitive match.
 */
export const ACCUMULATION_VERBS: Readonly<Record<string, AccumulationVerb>> = {
  append: { verb: "append", kind: "append", label: "append()" },
  push: { verb: "push", kind: "push", label: "push()" },
  concat: { verb: "concat", kind: "append", label: "concat()" },
  add: { verb: "add", kind: "insert", label: "add()" },
  insert: { verb: "insert", kind: "insert", label: "insert()" },
  upsert: { verb: "upsert", kind: "persist", label: "upsert()" },
  save: { verb: "save", kind: "persist", label: "save()" },
  store: { verb: "store", kind: "persist", label: "store()" },
  persist: { verb: "persist", kind: "persist", label: "persist()" },
  write: { verb: "write", kind: "persist", label: "write()" },
  index: { verb: "index", kind: "index", label: "index()" },
};

/**
 * Context-shaped identifier fragments. When one of these appears in the
 * variable / property / call target name near an accumulation verb, the
 * rule treats the site as a candidate.
 */
export const CONTEXT_IDENT_FRAGMENTS: Readonly<Record<string, string>> = {
  context: "agent context buffer",
  memory: "agent memory store",
  history: "conversation history buffer",
  conversation: "conversation buffer",
  messages: "message list",
  scratchpad: "agent scratchpad",
  notes: "agent notes buffer",
  thoughts: "agent thought buffer",
  reasoning: "agent reasoning buffer",
};

/**
 * Bound keywords — words that, if present within a bounded window of
 * lines around the accumulation site, indicate a mitigating bound is in
 * place. Absence = the finding's mitigation link present=false.
 */
export const BOUND_KEYWORDS: Readonly<Record<string, string>> = {
  limit: "size limit",
  max_size: "max-size check",
  max_length: "max-length check",
  truncate: "truncation call",
  clear: "clear call",
  reset: "reset call",
  evict: "eviction call",
  expire: "expiry / TTL",
  ttl: "TTL field",
};

/** Vector-store / embedding-store signal fragments. */
export const VECTOR_STORE_FRAGMENTS: Readonly<Record<string, string>> = {
  vector: "vector-store target",
  embed: "embedding store",
  pinecone: "Pinecone vector DB",
  chroma: "Chroma vector DB",
  weaviate: "Weaviate vector DB",
  qdrant: "Qdrant vector DB",
  faiss: "FAISS index",
};

/** Confidence cap for M6 (charter §Confidence cap). */
export const M6_CONFIDENCE_CAP = 0.72;

/** Window (in lines) around the accumulation site where we look for bounds. */
export const M6_BOUND_WINDOW_LINES = 6;
