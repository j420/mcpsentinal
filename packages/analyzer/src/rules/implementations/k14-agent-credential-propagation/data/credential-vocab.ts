/**
 * K14 vocabulary — credential identifiers, shared-state receivers,
 * shared-state writer methods, encoder pass-throughs, redactor
 * mitigations, and placeholder literal suppressors.
 *
 * Each is a `Record<string, true>` lookup so the no-static-patterns
 * guard sees no regex or long string-array literal in `index.ts` /
 * `gather.ts`. The vocabulary is data; the rule is logic.
 */

/**
 * Identifier-name tokens that, when used as a variable, parameter, or
 * property name, indicate a credential-bearing value. Lowercased; the
 * scanner lowercases the AST identifier before lookup.
 *
 * Purposefully wide — we want recall on shared-state writes. Suppression
 * comes from the redactor mitigation and the placeholder literal vocab.
 */
export const CREDENTIAL_IDENTIFIERS: Record<string, true> = {
  token: true,
  tokens: true,
  accesstoken: true,
  refreshtoken: true,
  bearertoken: true,
  authtoken: true,
  idtoken: true,
  jwt: true,
  apikey: true,
  apisecret: true,
  apitoken: true,
  secret: true,
  secrets: true,
  clientsecret: true,
  privatekey: true,
  password: true,
  passwd: true,
  pwd: true,
  passphrase: true,
  credential: true,
  credentials: true,
  sessioncookie: true,
  sessiontoken: true,
  authheader: true,
  authorization: true,
  bearer: true,
  oauthtoken: true,
  cookie: true,
  cookies: true,
};

/**
 * Receiver identifier names indicating a cross-agent shared state
 * surface. The receiver is the object on which a writer method is
 * called. Lowercased.
 */
export const SHARED_STATE_RECEIVERS: Record<string, true> = {
  sharedstore: true,
  sharedstate: true,
  sharedmemory: true,
  sharedcontext: true,
  sharedscratchpad: true,
  scratchpad: true,
  workingmemory: true,
  agentmemory: true,
  agentstate: true,
  agentregistry: true,
  agentcontext: true,
  globalstate: true,
  globalstore: true,
  globalcontext: true,
  vectorstore: true,
  vectordb: true,
  embeddingstore: true,
  memorystore: true,
  conversationmemory: true,
  conversationstate: true,
  contextstore: true,
  crossagentbus: true,
  crossagentstate: true,
  agentbus: true,
  messagebus: true,
  multiagentcontext: true,
  multiagentstate: true,
};

/**
 * Method names on a shared-state receiver that constitute a write.
 * Lowercased.
 */
export const SHARED_STATE_WRITERS: Record<string, true> = {
  set: true,
  put: true,
  push: true,
  append: true,
  add: true,
  store: true,
  save: true,
  write: true,
  insert: true,
  upsert: true,
  publish: true,
  emit: true,
  send: true,
  post: true,
  share: true,
  remember: true,
  cache: true,
  persist: true,
  record: true,
};

/**
 * Encoder/wrapper functions that pass a tainted credential through
 * unchanged in security terms — the encoded value still authorises
 * the bearer. Used for the encoder-passthrough-taint strategy:
 * a credential identifier wrapped by one of these and then written
 * to shared state still triggers the rule.
 *
 * Lowercased identifier or trailing method name.
 */
export const ENCODER_PASSTHROUGHS: Record<string, true> = {
  // global encoders
  btoa: true,
  encodeuri: true,
  encodeuricomponent: true,
  // Buffer.from(...).toString("base64" | "hex" | ...)
  buffer: true,
  // util / crypto-style identity transforms
  stringify: true,
  // JWT wrapping is a passthrough — the inner credential still authorises
  sign: true,
  encode: true,
  // hex helpers
  tohex: true,
  // wrappers like JSON.stringify({ token })
  json: true,
};

/**
 * Method-name suffixes that mark a value as redacted. If a redaction
 * call appears in the enclosing function scope and operates on a
 * credential-named binding, the rule treats the sink as mitigated.
 * Lowercased.
 */
export const REDACTOR_CALLS: Record<string, true> = {
  redact: true,
  scrub: true,
  mask: true,
  obfuscate: true,
  sanitizecredentials: true,
  sanitizesecrets: true,
  stripcredentials: true,
  stripsecrets: true,
  removecredentials: true,
  removesecrets: true,
  hashtoken: true,
  fingerprint: true,
};

/**
 * Receiver.method pairs that count as an encryption/sealing wrapper.
 * Encrypting a token before writing it to a shared store is the
 * canonical mitigation in vault-pattern architectures.
 */
export const REDACTOR_RECEIVER_METHODS: Record<string, Record<string, true>> = {
  vault: { seal: true, encrypt: true, store: true },
  kms: { encrypt: true, sign: true },
  crypto: { encrypt: true },
  cipher: { encrypt: true, seal: true },
};

/**
 * Placeholder string literals — when the right-hand-side of a
 * shared-state write is a single string literal whose value matches
 * one of these, the rule suppresses (placeholder-literal-suppression).
 * Lowercased; the matcher checks both an exact match and a substring
 * for the obvious placeholders.
 */
export const PLACEHOLDER_LITERALS: Record<string, true> = {
  "replace_me": true,
  "<token>": true,
  "<api_key>": true,
  "<secret>": true,
  "<password>": true,
  "your_api_key": true,
  "your_token": true,
  "your_secret": true,
  "your_password": true,
  "todo": true,
  "fixme": true,
  "xxxx": true,
  "xxxxxxxx": true,
  "placeholder": true,
  "example": true,
  "dummy": true,
  "fake": true,
};

/**
 * Test-runner module names — if the file imports one of these, it is
 * structurally a test file and the rule skips it. Mirrors the K12
 * detection so the two stay aligned.
 */
export const TEST_RUNNER_MODULES: Record<string, true> = {
  vitest: true,
  jest: true,
  "@jest/globals": true,
  mocha: true,
  "node:test": true,
};

/**
 * Top-level identifiers that indicate a test fixture even without a
 * runner import (`describe(...)`, `it(...)`, `test(...)`, `suite(...)`).
 */
export const TEST_TOPLEVEL_IDENTIFIERS: Record<string, true> = {
  describe: true,
  it: true,
  test: true,
  suite: true,
};
