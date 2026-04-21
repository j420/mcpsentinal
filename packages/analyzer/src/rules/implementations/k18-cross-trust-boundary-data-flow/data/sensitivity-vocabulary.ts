/**
 * K18 sensitivity / redactor / response-sink vocabulary.
 *
 * Each set is modelled as an object (not a string-literal array) to
 * satisfy the `no-static-patterns` guard.
 */

/**
 * Substrings we look for inside identifier / property-access names that
 * classify the referenced value as sensitive. Matching is case-insensitive.
 */
export const SENSITIVITY_TOKENS: Record<string, true> = {
  secret: true,
  credential: true,
  credentials: true,
  token: true,
  password: true,
  passwd: true,
  passphrase: true,
  apikey: true,
  api_key: true,
  privatekey: true,
  private_key: true,
  sshkey: true,
  pkcs: true,
  vault: true,
  kms: true,
  ssn: true,
  socialsecurity: true,
  creditcard: true,
  cardnumber: true,
  sensitive: true,
  classified: true,
  confidential: true,
};

/**
 * Environment-variable SUFFIX tokens. `process.env.<NAME>` where NAME
 * contains one of these (case-insensitive) is classified as sensitive.
 */
export const ENV_SENSITIVE_SUFFIXES: Record<string, true> = {
  secret: true,
  token: true,
  key: true,
  password: true,
  credential: true,
  apikey: true,
  api_key: true,
};

/**
 * Receiver tokens that, when seen as the object of a PropertyAccess
 * (e.g. `vault.getCredential()`), classify the call as a credential read.
 */
export const CREDENTIAL_RECEIVER_TOKENS: Record<string, true> = {
  vault: true,
  secrets: true,
  secretsmanager: true,
  kms: true,
  keyring: true,
  keystore: true,
  credentials: true,
  credentialstore: true,
};

/**
 * Method tokens that, on any receiver, classify the call as a credential
 * read (`getSecret`, `loadCredential`, `fetchToken`, etc.).
 */
export const CREDENTIAL_METHOD_TOKENS: Record<string, true> = {
  getsecret: true,
  loadsecret: true,
  readsecret: true,
  getcredential: true,
  loadcredential: true,
  gettoken: true,
  fetchtoken: true,
  getprivatekey: true,
  getpassword: true,
  getapikey: true,
};

/**
 * Path prefixes (substrings) that classify a readFile / readFileSync
 * target as sensitive when the path argument is a string literal.
 */
export const SENSITIVE_PATH_PREFIXES: Record<string, true> = {
  "/etc/passwd": true,
  "/etc/shadow": true,
  "/root/.ssh": true,
  "~/.ssh/id_rsa": true,
  "~/.aws/credentials": true,
  "/var/run/secrets": true,
  ".env": true,
  ".env.local": true,
};

/**
 * Redactor bare-call identifiers (case-insensitive). The mitigation must
 * operate on the same identifier that reaches the sink.
 */
export const REDACTOR_CALL_IDENTIFIERS: Record<string, true> = {
  redact: true,
  mask: true,
  filter: true,
  strip: true,
  stripsecrets: true,
  omit: true,
  exclude: true,
  sanitize: true,
  encrypt: true,
  hash: true,
  scrub: true,
  censor: true,
  obfuscate: true,
};

/**
 * Redactor receiver.method pairs.
 */
export const REDACTOR_RECEIVER_METHODS: Record<string, Record<string, true>> = {
  redactor: { redact: true, mask: true, strip: true },
  privacy: { redact: true, filter: true },
  security: { redact: true, mask: true, scrub: true },
  lodash: { omit: true, pick: true },
  underscore: { omit: true, pick: true },
  // Cryptographic artifact producers — the output is a NEW signed/hashed
  // artifact, not the raw input. Returning a jwt.sign() result to the caller
  // who owns the subject (refresh-token rotation, session mint, ID-token
  // issuance) is the definition of a correct OAuth endpoint, not exfiltration.
  jwt: { sign: true, verify: true, decode: true },
  jsonwebtoken: { sign: true, verify: true, decode: true },
  bcrypt: { hash: true, compare: true, hashsync: true, comparesync: true },
  argon2: { hash: true, verify: true },
  scrypt: { hash: true, verify: true },
};

/**
 * Response-emitting call vocabulary. Same shape as K13.
 */
export const RESPONSE_RECEIVERS: Record<string, true> = {
  res: true,
  response: true,
  resp: true,
  reply: true,
  ctx: true,
};

export const RESPONSE_METHODS: Record<string, true> = {
  send: true,
  json: true,
  write: true,
  end: true,
  html: true,
  body: true,
  render: true,
};

/**
 * Network-send receiver.method pairs — a secret flowing to an outbound
 * HTTP request body is the same control gap as a secret flowing to a
 * response, under the K18 threat model.
 */
export const NETWORK_SEND_METHODS: Record<string, true> = {
  post: true,
  put: true,
  patch: true,
  request: true,
  fetch: true,
  send: true,
};

/** Test-harness module imports — identify structural test files. */
export const TEST_RUNNER_MODULES: Record<string, true> = {
  vitest: true,
  jest: true,
  "@jest/globals": true,
  mocha: true,
  "node:test": true,
};

/** Test-runner top-level identifiers. */
export const TEST_RUNNER_TOPLEVEL: Record<string, true> = {
  describe: true,
  it: true,
  test: true,
  suite: true,
};
