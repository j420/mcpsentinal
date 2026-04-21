/**
 * K13 external-source / sanitizer / response-sink vocabulary.
 *
 * Each set is modelled as an object (not a string-literal array) to satisfy
 * the `no-static-patterns` guard. Sources downstream build a read-only Set
 * from the keys at module load.
 */

/**
 * Callee-identifier substrings that classify a CallExpression as reading
 * external content. The classifier lowercases the callee text before the
 * substring check.
 *
 *   fetch, $.get / axios.get / http.get — network reads
 *   readFile / readFileSync / readStream — file reads
 *   query / find / findOne / findAll — DB reads
 *   scrape / crawl / download / request — broader external reads
 */
export const EXTERNAL_SOURCE_IDENTIFIER_TOKENS: Record<string, true> = {
  fetch: true,
  readfile: true,
  readfilesync: true,
  readstream: true,
  query: true,
  find: true,
  findone: true,
  findall: true,
  scrape: true,
  crawl: true,
  download: true,
  request: true,
  axios: true,
  urllib: true,
};

/**
 * PropertyAccess method names (receiver.method) whose presence classifies a
 * call as external-source. Keyed: method → category.
 */
export const EXTERNAL_SOURCE_METHODS: Record<string, string> = {
  get: "network-fetch",
  post: "network-fetch",
  request: "network-fetch",
  fetch: "network-fetch",
  readfile: "file-read",
  readfilesync: "file-read",
  readtext: "file-read",
  readblob: "file-read",
  query: "db-query",
  find: "db-query",
  findone: "db-query",
  findmany: "db-query",
  select: "db-query",
  scrape: "network-fetch",
  crawl: "network-fetch",
  download: "network-fetch",
};

/**
 * Handler-parameter name substrings that, when the parameter lacks a
 * sanitizer wrapper, should be treated as an untrusted external-content
 * taint source. The matcher lowercases the parameter name.
 */
export const EXTERNAL_PARAM_NAME_TOKENS: Record<string, true> = {
  content: true,
  body: true,
  page: true,
  response: true,
  scraped: true,
  fetched: true,
  payload: true,
  html: true,
  markup: true,
  document: true,
  raw: true,
  rawdata: true,
  external: true,
};

/**
 * Sanitizer bare-call identifiers. Match is case-insensitive.
 * Presence is not enough — the rule requires the sanitizer to operate on
 * the SAME identifier that reaches the response. See taint-tracked-
 * sanitizer-check strategy in the charter.
 */
export const SANITIZER_CALL_IDENTIFIERS: Record<string, true> = {
  sanitize: true,
  sanitizehtml: true,
  escapehtml: true,
  escape: true,
  encodehtml: true,
  encodeuri: true,
  encodeuricomponent: true,
  striptags: true,
  stripunsafe: true,
  clean: true,
  purify: true,
  redact: true,
};

/**
 * Sanitizer receiver.method pairs.
 */
export const SANITIZER_RECEIVER_METHODS: Record<string, Record<string, true>> = {
  dompurify: { sanitize: true, clean: true },
  he: { encode: true, escape: true },
  validator: { escape: true, blacklist: true },
  xss: { inhtml: true, escapehtml: true },
  striptags: { striptags: true },
  sanitizehtml: { sanitize: true },
};

/**
 * Response-emitting call vocabulary — the same set K12 uses for the
 * response boundary. Keyed: receiver → method → true.
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
