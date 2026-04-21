/**
 * K17 HTTP-client vocabulary.
 *
 * Two-layer match: (receiver, method) pair. A bare `fetch(url)` is global
 * and matches via BARE_HTTP_CALLS. A chained `axios.get(url)` matches via
 * HTTP_CLIENT_RECEIVERS (receiver) AND HTTP_CLIENT_METHODS (method).
 *
 * Object-literal vocabulary; detection projects keys into ReadonlySet.
 */

/** Bare function identifiers that are global HTTP clients. */
export const BARE_HTTP_CALLS: Record<string, true> = {
  fetch: true,
};

/** Receiver identifiers of HTTP-client instances (dot-left of a method call). */
export const HTTP_CLIENT_RECEIVERS: Record<string, true> = {
  axios: true,
  got: true,
  undici: true,
  http: true,
  https: true,
  request: true,
  superagent: true,
  ky: true,
  needle: true,
  phin: true,
  bent: true,
};

/** Method names used on HTTP-client receivers. */
export const HTTP_CLIENT_METHODS: Record<string, true> = {
  get: true,
  post: true,
  put: true,
  delete: true,
  patch: true,
  head: true,
  options: true,
  request: true,
  fetch: true,
  stream: true,
  send: true,
};

/**
 * Receivers whose timeout option, when configured globally in the file,
 * covers subsequent bare calls on the same receiver. Example:
 *   `axios.defaults.timeout = 5000;` → subsequent axios.*(...) calls are
 *   covered. Keyed by receiver; value is the receiver label for display.
 */
export const RECEIVER_GLOBAL_TIMEOUT_PROPERTIES: Record<string, { path: string }> = {
  axios: { path: "defaults.timeout" },
};

/**
 * Receivers with a factory-style global timeout pattern like
 *   `got.extend({ timeout: { request: 5000 } })`.
 * Detection matches a CallExpression with receiver.method where the first
 * arg is an ObjectLiteral containing a timeout property.
 */
export const RECEIVER_FACTORY_TIMEOUT_METHODS: Record<string, Record<string, true>> = {
  axios: { create: true },
  got: { extend: true },
  ky: { create: true, extend: true },
};
