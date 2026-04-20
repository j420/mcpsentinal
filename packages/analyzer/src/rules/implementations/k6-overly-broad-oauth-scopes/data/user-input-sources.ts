/**
 * K6 user-input source vocabulary — identifiers and receiver-method pairs
 * that, when resolved as the VALUE of an OAuth scope assignment, mean the
 * scope is user-controlled.
 *
 * User-controlled scopes enable scope injection: an attacker who supplies
 * `?scope=admin` through a redirect can obtain broader permissions than
 * the server intended. This is the same substrate as OAuth 2.1's
 * "must not trust client-supplied scope without allowlist" rule.
 *
 * Detection in `../gather-ast.ts`:
 *
 *   1. The scope-value expression is walked. For every Identifier or
 *      PropertyAccessExpression encountered, check membership in
 *      USER_INPUT_IDENTIFIERS (bare) or USER_INPUT_RECEIVER_PROPERTIES
 *      (chains like `req.query.scope`, `params.scope`, `body.oauth_scope`).
 *
 *   2. If any leaf reference is a user-input source, the finding's
 *      source_type flips to "user-parameter" and a confidence factor is
 *      added ("user_controlled_scope").
 */

/**
 * Bare identifiers (single-level variable references) treated as user
 * input. Intentionally narrow: only names whose SEMANTIC meaning is
 * unambiguously "value arrived from outside this process". Naming-
 * convention heuristics (e.g. "requestedScope", "clientScope") are
 * explicitly excluded — those trigger false positives on validator
 * functions that legitimately split and reject user input.
 */
export const USER_INPUT_IDENTIFIERS: Record<string, true> = {
  userInput: true,
  user_input: true,
  userinput: true,
};

/**
 * Top-level receivers whose property access is implicitly user-controlled.
 * `req.query.scope` → receiver `req`, chain includes `query`. The rule
 * walks PropertyAccessExpression chains and matches when the BASE
 * receiver is in this map.
 */
export const USER_INPUT_RECEIVER_ROOTS: Record<string, true> = {
  req: true,
  request: true,
  ctx: true,
  event: true,
  args: true,
  params: true,
  query: true,
  body: true,
  headers: true,
  url: true,
  searchparams: true,
  // Generic frameworks
  context: true,
};

/**
 * Intermediate property names that confirm the base receiver is an
 * HTTP/MCP input surface. Used to disambiguate `ctx.user.email` (a
 * trusted value the server may have resolved) from `ctx.body.scope`
 * (user-controlled). Presence of one of these in the chain is required
 * when the base is a generic name like `ctx` or `event`.
 */
export const USER_INPUT_CHAIN_MARKERS: Record<string, true> = {
  body: true,
  query: true,
  params: true,
  headers: true,
  searchparams: true,
  url: true,
  input: true,
};
