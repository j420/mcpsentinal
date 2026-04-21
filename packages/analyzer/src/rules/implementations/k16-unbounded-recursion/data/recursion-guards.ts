/**
 * K16 recursion-guard vocabulary.
 *
 * Three classes:
 *   - DEPTH_PARAMETER_NAMES — identifier names used as an explicit recursion
 *     depth / level / counter parameter. Presence of one of these names in
 *     a function's parameter list (or as a local counter reset before the
 *     recursive call) is treated as a DEPTH-GUARD SIGNAL.
 *
 *   - DEPTH_CONSTANT_PREFIXES — UPPER_SNAKE constant-name prefixes that,
 *     when compared against the guard variable, indicate an explicit upper
 *     bound (MAX_DEPTH, MAX_LEVEL, MAX_RECURSION, etc.). Detection walks
 *     the function body for an if/return/throw check comparing a known
 *     guard parameter to an identifier starting with one of these prefixes.
 *
 *   - CYCLE_BREAKER_TYPES — built-in collection constructors (Set, Map,
 *     WeakSet, WeakMap) whose presence inside the function body — with the
 *     guard variable being added/checked against it — indicates a visited-
 *     set cycle breaker. This is the "graph with cycles" idiom.
 *
 * Vocabulary is object-literal shaped; detection projects keys into
 * ReadonlySet<string>. Zero regex.
 */

/** Identifier names recognised as an explicit recursion guard parameter. */
export const DEPTH_PARAMETER_NAMES: Record<string, true> = {
  depth: true,
  level: true,
  remaining: true,
  budget: true,
  maxdepth: true,
  maxlevel: true,
  maxrecursion: true,
  recursiondepth: true,
  counter: true,
  iterations: true,
  iteration: true,
  step: true,
  steps: true,
  hops: true,
  limit: true,
};

/**
 * Identifier prefixes recognised as an upper-bound constant when compared
 * against a guard parameter (e.g. `if (depth > MAX_DEPTH) return`).
 * Detection checks the literal token prefix — no regex.
 */
export const DEPTH_CONSTANT_PREFIXES: Record<string, true> = {
  MAX_: true,
  LIMIT_: true,
  BOUND_: true,
  CAP_: true,
};

/** Constructors whose instance, when consulted inside the function body
 *  relative to the recursive call, indicates a visited-set cycle breaker. */
export const CYCLE_BREAKER_TYPES: Record<string, true> = {
  set: true,
  map: true,
  weakset: true,
  weakmap: true,
};

/**
 * Method names on a visited-set collection whose presence (combined with an
 * `add` or `set` call) is accepted as "this function uses a cycle breaker".
 * Detection looks for a CallExpression whose method-name token matches.
 */
export const CYCLE_BREAKER_MEMBER_METHODS: Record<string, true> = {
  has: true,
  get: true,
  add: true,
  set: true,
};

/**
 * Tool-call method receivers used inside a function body indicate a tool
 * invocation — when combined with the function also being registered as a
 * tool handler, this is a "recursion via tool call" site. The receiver
 * vocabulary is intentionally narrow; extensions live in consumer repos.
 */
export const TOOL_CALL_RECEIVERS: Record<string, true> = {
  server: true,
  mcp: true,
  client: true,
  transport: true,
  session: true,
  agent: true,
};

/**
 * Method names on a tool-call receiver whose invocation indicates the
 * function is re-entering the tool-call boundary.
 */
export const TOOL_CALL_METHODS: Record<string, true> = {
  callTool: true,
  calltool: true,
  call: true,
  invoke: true,
  request: true,
  send: true,
  dispatch: true,
  execute: true,
};
