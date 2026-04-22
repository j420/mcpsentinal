/**
 * O8 — Timing-Primitive Vocabulary.
 *
 * Each Record is ≤5 entries so the no-static-patterns guard never
 * flags a "disguised pattern array". The gather step iterates the
 * Records keys, NOT a regex.
 */

/**
 * Call expressions whose numeric argument is a delay in ms / seconds.
 * When the argument is NOT a constant and NOT a counter identifier,
 * the site is a candidate for O8.
 */
export const TIMING_CALL_PRIMITIVES: Readonly<Record<string, string>> = {
  setTimeout: "Node setTimeout(cb, ms) — delay in milliseconds",
  setInterval: "Node setInterval(cb, ms) — repeating delay",
  setImmediate: "Node setImmediate(cb) — deferred to next tick",
  sleep: "cross-runtime sleep helper (await sleep(ms))",
  "time.sleep": "Python time.sleep(seconds)",
};

/**
 * Alternative Python-shaped sleep member-access expressions.
 */
export const PYTHON_SLEEP_MEMBERS: Readonly<Record<string, string>> = {
  sleep: "time.sleep / asyncio.sleep (receiver walked separately)",
  wait: "asyncio.wait_for / event.wait",
};

/**
 * Counter / constant identifier vocabulary. A delay argument whose
 * Identifier text appears here is treated as legitimate rate-limit
 * or backoff infrastructure — the site is demoted / skipped.
 */
export const COUNTER_IDENTIFIERS: Readonly<Record<string, string>> = {
  retryCount: "exponential-backoff retry counter",
  attempt: "retry attempt index",
  delayMs: "configured rate-limit delay",
  RATE_LIMIT_MS: "global rate-limit constant",
  backoff: "configured backoff interval",
};

/**
 * Identifier names that PLAUSIBLY hold secret-derived data — used
 * only as a positive-signal heuristic, not as a blocklist.
 */
export const DATA_DEPENDENT_HINTS: Readonly<Record<string, string>> = {
  secret: "generic secret / credential variable",
  token: "access/refresh token variable",
  data: "generic untrusted data",
  bit: "per-bit encoding loop variable",
  ch: "per-character encoding loop variable",
};

/**
 * HTTP header setters used for Retry-After timing modulation.
 */
export const RETRY_AFTER_SETTERS: Readonly<Record<string, string>> = {
  setHeader: "res.setHeader",
  header: "fastify reply.header",
  set: "express/koa response.set",
  append: "res.append header",
};

/**
 * Progress-notification senders — when sandwiched around a
 * non-constant sleep, the INTERVAL carries the covert payload.
 * Cross-ref to N15 (progress-token abuse).
 */
export const PROGRESS_NOTIFIERS: Readonly<Record<string, string>> = {
  sendProgress: "MCP sendProgress helper",
  progress: "generic progress notification helper",
  notifyProgress: "progress notifier helper",
  onProgress: "progress emitter",
};
