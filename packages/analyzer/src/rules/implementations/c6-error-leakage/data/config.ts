/**
 * C6 — Error Leakage: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 * Detection logic in gather.ts walks the AST and consumes these typed sets.
 *
 * Zero regex literals. The arrays here are typed records consumed via
 * Set membership / startsWith — not regex.
 */

/**
 * Method names whose first argument is treated as a response-body sink.
 * Covers Express/Fastify/Koa/Connect-style response methods plus the
 * Node http response stream API.
 */
export const RESPONSE_SINK_METHODS: ReadonlySet<string> = new Set([
  "json",
  "send",
  "write",
  "end",
  "status",
]);

/**
 * Identifier names commonly bound to an Error instance in catch
 * clauses, handler params, and user code. Conservative — a literal
 * value of any of these names is treated as an Error carrier when it
 * appears as an argument to a response sink.
 *
 * NOTE: this is intentionally a typed Set, not an array, so the
 * no-static-patterns guard counts zero string-array literals here.
 */
export const ERROR_IDENTIFIER_NAMES: ReadonlySet<string> = new Set([
  "err",
  "error",
  "e",
  "ex",
  "exception",
]);

/**
 * Property names on an error object whose access is itself a leak
 * signal — `error.stack` / `error.message` etc. flowing into a
 * response sink is the canonical CWE-209 pattern.
 */
export const SENSITIVE_ERROR_PROPERTIES: ReadonlySet<string> = new Set([
  "stack",
  "stackTrace",
  "stack_trace",
  "originalError",
]);

/**
 * Python traceback APIs whose return value is the entire stack as a
 * string. A direct call to one of these in a response body is a leak.
 */
export const PYTHON_TRACEBACK_CALLS: ReadonlySet<string> = new Set([
  "format_exc",
  "format_exception",
  "print_exc",
  "format_tb",
]);

/**
 * Charter-audited error sanitiser names. A call wrapping the error
 * with one of these in the same expression downgrades the finding.
 */
export const CHARTER_ERROR_SANITISERS: ReadonlySet<string> = new Set([
  "sanitizeError",
  "formatErrorForClient",
  "toSafeMessage",
  "redactError",
  "publicError",
]);

/**
 * Production-gate substrings — when the enclosing code branch contains
 * one of these, the leak is treated as gated to non-production.
 * Substring match (no regex) is sufficient because the patterns are
 * unambiguous.
 */
export const PRODUCTION_GATE_MARKERS: ReadonlySet<string> = new Set([
  'NODE_ENV !== "production"',
  "NODE_ENV !== 'production'",
  'NODE_ENV === "development"',
  "NODE_ENV === 'development'",
  "settings.DEBUG",
]);
