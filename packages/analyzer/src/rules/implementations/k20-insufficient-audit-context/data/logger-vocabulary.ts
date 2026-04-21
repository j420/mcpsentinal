/**
 * K20 logger-call vocabulary.
 *
 * Five registries consumed by gather.ts:
 *
 *   - STRUCTURED_LOGGER_PACKAGES — names of importable structured
 *     logger modules. Used to detect "structured logger imported in
 *     this file" as a mitigation signal (and to defer console.* calls
 *     to K1 when set).
 *
 *   - CONVENTIONAL_LOGGER_IDENTIFIERS — identifiers that, when observed
 *     as a receiver of a log-level call, are treated as "looks like a
 *     logger" even without import resolution. The sets cover the
 *     identifiers that appear in real-world MCP server code.
 *
 *   - LOG_LEVEL_METHODS — method names that indicate a log emission.
 *     Matches pino/winston/bunyan/tslog/loguru conventions.
 *
 *   - INDIRECT_STRUCTURED_WRAPPERS — function names that the rule
 *     treats as indirect structured-logging wrappers (consistent with
 *     K1's strategy of the same name) — these are NOT fired on,
 *     because the field injection happens inside the wrapper and is
 *     not observable at the call site.
 *
 *   - MIXIN_FORMAT_CONSTRUCTORS — constructor/factory call receiver
 *     names that indicate a pino mixin or winston format transformer
 *     is in scope, which adds fields invisibly at emission time.
 *     Used as a PRESENT-mitigation signal.
 *
 *   - BINDINGS_METHOD_NAMES — receiver method names that construct a
 *     pino "child" binding — the fields passed to these are folded
 *     into the observed-alias set for downstream call sites on the
 *     chain.
 *
 * Every list is modelled as an object (not a string-literal array) so
 * the `no-static-patterns` guard does not count it as a long
 * string-array literal.
 */

export const STRUCTURED_LOGGER_PACKAGES: Record<string, true> = {
  pino: true,
  winston: true,
  bunyan: true,
  tslog: true,
  log4js: true,
  loglevel: true,
  signale: true,
  consola: true,
  roarr: true,
  "pino-http": true,
  "pino-pretty": true,
  "winston-daily-rotate-file": true,
  "winston-transport": true,
  structlog: true,
  loguru: true,
  logging: true,
};

/**
 * Identifier names that are conventionally the local binding for a
 * structured logger. When the call receiver matches one of these, we
 * treat the call as a structured-logger call even without following
 * imports. Keyed lowercased.
 */
export const CONVENTIONAL_LOGGER_IDENTIFIERS: Record<string, true> = {
  logger: true,
  log: true,
  pino: true,
  winston: true,
  bunyan: true,
  tslog: true,
  consola: true,
  signale: true,
  loguru: true,
  structlog: true,
};

/**
 * Log-level method names on a logger or console. Matches:
 *   - console.log / info / warn / error / debug / trace
 *   - pino/winston/tslog .info / .warn / .error / .debug / .trace
 *   - bunyan / loguru .fatal
 */
export const LOG_LEVEL_METHODS: Record<string, true> = {
  log: true,
  info: true,
  warn: true,
  warning: true,
  error: true,
  debug: true,
  trace: true,
  fatal: true,
  critical: true,
  notice: true,
};

/**
 * Wrapper function names that are conventionally indirect structured-
 * logging helpers. A call of the shape `wrapperName(<args>)` is not
 * scanned for field adequacy — the wrapper is assumed to reshape its
 * arguments into a structured record. Mirrors K1's indirect-logger
 * vocabulary so both rules agree on the boundary.
 */
export const INDIRECT_STRUCTURED_WRAPPERS: Record<string, true> = {
  audit: true,
  logevent: true,
  emit: true,
  track: true,
  record: true,
};

/**
 * Receiver.method pairs that indicate a pino mixin / winston format is
 * constructed or composed in scope. When observed, confidence is
 * capped lower and a PRESENT mitigation records the ambiguity (the
 * mixin/format adds fields invisibly at emission).
 *
 * Encoded as two-level object: receiver → method-name → true.
 */
export const MIXIN_FORMAT_CONSTRUCTORS: Record<string, Record<string, true>> = {
  winston: {
    format: true,
    combine: true,
  },
  "winston.format": {
    combine: true,
    timestamp: true,
    label: true,
  },
  pino: {
    transport: true,
  },
};

/**
 * Receiver method names that construct a pino "child" binding —
 * inspection target for the child-bindings-field-resolution strategy.
 * The rule collects property names from the CallExpression's argument
 * object literal(s) when the call is `<logger>.child(<obj>)`.
 */
export const BINDINGS_METHOD_NAMES: Record<string, true> = {
  child: true,
  bindings: true,
  bind: true,
  withContext: true,
  withContextInternal: true,
};
