/**
 * K17 timeout-option vocabulary.
 *
 * Three classes:
 *   - CALL_TIMEOUT_OPTIONS — property names inside an HTTP call's options
 *     object that set a timeout. Presence of ANY of these is a mitigation.
 *   - ABORT_CONSTRUCTORS — constructor / factory names that produce an
 *     AbortSignal (new AbortController(), AbortSignal.timeout()).
 *   - CIRCUIT_BREAKER_PACKAGES — npm package names implementing circuit
 *     breakers. Presence in context.dependencies is a MITIGATION (signals
 *     the project has library-level timeout infrastructure).
 */

/** Option-property names inside an HTTP-call options object. */
export const CALL_TIMEOUT_OPTIONS: Record<string, true> = {
  timeout: true,
  signal: true,
  deadline: true,
  headerstimeout: true,
  bodytimeout: true,
  headers_timeout: true,
  body_timeout: true,
  requesttimeout: true,
  request_timeout: true,
  responsetimeout: true,
  response_timeout: true,
  connecttimeout: true,
  connect_timeout: true,
};

/**
 * Constructor / factory identifiers that produce an AbortSignal. The rule
 * considers an enclosing scope containing one of these to carry a timeout
 * mitigation if the produced signal is subsequently referenced.
 */
export const ABORT_CONSTRUCTORS: Record<string, true> = {
  abortcontroller: true,
  abortsignal: true,
};

/** Methods on AbortSignal that produce a time-bounded signal. */
export const ABORT_SIGNAL_METHODS: Record<string, true> = {
  timeout: true,
  any: true,
  abort: true,
};

/** Package names registered as circuit-breaker libraries. */
export const CIRCUIT_BREAKER_PACKAGES: Record<string, true> = {
  opossum: true,
  cockatiel: true,
  brakes: true,
  levee: true,
  hystrixjs: true,
  "circuit-breaker-js": true,
  "circuit-breaker": true,
};
