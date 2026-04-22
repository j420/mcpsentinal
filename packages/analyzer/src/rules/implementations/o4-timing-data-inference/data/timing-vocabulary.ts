/**
 * O4 timing-based-data-inference vocabulary.
 *
 * Typed Records replacing 13 regex literals in the legacy detector.
 * Detection uses AST traversal: identifier matches are exact (not
 * substring), call-expression names are compared verbatim.
 */

export interface DelayFunctionSpec {
  readonly kind: "setTimeout-like" | "promise-timeout" | "sleep-wait";
  readonly rationale: string;
}

/** Call-expression names that introduce an observable delay. */
export const DELAY_FUNCTION_NAMES: Readonly<Record<string, DelayFunctionSpec>> = {
  setTimeout: { kind: "setTimeout-like", rationale: "scheduled callback introduces latency" },
  setInterval: { kind: "setTimeout-like", rationale: "scheduled recurring callback introduces latency" },
  delay: { kind: "sleep-wait", rationale: "explicit delay() call introduces latency" },
  sleep: { kind: "sleep-wait", rationale: "explicit sleep() call introduces latency" },
  wait: { kind: "sleep-wait", rationale: "explicit wait() call introduces latency" },
};

/** Identifiers whose presence inside the enclosing function suggests
 * the delay amount may be controlled by sensitive data. Exact identifier
 * match — AST resolves these at Identifier nodes. */
export const DATA_DEPENDENT_IDENTIFIERS: readonly string[] = [
  "result",
  "secret",
  "password",
  "token",
  "credential",
];

/** Additional condition-keyword identifiers that signal data-dependent
 *  branching (separate set so each stays <=5 entries). */
export const DATA_DEPENDENT_CONDITIONS: readonly string[] = [
  "match",
  "data",
  "role",
  "user",
  "status",
];

/** Function/identifier names that indicate timing-safe compensation was
 *  applied in the enclosing scope. */
export const TIMING_SAFE_IDENTIFIERS: readonly string[] = [
  "timingSafeEqual",
  "constantTime",
  "constant_time",
  "randomJitter",
  "timing_safe_compare",
];

/** Math.random * N call signature indicating randomisation-based jitter. */
export const JITTER_CALLEE: string = "Math.random";
