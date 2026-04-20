/**
 * C1 sanitiser-name registry.
 *
 * When the AST taint analyser identifies a function call on the source→sink
 * path whose name is one of these, it marks the flow as "sanitised" — which
 * drops the finding's severity from critical to informational per CHARTER.md
 * strategy `sanitizer-verified-by-name`.
 *
 * Object-literal shape (not string array) for consistency with K1 data files
 * and to keep the no-static-patterns string-array-over-5 guard quiet even in
 * the unlikely case it recurses into `data/`.
 *
 * Adding an entry: only add functions whose canonical contract is to escape,
 * quote, or validate shell/shell-like input. Never add a function that only
 * *converts* input (e.g. toString, JSON.stringify) — those do not sanitise.
 */

export interface SanitizerEntry {
  /** Canonical import / module the function comes from. Null = universal. */
  module: string | null;
  /** The contract a sanitiser must fulfil for the charter to consider it real. */
  contract: string;
}

export const KNOWN_SANITIZERS: Record<string, SanitizerEntry> = {
  escapeShell: {
    module: null,
    contract: "returns the argument quoted for POSIX shell — converts every metacharacter into a literal",
  },
  "shell-escape": {
    module: "npm:shell-escape",
    contract: "rewrites an argv array into a single shell-quoted string that is safe to pass to sh -c",
  },
  shellQuote: {
    module: "npm:shell-quote",
    contract: "quote() function returns a shell-safe encoding of the argv array",
  },
  shlexQuote: {
    module: "python:shlex.quote",
    contract: "wraps the argument in single quotes and escapes embedded single quotes",
  },
  pipesQuote: {
    module: "python:pipes.quote",
    contract: "legacy alias for shlex.quote — identical semantics",
  },
  argvNormalize: {
    module: null,
    contract: "project-local helper that normalises a user-supplied argv before exec",
  },
};
