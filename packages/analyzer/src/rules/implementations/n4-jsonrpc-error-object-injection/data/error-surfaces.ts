/**
 * N4 — Vocabulary of user-input fragments and error-surface fragments.
 */

export interface UserInputSource {
  readonly fragment: string;
  readonly label: string;
}

export const USER_INPUT_SOURCES: Readonly<Record<string, UserInputSource>> = {
  "req.params": { fragment: "req.params", label: "req.params (JSON-RPC params)" },
  "req.body": { fragment: "req.body", label: "req.body" },
  "request.params": { fragment: "request.params", label: "request.params" },
  "request.body": { fragment: "request.body", label: "request.body" },
  "req.query": { fragment: "req.query", label: "req.query" },
  "params.arguments": { fragment: "params.arguments", label: "params.arguments (tool call args)" },
  "userinput": { fragment: "userinput", label: "userInput-named variable" },
};

export interface ErrorSurface {
  readonly fragment: string;
  readonly label: string;
}

export const ERROR_SURFACES: Readonly<Record<string, ErrorSurface>> = {
  "throw new error": { fragment: "throw new error", label: "throw new Error(...)" },
  "throw new rpcerror": { fragment: "throw new rpcerror", label: "throw new RpcError(...)" },
  "reject(new error": { fragment: "reject(new error", label: "reject(new Error(...))" },
  "error.message": { fragment: "error.message", label: "error.message field" },
  "error.data": { fragment: "error.data", label: "error.data field" },
  "err.stack": { fragment: "err.stack", label: "err.stack serialisation" },
  "stringify(req": { fragment: "stringify(req", label: "JSON.stringify(req)" },
};

/** Sanitiser fragments (when nearby, downgrade confidence). */
export const SANITISER_FRAGMENTS: Readonly<Record<string, string>> = {
  sanitise: "sanitiser call",
  sanitize: "sanitiser call",
  escape: "escape call",
  strip: "strip call",
  redact: "redact call",
  truncate: "truncate call",
};

export const N4_CONFIDENCE_CAP = 0.82;
export const N4_SANITISER_WINDOW = 4;
