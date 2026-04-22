/** M8 encoding-attack-on-input vocabulary. Typed records replacing 15 regex. */

export interface DecodeFunctionSpec {
  readonly name: string;
  readonly arg_constraint: "any" | "base64-literal";
  readonly rationale: string;
}

export const DECODE_FUNCTIONS: Readonly<Record<string, DecodeFunctionSpec>> = {
  decodeURIComponent: { name: "decodeURIComponent", arg_constraint: "any", rationale: "URL-decode" },
  decodeURI: { name: "decodeURI", arg_constraint: "any", rationale: "URL-decode" },
  unescape: { name: "unescape", arg_constraint: "any", rationale: "JS legacy unescape" },
  atob: { name: "atob", arg_constraint: "any", rationale: "base64 decode" },
};

export const DECODE_FUNCTIONS_EXTRA: Readonly<Record<string, DecodeFunctionSpec>> = {
  "String.fromCharCode": { name: "String.fromCharCode", arg_constraint: "any", rationale: "char-code decode" },
  "Buffer.from": { name: "Buffer.from", arg_constraint: "base64-literal", rationale: "Buffer.from only dangerous when encoding='base64'" },
};

export const INPUT_SOURCE_TOKENS: readonly string[] = [
  "params",
  "args",
  "input",
  "request",
  "req",
];

export const INPUT_SOURCE_TOKENS_EXTRA: readonly string[] = [
  "body",
  "query",
  "payload",
  "data",
];

export const POST_DECODE_VALIDATORS: readonly string[] = [
  "validate",
  "sanitize",
  "allowlist",
  "whitelist",
  "check",
];

export const POST_DECODE_VALIDATORS_EXTRA: readonly string[] = [
  "verify",
  "schema",
  "zod",
  "joi",
];
