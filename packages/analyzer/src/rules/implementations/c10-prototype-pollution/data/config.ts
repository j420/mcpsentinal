/**
 * C10 — Prototype Pollution: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 * Four typed records describe the detection surface:
 *
 *   1. MERGE_FUNCTION_NAMES — functions that MERGE a user object into a
 *      target (lodash _.merge family, Object.assign, deepmerge, etc.).
 *   2. CRITICAL_KEY_NAMES — property-access keys that, if written with a
 *      user-controlled value, directly pollute Object.prototype.
 *   3. USER_INPUT_RECEIVER_CHAINS — property chains that yield untrusted
 *      data (req.body, request.args, process.env).
 *   4. GUARD_FUNCTION_NAMES — calls / patterns that constitute a charter-
 *      audited mitigation (hasOwnProperty, Object.create(null), key
 *      allowlist functions).
 */

/** Functions whose call shape is `fn(target, userObj, ...)` and whose semantics include prototype-chain merge. */
export const MERGE_FUNCTION_NAMES: Record<string, { receivers: readonly string[]; merge_arg_start: number }> = {
  merge: { receivers: ["_", "lodash"], merge_arg_start: 1 },
  mergeWith: { receivers: ["_", "lodash"], merge_arg_start: 1 },
  defaultsDeep: { receivers: ["_", "lodash"], merge_arg_start: 1 },
  set: { receivers: ["_", "lodash"], merge_arg_start: 1 },
  assign: { receivers: ["Object"], merge_arg_start: 1 },
  fromEntries: { receivers: ["Object"], merge_arg_start: 0 },
  deepmerge: { receivers: [], merge_arg_start: 1 },
  extend: { receivers: ["$", "jQuery"], merge_arg_start: 1 },
};

/** Keys that directly pollute Object.prototype when written with a user-controlled value. */
export const CRITICAL_KEY_NAMES: readonly string[] = [
  "__proto__",
  "constructor",
  "prototype",
];

/** Property-chain sources that, when they flow into a merge sink, indicate user-controlled merge input. */
export const USER_INPUT_RECEIVER_CHAINS: readonly (readonly string[])[] = [
  ["req", "body"],
  ["req", "params"],
  ["req", "query"],
  ["request", "body"],
  ["request", "params"],
  ["request", "query"],
];

/** Function / method identifiers that count as charter-audited guards. */
export const GUARD_FUNCTION_NAMES: readonly string[] = [
  "hasOwnProperty",
  "freeze",
  "seal",
  "preventExtensions",
  "allowlistKey",
  "validateKey",
];

/**
 * Call patterns that remove the pollution risk by creating a
 * null-prototype object. If a merge target is built with one of
 * these patterns the charter treats the merge as mitigated.
 */
export const NULL_PROTO_CONSTRUCTOR_PATTERNS: readonly string[] = [
  "Object.create(null)",
  "Map",
];
