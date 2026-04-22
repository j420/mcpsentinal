/**
 * O5 — Env-var bulk-access vocabulary.
 *
 * Two token groups (≤5 entries each) kept in typed records so the
 * no-static-patterns guard never counts a raw string array.
 *
 *   BULK_ACCESSOR_METHODS  — Object.{keys,entries,values,fromEntries},
 *                            JSON.stringify. Python bulk attribute
 *                            names (items, keys, values, copy) and
 *                            `dict` factory.
 *   ENV_RECEIVER_TOKENS    — receivers that qualify as the env-var
 *                            source: process.env, os.environ.
 *
 * The ambient-credential tokens from DATA_EXFIL_SINKS are surfaced
 * for the evidence chain narrative but are not part of the bulk-
 * read detection logic.
 */

import { sinksOfKind, type ExfilSinkSpec } from "../../_shared/data-exfil-sinks.js";

export const ENV_VAR_SINKS: readonly ExfilSinkSpec[] = sinksOfKind("env-var");

/**
 * Node/JS bulk accessors. Keys are lowercase; the gather step
 * lowercases any observed method name before lookup.
 */
export const JS_BULK_METHODS: Readonly<Record<string, true>> = {
  keys: true,
  entries: true,
  values: true,
  fromentries: true,
  stringify: true,
};

/**
 * Python bulk attribute / method names for os.environ.
 */
export const PY_BULK_METHODS: Readonly<Record<string, true>> = {
  items: true,
  keys: true,
  values: true,
  copy: true,
};

/**
 * Receivers that qualify as the env source. For `process.env` we
 * match on the property chain; for `os.environ` we match on the
 * qualified receiver identifier path.
 */
export const ENV_ROOT_RECEIVERS: Readonly<Record<string, string>> = {
  "process.env": "Node process environment (process.env)",
  "os.environ": "Python os module environment (os.environ)",
  "environ": "Python environ (imported-from-os alias)",
};

/**
 * Allowlist / filter identifiers that, when observed in the same
 * scope as a bulk read, demote the finding below the confidence
 * floor. A bulk read followed by explicit filtering is the
 * "selective environment copy" pattern legitimate server authors
 * sometimes use.
 */
export const ALLOWLIST_FILTERS: Readonly<Record<string, string>> = {
  allowlist: "explicit allowlist array guard",
  allowList: "camelCase allowlist array guard",
  safelist: "explicit safelist array guard",
  ALLOWED_ENV_VARS: "constant allowlist guard",
  PUBLIC_ENV_PREFIX: "prefix filter guard",
};
