/**
 * C12 — Unsafe Deserialization: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 * Consumed by gather.ts to filter the shared taint-rule-kit's output.
 */

/** Sink categories reported by analyzeASTTaint that C12 treats as deserialisation sinks. */
export const C12_AST_SINK_CATEGORIES: readonly string[] = ["deserialization"] as const;

/** Sink categories reported by the lightweight analyzeTaint engine. */
export const C12_LIGHTWEIGHT_SINK_CATEGORIES: readonly string[] = ["deserialization"] as const;

/**
 * Charter-audited sanitiser names — functions whose contract is to
 * parse data without executing embedded code. Identification by name
 * alone; a reviewer must still confirm the binding points at the
 * canonical library function (CHARTER edge case sanitiser-identity
 * bypass). The charter-unknown branch emits the dedicated factor.
 */
export const C12_CHARTER_SANITISERS: ReadonlySet<string> = new Set([
  "safe_load",
  "SafeLoader",
  "json.loads",
  "JSON.parse",
  "literal_eval",
  "ast.literal_eval",
  "parseJson",
  "parseTyped",
  "msgpack.unpackb",
  "cbor.decode",
]);
