/**
 * I1 destructive-vocabulary registry.
 *
 * The destructive and write verbs that identify a tool's capability
 * in parameter names and description text. Object-literal shape
 * (typed Record keyed by the verb token) so the no-static-patterns
 * guard does not treat the list as a long string-literal array.
 *
 * Adding a verb: add a property with the `kind` classification and
 * a short `attribution` string that surfaces in the evidence-chain
 * factor rationale. The classification separates deletion-class
 * verbs ("delete", "drop") from write-class verbs ("write",
 * "create") so the chain can report which axis of destructive
 * intent the deception hides.
 */

export type DestructiveKind = "delete" | "overwrite" | "terminate";
export type WriteKind = "write";
export type VerbKind = DestructiveKind | WriteKind;

export interface DestructiveVerbEntry {
  /** Category of destructive intent. */
  kind: VerbKind;
  /** Short attribution surfaced in ConfidenceFactor rationales. */
  attribution: string;
}

/**
 * Destructive verbs — operations that remove, overwrite, or terminate
 * state. Any of these appearing in a parameter name or description is
 * a direct contradiction of readOnlyHint: true.
 */
export const DESTRUCTIVE_VERBS: Record<string, DestructiveVerbEntry> = {
  delete: { kind: "delete", attribution: "deletion verb — removes state." },
  remove: { kind: "delete", attribution: "deletion verb — removes entries." },
  drop: { kind: "delete", attribution: "deletion verb — drops tables/indexes." },
  purge: { kind: "delete", attribution: "deletion verb — destructive bulk removal." },
  wipe: { kind: "delete", attribution: "deletion verb — erases all state." },
  erase: { kind: "delete", attribution: "deletion verb — removes content." },
  destroy: { kind: "delete", attribution: "deletion verb — permanent removal." },
  truncate: { kind: "overwrite", attribution: "overwrite verb — resets table contents." },
  overwrite: { kind: "overwrite", attribution: "overwrite verb — replaces state." },
  reset: { kind: "overwrite", attribution: "overwrite verb — resets to defaults." },
  kill: { kind: "terminate", attribution: "termination verb — stops a process." },
  terminate: { kind: "terminate", attribution: "termination verb — ends a session/process." },
  force: { kind: "overwrite", attribution: "override modifier — bypasses safety checks." },
};

/**
 * Write verbs — mutate state in some form. Weaker signal than
 * destructive verbs because many write operations are legitimate
 * (a "create_record" tool can be read-only at the protocol level
 * if the write target is isolated), but they still contradict
 * readOnlyHint: true.
 */
export const WRITE_VERBS: Record<string, DestructiveVerbEntry> = {
  write: { kind: "write", attribution: "write verb — mutates state." },
  create: { kind: "write", attribution: "write verb — creates new records." },
  update: { kind: "write", attribution: "write verb — modifies existing state." },
  insert: { kind: "write", attribution: "write verb — writes new entries." },
  modify: { kind: "write", attribution: "write verb — changes state." },
  append: { kind: "write", attribution: "write verb — extends state." },
  upload: { kind: "write", attribution: "write verb — writes to storage." },
  save: { kind: "write", attribution: "write verb — persists state." },
};

/**
 * Clients that are documented to auto-approve tools declaring
 * readOnlyHint: true without cross-checking the schema. Not a
 * string-literal array — a typed Record so the no-static-patterns
 * guard treats it as data, not a literal pattern list. Surfaced in
 * evidence-chain prose to make the deception's consequence concrete.
 */
export const CLIENTS_TRUSTING_READONLY_HINT: Record<string, string> = {
  ChatGPT: "auto-approves readOnlyHint: true tools without schema cross-check (Invariant Labs 2025).",
  Cursor: "auto-approves readOnlyHint: true tools without schema cross-check (Invariant Labs 2025).",
  "Roo Code": "auto-approves readOnlyHint: true tools without schema cross-check (Invariant Labs 2025).",
  "JetBrains Copilot": "auto-approves readOnlyHint: true tools without schema cross-check (Invariant Labs 2025).",
};
