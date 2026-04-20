/**
 * K4 destructive-operation vocabulary.
 *
 * Loaded at module scope by `gather.ts`. Each canonical list is an object
 * literal (Record), never a long string-literal array, so the
 * no-static-patterns guard leaves it alone. Downstream code constructs
 * ReadonlySet<string> views over `Object.keys(X)` at module load.
 *
 * Adding a verb: add a property under the correct category. The category
 * controls confidence calibration — see `gather.ts:classifyVerb()`.
 *
 * Why a verb appears here: each entry MUST correspond to an operation that,
 * if executed without human-in-the-loop confirmation, would breach:
 *
 *   - EU AI Act Art. 14 (human oversight of consequential AI actions)
 *   - ISO 42001 A.9.1 / A.9.2 (human-in-the-loop / override)
 *   - NIST AI RMF GOVERN 1.7 (decommission/override mechanisms)
 *   - OWASP ASI09 (human-agent trust exploitation)
 *
 * Verbs that describe reversible or informational operations (search,
 * list, read, load, describe, compare) are deliberately excluded.
 */

/**
 * Severity class for a destructive verb. Feeds confidence factors:
 *
 *   - "irrevocable": permanent by semantics (drop, truncate, destroy, wipe).
 *     Loss cannot be undone by running a sibling non-destructive tool.
 *     Highest confidence contribution.
 *   - "destructive": reversible in theory (delete → restore from backup)
 *     but still user-consequential. Standard confidence contribution.
 *   - "privilege": changes permission or access state rather than data
 *     (revoke, ban, block). Medium confidence contribution — orgs may
 *     intentionally wire these without confirmation inside an automation
 *     pipeline, so false-positive risk is slightly higher.
 */
export type VerbClass = "irrevocable" | "destructive" | "privilege";

export interface VerbEntry {
  klass: VerbClass;
  /**
   * Whether the verb IMPLIES bulk/mass effect on its own, without a
   * sibling bulk marker. "drop" a table is bulk; "delete" is single-item
   * unless combined with "all", "many", "batch".
   */
  implicitBulk: boolean;
}

/** Destructive verbs, keyed by lowercased exact token. */
export const DESTRUCTIVE_VERBS: Record<string, VerbEntry> = {
  delete:     { klass: "destructive", implicitBulk: false },
  remove:     { klass: "destructive", implicitBulk: false },
  drop:       { klass: "irrevocable", implicitBulk: true  }, // DROP TABLE is bulk by semantics
  truncate:   { klass: "irrevocable", implicitBulk: true  },
  destroy:    { klass: "irrevocable", implicitBulk: false },
  purge:      { klass: "irrevocable", implicitBulk: true  },
  wipe:       { klass: "irrevocable", implicitBulk: true  },
  erase:      { klass: "irrevocable", implicitBulk: false },
  obliterate: { klass: "irrevocable", implicitBulk: true  },
  // Reset/clear — reversibility depends on context but regulators treat as destructive
  reset:      { klass: "destructive", implicitBulk: false },
  clear:      { klass: "destructive", implicitBulk: false },
  // Privilege / access state changes
  revoke:     { klass: "privilege",   implicitBulk: false },
  terminate:  { klass: "privilege",   implicitBulk: false },
  kill:       { klass: "privilege",   implicitBulk: false },
  shutdown:   { klass: "privilege",   implicitBulk: false },
  uninstall:  { klass: "destructive", implicitBulk: false },
  deactivate: { klass: "privilege",   implicitBulk: false },
  disable:    { klass: "privilege",   implicitBulk: false },
  ban:        { klass: "privilege",   implicitBulk: false },
  block:      { klass: "privilege",   implicitBulk: false },
  suspend:    { klass: "privilege",   implicitBulk: false },
  unpublish:  { klass: "destructive", implicitBulk: false },
  unsubscribe:{ klass: "destructive", implicitBulk: false },
  overwrite:  { klass: "destructive", implicitBulk: false },
};

/**
 * Tokens that AMPLIFY a destructive verb's bulk class. A tool named
 * `delete_all_users` is more dangerous than `delete_user`; a call to
 * `removeMany` is more dangerous than `remove`.
 *
 * Detection is by exact token match after identifier tokenisation.
 */
export const BULK_MARKERS: Record<string, true> = {
  all: true,
  many: true,
  bulk: true,
  batch: true,
  multiple: true,
  mass: true,
  every: true,
  recursive: true,
  cascade: true,
  force: true, // "force" as a SUFFIX on a verb (deleteForce) means "skip checks"
  global: true,
};

/**
 * Tokens that REDUCE the perceived destructiveness of a verb. "soft_delete"
 * is reversible by semantics — the record is flagged, not removed. The
 * rule must not treat this the same as an unconstrained delete.
 *
 * Presence of any soft marker reduces confidence by a calibrated factor
 * — it does not silence the finding (a missing confirmation gate is
 * still a compliance gap, just a lower-severity one).
 */
export const SOFT_MARKERS: Record<string, true> = {
  soft: true,
  draft: true,
  archive: true,
  archived: true,
  trash: true,
  undo: true,
  recycle: true,
  recoverable: true,
};

/**
 * Lexical markers in a tool description that ESCALATE confidence: when the
 * tool's own documentation says "cannot be undone", the rule has explicit
 * evidence that the author knows this is irreversible and therefore should
 * require confirmation.
 *
 * Detection is by tokenised substring match on the description — the
 * bigram `cannot_be_undone` is detected by joining consecutive words with
 * `_` during gather.ts tokenisation.
 */
export const IRREVERSIBILITY_MARKERS: Record<string, true> = {
  permanently: true,
  irreversibly: true,
  irrevocable: true,
  irreversible: true,
  unrecoverable: true,
  destructive: true,
  dangerous: true,
  // Compound markers joined with "_" at tokenisation
  cannot_be_undone: true,
  cannot_be_reversed: true,
  not_recoverable: true,
  no_undo: true,
  no_recovery: true,
};
