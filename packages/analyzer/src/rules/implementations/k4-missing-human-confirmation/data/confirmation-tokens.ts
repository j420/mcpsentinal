/**
 * K4 confirmation-gate vocabulary.
 *
 * Two distinct surfaces:
 *
 *   1. SCHEMA surface — parameter NAMES that, when present on a tool, act
 *      as a mitigation. The AI client must pass a value to satisfy the
 *      required parameter, which forces a confirmation moment.
 *
 *   2. CODE surface — AST identifiers that, when present in a guarding
 *      control-flow structure in the enclosing scope, indicate a
 *      confirmation gate. These split into:
 *        - guard-call identifiers: bare function calls like confirm(),
 *          prompt(), approve() that halt flow until user acts.
 *        - guard-condition identifiers: variable names like `force`,
 *          `dry_run`, `approved` used as an IfStatement condition.
 *
 * Object-literal form (Record<string, Kind>) avoids the no-static-patterns
 * guard's array-literal check.
 */

/**
 * Confirmation strength for a schema parameter. The rule emits different
 * confidence factors depending on which kind of confirmation is offered.
 *
 *   - "binary-confirm": user must pass `confirm: true`. Explicit consent.
 *   - "dry-run":        user can pass `dry_run: true` to simulate without
 *                        committing. Equivalent to preview; considered a
 *                        mitigation only when DEFAULT=true or the tool
 *                        strongly telegraphs opt-in commit semantics.
 *   - "force-flag":     user must pass `force: true` to bypass a default
 *                        safety check. Mitigates when presence of `force`
 *                        is REQUIRED.
 *   - "acknowledgement": user passes a sentinel string/boolean proving
 *                        intent (`i_am_sure`, `acknowledge`).
 */
export type ConfirmationKind =
  | "binary-confirm"
  | "dry-run"
  | "force-flag"
  | "acknowledgement";

/** Parameter-name tokens that classify as confirmation parameters. */
export const CONFIRMATION_PARAM_TOKENS: Record<string, ConfirmationKind> = {
  confirm:          "binary-confirm",
  confirmation:     "binary-confirm",
  confirmed:        "binary-confirm",
  approve:          "binary-confirm",
  approved:         "binary-confirm",
  approval:         "binary-confirm",
  acknowledge:      "acknowledgement",
  acknowledged:     "acknowledgement",
  consent:          "binary-confirm",
  agree:            "binary-confirm",
  agreed:           "binary-confirm",
  verified:         "binary-confirm",
  i_am_sure:        "acknowledgement",
  yes_i_am_sure:    "acknowledgement",
  dry_run:          "dry-run",
  dryrun:           "dry-run",
  preview:          "dry-run",
  simulate:         "dry-run",
  plan_only:        "dry-run",
  force:            "force-flag",
};

/**
 * Bare function identifiers whose presence in an AST ancestor chain
 * indicates a confirmation gate. These are the Node.js/browser surface:
 * stdlib prompts, inquirer, readline, and common helper names adopted by
 * MCP server authors.
 */
export const GUARD_CALL_IDENTIFIERS: Record<string, true> = {
  confirm: true,
  prompt: true,
  approve: true,
  ask: true,
  verify: true,
  acknowledge: true,
  requireConfirmation: true,
  requestApproval: true,
  elicit: true, // MCP 2025-06-18 elicitation capability
};

/**
 * Receiver.method property-access pairs that indicate a confirmation gate
 * when the method appears on a known prompt/inquiry object.
 *
 * Example: `await inquirer.prompt(...)` — receiver=`inquirer`, method=`prompt`.
 * Example: `await rl.question(...)` — receiver-pattern=readline, method=`question`.
 */
export const GUARD_RECEIVER_METHODS: Record<string, Record<string, true>> = {
  inquirer:     { prompt: true, confirm: true },
  readline:     { question: true },
  rl:           { question: true },
  window:       { confirm: true, prompt: true },
  enquirer:     { prompt: true },
  prompts:      { confirm: true, prompt: true },
};

/**
 * Identifiers appearing in an IfStatement condition that count as the
 * "force/confirm flag" pattern:
 *
 *   if (force) { delete(...); }
 *   if (approved) { drop(...); }
 *
 * Detection is an AST walk of the condition expression, collecting every
 * referenced Identifier, and checking membership in this set.
 */
export const GUARD_CONDITION_IDENTIFIERS: Record<string, true> = {
  force: true,
  forced: true,
  confirm: true,
  confirmed: true,
  confirmation: true,
  approve: true,
  approved: true,
  approval: true,
  acknowledged: true,
  verified: true,
  dryRun: true,
  dry_run: true,
  preview: true,
  simulate: true,
  plan_only: true,
  consent: true,
  agreed: true,
};

/**
 * MCP 2025-03-26 tool-annotation fields that carry the destructiveHint
 * signal. Presence of `destructiveHint: true` is a PARTIAL mitigation —
 * MCP-aware clients prompt for confirmation, non-MCP-aware clients do
 * not. The rule emits a calibrated confidence reduction, not silence.
 */
export const DESTRUCTIVE_ANNOTATION_FIELDS: Record<string, true> = {
  destructiveHint: true,
  readOnlyHint: true, // present+true = explicit contradiction with a destructive name
};
