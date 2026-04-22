/**
 * K5 vocabulary tables — loaded by gather.ts.
 */

export const AUTO_APPROVE_TOKENS: ReadonlySet<string> = new Set([
  "auto_approve",
  "autoApprove",
  "auto-approve",
  "skipConfirm",
  "skip_confirm",
  "skip_confirmation",
  "bypass_confirm",
  "bypassConfirmation",
  "no_confirm",
  "noConfirm",
  "disable_confirm",
  "force_approve",
  "forceApprove",
  "force_execute",
  "forceExecute",
  "yolo",
  "dangerously",
  "unsafe_mode",
  "unsafeMode",
  "non_interactive",
  "nonInteractive",
]);

export const CONFIRMATION_FUNCTION_NAMES: ReadonlySet<string> = new Set([
  "confirm",
  "askUser",
  "requireApproval",
  "requireConfirmation",
  "promptUser",
  "getUserConfirmation",
  "checkApproval",
]);

export const ENV_VAR_BYPASS_TOKENS: ReadonlySet<string> = new Set([
  "AUTO_APPROVE",
  "NO_CONFIRM",
  "SKIP_CONFIRM",
  "YOLO",
  "MCP_NON_INTERACTIVE",
  "UNSAFE_MODE",
]);
