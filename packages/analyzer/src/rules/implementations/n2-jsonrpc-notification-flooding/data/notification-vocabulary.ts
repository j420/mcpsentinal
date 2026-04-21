/**
 * N2 — Typed vocabularies for notification-flooding detection.
 *
 * Structured records, not plain string arrays.
 */

export type NotificationRole =
  | "emit-call" // identifier names a notification-producing call
  | "loop-kind" // AST kind identifier for a loop statement
  | "timer-name" // JS timer function that executes a callback repeatedly
  | "throttle-name"; // identifier name that bounds emission rate

/** Methods/verbs that produce a JSON-RPC notification or wire-level push. */
export const NOTIFICATION_VERBS: Record<string, NotificationRole> = {
  notify: "emit-call",
  notification: "emit-call",
  emit: "emit-call",
  push: "emit-call",
  broadcast: "emit-call",
  publish: "emit-call",
  sendnotification: "emit-call",
  sendevent: "emit-call",
  sendlogmessage: "emit-call",
  onlog: "emit-call",
  progressnotification: "emit-call",
};

/** Timer callbacks that execute the enclosed closure on a schedule. */
export const TIMER_FUNCTIONS: Record<string, NotificationRole> = {
  setInterval: "timer-name",
  setImmediate: "timer-name",
};

/** Vocabulary that indicates intentional rate limiting / back-pressure. */
export const THROTTLE_TOKENS: Record<string, NotificationRole> = {
  throttle: "throttle-name",
  debounce: "throttle-name",
  ratelimit: "throttle-name",
  rate_limit: "throttle-name",
  sleep: "throttle-name",
  delay: "throttle-name",
  settimeout: "throttle-name",
  break_keyword: "throttle-name",
  return_keyword: "throttle-name",
};
