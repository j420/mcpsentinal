/** M7 multi-turn-state-injection vocabulary. Typed records replacing 3 regex. */

export const CONVERSATION_STATE_TOKENS: readonly string[] = [
  "conversation",
  "chat",
  "history",
  "messages",
  "context",
];

export const CONVERSATION_STATE_TOKENS_EXTRA: readonly string[] = [
  "dialog",
  "turns",
  "thread",
  "memory",
];

export const MUTATION_METHOD_NAMES: readonly string[] = [
  "push",
  "unshift",
  "splice",
  "pop",
  "shift",
];

export const MUTATION_METHOD_NAMES_EXTRA: readonly string[] = [
  "concat",
  "append",
  "prepend",
  "insert",
  "inject",
];

/** Safe read-only method names — used to filter out harmless accesses. */
export const READ_ONLY_METHOD_NAMES: readonly string[] = [
  "get",
  "read",
  "filter",
  "map",
  "slice",
];
