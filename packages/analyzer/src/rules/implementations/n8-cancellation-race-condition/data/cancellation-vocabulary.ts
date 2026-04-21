/**
 * N8 — Typed vocabularies for cancellation race detection.
 */

export type CancellationRole =
  | "cancel-handler"
  | "abort-signal"
  | "mutation-verb"
  | "transaction-verb"
  | "lock-verb";

/** Identifier names that register or handle a cancellation. */
export const CANCEL_HANDLERS: Record<string, CancellationRole> = {
  oncancel: "cancel-handler",
  oncancelled: "cancel-handler",
  oncancellation: "cancel-handler",
  handlecancel: "cancel-handler",
  handlecancelled: "cancel-handler",
  cancelhandler: "cancel-handler",
};

export const ABORT_SIGNAL_NAMES: Record<string, CancellationRole> = {
  AbortController: "abort-signal",
  AbortSignal: "abort-signal",
  signal: "abort-signal",
};

/** Mutation method names. Presence near a cancel handler is evidence of the race. */
export const MUTATION_VERBS: Record<string, CancellationRole> = {
  write: "mutation-verb",
  writefile: "mutation-verb",
  writesync: "mutation-verb",
  insert: "mutation-verb",
  update: "mutation-verb",
  delete: "mutation-verb",
  deletemany: "mutation-verb",
  deleteone: "mutation-verb",
  remove: "mutation-verb",
  rollback: "mutation-verb",
  drop: "mutation-verb",
  execute: "mutation-verb",
  run: "mutation-verb",
  exec: "mutation-verb",
  save: "mutation-verb",
  put: "mutation-verb",
  post: "mutation-verb",
  commit: "mutation-verb",
  deletepartial: "mutation-verb",
};

/** Transaction / atomicity vocabulary. Presence inverts the finding. */
export const TRANSACTION_VERBS: Record<string, CancellationRole> = {
  begintransaction: "transaction-verb",
  starttransaction: "transaction-verb",
  transaction: "transaction-verb",
  atomic: "transaction-verb",
  savepoint: "transaction-verb",
  tx: "transaction-verb",
};

/** Lock / mutex vocabulary. Presence inverts the finding. */
export const LOCK_VERBS: Record<string, CancellationRole> = {
  lock: "lock-verb",
  mutex: "lock-verb",
  semaphore: "lock-verb",
  acquire: "lock-verb",
  synchronized: "lock-verb",
};
