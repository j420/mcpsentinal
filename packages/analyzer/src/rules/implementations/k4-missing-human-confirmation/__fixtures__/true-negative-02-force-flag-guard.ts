/**
 * K4 TN-02 — `if (force) { ... }` — the IfStatement condition references
 * a guard-flag identifier (`force`) from the guard-condition set.
 * No finding expected.
 */

const db = { deleteAll(): void { /* real */ } };

export function cleanup(force: boolean): void {
  if (force) {
    db.deleteAll();
  }
}
