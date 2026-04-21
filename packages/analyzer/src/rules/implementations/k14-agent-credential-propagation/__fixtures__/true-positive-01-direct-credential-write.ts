/**
 * K14 TP-01 — direct credential write to a cross-agent shared store.
 *
 * Pattern: a credential-named identifier (`token`) is passed directly to
 * a writer method on a known shared-state receiver (`sharedStore.set`).
 * No redactor in scope. Expected: one finding, kind=direct-credential-write.
 */

declare const sharedStore: { set(key: string, value: unknown): void };

export async function persistAuth(token: string): Promise<void> {
  sharedStore.set("auth", token);
}
