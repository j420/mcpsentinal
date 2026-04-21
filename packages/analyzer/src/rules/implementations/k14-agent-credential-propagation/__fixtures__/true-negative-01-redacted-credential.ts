/**
 * K14 TN-01 — credential redacted before write.
 *
 * Pattern: `vault.seal(token)` is observed in the enclosing function
 * scope; the seal call is the canonical mitigation. The rule should
 * not fire even though a credential identifier and a shared-state
 * sink both appear in the same function.
 */

declare const sharedStore: { set(key: string, value: unknown): void };
declare const vault: { seal(input: string): string };

export function persistAuthSafely(token: string): void {
  const sealed = vault.seal(token);
  sharedStore.set("auth", sealed);
}
