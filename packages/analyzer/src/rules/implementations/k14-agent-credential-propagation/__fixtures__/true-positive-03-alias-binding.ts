/**
 * K14 TP-03 — credential written via alias binding.
 *
 * Pattern: `const s = sharedStore` then `s.set(...)`. A detector that
 * only matches the literal name `sharedStore` misses this. The rule
 * must resolve the single-step alias. Expected: one finding,
 * kind=alias-credential-write.
 */

declare const sharedStore: { set(key: string, value: unknown): void };

export function aliasedWrite(bearer: string): void {
  const s = sharedStore;
  s.set("auth", { bearer });
}
