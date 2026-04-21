/**
 * K4 TN-04 — forward-flow guard: `await confirm(...)` sits on a preceding
 * sibling statement in the same Block as the destructive call. The
 * preceding-sibling walker in gather-ast.ts recognises this pattern even
 * though the destructive call is NOT inside an IfStatement's thenStatement.
 */

declare function confirm(msg: string): Promise<boolean>;
const cache = { purge(): void { /* real */ } };

export async function flushCache(): Promise<void> {
  await confirm("Purge the cache now?");
  cache.purge();
}
