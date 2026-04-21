/**
 * K14 TN-02 — credential written to a per-agent private store.
 *
 * The receiver `agentLocalCache` is NOT in the K14 cross-agent
 * vocabulary. Per-agent caches are out of scope; the rule should
 * not fire.
 */

declare const agentLocalCache: { set(key: string, value: unknown): void };

export function cacheLocally(token: string): void {
  agentLocalCache.set("auth", token);
}
