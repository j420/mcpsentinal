/**
 * K17 TP-03 — bare got() call without timeout; no got.extend({ timeout })
 * in this file. Expected: one finding.
 */

import got from "got";

export async function loadResource(url: string): Promise<unknown> {
  return got(url);
}
