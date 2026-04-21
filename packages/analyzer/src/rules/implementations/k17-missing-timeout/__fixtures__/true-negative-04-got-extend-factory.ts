/**
 * K17 TN-04 — got.extend({ timeout }) factory pattern. Both the bare
 * `got(...)` call and an instance created from the factory are covered.
 * Expected: no finding.
 */

import got from "got";

got.extend({ timeout: { request: 5000 } });

export async function getThing(): Promise<unknown> {
  return got("https://api.example.com/thing");
}
