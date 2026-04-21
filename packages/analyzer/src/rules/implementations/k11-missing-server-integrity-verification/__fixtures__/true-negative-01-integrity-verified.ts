/**
 * K11 TN-01 — dynamic import paired with a local SHA-256 check.
 * The ancestor walk sees `createHash` + `expectedSha256` variable — the
 * mitigation is present and the finding is suppressed.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

declare const config: { serverModulePath: string; expectedSha256: string };

export async function loadServer(): Promise<void> {
  const bytes = readFileSync(config.serverModulePath);
  const actualSha256 = createHash("sha256").update(bytes).digest("hex");
  if (actualSha256 !== config.expectedSha256) {
    throw new Error("integrity check failed");
  }
  const mod = await import(config.serverModulePath);
  (mod as { register: () => void }).register();
}
