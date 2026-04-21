/**
 * K7 TN-03 — expiresIn specified in milliseconds ("86400000ms" = 24h).
 * The parser divides by 1000 to yield 86400s, within policy. Expected:
 * no finding. This fixture proves the rule does NOT over-flag `ms`-
 * suffixed values as if they were seconds.
 */

import jwt from "jsonwebtoken";

export function issueMsToken(userId: string): string {
  return jwt.sign({ userId }, "secret-key", { expiresIn: "86400000ms" });
}
