/**
 * K7 TN-01 — jwt.sign with expiresIn: "1h" (1 hour).
 * Well within the 24h access-token policy. Expected: no finding.
 */

import jwt from "jsonwebtoken";

export function issueShortToken(userId: string): string {
  return jwt.sign({ userId }, "secret-key", { expiresIn: "1h" });
}
