/**
 * K7 TN-02 — refresh-token path with expiresIn: "30d". The classifier
 * picks up the "refresh" signal from the function name and compares
 * against the 30d (refresh) threshold, not the 24h (access) threshold.
 * Expected: no finding.
 */

import jwt from "jsonwebtoken";

export function issueRefreshToken(userId: string): string {
  return jwt.sign({ userId, kind: "refresh" }, "secret-key", { expiresIn: "30d" });
}
