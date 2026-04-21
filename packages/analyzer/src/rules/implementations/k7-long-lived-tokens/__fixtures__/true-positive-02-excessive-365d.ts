/**
 * K7 TP-02 — jwt.sign with expiresIn: "365d" (1 year).
 * Expected: excessive-expiry finding; duration parsed to 31536000s.
 */

import jwt from "jsonwebtoken";

export function issueAnnualToken(userId: string): string {
  return jwt.sign({ userId }, "secret-key", { expiresIn: "365d" });
}
