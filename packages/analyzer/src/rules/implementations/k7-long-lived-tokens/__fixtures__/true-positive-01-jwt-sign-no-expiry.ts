/**
 * K7 TP-01 — jwt.sign(...) with no expiresIn in the options object.
 * The token never expires. Expected: no-expiry finding.
 */

import jwt from "jsonwebtoken";

export function issueToken(userId: string): string {
  return jwt.sign({ userId }, "secret-key");
}
