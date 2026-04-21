/**
 * K7 TP-03 — jwt.verify options with ignoreExpiration: true.
 * The verifier accepts expired tokens. Flagged via the expiry-assignment
 * path as disabled-expiry.
 */

export const verifyOptions = {
  algorithms: ["HS256"],
  ignoreExpiration: true,
};
