// True positive: algorithms array contains the literal string "none".
// A forged token with alg=none passes validation with no signature.
import jwt from "jsonwebtoken";

export function authorize(token: string, publicKey: string) {
  const claims = jwt.verify(token, publicKey, { algorithms: ["RS256", "none"] });
  return claims;
}
