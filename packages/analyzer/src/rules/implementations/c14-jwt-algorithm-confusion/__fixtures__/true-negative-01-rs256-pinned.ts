// True negative: algorithms pinned to ["RS256"], no 'none', no
// ignoreExpiration. The charter rewards this shape — no finding.
import jwt from "jsonwebtoken";

export function authorize(token: string, publicKey: string) {
  const claims = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
  return claims;
}
