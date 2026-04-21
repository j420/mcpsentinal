// True positive: jwt.verify called with only token + secret — no options
// argument pins the algorithms. Historical jsonwebtoken accepts any alg
// in the token, including 'none'.
import jwt from "jsonwebtoken";

export function authorize(token: string, secret: string) {
  return jwt.verify(token, secret);
}
