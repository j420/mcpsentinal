/** O4 TN-01 — crypto.timingSafeEqual mitigates the side channel. */
export const source = `
import crypto from "crypto";
function verify(input) {
  const secret = loadSecret();
  const ok = crypto.timingSafeEqual(Buffer.from(input), Buffer.from(secret));
  if (ok) {
    setTimeout(() => respond(true), 100);
  }
}
`;
