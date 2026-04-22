// True negative: crypto.timingSafeEqual on equal-length buffers. The
// presence of timingSafeEqual anywhere in the source clears the
// finding (mitigation marker scope is file-level, conservatively).
import crypto from "node:crypto";

const apiKey = process.env.API_KEY ?? "";

export function checkAuth(req: { headers: { authorization?: string } }): boolean {
  const provided = req.headers.authorization ?? "";
  if (provided.length !== apiKey.length) return false;
  return crypto.timingSafeEqual(Buffer.from(apiKey), Buffer.from(provided));
}
