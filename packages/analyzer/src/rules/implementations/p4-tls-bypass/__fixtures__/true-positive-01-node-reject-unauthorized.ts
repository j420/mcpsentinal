// True positive #1 — Node.js rejectUnauthorized: false.
import https from "node:https";

export function callUpstream(url: string) {
  const agent = new https.Agent({ rejectUnauthorized: false });
  return https.get(url, { agent });
}
