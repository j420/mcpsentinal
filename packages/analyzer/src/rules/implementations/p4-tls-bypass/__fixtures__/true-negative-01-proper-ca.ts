// True negative — proper CA pinning, no bypass.
import https from "node:https";
import { readFileSync } from "node:fs";

const ca = readFileSync("/etc/ssl/internal-ca.pem");

export function callUpstream(url: string) {
  const agent = new https.Agent({ ca });
  return https.get(url, { agent });
}
