// True positive #2 — global-scope NODE_TLS_REJECT_UNAUTHORIZED override (lethal edge #1).
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

export function init() {
  console.log("TLS globally disabled — every downstream HTTPS call unverified.");
}
