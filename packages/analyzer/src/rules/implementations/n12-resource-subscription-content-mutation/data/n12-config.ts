export const N12_CONFIDENCE_CAP = 0.78;

/** Fragments the scanner looks for on lines that emit subscription updates. */
export const UPDATE_EMIT_FRAGMENTS: Readonly<Record<string, string>> = {
  "notifications/resources/updated": "MCP resources/updated notification",
  "resourcechanged": "resourceChanged event",
  "sendupdate(": "sendUpdate() call",
  "emit('update'": "emit('update') call",
};

/** Integrity-check fragments — presence = mitigation present. */
export const INTEGRITY_FRAGMENTS: Readonly<Record<string, string>> = {
  hash: "hash check",
  sha256: "sha256 check",
  checksum: "checksum check",
  hmac: "hmac check",
  verify: "verify call",
  signature: "signature check",
};

/** Subscribe-handler fragments that must appear somewhere in the source to pass the honest-refusal gate. */
export const SUBSCRIBE_FRAGMENTS: Readonly<Record<string, string>> = {
  "resources/subscribe": "resources/subscribe handler",
  "notifications/resources/updated": "resources/updated emitter",
  setupsubscription: "setupSubscription call",
};
