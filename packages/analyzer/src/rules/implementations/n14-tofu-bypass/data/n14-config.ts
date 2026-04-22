export const N14_CONFIDENCE_CAP = 0.78;

export const BYPASS_FRAGMENTS: Readonly<Record<string, string>> = {
  "ignorefingerprint": "ignoreFingerprint flag",
  "skiphostkey": "skipHostKeyCheck flag",
  "verify: false": "verify: false flag",
  "rejectunauthorized: false": "rejectUnauthorized: false",
  "noverify": "noVerify flag",
};

export const TOFU_CONTEXT_FRAGMENTS: Readonly<Record<string, string>> = {
  "trust-on-first-use": "TOFU trust model",
  "known_hosts": "known_hosts file",
  fingerprint: "fingerprint-based trust",
  pinning: "key pinning",
  "first connect": "first-connect trust",
};

export const FIRST_CONNECT_ACCEPT_FRAGMENTS: Readonly<Record<string, string>> = {
  accept_first: "accept_first-connect marker",
  trust_first: "trust_first marker",
  "accept any": "accept-any-identity marker",
  auto_pin: "auto_pin-on-first-connect marker",
  save_fingerprint: "save_fingerprint marker",
};
