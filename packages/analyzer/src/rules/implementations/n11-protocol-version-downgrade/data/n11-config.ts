/**
 * N11 — per-rule config.
 */

export const N11_CONFIDENCE_CAP = 0.85;

/** Version-echo shapes. */
export const VERSION_ECHO_FRAGMENTS: Readonly<Record<string, string>> = {
  "req.params.protocolversion": "req.params.protocolVersion reflect",
  "request.params.protocolversion": "request.params.protocolVersion reflect",
  "protocolversion: req": "protocolVersion: req.*",
  "accept any version": "explicit any-version acceptance",
  "accept all versions": "accept-all-versions marker",
};

/** Rejection / enforcement fragments. */
export const ENFORCEMENT_FRAGMENTS: Readonly<Record<string, string>> = {
  reject: "reject call",
  throw: "throw on version mismatch",
  "minprotocolversion": "minProtocolVersion compare",
  supportedversions: "supportedVersions allowlist",
  semver: "semver comparator",
};

/** Protocol-version string fragments the scanner recognises. */
export const VERSION_LITERALS: Readonly<Record<string, string>> = {
  "2024-11-05": "baseline version literal",
  "2025-03-26": "annotations version literal",
  "2025-06-18": "elicitation version literal",
  "2025-11-25": "refinement version literal",
};
