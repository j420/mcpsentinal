/**
 * P4 — canonical TLS-bypass pattern registry.
 *
 * Each entry describes one bypass pattern as a whole-token match
 * against a single line. No regex literals; pattern matching is
 * boundary-aware string scanning.
 */

export type LanguageFamily = "node" | "python" | "go" | "java" | "cli";

export type BypassMatchKind =
  | "kv-false"            // `<key>: false` or `<key>=false`
  | "kv-true"             // `<key>: true` or `<key>=true` (e.g. InsecureSkipVerify)
  | "kv-zero-string"      // `<key>="0"` (NODE_TLS_REJECT_UNAUTHORIZED=0)
  | "bare-token"          // token presence on line (e.g. CERT_NONE, TrustAllCerts)
  | "cli-insecure-flag";  // --insecure / --no-check-certificate

export interface BypassPattern {
  id: string;
  language: LanguageFamily;
  /** Token or key to look for. */
  key: string;
  matchKind: BypassMatchKind;
  /** Whether this bypass affects the whole process (global override). */
  globalScope: boolean;
  description: string;
  weight: number;
}

export const BYPASS_PATTERNS: Record<string, BypassPattern> = {
  "node-rejectUnauthorized-false": {
    id: "node-rejectUnauthorized-false",
    language: "node",
    key: "rejectUnauthorized",
    matchKind: "kv-false",
    globalScope: false,
    description: "Node.js rejectUnauthorized: false disables certificate validation for the call / agent.",
    weight: 0.95,
  },
  "node-NODE_TLS_REJECT_UNAUTHORIZED": {
    id: "node-NODE_TLS_REJECT_UNAUTHORIZED",
    language: "node",
    key: "NODE_TLS_REJECT_UNAUTHORIZED",
    matchKind: "kv-zero-string",
    globalScope: true,
    description:
      "NODE_TLS_REJECT_UNAUTHORIZED=\"0\" disables TLS verification for the entire Node.js " +
      "process — every library that issues HTTPS calls downstream is affected.",
    weight: 1.0,
  },
  "python-verify-False": {
    id: "python-verify-False",
    language: "python",
    key: "verify",
    matchKind: "kv-false",
    globalScope: false,
    description: "Python requests verify=False disables certificate validation.",
    weight: 0.92,
  },
  "python-CERT_NONE": {
    id: "python-CERT_NONE",
    language: "python",
    key: "ssl.CERT_NONE",
    matchKind: "bare-token",
    globalScope: false,
    description: "ssl.CERT_NONE sets the ssl.SSLContext to not verify any certificate.",
    weight: 0.93,
  },
  "python-create-unverified": {
    id: "python-create-unverified",
    language: "python",
    key: "_create_unverified_context",
    matchKind: "bare-token",
    globalScope: false,
    description: "ssl._create_unverified_context() returns an SSLContext with verification disabled.",
    weight: 0.95,
  },
  "go-InsecureSkipVerify": {
    id: "go-InsecureSkipVerify",
    language: "go",
    key: "InsecureSkipVerify",
    matchKind: "kv-true",
    globalScope: false,
    description: "Go tls.Config{InsecureSkipVerify: true} disables certificate validation.",
    weight: 0.95,
  },
  "java-TrustAllCerts": {
    id: "java-TrustAllCerts",
    language: "java",
    key: "TrustAllCerts",
    matchKind: "bare-token",
    globalScope: false,
    description: "Java trust-all X509TrustManager class/name — accepts any certificate.",
    weight: 0.9,
  },
  "cli-curl-insecure": {
    id: "cli-curl-insecure",
    language: "cli",
    key: "--insecure",
    matchKind: "cli-insecure-flag",
    globalScope: false,
    description: "curl / wget --insecure — CLI TLS bypass in build / start scripts.",
    weight: 0.85,
  },
  "cli-no-check-certificate": {
    id: "cli-no-check-certificate",
    language: "cli",
    key: "--no-check-certificate",
    matchKind: "cli-insecure-flag",
    globalScope: false,
    description: "wget --no-check-certificate or equivalent CLI TLS-bypass flag.",
    weight: 0.85,
  },
};

/**
 * Supplementary amplifier tokens that raise confidence when combined
 * with a true bypass. The amplifier alone is not a finding.
 */
export const AMPLIFIER_TOKENS: Record<string, { description: string }> = {
  disable_warnings: { description: "urllib3.disable_warnings — commonly paired with verify=False" },
  InsecureRequestWarning: { description: "urllib3 InsecureRequestWarning — suppression signal" },
};
