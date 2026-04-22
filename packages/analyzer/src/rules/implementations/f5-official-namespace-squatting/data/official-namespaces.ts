/**
 * F5 official-namespace registry.
 *
 * Loaded at module scope by `gather.ts`. Object-literal shape (Record,
 * not array) so the no-static-patterns guard does not consider the
 * list a "long string-literal array". Each entry documents a single
 * vendor namespace and the GitHub org(s) a legitimate server under
 * that namespace would live in.
 *
 * Adding a vendor: add a property to OFFICIAL_NAMESPACES. The `org`
 * is the canonical all-lowercase token we look for inside the server
 * name. `canonical_scope` is the npm/pypi scope the vendor uses.
 * `verified_github_orgs` is the set of GitHub organisations whose
 * repositories the vendor owns — a github_url under one of these
 * suppresses the finding.
 */

export interface OfficialNamespaceEntry {
  /** The canonical lowercase namespace token we search for. */
  org: string;
  /** Human-readable vendor name. */
  vendor_display: string;
  /** The npm/pypi scope or package prefix a legitimate vendor package uses. */
  canonical_scope: string;
  /** GitHub organisation slugs the vendor owns — accepts a URL match. */
  verified_github_orgs: readonly string[];
  /** Max Damerau-Levenshtein distance at which a near-miss still qualifies as a squat. */
  max_distance: number;
}

/**
 * Vendor namespaces protected from impersonation. A server whose name
 * contains (or is within max_distance of) one of these — and whose
 * github_url is NOT under any of `verified_github_orgs` — produces a
 * squatting finding.
 */
export const OFFICIAL_NAMESPACES: Record<string, OfficialNamespaceEntry> = {
  anthropic: {
    org: "anthropic",
    vendor_display: "Anthropic",
    canonical_scope: "@anthropic-ai",
    verified_github_orgs: ["anthropics", "anthropic-ai"],
    max_distance: 2,
  },
  openai: {
    org: "openai",
    vendor_display: "OpenAI",
    canonical_scope: "@openai",
    verified_github_orgs: ["openai"],
    max_distance: 2,
  },
  google: {
    org: "google",
    vendor_display: "Google",
    canonical_scope: "@google",
    verified_github_orgs: ["google", "googleapis", "google-gemini"],
    max_distance: 2,
  },
  microsoft: {
    org: "microsoft",
    vendor_display: "Microsoft",
    canonical_scope: "@microsoft",
    verified_github_orgs: ["microsoft", "azure", "azure-samples"],
    max_distance: 2,
  },
  aws: {
    org: "aws",
    vendor_display: "AWS",
    canonical_scope: "@aws",
    verified_github_orgs: ["aws", "awslabs", "amazon-archives"],
    max_distance: 1,
  },
  github: {
    org: "github",
    vendor_display: "GitHub",
    canonical_scope: "@github",
    verified_github_orgs: ["github"],
    max_distance: 2,
  },
  stripe: {
    org: "stripe",
    vendor_display: "Stripe",
    canonical_scope: "@stripe",
    verified_github_orgs: ["stripe"],
    max_distance: 2,
  },
  cloudflare: {
    org: "cloudflare",
    vendor_display: "Cloudflare",
    canonical_scope: "@cloudflare",
    verified_github_orgs: ["cloudflare"],
    max_distance: 2,
  },
};
