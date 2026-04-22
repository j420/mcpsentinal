/**
 * L10 registry-metadata-spoofing vocabulary.
 *
 * Typed Records replacing 2 regex + 1 big-array from the legacy detector:
 *   - PROTECTED_VENDORS (12 names, previously >5 array literal)
 *   - AUTHOR_FIELDS regex
 *   - VENDOR_REGEX (dynamically constructed from PROTECTED_VENDORS)
 */

export interface VendorEntry {
  readonly kind: "ai-vendor" | "cloud-vendor" | "platform-vendor";
  readonly rationale: string;
}

export const PROTECTED_VENDORS: Readonly<Record<string, VendorEntry>> = {
  anthropic: { kind: "ai-vendor", rationale: "AI foundation model vendor" },
  openai: { kind: "ai-vendor", rationale: "AI foundation model vendor" },
  google: { kind: "ai-vendor", rationale: "AI foundation model vendor" },
  microsoft: { kind: "cloud-vendor", rationale: "Cloud + AI vendor" },
  aws: { kind: "cloud-vendor", rationale: "Cloud vendor" },
  amazon: { kind: "cloud-vendor", rationale: "Cloud vendor" },
  github: { kind: "platform-vendor", rationale: "Developer platform" },
  stripe: { kind: "platform-vendor", rationale: "Payments platform" },
  cloudflare: { kind: "platform-vendor", rationale: "CDN / DNS platform" },
  meta: { kind: "ai-vendor", rationale: "AI foundation model vendor" },
  facebook: { kind: "ai-vendor", rationale: "AI foundation model vendor" },
  apple: { kind: "cloud-vendor", rationale: "Platform vendor" },
};

export const AUTHOR_FIELD_NAMES: readonly string[] = [
  "author",
  "publisher",
  "organization",
  "maintainer",
  "vendor",
];

export const AUTHOR_FIELD_EXTRA: readonly string[] = [
  "company",
  "sponsor",
  "owner",
];
