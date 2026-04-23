import type { ComplianceReport, FrameworkId, SignedComplianceReport } from "../types.js";

/**
 * SVG badge renderer for a single framework. Badges embed the attestation
 * as an XML comment for regulator verification alongside a visible
 * compliance indicator that humans can read at a glance. Agent 4 owns
 * this implementation; the interface lives here so that badges compile
 * against the stable report model.
 */
export interface ComplianceBadgeRenderer {
  framework: FrameworkId;
  render(report: ComplianceReport, attestation: SignedComplianceReport["attestation"]): string;
}

const registry = new Map<FrameworkId, ComplianceBadgeRenderer>();

export function registerBadge(framework: FrameworkId, r: ComplianceBadgeRenderer): void {
  if (r.framework !== framework) {
    throw new Error(
      `Badge.framework mismatch: expected ${framework}, got ${r.framework}`,
    );
  }
  registry.set(framework, r);
}

export function getBadge(framework: FrameworkId): ComplianceBadgeRenderer | undefined {
  return registry.get(framework);
}

/** Test-only hook — Agent 4 does not need this. */
export function __clearBadgeRegistry(): void {
  registry.clear();
}
