/**
 * Rule Relevance System — Connects profiler, threat model, and evidence standards.
 *
 * This is the bridge between "what does this server do" (profiler) and
 * "what rules should we run" (threat model). It ensures:
 *
 * 1. Rules only produce scored findings when they're relevant to the server
 * 2. Findings meet the evidence standard for their threat category
 * 3. Low-relevance findings are preserved but don't affect the score
 * 4. Every finding includes the threat context (why we checked, what attack it maps to)
 */

import type { TypedFinding } from "./rules/base.js";
import type { ServerProfile } from "./profiler.js";
import type { EvidenceChain } from "./evidence.js";
import { renderEvidenceNarrative } from "./evidence.js";
import {
  getRelevantRuleIds,
  getEvidenceStandard,
  selectThreats,
  type ThreatDefinition,
  type EvidenceStandard,
} from "./threat-model.js";

// ─── Enhanced Finding ─────────────────────────────────────────────────────────

/**
 * A finding annotated with relevance and threat context.
 * Self-contained type (does not extend FindingInput to avoid cross-package resolution issues).
 */
export interface AnnotatedFinding {
  rule_id: string;
  severity: string;
  evidence: string;
  remediation: string;
  owasp_category: string | null;
  mitre_technique: string | null;

  /** Whether this rule is relevant to the server's profile */
  relevant: boolean;

  /** The threat definition that motivated this check (null for universal rules) */
  threat_id: string | null;

  /** Structured evidence chain (null if rule hasn't been upgraded to evidence chains) */
  evidence_chain: EvidenceChain | null;

  /** Confidence from the evidence chain or the original rule */
  confidence: number;

  /** Whether this finding meets the evidence standard for its threat */
  meets_evidence_standard: boolean;
}

// ─── Relevance Filter ─────────────────────────────────────────────────────────

/**
 * Filter and annotate findings based on server profile and threat model.
 *
 * Findings from irrelevant rules are preserved (for completeness) but marked
 * as `relevant: false`. Only relevant findings that meet the evidence standard
 * should count toward the server's score.
 */
export function annotateFindings(
  findings: TypedFinding[],
  profile: ServerProfile,
): AnnotatedFinding[] {
  const relevantRuleIds = getRelevantRuleIds(profile);
  const threats = selectThreats(profile);
  const threatByRule = buildRuleToThreatMap(threats);

  return findings.map((finding) => {
    const relevant = relevantRuleIds.has(finding.rule_id);
    const threat = threatByRule.get(finding.rule_id) ?? null;
    const standard = getEvidenceStandard(finding.rule_id, profile);

    // Check if the finding's evidence chain meets the standard
    const chain = finding.metadata?.evidence_chain as EvidenceChain | undefined;
    const meetsStandard = chain && standard
      ? evaluateEvidenceStandard(chain, standard)
      : !standard; // No standard = universal rule, always meets

    return {
      rule_id: finding.rule_id,
      severity: finding.severity,
      evidence: chain
        ? renderEvidenceNarrative(chain)
        : finding.evidence,
      remediation: finding.remediation,
      owasp_category: finding.owasp_category,
      mitre_technique: finding.mitre_technique,
      relevant,
      threat_id: threat?.id ?? null,
      evidence_chain: chain ?? null,
      confidence: chain?.confidence ?? finding.confidence,
      meets_evidence_standard: meetsStandard,
    };
  });
}

/** A scored finding ready for database insertion (matches FindingInput shape) */
export interface ScoredFinding {
  rule_id: string;
  severity: string;
  evidence: string;
  remediation: string;
  owasp_category: string | null;
  mitre_technique: string | null;
}

/**
 * From annotated findings, produce the final scored findings.
 *
 * Only findings that are BOTH relevant AND meet the evidence standard
 * are included in the scored output. Others are preserved as informational.
 */
export function scoredFindings(annotated: AnnotatedFinding[]): ScoredFinding[] {
  return annotated
    .filter((f) => f.relevant && f.meets_evidence_standard)
    .map((f) => ({
      rule_id: f.rule_id,
      severity: f.severity,
      evidence: f.evidence,
      remediation: f.remediation,
      owasp_category: f.owasp_category,
      mitre_technique: f.mitre_technique,
    }));
}

/**
 * Get findings that were generated but not scored (for transparency).
 * These can be shown in the UI as "additional observations" with lower prominence.
 */
export function unscoredFindings(annotated: AnnotatedFinding[]): AnnotatedFinding[] {
  return annotated.filter((f) => !f.relevant || !f.meets_evidence_standard);
}

// ─── Evidence Standard Evaluation ─────────────────────────────────────────────

function evaluateEvidenceStandard(
  chain: EvidenceChain,
  standard: EvidenceStandard,
): boolean {
  // Check minimum chain length
  if (chain.links.length < standard.min_chain_length) {
    return false;
  }

  // Check source requirement
  if (standard.requires_source && !chain.links.some((l) => l.type === "source")) {
    return false;
  }

  // Check sink requirement
  if (standard.requires_sink && !chain.links.some((l) => l.type === "sink")) {
    return false;
  }

  // Check minimum confidence
  if (chain.confidence < standard.min_confidence) {
    return false;
  }

  return true;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function buildRuleToThreatMap(threats: ThreatDefinition[]): Map<string, ThreatDefinition> {
  const map = new Map<string, ThreatDefinition>();
  for (const threat of threats) {
    for (const ruleId of threat.rule_ids) {
      // If a rule appears in multiple threats, keep the first (most specific)
      if (!map.has(ruleId)) {
        map.set(ruleId, threat);
      }
    }
  }
  return map;
}

// ─── Profile Report ───────────────────────────────────────────────────────────

/**
 * Generate a human-readable report of the server's profile and threat model.
 * This is included in the scan output for transparency.
 */
export function generateProfileReport(profile: ServerProfile): string {
  const lines: string[] = [];

  lines.push("═══ SERVER SECURITY PROFILE ═══");
  lines.push("");
  lines.push(profile.summary);
  lines.push("");

  // Capabilities
  lines.push("CAPABILITIES:");
  for (const cap of profile.capabilities.filter((c) => c.confidence >= 0.5)) {
    const evidenceSummary = cap.evidence
      .map((e) => `  - [${e.source}] ${e.detail} (weight: ${e.weight.toFixed(2)})`)
      .join("\n");
    lines.push(`  ${cap.capability} — confidence: ${(cap.confidence * 100).toFixed(0)}%`);
    lines.push(evidenceSummary);
  }
  lines.push("");

  // Attack surfaces
  lines.push("ATTACK SURFACES:");
  if (profile.attack_surfaces.length === 0) {
    lines.push("  Minimal attack surface detected");
  }
  for (const surface of profile.attack_surfaces) {
    lines.push(`  • ${surface}`);
  }
  lines.push("");

  // Data flow pairs
  if (profile.data_flow_pairs.length > 0) {
    lines.push("DATA FLOW CHAINS:");
    for (const pair of profile.data_flow_pairs) {
      lines.push(`  ${pair.source_tool} → ${pair.sink_tool} (${pair.flow_type})`);
    }
    lines.push("");
  }

  // Relevant threats
  const threats = selectThreats(profile);
  if (threats.length > 0) {
    lines.push("APPLICABLE THREAT MODELS:");
    for (const threat of threats) {
      const refs = threat.references.map((r) => r.id).join(", ");
      lines.push(`  [${threat.id}] ${threat.name}`);
      lines.push(`    Rules: ${threat.rule_ids.join(", ")}`);
      lines.push(`    References: ${refs}`);
      lines.push(`    Evidence standard: ${threat.evidence_standard.description}`);
    }
    lines.push("");
  }

  // What was NOT checked and why
  const relevantIds = getRelevantRuleIds(profile);
  const allRuleCategories = ["C", "D", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q"];
  const skippedCategories = allRuleCategories.filter(
    (cat) => !Array.from(relevantIds).some((id) => id.startsWith(cat)),
  );
  if (skippedCategories.length > 0) {
    lines.push("NOT APPLICABLE (server lacks required capabilities):");
    lines.push(`  Rule categories: ${skippedCategories.join(", ")}`);
    lines.push("");
  }

  return lines.join("\n");
}
