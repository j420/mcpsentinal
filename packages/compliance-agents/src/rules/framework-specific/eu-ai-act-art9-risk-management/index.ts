/**
 * Rule: eu-ai-act-art9-risk-management
 *
 * Framework-specific Art.9 rule. Deterministic violation when no
 * integrity markers are present AND no capability is declared.
 */

import type { AnalysisContext } from "@mcp-sentinel/analyzer";

import {
  ComplianceRule,
  type ComplianceRuleMetadata,
} from "../../base-rule.js";
import type {
  EvidenceBundle,
  EvidencePointer,
  JudgedTestResult,
  RawTestResult,
} from "../../../types.js";
import {
  INTEGRITY_MARKERS,
  makeBundle,
  sourceTokenHits,
  standardJudge,
} from "../../../rule-kit/index.js";

interface Art9Failure {
  id:
    | "no-integrity-markers"
    | "no-declared-capabilities";
  description: string;
}

interface Art9Facts {
  art9_failures: Art9Failure[];
  art9_risk_mgmt: string;
  integrity_markers_found: string[];
  any_capability_declared: boolean;
}

const METADATA: ComplianceRuleMetadata = {
  id: "eu-ai-act-art9-risk-management",
  name: "EU AI Act Article 9 — Risk Management System",
  severity: "high",
  intent:
    "An MCP server claiming EU AI Act Art.9 compliance MUST expose structurally-checkable risk artifacts: supply-chain integrity evidence AND a declared capability surface.",
  applies_to: [
    {
      framework: "eu_ai_act",
      category: "Article 9 — Risk Management System",
      control: "Art.9",
      sub_control: "Art.9(1-9)",
    },
  ],
  threat_refs: [
    {
      id: "EU-AI-Act-Art9-1",
      title: "EU AI Act Art.9(1) — risk management mandate",
      year: 2024,
      relevance: "Direct legal basis for establishing a risk management system for high-risk AI.",
    },
    {
      id: "EU-AI-Act-Art9-2",
      title: "EU AI Act Art.9(2) — iterative lifecycle process",
      year: 2024,
      relevance: "Defines the continuous nature of the risk management system that this rule checks evidence of.",
    },
    {
      id: "NIST-AI-RMF-GOVERN-1",
      title: "NIST AI RMF GOVERN function — governance and accountability",
      relevance: "Parallel framework whose artifacts are accepted as Art.9-compatible evidence.",
    },
    {
      id: "SLSA-V1.0",
      title: "SLSA Supply-chain Levels for Software Artifacts v1.0",
      relevance: "Provenance framework that produces the integrity evidence this rule scans for.",
    },
  ],
  strategies: ["supply-chain-pivot", "config-drift", "audit-erasure"],
  remediation:
    "Check in a lockfile (package-lock.json, pnpm-lock.yaml, poetry.lock), generate a SLSA v1.0 provenance statement for every release, declare the logging capability in the initialize response, and publish a signed SBOM attestation.",
};

class EUAIActArt9RiskManagementRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const integrityHits = sourceTokenHits(context, INTEGRITY_MARKERS);
    const declared = context.declared_capabilities ?? null;
    const anyDeclared = Boolean(
      declared?.tools ||
        declared?.resources ||
        declared?.prompts ||
        declared?.logging ||
        declared?.sampling,
    );

    const failures: Art9Failure[] = [];
    const pointers: EvidencePointer[] = [];

    if (integrityHits.length === 0) {
      failures.push({
        id: "no-integrity-markers",
        description:
          "No lockfile / SLSA / SBOM / sigstore markers in source — Art.9 supply-chain evidence missing.",
      });
      pointers.push({
        kind: "source-file",
        label: "no-integrity-markers",
        location: "source_files",
        observed: "no package-lock.json / pnpm-lock.yaml / slsa-provenance / sigstore hits",
      });
    }

    if (!anyDeclared) {
      failures.push({
        id: "no-declared-capabilities",
        description:
          "Server boots with no declared capability — Art.9 requires a known, assessable surface.",
      });
      pointers.push({
        kind: "capability",
        label: "no-declared-capabilities",
        location: "capabilities.*",
        observed: "initialize_metadata carries no declared capability object",
      });
    }

    const facts: Art9Facts = {
      art9_failures: failures,
      art9_risk_mgmt: "art9_risk_mgmt",
      integrity_markers_found: integrityHits,
      any_capability_declared: anyDeclared,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary:
        failures.length > 0
          ? `${failures.length} EU AI Act Art.9 risk-management failure(s)`
          : `Art.9 artifacts present (integrity=${integrityHits.length}, declared=${anyDeclared})`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: failures.length > 0,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as Art9Facts;
    const deterministicIds: string[] = (facts.art9_failures ?? []).map((f) => f.id);
    if (deterministicIds.length > 0) deterministicIds.push("art9_risk_mgmt");
    const result = standardJudge({
      raw,
      deterministic: deterministicIds,
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const euAIActArt9RiskManagementRule = new EUAIActArt9RiskManagementRule();
