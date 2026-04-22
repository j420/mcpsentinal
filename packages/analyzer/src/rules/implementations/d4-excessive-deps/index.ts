/**
 * D4 — Excessive Dependency Count (v2)
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherD4, type D4Gathered } from "./gather.js";
import {
  stepCountManifest,
  stepAuditUnused,
  stepCheckMonorepoMarkers,
} from "./verification.js";

const RULE_ID = "D4";
const RULE_NAME = "Excessive Dependency Count";
const OWASP = "MCP08-dependency-vuln" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.6;

const REMEDIATION =
  "Audit the dependency list for unused or redundant packages and remove them. Run `depcheck` " +
  "(npm) or `pip-extra-reqs`/`deptry` (Python) to identify candidates. Consider splitting the " +
  "project into focused sub-packages, or consolidating overlapping libraries. Track the baseline " +
  "count in the project README so future drift is visible to reviewers.";

const REF_SLSA = {
  id: "SLSA-Supply-Chain-Levels",
  title: "Supply-chain Levels for Software Artifacts (SLSA) v1.0",
  url: "https://slsa.dev/spec/v1.0/",
  relevance:
    "SLSA articulates dependency blast-radius: controls (provenance, isolated builds, hermetic " +
    "sources) scale linearly with the dependency count. A project that exceeds its organisational " +
    "threshold without tooling is ambient-risk under SLSA-2+ expectations.",
} as const;

class ExcessiveDependencyCountRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { dependencies: true };
  readonly technique: AnalysisTechnique = "dependency-audit";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherD4(context);
    if (!gathered.isExcessive) return [];
    return [this.buildFinding(gathered)];
  }

  private buildFinding(gathered: D4Gathered): RuleResult {
    const sampleText =
      gathered.sampleNames.length > 0
        ? `Sample: ${gathered.sampleNames.join(", ")} (+${gathered.count - gathered.sampleNames.length} more).`
        : "";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: gathered.manifestLocation,
        observed: `Manifest declares ${gathered.count} direct dependencies (threshold: 50). ${sampleText}`,
        rationale:
          "Every direct dependency is an external-content trust boundary. As the number of trust " +
          "boundaries grows, the probability that at least one is compromised or unmaintained " +
          "tends to 1.",
      })
      .sink({
        sink_type: "code-evaluation",
        location: gathered.manifestLocation,
        observed:
          `${gathered.count} dependencies resolve to untold transitive trees; each one is a potential ` +
          `entry point for supply-chain compromise (malicious install hook, compromised publisher, ` +
          `typosquat, abandonment).`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: gathered.manifestLocation,
        detail:
          "No evidence of a dependency-minimisation policy. Unused, redundant, or overlapping " +
          "dependencies are not removed before release.",
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "server-host",
        exploitability: "complex",
        scenario:
          `With ${gathered.count} direct deps + transitive closure, the realistic probability ` +
          `of AT LEAST ONE package being compromised or unmaintained is large. Any such package ` +
          `can pivot into RCE in the MCP server's host environment via install hooks or first-import ` +
          `side effects.`,
      })
      .factor(
        "dependency_count_over_threshold",
        gathered.isExtreme ? 0.1 : 0.05,
        `Direct dependency count ${gathered.count} exceeds the ${gathered.isExtreme ? "extreme" : "excessive"} ` +
          `threshold. ${gathered.isExtreme ? "Beyond 200 deps the project is unauditable without tooling." : "Between 50 and 200 deps the project is borderline — investigate."}`,
      );

    builder.reference(REF_SLSA);
    builder.verification(stepCountManifest(gathered));
    builder.verification(stepAuditUnused(gathered));
    builder.verification(stepCheckMonorepoMarkers(gathered));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "low",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `D4 charter caps confidence at ${cap}. Dependency count is a policy-dependent signal: ` +
      `legitimately dependency-rich frameworks (Next.js, Babel toolchains) routinely cross 50 ` +
      `without being bloated.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ExcessiveDependencyCountRule());

export { ExcessiveDependencyCountRule };
