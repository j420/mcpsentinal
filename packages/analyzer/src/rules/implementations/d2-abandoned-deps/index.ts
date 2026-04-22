/**
 * D2 — Abandoned Dependencies (v2)
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
import { gatherD2, type AbandonedSite } from "./gather.js";
import {
  stepCheckPublishDate,
  stepCheckRepoActivity,
  stepInspectManifest,
} from "./verification.js";

const RULE_ID = "D2";
const RULE_NAME = "Abandoned Dependencies";
const OWASP = "MCP08-dependency-vuln" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.7;

const REMEDIATION =
  "Replace the abandoned dependency with an actively maintained alternative. " +
  "Where no alternative exists, vendor the minimal code the project uses and delete " +
  "the dependency. If the package is internal/private and legitimately stable, mark " +
  "it as such in a repository-local allowlist so the scanner can skip it on future " +
  "runs. Track the abandonment risk in the project's SBOM per ISO 27001 A.8.8.";

const REF_OWASP_A06 = {
  id: "OWASP-A062021",
  title: "OWASP Top 10 A06:2021 — Vulnerable and Outdated Components",
  url: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
  relevance:
    "A06:2021 explicitly names 'software component is unsupported or out of date' as a core " +
    "diagnostic. An abandoned dependency is the archetypal outdated component: future " +
    "vulnerabilities will never be patched by its maintainer.",
} as const;

class AbandonedDependenciesRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { dependencies: true };
  readonly technique: AnalysisTechnique = "dependency-audit";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherD2(context);
    return gathered.sites.map((site) => this.buildFinding(site));
  }

  private buildFinding(site: AbandonedSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.dependencyLocation,
        observed:
          `Dependency ${site.ecosystem}:${site.name}@${site.version} last published ` +
          `${site.ageMonths} months ago (${site.lastUpdated}).`,
        rationale:
          "An unmaintained dependency receives no patches for newly disclosed vulnerabilities. " +
          "Every published CVE in the package after its last release date remains permanently " +
          "exposed; the only remediation is removal or fork.",
      })
      .sink({
        sink_type: "code-evaluation",
        location: site.dependencyLocation,
        observed:
          `${site.name}@${site.version} imports unchanged code; any latent vulnerability in the ` +
          `published artifact will execute within the MCP server's privilege context whenever a ` +
          `code path through this dependency is reached.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: site.dependencyLocation,
        detail:
          "No active maintainer to issue a security patch. The project cannot rely on upstream " +
          "release cadence to remediate future CVEs.",
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "server-host",
        exploitability: "complex",
        scenario:
          `A future CVE discovered in ${site.name} is never patched. An attacker who reaches a ` +
          `code path through this dependency executes exploit code with the MCP server's tool ` +
          `authority — a permanent supply-chain exposure until the dependency is removed or forked.`,
      })
      .factor(
        "abandoned_age_over_threshold",
        site.isHighRisk ? 0.15 : 0.08,
        `Package last published ${site.ageMonths} months ago — ` +
          (site.isHighRisk
            ? `past the 36-month "high risk" boundary; abandonment is highly likely.`
            : `past the 12-month abandonment threshold; requires reviewer confirmation.`),
      );

    builder.reference(REF_OWASP_A06);
    builder.verification(stepCheckPublishDate(site));
    builder.verification(stepCheckRepoActivity(site));
    builder.verification(stepInspectManifest(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "medium",
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
      `D2 charter caps confidence at ${cap}. Age is a PROXY for abandonment — stable-and-complete ` +
      `packages, private dependencies with infrequent releases, and packages awaiting upcoming ` +
      `major releases all legitimately cross the 12-month boundary without being truly abandoned.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new AbandonedDependenciesRule());

export { AbandonedDependenciesRule };
