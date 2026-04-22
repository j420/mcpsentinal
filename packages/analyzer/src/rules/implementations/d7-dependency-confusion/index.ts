/**
 * D7 — Dependency Confusion Attack Risk (v2)
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
import { gatherD7, type ConfusionSite } from "./gather.js";
import {
  stepCheckPublicRegistry,
  stepInspectRegistryPin,
  stepInspectManifest,
} from "./verification.js";

const RULE_ID = "D7";
const RULE_NAME = "Dependency Confusion Attack Risk";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.8;

const REMEDIATION =
  "Verify the scoped package is resolved from the private registry, not the public one. Pin the " +
  "scope in `.npmrc` / `pip.conf`: `@your-scope:registry=https://your-private-registry`. If the " +
  "installed version is a public-registry impostor, remove it immediately, audit the build " +
  "environment for install-time artifacts, and rotate any secrets the build had access to. " +
  "Publish placeholder packages to the public registry for every private scope to block future " +
  "Birsan-style attacks.";

const REF_BIRSAN = {
  id: "BIRSAN-2021",
  title: "Alex Birsan — Dependency Confusion (Feb 2021)",
  url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
  year: 2021,
  relevance:
    "Birsan's 2021 research established the artificially-high-version technique for attacking " +
    "scoped packages across Microsoft, Apple, PayPal, and 35+ other Fortune-500 companies. " +
    "A scoped package with major ≥99 is a direct match for the published attack signature.",
} as const;

class DependencyConfusionAttackRiskRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { dependencies: true };
  readonly technique: AnalysisTechnique = "dependency-audit";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherD7(context);
    return gathered.sites.map((site) => this.buildFinding(site));
  }

  private buildFinding(site: ConfusionSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.dependencyLocation,
        observed:
          `Scoped package ${site.name} resolved at version ${site.version} (major ${site.major}). ` +
          `Threshold: ≥${99} is suspicious, ≥${999} is highly suspicious.`,
        rationale:
          "Alex Birsan's 2021 dependency-confusion technique publishes public-registry packages " +
          "with artificially-high version numbers under scoped names that match internal private " +
          "packages. Package managers prefer higher public versions over private ones by default, " +
          "executing attacker-controlled install hooks on corporate build infrastructure.",
      })
      .sink({
        sink_type: "command-execution",
        location: site.dependencyLocation,
        observed:
          `If ${site.name}@${site.version} is the public-registry impostor, its postinstall hook ` +
          `executes attacker code in the build environment with the CI runner's credentials.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: {
          kind: "config",
          file: ".npmrc",
          json_pointer: `/${site.scope}:registry`,
        },
        detail:
          `No registry-scope pin has been observed for ${site.scope}. Without the pin the package ` +
          `manager resolves against the public registry first. This is the precondition Birsan's ` +
          `technique exploits.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `An attacker publishes ${site.name}@${site.version} to the public registry with a malicious ` +
          `postinstall script. The next \`npm install\` (or equivalent) run in the project's CI, on ` +
          `a developer machine, or in a container build resolves the PUBLIC version (major ` +
          `${site.major} ≥ private major). The malicious install hook runs with the CI runner's ` +
          `credentials — Birsan collected $130k in bounties across 35+ companies from exactly this ` +
          `chain.`,
      })
      .factor(
        "suspicious_major_version",
        site.isHighlySuspicious ? 0.15 : 0.09,
        `Scoped package ${site.name} pinned at major ${site.major}. ` +
          (site.isHighlySuspicious
            ? `Major ≥999 matches the highest tier of Birsan-style impostor version numbers.`
            : `Major ≥99 matches Birsan's original impostor version signature.`),
      );

    if (site.knownPrivateMatch) {
      builder.factor(
        "known_private_namespace_prefix_match",
        0.05,
        `Scope \`${site.scope}\` matches a curated known-private-namespace entry ` +
          `(${site.knownPrivateMatch.org_name}). Historical compromise documented at ` +
          `${site.knownPrivateMatch.citation_url}.`,
      );
    }

    builder.reference(REF_BIRSAN);
    builder.verification(stepCheckPublicRegistry(site));
    builder.verification(stepInspectRegistryPin(site));
    builder.verification(stepInspectManifest(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "high",
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
      `D7 charter caps confidence at ${cap}. The major-version threshold is a strong indicator but ` +
      `not a proof — legitimate high-version projects and CalVer usage are false-positive classes.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new DependencyConfusionAttackRiskRule());

export { DependencyConfusionAttackRiskRule };
