/**
 * D3 — Typosquatting Risk in Dependencies (v2)
 *
 * Orchestrator. Translates the deterministic classifications produced by
 * `gather.ts` into RuleResult[] with v2-compliant EvidenceChains:
 *
 *   - every link carries a structured Location (dependency + config);
 *   - every VerificationStep.target is a Location;
 *   - threat_reference cites ISO 27001 A.5.21 as the primary control
 *     (Alex Birsan 2021 and OWASP MCP10 are additional charter refs);
 *   - confidence capped at 0.90 per charter — similarity is fuzzy and
 *     leaves room for legitimate namespace forks the allowlist missed.
 *
 * Zero regex. All data lives in `./data/*.ts` as Record<…> maps.
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
import { gatherD3, type TyposquatSite } from "./gather.js";
import {
  stepInspectDependency,
  stepConfirmSimilarity,
  stepInspectManifest,
  stepCompareRegistry,
} from "./verification.js";

const RULE_ID = "D3";
const RULE_NAME = "Typosquatting Risk in Dependencies";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.9;

const REMEDIATION =
  "Verify that the flagged dependency is the package you intended to install. " +
  "Open the registry page for the candidate and compare publisher, publish date, " +
  "download count, and postinstall scripts against the target. If it is not the " +
  "intended package, replace it with the legitimate target, regenerate the lockfile, " +
  "and audit the install environment (CI and developer machines) for any artifacts " +
  "the malicious package may have written. Adopt a typosquat-aware package firewall " +
  "(Socket.dev, Snyk Advisor, GitHub Dependabot) that rejects near-miss names at " +
  "install time, in line with ISO 27001 A.5.21 supply-chain controls.";

const REF_ISO_A521 = {
  id: "ISO-27001-A.5.21",
  title: "ISO/IEC 27001:2022 Annex A Control 5.21 — ICT Supply Chain Security",
  url: "https://www.iso.org/standard/82875.html",
  relevance:
    "A.5.21 requires processes to verify third-party suppliers and the components " +
    "they deliver. A lexically near-miss dependency name is a supply-chain anomaly " +
    "that the control requires be detected and reviewed before the component is " +
    "accepted.",
} as const;

class TyposquattingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { dependencies: true };
  readonly technique: AnalysisTechnique = "similarity";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherD3(context);
    return gathered.sites.map((site) => this.buildFinding(site));
  }

  private buildFinding(site: TyposquatSite): RuleResult {
    const severity = site.classifier === "confirmed-typosquat" ? "critical" : "high";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.dependencyLocation,
        observed: describeSource(site),
        rationale:
          "Dependency names are external content resolved from public package registries. " +
          "A near-miss to a popular canonical name is a supply-chain anomaly under ISO 27001 " +
          "A.5.21 — the package manager installs whichever spelling is declared, with no " +
          "built-in guard against lexically similar substitutions.",
      })
      .propagation({
        propagation_type: "direct-pass",
        location: site.configLocation,
        observed:
          `The manifest entry at ${site.configLocation.kind === "config" ? site.configLocation.json_pointer : "<config>"} ` +
          `directs the package manager to resolve and install ${site.candidate}@${site.version}. ` +
          `Resolution is purely string-matched against the registry — a typosquatted name ` +
          `installs whatever code the squatter published.`,
      })
      .sink({
        sink_type: "command-execution",
        location: site.dependencyLocation,
        observed:
          `Malicious package \`${site.candidate}\` executes attacker code in the build environment ` +
          `or at import time. Attack classifier: ${site.classifier}. Target shadowed: \`${site.target}\`.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: site.configLocation,
        detail:
          "Lockfiles pin versions but do not pin the spelling of the dependency name. The " +
          "static analyser cannot confirm whether a typosquat-aware package firewall " +
          "(Socket.dev, Snyk Advisor) is in the CI chain; the auditor must verify.",
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          `A developer installs \`${site.candidate}\` by typo, copy-paste, or autocomplete. ` +
          `The package's postinstall hook runs during installation with the developer's or ` +
          `CI runner's credentials, or the payload executes on first import when the MCP ` +
          `server starts. An MCP server compromised this way delegates full tool authority ` +
          `to attacker code on every downstream agent interaction.`,
      });

    addClassifierFactor(builder, site);
    addAgreementFactor(builder, site);
    if (site.visualVariant) {
      builder.factor(
        "visual_confusable_variant_matched",
        0.1,
        `The candidate contains the visual-confusable grapheme that, after ASCII ` +
          `substitution, becomes "${site.visualVariant}" — which matches the target ` +
          `\`${site.target}\`. This is exactly the rn/m, cl/d, vv/w class the charter ` +
          `requires we detect.`,
      );
    }
    if (site.unicodeVariant) {
      builder.factor(
        "unicode_confusable_variant_matched",
        0.12,
        `Unicode normalisation of the candidate yields "${site.unicodeVariant}", which ` +
          `matches the target \`${site.target}\`. Registries do not normalise at ` +
          `resolution time, so the visually identical name installs a distinct ` +
          `attacker-controlled package.`,
      );
    }
    builder.factor(
      "legitimate_fork_allowlist_consulted",
      -0.04,
      `The candidate was not in legitimate-forks.ts at scan time. The rule records this ` +
        `explicitly so the finding can be dismissed by adding to the allowlist, with ` +
        `audit trail, if the reviewer confirms the dependency is a sanctioned variant.`,
    );

    builder.reference(REF_ISO_A521);
    builder.verification(stepInspectDependency(site));
    builder.verification(stepConfirmSimilarity(site));
    builder.verification(stepInspectManifest(site));
    builder.verification(stepCompareRegistry(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

// ─── Factor builders ───────────────────────────────────────────────────────

function addClassifierFactor(
  builder: EvidenceChainBuilder,
  site: TyposquatSite,
): void {
  switch (site.classifier) {
    case "confirmed-typosquat":
      builder.factor(
        "confirmed_typosquat_registry_hit",
        0.22,
        `The name \`${site.candidate}\` is present in the confirmed-typosquat registry ` +
          `(CONFIRMED_TYPOSQUATS) — documented by at least one public advisory ` +
          `(Socket.dev, Wiz Research, npm security advisories) as impersonating ` +
          `\`${site.target}\`. This is the highest-confidence class the rule emits.`,
      );
      break;
    case "scope-squat":
      builder.factor(
        "scope_squat_of_official",
        0.14,
        `The candidate's unscoped tail matches the official scoped target ` +
          `\`${site.target}\` but under a different scope (or no scope at all). ` +
          `Scope replacement is the canonical impersonation vector for organisation-` +
          `owned namespaces.`,
      );
      break;
    case "levenshtein-near":
      builder.factor(
        "target_distance_under_threshold",
        0.1,
        `Damerau-Levenshtein distance ${site.distance} between \`${site.candidate}\` and ` +
          `\`${site.target}\` is within the target's declared ceiling of ` +
          `${site.targetMeta.max_distance}. Combined with the Jaro-Winkler agreement ` +
          `check, this is the distance-only classifier — the most common class.`,
      );
      break;
    case "visual-confusable":
      builder.factor(
        "target_distance_under_threshold",
        0.12,
        `After applying an ASCII visual-confusable substitution, the candidate is ` +
          `distance ${site.distance} from \`${site.target}\`. The charter's rn/m, cl/d, ` +
          `vv/w class. Visual substitution catches attacks that pure Damerau-Levenshtein ` +
          `would miss without confusable context.`,
      );
      break;
    case "unicode-confusable":
      builder.factor(
        "unicode_normalisation_matches_target",
        0.15,
        `Unicode normalisation of \`${site.candidate}\` produces a name matching ` +
          `\`${site.target}\`. Registries do not apply this normalisation at resolution ` +
          `time, enabling visually identical impersonation.`,
      );
      break;
  }
}

function addAgreementFactor(
  builder: EvidenceChainBuilder,
  site: TyposquatSite,
): void {
  if (site.classifier === "confirmed-typosquat") return;
  if (site.jaroWinklerScore >= 0.9) {
    builder.factor(
      "algorithm_agreement_high",
      0.06,
      `Jaro-Winkler similarity ${site.jaroWinklerScore.toFixed(3)} ≥ 0.90 — two ` +
        `complementary algorithms (Damerau-Levenshtein + Jaro-Winkler) agree on the ` +
        `similarity claim. Agreement across algorithms is the filter against ` +
        `single-algorithm noise.`,
    );
  } else if (site.jaroWinklerScore >= 0.8) {
    builder.factor(
      "algorithm_agreement_moderate",
      0.02,
      `Jaro-Winkler similarity ${site.jaroWinklerScore.toFixed(3)} clears the agreement ` +
        `floor (0.80) but is below the high-agreement band — the finding stands but ` +
        `reviewer confirmation is advised.`,
    );
  } else {
    builder.factor(
      "algorithm_agreement_below_floor",
      -0.08,
      `Jaro-Winkler similarity ${site.jaroWinklerScore.toFixed(3)} is below the 0.80 ` +
        `agreement floor — the finding is retained because another classifier (scope ` +
        `squat, confusable, registry hit) produced it, but the distance-only signal ` +
        `is weak.`,
    );
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function describeSource(site: TyposquatSite): string {
  switch (site.classifier) {
    case "confirmed-typosquat":
      return (
        `Dependency ${site.ecosystem}:${site.candidate}@${site.version} is a ` +
        `confirmed typosquat of ${site.target} in the CONFIRMED_TYPOSQUATS registry.`
      );
    case "scope-squat":
      return (
        `Dependency ${site.ecosystem}:${site.candidate}@${site.version} is a ` +
        `scope-squat of the official ${site.target} — same unscoped tail, ` +
        `different scope.`
      );
    case "levenshtein-near":
      return (
        `Dependency ${site.ecosystem}:${site.candidate}@${site.version} is within ` +
        `Damerau-Levenshtein distance ${site.distance} of ${site.target} ` +
        `(threshold ${site.targetMeta.max_distance}).`
      );
    case "visual-confusable":
      return (
        `Dependency ${site.ecosystem}:${site.candidate}@${site.version} contains a ` +
        `visual-confusable grapheme that, after substitution, matches ${site.target}.`
      );
    case "unicode-confusable":
      return (
        `Dependency ${site.ecosystem}:${site.candidate}@${site.version} contains ` +
        `Unicode confusable characters; after normalisation it matches ${site.target}.`
      );
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `D3 charter caps confidence at ${cap} — similarity is fuzzy and a candidate ` +
      `within Damerau-Levenshtein distance of a popular target can still be a ` +
      `legitimate namespace fork or internal alias the allowlist has not yet ` +
      `captured. The 0.10 gap signals "strong static evidence, reviewer should ` +
      `corroborate against the public registry before removal".`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new TyposquattingRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { TyposquattingRule };
