/**
 * D5 — Known Malicious Packages (v2)
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
import { gatherD5, type MaliciousPackageSite } from "./gather.js";
import {
  stepConsultAdvisory,
  stepInspectManifest,
  stepCheckPostinstall,
} from "./verification.js";

const RULE_ID = "D5";
const RULE_NAME = "Known Malicious Packages";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.95;

const REMEDIATION =
  "Remove the flagged package immediately. Regenerate the lockfile from scratch. Audit the " +
  "build environment (CI runners + developer machines) for artifacts the package may have " +
  "written during install — stolen credentials, persistence hooks, or outbound network " +
  "connections. Rotate every secret the build environment had access to. Report the package " +
  "to the registry's security team if it is not already taken down.";

const REF_OWASP_MCP10 = {
  id: "OWASP-MCP10-Supply-Chain",
  title: "OWASP MCP Top 10 — MCP10 Supply Chain",
  url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  relevance:
    "MCP10 explicitly requires blocking dependencies listed in authoritative malicious-package " +
    "databases at install time. D5 is the static-analysis mirror of the runtime control.",
} as const;

class KnownMaliciousPackagesRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { dependencies: true };
  readonly technique: AnalysisTechnique = "dependency-audit";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherD5(context);
    return gathered.sites.map((site) => this.buildFinding(site));
  }

  private buildFinding(site: MaliciousPackageSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.dependencyLocation,
        observed:
          `Dependency ${site.ecosystem}:${site.name}@${site.version} matches a confirmed ` +
          `malicious-package entry. Matched name: "${site.matchedName}"` +
          (site.viaUnicodeNormalisation
            ? ` (after Unicode homoglyph normalisation of the declared name).`
            : `.`),
        rationale:
          `The advisory at ${site.spec.advisory_url} identifies "${site.matchedName}" as a ` +
          `confirmed malicious package: ${site.spec.incident_summary}. Confirmed-malicious ` +
          `classification is the highest-confidence supply-chain signal the scanner emits.`,
      })
      .sink({
        sink_type: "command-execution",
        location: site.dependencyLocation,
        observed:
          `Malicious package "${site.matchedName}" executes attacker-controlled code at install ` +
          `time (postinstall hook) or at first-import, depending on the variant described in ` +
          `${site.spec.advisory_url}.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: site.configLocation,
        detail:
          "The manifest directly lists the malicious package; no block was in place at resolution " +
          "time. Registry-side blocking would have prevented this; lockfile pinning does not.",
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          `The malicious package executes attacker code the first time npm install / pip install ` +
          `runs. In the MCP server context the payload inherits the full authority delegated to the ` +
          `server: filesystem access, credentials, network egress. Historical incidents of this ` +
          `class (${site.spec.incident_summary}) routinely exfiltrate tokens, install persistence, ` +
          `or ship coin miners.`,
      })
      .factor(
        "confirmed_malicious_package_hit",
        0.25,
        `"${site.matchedName}" is present in the confirmed-malicious-package registry. Advisory: ` +
          `${site.spec.advisory_url} (disclosed ${site.spec.disclosed}).`,
      );

    if (site.viaUnicodeNormalisation) {
      builder.factor(
        "unicode_homoglyph_normalisation_hit",
        0.1,
        `The declared name "${site.name}" is not literally present in the blocklist, but its ` +
          `Unicode-normalised form "${site.matchedName}" IS — indicating a homoglyph attack ` +
          `(Cyrillic / Greek / Fullwidth codepoint substitution). Cross-references rule A6.`,
      );
    }

    if (site.spec.cvss_v3 !== undefined) {
      builder.factor(
        "cvss_v3_published",
        Math.min(0.08, site.spec.cvss_v3 / 100),
        `The advisory assigned CVSS v3 score ${site.spec.cvss_v3}.`,
      );
    }

    builder.reference({
      id: "INCIDENT-" + site.matchedName.replace("/", "_").replace("@", ""),
      title: `Known malicious package: ${site.matchedName}`,
      url: site.spec.advisory_url,
      relevance: site.spec.incident_summary,
    });
    // Fallback primary ref — always OWASP MCP10 for scoring + traceability.
    builder.reference(REF_OWASP_MCP10);

    builder.verification(stepConsultAdvisory(site));
    builder.verification(stepInspectManifest(site));
    builder.verification(stepCheckPostinstall(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "critical",
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
      `D5 charter caps confidence at ${cap}. The reserved 0.05 head-room covers the edge case of ` +
      `a rehabilitated package still listed for historical reasons.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new KnownMaliciousPackagesRule());

export { KnownMaliciousPackagesRule };
