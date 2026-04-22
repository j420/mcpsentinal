/**
 * D1 — Known CVEs in Dependencies (v2)
 *
 * Orchestrator. Turns the deterministic facts gathered by gather.ts into
 * RuleResult[] with a v2-compliant EvidenceChain:
 *
 *   - every link carries a structured Location (dependency + config);
 *   - VerificationStep.target is a Location;
 *   - threat_reference cites ISO 27001 A.8.8 (CVE-backed precedents are
 *     recorded as confidence-factor rationale, the chain cites the
 *     governance control);
 *   - confidence capped at 0.92 per charter.
 *
 * No regex. Zero string-array literals > 5. All data is structured.
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
import { gatherD1, type KnownCveSite } from "./gather.js";
import {
  stepInspectDependency,
  stepCrossReferenceAdvisory,
  stepInspectManifest,
} from "./verification.js";

const RULE_ID = "D1";
const RULE_NAME = "Known CVEs in Dependencies";
const OWASP = "MCP08-dependency-vuln" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.92;

const REMEDIATION =
  "Update the flagged dependency to a version that resolves every listed CVE. " +
  "Consult the NVD or OSV advisory linked in the finding for the minimum safe " +
  "version. Re-run `npm audit` / `pip-audit` / `osv-scanner` after the bump to " +
  "confirm no residual advisories remain. Where a patched version is not yet " +
  "released, apply an override (npm `overrides`, `resolutions`, `pnpm.overrides`, " +
  "or a Python constraints file) to pin a compatible fix, and file a tracking " +
  "issue so the override is removed when the upstream fix lands.";

const REF_ISO_A88 = {
  id: "ISO-27001-A.8.8",
  title: "ISO/IEC 27001:2022 Annex A Control 8.8 — Management of Technical Vulnerabilities",
  url: "https://www.iso.org/standard/82875.html",
  relevance:
    "A.8.8 requires timely identification of technical vulnerabilities and evaluation " +
    "of the organisation's exposure. A dependency with a published, unpatched CVE is " +
    "the canonical A.8.8 finding — the control mandates remediation or documented " +
    "risk acceptance.",
} as const;

class KnownCvesInDependenciesRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { dependencies: true };
  readonly technique: AnalysisTechnique = "dependency-audit";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherD1(context);
    return gathered.sites.map((site) => this.buildFinding(site));
  }

  private buildFinding(site: KnownCveSite): RuleResult {
    const cveList = site.cveIds.join(", ");

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.dependencyLocation,
        observed:
          `Dependency ${site.ecosystem}:${site.name}@${site.version} carries published CVE(s): ${cveList}.`,
        rationale:
          "Third-party package dependencies are external content resolved from public " +
          "registries. A version with a published CVE ships the vulnerable code path as-is; " +
          "the MCP server's runtime inherits the vulnerability the moment the dependency " +
          "is imported.",
      })
      .sink({
        sink_type: "code-evaluation",
        location: site.dependencyLocation,
        observed:
          `Vulnerable code paths are resolved from ${site.name}@${site.version}. Advisories: ${cveList}.`,
        cve_precedent: site.primaryCveId,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: site.dependencyLocation,
        detail:
          `No patched version is pinned — ${site.name}@${site.version} remains exposed. ` +
          `npm overrides / pnpm overrides / pip constraints files could pin a patched fork, ` +
          `but the static analyser has not observed such a pin.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `An attacker who reaches a code path backed by ${site.name}@${site.version} exploits ` +
          `${site.primaryCveId} to execute arbitrary code in the MCP server's host process. ` +
          `Because MCP servers typically run with delegated tool authority (filesystem, network, ` +
          `credentials), the blast radius extends to everything the server is authorised to touch.`,
      })
      .factor(
        "known_cve_presence",
        0.22,
        `The auditor returned ${site.cveIds.length} CVE id(s) for ${site.name}@${site.version}: ` +
          `${cveList}. These are drawn from authoritative advisory databases (NVD / OSV) — the ` +
          `presence of any one id is sufficient to treat the package as affected.`,
      )
      .factor(
        "exact_version_pinned",
        0.04,
        `The manifest pins version ${site.version} exactly; there is no semver range that ` +
          `could silently resolve to a patched release. The vulnerable version is the installed ` +
          `version until the manifest is changed.`,
      );

    if (site.cveIds.length > 1) {
      builder.factor(
        "multi_cve_dependency",
        0.04,
        `${site.name}@${site.version} is affected by ${site.cveIds.length} advisories, not just ` +
          `one — the dependency is a cumulative risk, increasing the likelihood that at least ` +
          `one of the CVEs has a publicly available exploit.`,
      );
    }

    builder.reference(REF_ISO_A88);
    builder.verification(stepInspectDependency(site));
    builder.verification(stepCrossReferenceAdvisory(site));
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
      `D1 charter caps confidence at ${cap} — CVE snapshots are point-in-time and the auditor ` +
      `mirror may trail the upstream advisory database. The remaining head-room preserves the ` +
      `possibility that the finding is a rejected/withdrawn id the scanner has not yet refreshed.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new KnownCvesInDependenciesRule());

export { KnownCvesInDependenciesRule };
