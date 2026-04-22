/** L8 — Version Rollback Attack (v2). Structural JSON + AST walker; zero regex; cap 0.85. */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherL8, type RollbackSite } from "./gather.js";
import {
  stepInspectOverride,
  stepCheckCve,
  stepCheckCritical,
} from "./verification.js";

const RULE_ID = "L8";
const RULE_NAME = "Version Rollback Attack";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0017" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Do not override dependencies to pre-1.x or explicitly bounded-low " +
  "versions without a documented reason and a CVE-review. Let the package " +
  "manager resolve the latest secure version unless there is a verified " +
  "incompatibility. For MCP-critical SDKs (modelcontextprotocol, mcp-sdk, " +
  "fastmcp, anthropic, openai), pin to a CURRENT secure tag and watch " +
  "for upstream security advisories.";

const REF_COSAI_T6 = {
  id: "CoSAI-MCP-T6",
  title: "CoSAI MCP Security — T6: Supply Chain Integrity",
  url: "https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy",
  relevance:
    "Dependency version overrides bypass supply-chain integrity when they " +
    "force installation of historically vulnerable versions.",
} as const;

class L8Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherL8(context);
    return sites.map((site) => this.buildFinding(site));
  }

  private buildFinding(site: RollbackSite): RuleResult {
    const severity = site.is_mcp_critical ? "critical" as const : "high" as const;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: `${site.package_name}: "${site.version_spec}"`,
        rationale:
          site.kind === "json-override"
            ? `Package.json ${site.section_or_line} override pins "${site.package_name}" ` +
              `to "${site.version_spec}". Old versions may contain patched CVEs.`
            : `Install command on ${site.section_or_line} pins "${site.package_name}" ` +
              `to "${site.version_spec}".`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: site.location,
        observed:
          `Dependency pinned to old version "${site.version_spec}" — may ` +
          `restore known vulnerabilities at install time.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: site.is_mcp_critical ? "moderate" : "complex",
        scenario:
          `Rollback forces installation of an older dependency. If the old ` +
          `version has known CVEs, the fix is undone. Supply-chain attackers ` +
          `use overrides to re-expose vulnerable packages that the ecosystem ` +
          `has already patched.`,
      })
      .factor(
        "old_version_confidence",
        site.is_mcp_critical ? 0.12 : 0.08,
        `Version "${site.version_spec}" parsed as "old" by semver walker`,
      );

    if (site.is_mcp_critical) {
      builder.factor(
        "mcp_critical_escalation",
        0.08,
        `Package "${site.package_name}" matches an MCP-critical prefix`,
      );
    }

    builder.reference(REF_COSAI_T6);
    builder.verification(stepInspectOverride(site));
    builder.verification(stepCheckCve(site));
    builder.verification(stepCheckCritical(site));

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

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale: `L8 cap ${cap}: cannot prove CVE presence without OSV cross-check.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new L8Rule());
export { L8Rule };
