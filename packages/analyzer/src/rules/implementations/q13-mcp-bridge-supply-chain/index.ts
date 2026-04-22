/**
 * Q13 — MCP Bridge Package Supply Chain Attack (Rule Standard v2).
 *
 * Detects unpinned npx / uvx invocations of known MCP bridge
 * packages (mcp-remote, mcp-proxy, mcp-gateway, fastmcp,
 * @modelcontextprotocol/sdk) in shell literals, child_process
 * calls, and manifest version ranges. CVE-2025-6514 precedent.
 * Confidence cap 0.80.
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
import { gatherQ13, type BridgeSupplyChainSite } from "./gather.js";
import { stepInspectSite, stepPinGuidance } from "./verification.js";

const RULE_ID = "Q13";
const RULE_NAME = "MCP Bridge Package Supply Chain Attack";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Pin every MCP bridge package to an exact version. Replace " +
  "`npx mcp-remote` with `npx mcp-remote@1.2.3`; replace " +
  "`uvx fastmcp` with `uvx fastmcp==1.2.3`; replace " +
  "'^1.0.0' / '~1.0.0' / 'latest' in package manifests with " +
  "the exact version you audited. Use a lockfile and verify " +
  "package integrity (npm audit signatures / pip --require-hashes) " +
  "in your deployment pipeline. CVE-2025-6514 was a CVSS 9.6 RCE " +
  "in mcp-remote; pinning would have blocked it.";

const STRATEGY_SHARED_VOCAB = "shared-bridge-sinks-vocabulary";
const STRATEGY_NPX_UVX = "npx-uvx-shell-scan";
const STRATEGY_CHILD_PROC = "child-process-arg-scan";
const STRATEGY_MANIFEST_RANGE = "manifest-range-loose-match";

class McpBridgeSupplyChainRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "dependency-audit";

  readonly edgeCaseStrategies = [
    STRATEGY_SHARED_VOCAB,
    STRATEGY_NPX_UVX,
    STRATEGY_CHILD_PROC,
    STRATEGY_MANIFEST_RANGE,
  ] as const;

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherQ13(context);
    return gathered.sites.map((s) => this.buildFinding(s)).slice(0, 10);
  }

  private buildFinding(site: BridgeSupplyChainSite): RuleResult {
    const chain = this.buildChain(site);
    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }

  private buildChain(site: BridgeSupplyChainSite): EvidenceChain {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `An unpinned invocation of "${site.packageName}" ingests ` +
          `whatever the registry serves at runtime. The attacker only ` +
          `needs to publish a malicious version once; the next ` +
          `execution trusts it.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: site.location,
        observed:
          `${site.kind}: fetched-and-executed code flows into the MCP ` +
          `bridge with full process authority.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: site.location,
        observed: `Unpinned ${site.packageName} invocation (${site.kind}).`,
        cve_precedent: "CVE-2025-6514",
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          `A compromised or typosquatted bridge-package version ` +
          `executes with full user authority the first time the user ` +
          `runs the server. CVE-2025-6514 is the canonical precedent: ` +
          `CVSS 9.6 RCE in mcp-remote.`,
      })
      .factor(
        "unpinned_bridge_invocation_observed",
        0.14,
        `AST detected ${site.kind} referencing "${site.packageName}" ` +
          `with no version pin (${STRATEGY_NPX_UVX} / ` +
          `${STRATEGY_CHILD_PROC} / ${STRATEGY_MANIFEST_RANGE}).`,
      )
      .factor(
        "cve_precedent_available",
        0.08,
        `CVE-2025-6514 demonstrated RCE via the same unpinned-fetch ` +
          `pattern on mcp-remote.`,
      );

    builder.reference({
      id: "CVE-2025-6514",
      title: "mcp-remote OS command injection (CVSS 9.6)",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
      relevance:
        "Demonstrates that unpinned MCP bridge fetches can — and " +
        "did — serve RCE payloads in the wild.",
    });

    builder.verification(stepInspectSite(site));
    builder.verification(stepPinGuidance(site));

    const chain = builder.build();
    return capConfidence(chain, CONFIDENCE_CAP);
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `Q13 charter caps confidence at ${cap}. Static analysis cannot ` +
      `be 100% sure the shell literal actually runs; dead / ` +
      `comment-wrapped invocations would produce a false positive.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new McpBridgeSupplyChainRule());

export { McpBridgeSupplyChainRule };
