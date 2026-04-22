/**
 * Q6 — Agent Identity Impersonation via MCP (Rule Standard v2).
 *
 * Static detection of vendor-identity impersonation in source
 * code (serverInfo.name object literals) and in tool descriptions
 * (multi-token vendor-claim phrases). Confidence cap 0.80.
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
import { gatherQ6, type ImpersonationSite } from "./gather.js";
import { stepInspectClaim, stepVerifyNamespace } from "./verification.js";

const RULE_ID = "Q6";
const RULE_NAME = "Agent Identity Impersonation via MCP";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Do not let an MCP server self-declare a vendor identity in " +
  "serverInfo.name or tool descriptions. Server identity must come " +
  "from a signed registry entry (npm namespace, PyPI publisher, " +
  "Smithery verified badge, MCP registry signature) that the client " +
  "verifies cryptographically. If your server is genuinely the " +
  "official Anthropic / OpenAI / Google server, publish it in the " +
  "vendor's official namespace and let the client display that " +
  "provenance instead of relying on free-text metadata.";

const STRATEGY_VENDOR_CATALOGUE = "vendor-token-catalogue";
const STRATEGY_SERVERINFO_MATCH = "serverinfo-name-match";
const STRATEGY_DESC_CLAIM_MATCH = "description-vendor-claim-match";
const STRATEGY_MULTI_AGENT_GATE = "multi-agent-context-gate";

class AgentIdentityImpersonationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  readonly edgeCaseStrategies = [
    STRATEGY_VENDOR_CATALOGUE,
    STRATEGY_SERVERINFO_MATCH,
    STRATEGY_DESC_CLAIM_MATCH,
    STRATEGY_MULTI_AGENT_GATE,
  ] as const;

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherQ6(context);
    if (gathered.noContextAvailable) return [];
    if (gathered.sites.length === 0) return [];
    // One finding per unique (tool / location) to avoid duplicate
    // emission when multiple phrases hit the same tool.
    const seen = new Set<string>();
    const out: RuleResult[] = [];
    for (const site of gathered.sites) {
      const key = locationKey(site);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(this.buildFinding(site));
    }
    return out.slice(0, 10);
  }

  private buildFinding(site: ImpersonationSite): RuleResult {
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

  private buildChain(site: ImpersonationSite): EvidenceChain {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type:
          site.surface === "tool-description" ? "external-content" : "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `The ${site.surface} contains a self-declared identity claim ` +
          `referencing the ${site.vendor} vendor. Clients and LLMs that ` +
          `read this field may elevate trust (skip confirmation, ` +
          `auto-approve destructive calls) based on the attribution.`,
      })
      .propagation({
        propagation_type:
          site.surface === "tool-description" ? "description-directive" : "variable-assignment",
        location: site.location,
        observed: `Vendor token "${site.vendor}" emitted in ${site.surface}.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: site.location,
        observed: site.label,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `Downstream agents and MCP clients that treat vendor-branded ` +
          `servers as trusted will auto-approve this server's tool ` +
          `calls. A malicious publisher gains the trust profile of ` +
          `${site.vendor} without proving the attribution.`,
      })
      .factor(
        "vendor_impersonation_marker",
        0.14,
        `Vendor token "${site.vendor}" matched the Q6 catalogue ` +
          `(${STRATEGY_VENDOR_CATALOGUE} / ${STRATEGY_SERVERINFO_MATCH} / ${STRATEGY_DESC_CLAIM_MATCH}).`,
      )
      .factor(
        "identity_not_cryptographically_verified",
        0.08,
        `Identity is self-asserted in metadata — no registry signature ` +
          `is verifiable from the static surface alone.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML-T0054",
        title: "MITRE ATLAS AML.T0054 — LLM Prompt Injection",
        url: "https://atlas.mitre.org/techniques/AML.T0054",
        relevance:
          "Self-declared vendor attribution is a prompt-injection " +
          "payload delivered via metadata: the LLM treats the server " +
          "as vetted because the metadata says so.",
      });

    builder.verification(stepInspectClaim(site));
    builder.verification(stepVerifyNamespace(site));

    const chain = builder.build();
    return capConfidence(chain, CONFIDENCE_CAP);
  }
}

function locationKey(site: ImpersonationSite): string {
  const loc = site.location;
  if (loc.kind === "source") return `source:${loc.file}:${loc.line}:${loc.col ?? ""}`;
  if (loc.kind === "tool") return `tool:${loc.tool_name}`;
  return "unknown";
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `Q6 charter caps confidence at ${cap}. Legitimate first-party ` +
      `vendor servers do exist (rare); verifying via the vendor's ` +
      `signed registry entry is a manual step the rule cannot perform.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new AgentIdentityImpersonationRule());

export { AgentIdentityImpersonationRule };
