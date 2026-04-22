/**
 * Q15 — A2A/MCP Protocol Boundary Confusion (Rule Standard v2).
 *
 * Cross-ecosystem emergent: AAIF (Dec 2025) hosts both Google A2A
 * and Anthropic MCP. Servers bridging both protocols expose a
 * boundary on which trust levels do not translate and content
 * policies do not carry. Q15 detects (A2A surface read) × (MCP
 * context sink) within the same enclosing function.
 *
 * Honest-refusal gate: skip when no A2A surface exists in source.
 *
 * Confidence cap: 0.78 per CHARTER. Architectural-not-incident-
 * backed at scale; cap preserves reviewer headroom.
 *
 * Zero regex literals.
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
import { gatherQ15, type Q15Site } from "./gather.js";
import {
  stepInspectA2aSurface,
  stepInspectMcpSink,
  stepCheckContentPolicy,
} from "./verification.js";

const RULE_ID = "Q15";
const RULE_NAME = "A2A/MCP Protocol Boundary Confusion";
const OWASP = "MCP06-excessive-permissions" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.78;

const REMEDIATION =
  "Servers bridging A2A and MCP must (1) sanitize every A2A skill / " +
  "TextPart / FilePart / DataPart / push-notification payload before it " +
  "enters an MCP tool description, input, or response; (2) re-apply MCP " +
  "content policies to A2A-sourced data at the boundary, never trust the " +
  "A2A-side check; (3) require cryptographic verification for A2A agent " +
  "discovery and registration (arXiv 2602.19555 fake-agent-advertisement); " +
  "(4) maintain separate permission models for A2A and MCP operations so " +
  "trust in one protocol does not auto-grant trust in the other; and " +
  "(5) log every cross-protocol data crossing with a correlation ID that " +
  "ties the MCP finding back to the originating A2A payload.";

const STRATEGY_SURFACE = "a2a-protocol-surface-catalogue";
const STRATEGY_FLOW = "a2a-to-mcp-flow-detection";
const STRATEGY_CARD = "agent-card-skill-ingestion";
const STRATEGY_PART = "part-based-content-policy-bypass";
const STRATEGY_HONEST_REFUSAL = "honest-refusal-no-a2a-surface";

const FACTOR_SURFACE = "a2a_protocol_surface_observed";
const FACTOR_FLOW = "flow_into_mcp_context";
const FACTOR_DISCOVERY = "unverified_discovery_or_uri";
const FACTOR_POLICY = "content_policy_demotes";

class Q15Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  readonly edgeCaseStrategies = [
    STRATEGY_SURFACE,
    STRATEGY_FLOW,
    STRATEGY_CARD,
    STRATEGY_PART,
    STRATEGY_HONEST_REFUSAL,
  ] as const;

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherQ15(context);
    if (!gathered.hasA2aSurface) return [];

    const findings: RuleResult[] = [];
    const seen = new Set<string>();
    for (const site of gathered.sites) {
      const key = siteKey(site);
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(this.buildFinding(site));
    }
    return findings.slice(0, 10);
  }

  private buildFinding(site: Q15Site): RuleResult {
    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain: this.buildChain(site),
    };
  }

  private buildChain(site: Q15Site): EvidenceChain {
    const kinds = Array.from(new Set(site.a2aSurfaces.map((s) => s.kind)));
    const primarySurface = site.a2aSurfaces[0];
    const primarySink = site.mcpSinks[0];
    const hasDiscovery = kinds.includes("discovery") || kinds.includes("uri");

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "agent-output",
        location: primarySurface.location,
        observed:
          `A2A surface: ${kinds.join(" / ")} ` +
          `(tokens: ${site.a2aSurfaces.slice(0, 5).map((s) => s.token).join(", ")})`,
        rationale:
          `The enclosing function reads from A2A protocol surfaces ` +
          `(${kinds.join(" / ")}). Agent Card skill metadata, TaskResult parts ` +
          `(TextPart / FilePart / DataPart), push-notification payloads, and ` +
          `agent-discovery results arrive with no MCP content policy attached ` +
          `— the client LLM receives them via whatever MCP sink this function ` +
          `later reaches.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: primarySink.location,
        observed:
          `A2A-sourced values flow into MCP sink "${primarySink.sinkName}" ` +
          `in the same enclosing function. The boundary is crossed without a ` +
          `re-validation step.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: primarySink.location,
        observed:
          `MCP sink "${primarySink.sinkName}" admits the A2A-sourced value ` +
          `into the MCP tool context. Any prompt injection, unsanitised part ` +
          `content, or adversarially-advertised skill metadata is now in ` +
          `scope for the client LLM.`,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "other-agents",
        exploitability: "moderate",
        scenario:
          `An attacker controlling an A2A agent publishes an Agent Card with ` +
          `a skill description that contains a prompt-injection payload, ` +
          `or a TaskResult whose TextPart carries tool-hijack instructions. ` +
          `The bridge reads the A2A surface and forwards it to the MCP sink. ` +
          `The downstream MCP client LLM processes the A2A-sourced bytes ` +
          `under MCP trust. AAIF (Dec 2025) created this boundary; Q15 flags ` +
          `the code that does not enforce a cross-protocol policy.`,
      })
      .factor(
        FACTOR_SURFACE,
        0.10,
        `A2A surfaces observed: ${kinds.join(" / ")} ` +
          `(${site.a2aSurfaces.length} hits; ${STRATEGY_SURFACE}).`,
      )
      .factor(
        FACTOR_FLOW,
        0.12,
        `MCP sink "${primarySink.sinkName}" in the same enclosing function ` +
          `(${STRATEGY_FLOW}).`,
      )
      .factor(
        FACTOR_DISCOVERY,
        hasDiscovery ? 0.06 : 0.0,
        hasDiscovery
          ? `Discovery / a2a:// surface also present — unverified agent ` +
            `advertisement compounds the boundary risk (arXiv 2602.19555).`
          : `No discovery / a2a:// surface — boundary risk is Agent-Card / ` +
            `Part-only.`,
      )
      .factor(
        FACTOR_POLICY,
        site.contentPolicyIdentifier ? -0.15 : 0.04,
        site.contentPolicyIdentifier
          ? `Content-policy identifier "${site.contentPolicyIdentifier}" in ` +
            `scope demotes the finding — confirm the policy runs on the ` +
            `A2A-sourced value on every path.`
          : `No content-policy identifier in scope — A2A payloads reach the ` +
            `MCP sink raw.`,
      )
      .reference({
        id: "AAIF-Linux-Foundation",
        title: "Linux Foundation AAIF — A2A + MCP interop (Dec 2025)",
        url: "https://aaif.foundation/",
        relevance:
          "The AAIF umbrella formalised A2A + MCP interoperability in " +
          "December 2025. Q15 detects the code patterns that mix the two " +
          "protocols without a cross-protocol trust / content-policy " +
          "mapping — the architectural gap interoperability created.",
      })
      .verification(stepInspectA2aSurface(site))
      .verification(stepInspectMcpSink(site))
      .verification(stepCheckContentPolicy(site));

    return capConfidence(builder.build(), CONFIDENCE_CAP);
  }
}

function siteKey(site: Q15Site): string {
  const loc = site.enclosingFunctionLocation;
  if (loc && loc.kind === "source") return `${loc.file}:${loc.line}`;
  const sink = site.mcpSinks[0]?.location;
  return sink && sink.kind === "source" ? `${sink.file}:${sink.line}` : "module";
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `Q15 charter caps confidence at ${cap}. Novel cross-protocol attack ` +
      `class with limited incident history at scale (AAIF only formalised ` +
      `Dec 2025); the cap preserves reviewer headroom for the inevitable ` +
      `legitimate-bridge counterexamples.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new Q15Rule());

export { Q15Rule };
