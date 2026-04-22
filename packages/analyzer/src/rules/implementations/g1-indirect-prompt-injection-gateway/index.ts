/**
 * G1 — Indirect Prompt Injection Gateway (Rule Standard v2).
 *
 * The #1 real-world MCP attack vector (Rehberger 2024, Invariant Labs 2025,
 * Wiz Research 2025, MITRE ATLAS AML.T0054.001). A tool that ingests content
 * from a source an attacker can influence — web scrape, email, issue comment,
 * shared filesystem path, chat stream, or MCP resource — is a gateway for
 * indirect prompt injection when the same server exposes any tool the agent
 * can subsequently invoke as a sink.
 *
 * Unlike A1 / A7 / A9 / G2 / G3 (payload-level signals inside tool
 * metadata), G1 is a *structural* precondition: the gateway does nothing
 * malicious itself; it is simply a well-meaning reader of untrusted bytes.
 * The exploitability is the coexistence with a reachable sink, so no static
 * check of tool descriptions can replace the capability-pair inference.
 *
 * Emits ONE G1 finding per gateway on the server. No companion rule ids —
 * G1 is not a parent for F/I companions; those live in their own charters.
 *
 * Detection:
 *   1. gather step runs capability-graph classification on every tool.
 *   2. Any node classified `ingests-untrusted` (≥ 0.4 confidence) or
 *      `accesses-filesystem` (≥ 0.4) becomes a gateway candidate.
 *   3. Any node classified `sends-network`, `writes-data`, `executes-code`,
 *      or `modifies-config` (≥ 0.5) becomes a sink candidate.
 *   4. Each gateway is paired with the most severe reachable sink.
 *   5. If the gateway declares a sanitizer parameter (sanitize_output,
 *      strip_html, content_filter, clean_markdown, escape_content), the
 *      mitigation link is recorded as present=true and the builder drops
 *      confidence -0.30.
 *   6. Confidence capped at 0.75 per charter.
 *
 * Zero regex literals. Zero string-literal arrays > 5. Vocabulary lives in
 * `./data/ingestion-capabilities.ts` as typed records.
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
import type { Location } from "../../location.js";
import {
  gatherG1,
  type GatewayNode,
  type GatewayPair,
  type SinkNode,
} from "./gather.js";
import {
  G1_CONFIDENCE_CAP,
  G1_MIN_BASE_CONFIDENCE,
} from "./data/ingestion-capabilities.js";
import {
  buildAgentContextPropagationStep,
  buildIngestionSourceStep,
  buildMitigationStep,
  buildSinkStep,
} from "./verification.js";

const RULE_ID = "G1";
const RULE_NAME = "Indirect Prompt Injection Gateway";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0054.001";

const REMEDIATION =
  "This tool ingests content from sources an attacker can influence (web pages, " +
  "emails, messages, files, database rows, issue trackers, MCP resources). The " +
  "content returned is processed by the agent without a declared trust boundary, " +
  "creating an indirect prompt injection gateway. Required mitigations: " +
  "(a) document every untrusted ingestion surface in the server's README, " +
  "(b) wrap returned content in explicit delimiters ([BEGIN EXTERNAL CONTENT] … " +
  "[END EXTERNAL CONTENT]) before returning to the agent, (c) strip HTML / " +
  "markdown / control characters in a sanitiser the agent cannot disable via a " +
  "tool argument, (d) require a user confirmation on any tool call whose " +
  "arguments are sourced from a prior ingestion tool's output. References: " +
  "Rehberger (2024) 'Compromising Claude via MCP web scraping'; Invariant Labs " +
  "(2025) 'MCP Indirect Injection Attacks'; MITRE ATLAS AML.T0054.001.";

// ─── Rule class ────────────────────────────────────────────────────────────

class IndirectPromptInjectionGatewayRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "capability-graph";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.tools || context.tools.length === 0) return [];

    const gathered = gatherG1(context);
    if (gathered.pairs.length === 0) return [];

    const findings: RuleResult[] = [];
    for (const pair of gathered.pairs) {
      const finding = this.buildFinding(pair);
      if (finding) findings.push(finding);
    }
    return findings;
  }

  private buildFinding(pair: GatewayPair): RuleResult | null {
    const { gateway, sinks, primary_sink: sink } = pair;

    // Gate on minimum base confidence from the classifier. Utility tools
    // can accidentally pick up a weak "ingests-untrusted" signal; below
    // the floor we do not fire (charter §Confidence cap).
    if (gateway.confidence < G1_MIN_BASE_CONFIDENCE) return null;

    const gatewayLoc: Location =
      gateway.origin === "resource"
        ? {
            kind: "resource",
            uri: gateway.resource_uri ?? gateway.tool_name,
            field: "uri",
          }
        : { kind: "tool", tool_name: gateway.tool_name };
    const propagationLoc: Location = { kind: "capability", capability: "tools" };
    const sinkLoc: Location = { kind: "tool", tool_name: sink.tool_name };

    const impactType: "data-exfiltration" | "cross-agent-propagation" =
      sink.sink_role === "network_egress" || sink.sink_role === "filesystem_write"
        ? "data-exfiltration"
        : "cross-agent-propagation";
    const scope: "ai-client" | "user-data" | "connected-services" =
      sink.sink_role === "network_egress" ? "user-data" : "ai-client";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type:
          gateway.origin === "resource" ? "external-content" : "external-content",
        location: gatewayLoc,
        observed:
          `Gateway: ${labelForGateway(gateway)} classified ` +
          `${gateway.capability} (ingestion-kind=${gateway.ingestion_kind}, ` +
          `trust=${gateway.trust_boundary}) at ` +
          `${(gateway.confidence * 100).toFixed(0)}% confidence from ` +
          `${gateway.signal_count} capability signal(s).`,
        rationale:
          `The capability-graph analyzer attributes the gateway as: ` +
          `"${gateway.attribution}". Any content delivered through this tool ` +
          `can carry prompt-injection instructions the agent will read as if ` +
          `they were legitimate context.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: propagationLoc,
        observed:
          `Propagation channel: the MCP tools surface itself. Response bytes ` +
          `from "${gateway.tool_name}" enter the agent's reasoning context; ` +
          `the agent's next tool call can carry an adversary-controlled ` +
          `instruction into the sink. The server exposes ${sinks.length} ` +
          `reachable sink${sinks.length === 1 ? "" : "s"} ` +
          `(canonical: "${sink.tool_name}" — ${sink.sink_role}).`,
      })
      .sink({
        sink_type: sinkTypeFor(sink.sink_role),
        location: sinkLoc,
        observed:
          `Canonical sink: tool "${sink.tool_name}" classified ` +
          `${sink.capability} at ${(sink.confidence * 100).toFixed(0)}% ` +
          `confidence. Role: ${sink.sink_role}. Attribution: ` +
          `"${sink.attribution}".`,
      });

    if (gateway.sanitizer_declared && gateway.sanitizer_parameter) {
      builder.mitigation({
        mitigation_type: "sanitizer-function",
        present: true,
        location: {
          kind: "parameter",
          tool_name: gateway.tool_name,
          parameter_path: `input_schema.properties.${gateway.sanitizer_parameter}`,
        },
        detail:
          `Gateway declares parameter "${gateway.sanitizer_parameter}" which ` +
          `reads as a content sanitiser. Verify enforcement (default-on, ` +
          `not agent-disablable) before treating as a real mitigation.`,
      });
    } else {
      builder.mitigation({
        mitigation_type: "sanitizer-function",
        present: false,
        location: gatewayLoc,
        detail:
          `No content-sanitiser parameter declared on "${gateway.tool_name}". ` +
          `Returned content flows into agent context verbatim.`,
      });
    }

    builder
      .impact({
        impact_type: impactType,
        scope,
        exploitability: exploitabilityForGateway(gateway),
        scenario:
          `An attacker plants instructions in content the gateway ` +
          `"${gateway.tool_name}" (${gateway.ingestion_kind}) will fetch. ` +
          `The user's agent reads the content as legitimate tool output, ` +
          `follows the injected instruction, and invokes ` +
          `"${sink.tool_name}" (${sink.sink_role}) with attacker-chosen ` +
          `arguments. Neither tool is individually dangerous; the ` +
          `coexistence on a single server — without an agent-enforced ` +
          `trust boundary — is.`,
      })
      .factor(
        "ingestion_capability_confidence",
        gateway.confidence - 0.5,
        `Gateway "${gateway.tool_name}" ingestion classification confidence ` +
          `${(gateway.confidence * 100).toFixed(0)}% (${gateway.signal_count} ` +
          `signal${gateway.signal_count === 1 ? "" : "s"}). Attribution: ` +
          `${gateway.attribution}`,
      )
      .factor(
        "sink_reachability",
        sinks.length >= 2 ? 0.08 : 0.04,
        `Server exposes ${sinks.length} reachable sink` +
          `${sinks.length === 1 ? "" : "s"}: ` +
          `${sinks.map((s) => `${s.tool_name}(${s.sink_role})`).join(", ")}. ` +
          `More sinks → larger attack surface once the gateway is exploited.`,
      )
      .factor(
        gateway.signal_count > 3
          ? "multi_signal_gateway"
          : "single_signal_gateway",
        gateway.signal_count > 3 ? 0.05 : 0.0,
        gateway.signal_count > 3
          ? `${gateway.signal_count} independent capability signals corroborate ` +
            `the gateway classification.`
          : `${gateway.signal_count} signal(s) — classification is structurally ` +
            `sound but modestly supported.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0054.001",
        title:
          "MITRE ATLAS AML.T0054.001 — Indirect Prompt Injection",
        url: "https://atlas.mitre.org/techniques/AML.T0054.001",
        relevance:
          "G1 is the static-time detector for the structural precondition of " +
          "AML.T0054.001: the agent ingests attacker-reachable content through " +
          "one tool and can invoke a side-effecting tool on the same server.",
      })
      .verification(buildIngestionSourceStep(gateway))
      .verification(buildAgentContextPropagationStep(gateway, sink))
      .verification(buildSinkStep(sink));

    if (gateway.sanitizer_declared && gateway.sanitizer_parameter) {
      builder.verification(
        buildMitigationStep(gateway, gateway.sanitizer_parameter),
      );
    }

    const chain = capConfidence(builder.build(), G1_CONFIDENCE_CAP);

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

// ─── Helpers ────────────────────────────────────────────────────────────────

function labelForGateway(g: GatewayNode): string {
  return g.origin === "resource"
    ? `resource "${g.tool_name}" (${g.resource_uri ?? "<no-uri>"})`
    : `tool "${g.tool_name}"`;
}

function sinkTypeFor(
  role: SinkNode["sink_role"],
):
  | "network-send"
  | "file-write"
  | "code-evaluation"
  | "config-modification"
  | "command-execution" {
  switch (role) {
    case "network_egress":
      return "network-send";
    case "filesystem_write":
      return "file-write";
    case "code_execution":
      return "command-execution";
    case "config_modification":
      return "config-modification";
    case "agent_state_write":
      return "config-modification";
  }
}

function exploitabilityForGateway(
  g: GatewayNode,
): "trivial" | "moderate" | "complex" {
  // Web ingestion is trivially exploitable (attacker publishes a page).
  // Email is trivial (send a message). Issue-tracker is trivial (comment).
  // Filesystem/database/chat require prior positioning — moderate.
  if (
    g.ingestion_kind === "web" ||
    g.ingestion_kind === "email" ||
    g.ingestion_kind === "issue_tracker" ||
    g.ingestion_kind === "rss" ||
    g.ingestion_kind === "resource_fetch"
  ) {
    return "trivial";
  }
  return "moderate";
}

/**
 * Clamp `chain.confidence` to the charter cap. Records the clamp in
 * `confidence_factors` so the cap is auditable, not a magic number.
 */
function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `G1 charter caps confidence at ${cap} — capability-pair inference ` +
      `cannot observe the actual prompt-injection content at scan time, ` +
      `only the structural precondition (gateway + reachable sink).`,
  });
  chain.confidence = cap;
  return chain;
}

// ─── Registration ─────────────────────────────────────────────────────────

registerTypedRuleV2(new IndirectPromptInjectionGatewayRule());

export { IndirectPromptInjectionGatewayRule };
