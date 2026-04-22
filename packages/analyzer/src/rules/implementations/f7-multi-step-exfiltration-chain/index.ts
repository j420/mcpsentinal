/**
 * F7 — Multi-Step Exfiltration Chain (Rule Standard v2).
 *
 * Detects read→(transform)*→send paths inside a single MCP server. The
 * capability-graph analyzer produces `exfiltration_chain` patterns via BFS
 * path-finding between reader and sender nodes; F7 wraps those patterns
 * with typed endpoint evidence and a Rule Standard v2 chain.
 *
 * Distinct from F1: F7 does NOT require the untrusted-content leg and
 * does NOT cap the total score — it adds a severity-weighted penalty like
 * every other critical finding.
 *
 * Threat intelligence (see CHARTER.md):
 *   - Embrace The Red (2024 Q4) — multi-step exfil against Claude Desktop
 *   - Invariant Labs (2026) — MCP tool-poisoning chain patterns
 *   - MITRE ATLAS AML.T0057 — LLM Data Leakage
 *
 * Zero regex literals, zero string-arrays > 5. Reader/sender vocabulary
 * lives in `./data/transform-capabilities.ts` as typed records.
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
  gatherF7,
  type ChainPath,
  type F7Gathered,
} from "./gather.js";
import { F7_CONFIDENCE_CAP } from "./data/transform-capabilities.js";
import {
  stepInspectReader,
  stepInspectSender,
  stepInspectTransformHop,
  stepTraceChain,
} from "./verification.js";

const RULE_ID = "F7";
const RULE_NAME = "Multi-Step Exfiltration Chain";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0057";

const REMEDIATION =
  "This server provides a complete multi-step data exfiltration chain (read → " +
  "[transform] → send). Remediate by (a) splitting the reader and sender tools " +
  "into separate servers operated at different trust levels, (b) requiring " +
  "human-in-the-loop approval for any tool call whose arguments include data " +
  "read by another tool earlier in the session, (c) adding a destination " +
  "allowlist to the sender tool so attacker-chosen endpoints are rejected, or " +
  "(d) tagging read outputs with a data-classification label the sender enforces. " +
  "Until mitigated, the server cannot resist Rehberger-class (Embrace The Red, " +
  "2024) multi-step exfiltration chains.";

class ExfiltrationChainRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true, min_tools: 2 };
  readonly technique: AnalysisTechnique = "capability-graph";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.tools || context.tools.length < 2) return [];

    const gathered = gatherF7(context);
    if (gathered.chains.length === 0) return [];

    return gathered.chains.map((chain) => this.buildFinding(chain, gathered));
  }

  private buildFinding(chain: ChainPath, g: F7Gathered): RuleResult {
    const readerLoc: Location = { kind: "tool", tool_name: chain.reader.tool_name };
    const senderLoc: Location = { kind: "tool", tool_name: chain.sender.tool_name };
    // Propagation Location — the first transformation hop if any, else the sender.
    const propLoc: Location =
      chain.transforms.length > 0
        ? { kind: "tool", tool_name: chain.transforms[0] }
        : senderLoc;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: readerLoc,
        observed:
          `Reader hop: tool "${chain.reader.tool_name}" classified ` +
          `${chain.reader.capability} at ${(chain.reader.confidence * 100).toFixed(0)}% ` +
          `confidence from ${chain.reader.signal_count} signals. Graph centrality ` +
          `${(chain.reader.centrality * 100).toFixed(0)}%.`,
        rationale:
          `Capability-graph analyzer attributed this reader as: ${chain.reader.attribution}`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: propLoc,
        observed:
          chain.transforms.length > 0
            ? `Chain of ${chain.hops.length} hops: ${chain.hops.join(" → ")}. Transformation ` +
              `hops: ${chain.transforms.join(", ")} — sensitive bytes laundered through ` +
              `intermediate tools before reaching the sender.`
            : `Direct 2-hop reader→sender path: ${chain.hops.join(" → ")}. The AI agent is ` +
              `the connecting hop; no tool-level isolation exists between reader and sender.`,
      })
      .sink({
        sink_type: "network-send",
        location: senderLoc,
        observed:
          `Sender hop: tool "${chain.sender.tool_name}" classified ` +
          `${chain.sender.capability} at ${(chain.sender.confidence * 100).toFixed(0)}% ` +
          `confidence from ${chain.sender.signal_count} signals. Graph centrality ` +
          `${(chain.sender.centrality * 100).toFixed(0)}%.`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "user-data",
        exploitability: "moderate",
        scenario:
          `An instruction delivered via the user's prompt or an upstream untrusted-content ` +
          `tool directs the agent to read via "${chain.reader.tool_name}", launder the ` +
          `bytes through ${chain.transforms.length || "no"} transformation hop(s), and POST ` +
          `them via "${chain.sender.tool_name}" to an attacker-chosen endpoint. No single ` +
          `tool in the chain is individually dangerous — the combination is. This is the ` +
          `exact pattern Johann Rehberger (Embrace The Red, 2024) demonstrated against ` +
          `Claude Desktop.`,
      })
      .factor(
        "chain_length",
        chain.hops.length > 2 ? 0.05 : 0.0,
        `${chain.hops.length}-hop chain: ` +
          (chain.hops.length > 2
            ? `transformation hops present — laundering step adds sophistication.`
            : `direct reader→sender path — simplest exfil shape.`),
      )
      .factor(
        "reader_centrality",
        chain.reader.centrality > 0.5 ? 0.05 : 0.0,
        `Reader "${chain.reader.tool_name}" centrality ` +
          `${(chain.reader.centrality * 100).toFixed(0)}% — ` +
          (chain.reader.centrality > 0.5
            ? "high-centrality reader is a critical data-flow bottleneck."
            : "low-centrality reader; the chain is localized but still valid."),
      )
      .factor(
        "sender_centrality",
        chain.sender.centrality > 0.5 ? 0.05 : 0.0,
        `Sender "${chain.sender.tool_name}" centrality ` +
          `${(chain.sender.centrality * 100).toFixed(0)}% — ` +
          (chain.sender.centrality > 0.5
            ? "high-centrality sender is a critical egress bottleneck."
            : "low-centrality sender; still the terminal hop of the chain."),
      )
      .factor(
        "transform_step_present",
        chain.transforms.length > 0 ? 0.1 : 0.0,
        chain.transforms.length > 0
          ? `Transformation hops [${chain.transforms.join(", ")}] present — the ` +
            `laundering step is what makes Embrace-The-Red-class chains work in ` +
            `production: base64/hex/URL-encode converts sensitive bytes into a ` +
            `form the sender will accept.`
          : `No transformation hops observed — direct reader→sender exfiltration.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0057",
        title: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
        url: "https://atlas.mitre.org/techniques/AML.T0057",
        relevance:
          "F7 is the static-time detector for the structural precondition of AML.T0057: " +
          "a server shape in which the agent can be directed to read sensitive data and " +
          "transmit it externally through the same tool surface.",
      });

    builder.verification(stepInspectReader(chain.reader));
    for (let i = 0; i < chain.transforms.length; i++) {
      builder.verification(
        stepInspectTransformHop(chain.transforms[i], i + 2, chain.hops.length),
      );
    }
    builder.verification(stepInspectSender(chain.sender));
    builder.verification(stepTraceChain(chain.hops));

    const chainResult = clampConfidence(builder.build(), F7_CONFIDENCE_CAP);
    // Suppress unused-variable warning for `g` when no diagnostics emitted from it.
    void g;

    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain: chainResult,
    };
  }
}

function clampConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `F7 charter caps confidence at ${cap} — capability classification is ` +
      `multi-signal probabilistic and graph edges are inferred (type compatibility, ` +
      `not observed runtime data flow).`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ExfiltrationChainRule());

export { ExfiltrationChainRule };
