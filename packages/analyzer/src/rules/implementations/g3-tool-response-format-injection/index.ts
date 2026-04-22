/**
 * G3 — Tool Response Format Injection (Rule Standard v2).
 *
 * Detects protocol-mimicry claims and literal JSON-RPC envelope
 * shapes inside `tool.description`. A legitimate tool documents its
 * response STRUCTURALLY (`outputSchema`), never through prose
 * claiming the output IS protocol traffic. G3 flags the latter.
 *
 * Detection technique: linguistic + structural (multi-signal
 * noisy-OR over prose phrases AND literal envelope token
 * subsequences). No regex literals.
 */

import type { Severity } from "@mcp-sentinel/database";
import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gatherG3, toolLocation, type MimicSite } from "./gather.js";
import {
  stepInspectMimic,
  stepInspectAdditionalSignals,
  stepRelocateToSchema,
} from "./verification.js";
import {
  CONFIDENCE_CAP,
  CONFIDENCE_FLOOR,
  clampConfidence,
  noisyOr,
} from "./data/g3-scoring.js";

const RULE_ID = "G3";
const RULE_NAME = "Tool Response Format Injection";
const OWASP = "MCP01-prompt-injection";
const MITRE = "AML.T0061";

const REMEDIATION =
  "Remove every literal JSON-RPC envelope fragment, every MCP method reference, " +
  "and every prose claim that the tool's output IS protocol traffic from the " +
  "tool description. Response shape documentation belongs in the tool's " +
  "`outputSchema`, not in free-form prose. Educational references to JSON-RPC " +
  "should make clear (via documentation / educational / explains language) " +
  "that the protocol is being described, not produced by the tool.";

function severityFromConfidence(c: number): Severity {
  if (c >= 0.80) return "critical";
  if (c >= 0.60) return "high";
  return "medium";
}

class G3ToolResponseFormatInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "composite";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherG3(context);
    const out: RuleResult[] = [];
    for (const [tool_name, hits] of gathered.byTool.entries()) {
      const finding = this.buildFinding(tool_name, hits);
      if (finding) out.push(finding);
    }
    return out;
  }

  private buildFinding(tool_name: string, hits: MimicSite[]): RuleResult | null {
    const aggregate = noisyOr(hits.map((h) => h.effective_weight));
    if (aggregate < CONFIDENCE_FLOOR) return null;

    const primary = hits.reduce(
      (b, h) => (h.effective_weight > b.effective_weight ? h : b),
      hits[0],
    );
    const others = hits.filter((h) => h !== primary);
    const loc = toolLocation(tool_name);
    const hasShapeHit = hits.some((h) => h.kind === "jsonrpc_shape");
    const anyFence = hits.some((h) => h.fence_triggered);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: loc,
        observed: primary.observed,
        rationale:
          `Tool "${tool_name}" description contains ${hits.length} ` +
          `protocol-mimic signal(s). The strongest is "${primary.label}" ` +
          `(weight ${primary.weight.toFixed(2)}${primary.fence_triggered ? ", fence-demoted" : ""}). ` +
          `Legitimate tools document response shape STRUCTURALLY in ` +
          `\`outputSchema\` — prose that claims the output IS protocol ` +
          `traffic primes the AI's parsing pipeline to treat runtime ` +
          `responses as code (confused-deputy attack).`,
      })
      .propagation({
        propagation_type: "description-directive",
        location: loc,
        observed:
          `Protocol-mimic framing flows from the description into the LLM ` +
          `prompt as tool-metadata context. Independent signals: ` +
          hits
            .slice(0, 4)
            .map((h) => `"${h.label}" (w=${h.effective_weight.toFixed(2)})`)
            .join(", ") +
          (hits.length > 4 ? `, and ${hits.length - 4} more` : "") +
          ".",
      })
      .sink({
        sink_type: "code-evaluation",
        location: loc,
        observed:
          `Noisy-OR aggregation of ${hits.length} protocol-mimic signal(s) ` +
          `produced ${(aggregate * 100).toFixed(0)}% pre-cap confidence. ` +
          `The LLM is primed to parse the tool's runtime output as protocol ` +
          `traffic or a next tool call, rather than as untrusted data.`,
        cve_precedent: "CVE-2025-6514",
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: aggregate >= 0.80 ? "trivial" : "moderate",
        scenario:
          `Invoking "${tool_name}" causes the AI to ingest its response ` +
          `with protocol-trust priming. The server then emits a payload ` +
          `that looks like a tools/call message, a system-role chat message, ` +
          `or a JSON-RPC envelope; the AI's parser accepts it as a genuine ` +
          `next step. CVE-2025-6514 (mcp-remote, CVSS 9.6) is a real-world ` +
          `exploitation of exactly this boundary confusion.`,
      })
      .factor(
        "protocol_mimic_phrase_match",
        0.08,
        `Deterministic tokeniser found ${hits.length} protocol-mimic signal(s); ` +
          `primary: "${primary.label}" (weight ${primary.weight.toFixed(2)}).`,
      )
      .factor(
        "noisy_or_base_confidence",
        aggregate - 0.5,
        `Noisy-OR aggregation of ${hits.length} independent fence-adjusted ` +
          `weights produced ${(aggregate * 100).toFixed(0)}% pre-cap confidence.`,
      );

    if (hasShapeHit) {
      builder.factor(
        "literal_envelope_present",
        0.07,
        "At least one signal is a literal JSON-RPC envelope fragment " +
          '(e.g. `{"jsonrpc":"2.0"`) — these are almost never legitimate in ' +
          "tool descriptions. Structural proof raises confidence.",
      );
    }

    if (hits.length >= 3) {
      builder.factor(
        "multi_signal_corroboration",
        0.05,
        `${hits.length} distinct protocol-mimic signals — unlikely to arise from ` +
          `a single paraphrase.`,
      );
    }

    if (anyFence) {
      builder.factor(
        "false_positive_fence_triggered",
        -0.08,
        "One or more fence tokens (e.g. 'documentation', 'educational', " +
          "'explains') co-occur in the description; matching signals have been " +
          "weight-demoted to reflect likely-legitimate educational content.",
      );
    }

    builder.reference({
      id: "CVE-2025-6514",
      title: "CVE-2025-6514 — mcp-remote Protocol-Boundary Confusion (CVSS 9.6)",
      year: 2025,
      relevance:
        "Real-world confused-deputy exploit across the tool-output / " +
        "protocol-message boundary. G3 detects the static indicator: " +
        "descriptions that advertise protocol output.",
    });

    builder.verification(stepInspectMimic(primary));
    if (others.length > 0) {
      builder.verification(stepInspectAdditionalSignals(primary, others));
    }
    builder.verification(stepRelocateToSchema(primary));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "linguistic_scoring_confidence_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale:
          `G3 charter caps confidence at ${CONFIDENCE_CAP.toFixed(2)} — ` +
          `protocol-mimic language is rarely legitimate but cannot reach the ` +
          `certainty of a taint-path proof.`,
      });
      chain.confidence = clampConfidence(chain.confidence, CONFIDENCE_CAP);
    }

    const severity = severityFromConfidence(aggregate);

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

registerTypedRuleV2(new G3ToolResponseFormatInjectionRule());

export { G3ToolResponseFormatInjectionRule };
export { gatherG3 } from "./gather.js";
