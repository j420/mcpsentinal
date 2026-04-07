/**
 * M5 — Context Window Flooding (v2: Noisy-OR Linguistic Scoring)
 *
 * REPLACES the regex: /(?:detailed|verbose|comprehensive|extensive|complete)\s+(?:output|response|result|data)/i
 *
 * Old behavior: Single regex matching "detailed output" or "comprehensive response".
 *   False negative: "returns all records without limit" (no keyword pair)
 *   False negative: "dumps the entire database" (different phrasing)
 *   False positive: "returns detailed error messages" (diagnostic, not flooding)
 *
 * New behavior: Noisy-OR multi-signal linguistic scoring:
 *   1. Detect verbose output promises (detailed, comprehensive, extensive, complete)
 *   2. Detect unbounded output claims (all records, entire database, full dump)
 *   3. Detect missing pagination signals (no limit, unlimited, no pagination)
 *   4. Detect description length anomaly (flooding via description itself)
 *   5. Detect context-exhausting patterns (recursive, nested, full tree)
 *   6. Pagination/limit mitigation detection reduces confidence
 *   7. Noisy-OR: P(flood) = 1 - Π(1 - wᵢ) for each matched signal
 *
 * Frameworks:
 *   - OWASP MCP01: Prompt injection — flooding pushes safety context out of window
 *   - OWASP ASI08: Denial of service — context exhaustion is a DoS vector
 *   - CoSAI MCP-T10: Resource exhaustion via oversized responses
 *   - MAESTRO L4: Infrastructure layer — context window is a shared resource
 */

import type { AnalysisContext } from "../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../base.js";
import { EvidenceChainBuilder } from "../../evidence.js";

const RULE_ID = "M5";
const RULE_NAME = "Context Window Flooding";

/** Description length threshold (chars) — beyond this the description itself is a flooding vector */
const DESC_LENGTH_THRESHOLD = 2000;

/** Linguistic signals with independent threat probabilities */
const FLOODING_SIGNALS: Array<{ regex: RegExp; desc: string; weight: number }> = [
  // Verbose output promises
  { regex: /\b(?:detailed|verbose|comprehensive|extensive|exhaustive|complete)\s+(?:output|response|result|data|dump|listing|report)\b/i,
    desc: "verbose output promise", weight: 0.55 },

  // Unbounded data claims
  { regex: /\b(?:all\s+(?:records|entries|rows|items|data|files|results)|entire\s+(?:database|table|collection|directory|tree)|full\s+(?:dump|export|listing|contents|output))\b/i,
    desc: "unbounded data return", weight: 0.70 },

  // Explicit no-limit claims
  { regex: /\b(?:no\s+(?:limit|pagination|cap|bound|maximum|truncat)|unlimited|unbounded|without\s+(?:limit|pagination|truncat))\b/i,
    desc: "explicit no-limit claim", weight: 0.75 },

  // Recursive/nested expansion
  { regex: /\b(?:recursive(?:ly)?|nested|deep\s+(?:scan|search|traversal)|full\s+(?:tree|graph|hierarchy))\s+/i,
    desc: "recursive expansion risk", weight: 0.50 },

  // Raw/unfiltered output
  { regex: /\b(?:raw|unfiltered|unprocessed|unsummarized)\s+(?:output|response|data|content|result)\b/i,
    desc: "unfiltered output", weight: 0.55 },

  // "everything" / "all at once" claims
  { regex: /\b(?:returns?\s+everything|dumps?\s+everything|all\s+at\s+once|complete\s+(?:contents?|snapshot))\b/i,
    desc: "total data return claim", weight: 0.65 },
];

/** Pagination/limit mitigation patterns — presence reduces confidence */
const PAGINATION_MITIGATIONS = [
  /\b(?:pagina|page_size|per_page|offset|cursor|max_results|top_n|batch_size)\b/i,
  /\b(?:truncat|summariz|condensed?|brief|concise)\b/i,
  // "limit" as mitigation only when NOT preceded by "no" or "without"
  /(?<!\bno\s)(?<!\bwithout\s)\blimit\b/i,
];

class ContextWindowFloodingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.tools || context.tools.length === 0) return [];
    const findings: RuleResult[] = [];

    for (const tool of context.tools) {
      const desc = tool.description || "";

      const matchedSignals: string[] = [];
      const matchedWeights: number[] = [];

      // Check linguistic signals
      for (const { regex, desc: signalDesc, weight } of FLOODING_SIGNALS) {
        if (regex.test(desc)) {
          matchedSignals.push(signalDesc);
          matchedWeights.push(weight);
        }
      }

      // Check description length anomaly (the description itself can flood)
      if (desc.length > DESC_LENGTH_THRESHOLD) {
        matchedSignals.push(`description length anomaly (${desc.length} chars)`);
        matchedWeights.push(0.45);
      }

      // Check schema for unbounded output parameters
      if (tool.input_schema) {
        const schemaStr = JSON.stringify(tool.input_schema);
        if (/\b(?:include_all|no_limit|unlimited|dump_all|full_output)\b/i.test(schemaStr)) {
          matchedSignals.push("schema contains unbounded output parameter");
          matchedWeights.push(0.60);
        }
      }

      if (matchedSignals.length === 0) continue;

      // Noisy-OR: P(flood) = 1 - Π(1 - wᵢ)
      let confidence = 1 - matchedWeights.reduce((prod, w) => prod * (1 - w), 1);

      // Pagination/limit mitigation reduces confidence
      const hasPagination = PAGINATION_MITIGATIONS.some(p => p.test(desc)) ||
        !!(tool.input_schema && /\b(?:limit|page|offset|cursor|max)\b/i.test(JSON.stringify(tool.input_schema)));

      if (hasPagination) {
        confidence *= 0.4; // Significant reduction — pagination present
        matchedSignals.push("(mitigated: pagination/limit detected)");
      }

      confidence = Math.min(0.98, confidence);

      if (confidence >= 0.40) {
        const severity = confidence >= 0.70 ? "high" as const
          : confidence >= 0.50 ? "medium" as const
          : "low" as const;

        findings.push(this.buildFinding(tool.name, desc, matchedSignals, confidence, severity, hasPagination));
      }
    }

    return findings;
  }

  private buildFinding(
    toolName: string, desc: string,
    signals: string[], confidence: number,
    severity: "high" | "medium" | "low",
    hasPagination: boolean,
  ): RuleResult {
    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "external-content",
      location: `tool "${toolName}"`,
      observed: desc.slice(0, 200),
      rationale:
        `Tool "${toolName}" description contains ${signals.length} context flooding signal(s): ` +
        signals.join(", ") + ". " +
        "Tools promising unbounded output can exhaust the AI client's context window, " +
        "pushing safety instructions and prior context out of the attention window.",
    });

    builder.impact({
      impact_type: "denial-of-service",
      scope: "ai-client",
      exploitability: signals.length >= 2 ? "moderate" : "complex",
      scenario:
        `Tool response floods the AI client's context window with data. ` +
        `Safety instructions, user context, and prior tool results are pushed out ` +
        `of the effective attention window. This enables: (1) safety bypass — model ` +
        `loses access to its safety context, (2) injection amplification — attacker ` +
        `payload in the flood data gets disproportionate attention weight, ` +
        `(3) denial of service — context exhaustion prevents further useful interaction.`,
    });

    if (hasPagination) {
      builder.mitigation({
        mitigation_type: "input-validation",
        present: true,
        location: `tool "${toolName}" schema/description`,
        detail: "Pagination or limit parameters detected — flooding partially mitigated",
      });
    }

    builder.factor(
      "linguistic_scoring", confidence - 0.20,
      `Noisy-OR of ${signals.length} signal(s): [${signals.join("; ")}]`,
    );

    builder.reference({
      id: "CoSAI-MCP-T10",
      title: "CoSAI MCP Security — T10: Resource Exhaustion",
      relevance: "Context window is a finite resource. Unbounded tool output exhausts it.",
    });

    builder.verification({
      step_type: "inspect-source",
      instruction: `Review tool "${toolName}" for unbounded output. Check if pagination/limits are available and enforced.`,
      target: `tool:${toolName}`,
      expected_observation: `Flooding signals: ${signals.join(", ")}`,
    });

    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: "MCP01-prompt-injection",
      mitre_technique: null,
      remediation:
        "Tool responses should be concise by default. Offer pagination for large data sets. " +
        "Add limit/max_results parameters. Truncate responses exceeding reasonable thresholds. " +
        "Never return unbounded data sets.",
      chain: builder.build(),
    };
  }
}

registerTypedRuleV2(new ContextWindowFloodingRule());
