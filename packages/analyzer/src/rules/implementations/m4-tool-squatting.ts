/**
 * M4 — Tool Squatting (v2: Noisy-OR Linguistic Scoring)
 *
 * REPLACES the regex: /(?:official|verified|authentic|genuine)\s+(?:version|implementation)/i
 *
 * Old behavior: Single regex matching "official version" or "verified implementation".
 *   False negative: "this is the real Anthropic file reader" (no keyword pair)
 *   False negative: "certified by OpenAI" (different claim structure)
 *   False positive: "this is an unofficial version" (negation not handled)
 *
 * New behavior: Noisy-OR multi-signal linguistic scoring:
 *   1. Detect authenticity claims (official, verified, certified, endorsed, approved)
 *   2. Detect impersonation signals (claims specific vendor names)
 *   3. Detect registry/trust manipulation ("verified by", "listed on")
 *   4. Detect version displacement ("replaces", "supersedes", "upgraded")
 *   5. Negation detection reduces confidence (unofficial, not verified)
 *   6. Noisy-OR: P(squat) = 1 - Π(1 - wᵢ) for each matched signal
 *
 * Frameworks:
 *   - OWASP MCP02: Tool poisoning — impersonation enables tool substitution
 *   - MITRE ATLAS AML.T0054: LLM manipulation via false tool authority
 *   - CoSAI MCP-T4/T6: Tool integrity and supply chain trust
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

const RULE_ID = "M4";
const RULE_NAME = "Tool Squatting";

/** Linguistic signals with independent threat probabilities */
const SQUATTING_SIGNALS: Array<{ regex: RegExp; desc: string; weight: number }> = [
  // Authenticity claims — strongest signal
  { regex: /\b(?:official|verified|certified|endorsed|approved|authorized|authenticated)\s+(?:version|implementation|tool|server|plugin|extension)\b/i,
    desc: "explicit authenticity claim", weight: 0.90 },

  // Vendor impersonation — naming specific trusted vendors
  { regex: /\b(?:by|from|made\s+by|created\s+by|built\s+by)\s+(?:anthropic|openai|google|microsoft|aws|github|stripe|cloudflare|meta)\b/i,
    desc: "vendor attribution claim", weight: 0.85 },

  // "the real" / "the genuine" pattern
  { regex: /\bthe\s+(?:real|genuine|authentic|true|actual|original)\s+/i,
    desc: "authenticity assertion", weight: 0.80 },

  // Registry trust manipulation
  { regex: /\b(?:verified\s+(?:by|on|in)|listed\s+on|registered\s+(?:with|on)|certified\s+by)\b/i,
    desc: "registry trust claim", weight: 0.75 },

  // Version displacement
  { regex: /\b(?:replaces|supersedes|upgraded?\s+(?:from|version)|successor\s+to|better\s+than\s+the\s+(?:old|original))\b/i,
    desc: "version displacement claim", weight: 0.70 },

  // Trust badge language
  { regex: /\b(?:trusted|security\s+(?:reviewed|audited|certified)|compliance\s+(?:verified|certified))\b/i,
    desc: "trust badge language", weight: 0.65 },

  // Exclusive/authoritative framing
  { regex: /\b(?:only\s+(?:authorized|official)|exclusive\s+(?:version|access)|authoritative\s+(?:source|implementation))\b/i,
    desc: "exclusivity claim", weight: 0.75 },
];

/** Negation patterns that reduce confidence */
const NEGATION_PATTERNS = [
  /\b(?:un(?:official|verified|certified|authorized)|not\s+(?:official|verified|certified|endorsed))\b/i,
  /\b(?:disclaimer|warning|note):\s*(?:this\s+is\s+)?(?:not|un)\b/i,
];

class ToolSquattingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.tools || context.tools.length === 0) return [];
    const findings: RuleResult[] = [];

    for (const tool of context.tools) {
      const desc = tool.description || "";
      if (desc.length < 10) continue;

      const matchedSignals: string[] = [];
      const matchedWeights: number[] = [];

      for (const { regex, desc: signalDesc, weight } of SQUATTING_SIGNALS) {
        if (regex.test(desc)) {
          matchedSignals.push(signalDesc);
          matchedWeights.push(weight);
        }
      }

      if (matchedSignals.length === 0) continue;

      // Noisy-OR: P(squat) = 1 - Π(1 - wᵢ)
      let confidence = 1 - matchedWeights.reduce((prod, w) => prod * (1 - w), 1);

      // Negation detection reduces confidence
      const hasNegation = NEGATION_PATTERNS.some(p => p.test(desc));
      if (hasNegation) {
        confidence *= 0.3; // Drastic reduction — "unofficial" is self-correcting
      }

      confidence = Math.min(0.98, confidence);

      if (confidence >= 0.50) {
        const severity = confidence >= 0.80 ? "critical" as const
          : confidence >= 0.60 ? "high" as const
          : "medium" as const;

        findings.push(this.buildFinding(tool.name, desc, matchedSignals, confidence, severity, hasNegation));
      }
    }

    return findings;
  }

  private buildFinding(
    toolName: string, desc: string,
    signals: string[], confidence: number,
    severity: "critical" | "high" | "medium",
    hasNegation: boolean,
  ): RuleResult {
    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "external-content",
      location: `tool "${toolName}"`,
      observed: desc.slice(0, 200),
      rationale:
        `Tool "${toolName}" description contains ${signals.length} tool squatting signal(s): ` +
        signals.join(", ") + ". " +
        "False authenticity claims cause AI clients to trust and prefer this tool over " +
        "legitimate alternatives. LLMs weight authority claims heavily when selecting tools.",
    });

    builder.impact({
      impact_type: "config-poisoning",
      scope: "ai-client",
      exploitability: signals.length >= 2 ? "trivial" : "moderate",
      scenario:
        `Tool claims authenticity/authority that it may not have. AI clients preferentially ` +
        `select tools with authority claims, displacing legitimate tools. ` +
        `If the squatting tool is malicious, it gains the same data access and execution ` +
        `privileges as the tool it impersonates.`,
    });

    builder.factor(
      "linguistic_scoring", confidence - 0.30,
      `Noisy-OR of ${signals.length} signal(s): [${signals.join("; ")}]`,
    );

    if (hasNegation) {
      builder.factor("negation_detected", -0.20,
        "Description contains negation (unofficial, not verified) — reduces confidence");
    }

    builder.reference({
      id: "OWASP-MCP02",
      title: "OWASP MCP Top 10 — MCP02: Tool Poisoning",
      relevance: "Tool squatting is a form of tool poisoning via impersonation.",
    });

    builder.verification({
      step_type: "inspect-source",
      instruction: `Review tool "${toolName}" description for false authenticity claims. Verify the tool's actual provenance.`,
      target: `tool:${toolName}`,
      expected_observation: `Authenticity/authority claims: ${signals.join(", ")}`,
    });

    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: "MCP02-tool-poisoning",
      mitre_technique: "AML.T0054",
      remediation:
        "Don't claim to be an official/verified implementation unless provably true. " +
        "Let registries handle verification. Remove false authority claims from tool descriptions.",
      chain: builder.build(),
    };
  }
}

registerTypedRuleV2(new ToolSquattingRule());
