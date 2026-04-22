/**
 * A5 — Description Length Anomaly (Rule Standard v2).
 *
 * Structural check: flag tool descriptions exceeding a calibrated
 * length threshold. Low severity by design; the signal is a
 * surface-level anomaly, not a proof.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gatherA5, toolLocation, type LengthSite } from "./gather.js";
import {
  stepInspectFullDescription,
  stepCheckForBrevityAlternative,
} from "./verification.js";
import { LENGTH_THRESHOLDS } from "./data/thresholds.js";

const RULE_ID = "A5";
const RULE_NAME = "Description Length Anomaly";
const OWASP = "MCP01-prompt-injection";
const MITRE = "AML.T0054";

const REMEDIATION =
  "Shorten tool descriptions to under 500 characters. Move detailed behavioural " +
  "documentation to external references (README, docs site). Long descriptions " +
  "are a known obfuscation vehicle for prompt-injection payloads; shorter " +
  "descriptions are easier for human reviewers to validate.";

class A5DescriptionLengthAnomalyRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    return gatherA5(context).map((s) => this.buildFinding(s));
  }

  private buildFinding(site: LengthSite): RuleResult {
    const loc = toolLocation(site.tool_name);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: loc,
        observed: `Description length: ${site.length} chars (threshold ${LENGTH_THRESHOLDS.minimum_length}).`,
        rationale:
          `Tool "${site.tool_name}" has a ${site.length}-character description — ` +
          `roughly ${(site.length / LENGTH_THRESHOLDS.minimum_length).toFixed(1)}× the ` +
          `${LENGTH_THRESHOLDS.minimum_length}-char threshold. Excessively long ` +
          `descriptions are a known obfuscation vehicle for prompt-injection payloads ` +
          `buried in otherwise benign-looking prose.`,
      })
      .propagation({
        propagation_type: "description-directive",
        location: loc,
        observed:
          `All ${site.length} characters of description are passed to the LLM ` +
          `verbatim. Recency bias in attention places the tail at maximum ` +
          `effective impact.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: loc,
        observed:
          `The LLM ingests the full description as tool-catalog context on every ` +
          `turn in which the tool could be called.`,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `An injection payload buried in the tail of a ${site.length}-character ` +
          `description is unlikely to be caught in human PR review but is processed ` +
          `by the model with full attention on every turn.`,
      })
      .factor(
        "description_length",
        site.raw_confidence - 0.3,
        `Description length ${site.length} chars exceeds threshold by ${site.length - LENGTH_THRESHOLDS.minimum_length} chars.`,
      );

    builder.reference({
      id: "OWASP-MCP01",
      title: "OWASP MCP Top 10 — MCP01 Prompt Injection",
      url: "https://owasp.org/www-project-mcp-top-10/",
      relevance:
        "Length is a weak but reliable component of multi-signal prompt-injection " +
        "detection per OWASP MCP01 guidance.",
    });

    builder.verification(stepInspectFullDescription(site));
    builder.verification(stepCheckForBrevityAlternative(site));

    const chain = builder.build();
    // Explicit cap per charter.
    if (chain.confidence > LENGTH_THRESHOLDS.confidence_cap) {
      chain.confidence_factors.push({
        factor: "length_only_cap",
        adjustment: LENGTH_THRESHOLDS.confidence_cap - chain.confidence,
        rationale: `A5 charter caps confidence at ${LENGTH_THRESHOLDS.confidence_cap} ` +
          `— length alone is a weak signal.`,
      });
      chain.confidence = LENGTH_THRESHOLDS.confidence_cap;
    }

    return {
      rule_id: RULE_ID,
      severity: "low",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new A5DescriptionLengthAnomalyRule());

export { A5DescriptionLengthAnomalyRule };
