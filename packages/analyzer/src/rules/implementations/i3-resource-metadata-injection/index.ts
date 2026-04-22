/**
 * I3 — Resource Metadata Injection (Rule Standard v2).
 *
 * Scans every declared MCP resource's name + description + URI for
 * injection-phrase token sequences from the shared INJECTION_PHRASES
 * catalogue. Fires per resource whose aggregated noisy-OR weight
 * exceeds the charter threshold.
 *
 * No regex literals. No string arrays > 5.
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
import { gatherI3, type I3Fact } from "./gather.js";
import { I3_CONFIDENCE_CAP } from "./data/config.js";
import {
  stepInspectResourceMetadata,
  stepCompareAgainstToolA1,
} from "./verification.js";

const RULE_ID = "I3";
const RULE_NAME = "Resource Metadata Injection";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0054.001";

const REMEDIATION =
  "Sanitise resource metadata BEFORE emitting it to the MCP client. " +
  "(a) Reject role-override phrases (\"ignore previous instructions\", " +
  "\"disregard prior\") in resource names and descriptions. (b) Refuse " +
  "LLM delimiter tokens (<|im_start|>, <|system|>, <|endoftext|>) in any " +
  "metadata field — these are implementation artefacts, not user content. " +
  "(c) Treat URI path fragments as attacker-controllable when the URI is " +
  "constructed from a tool argument. Cross-reference A1 and A7 for the " +
  "tool-description counterpart, and I4 for dangerous URI schemes.";

class ResourceMetadataInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { resources: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherI3(context);
    if (gathered.facts.length === 0) return [];

    const results: RuleResult[] = [];
    for (const fact of gathered.facts) {
      results.push(this.buildFinding(fact));
    }
    return results;
  }

  private buildFinding(fact: I3Fact): RuleResult {
    const resourceLoc: Location = {
      kind: "resource",
      uri: fact.resource_uri,
      field: "description",
    };

    const hitDescriptor = fact.hits
      .map((h) => `${h.spec.kind}@${h.matched_field}(${h.key})`)
      .join(", ");

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: resourceLoc,
        observed: fact.combined_text_preview,
        rationale:
          "MCP resources are enumerated by clients on connect. Injection " +
          "phrases in the name, description, or URI fields run as behavioural " +
          "directives every time the client refreshes its resource list — " +
          "before any tool is invoked and before any user prompt is entered. " +
          "The client has no spec-mandated sanitiser at this surface.",
      })
      .sink({
        sink_type: "code-evaluation",
        location: resourceLoc,
        observed:
          `Injection catalogue hits: ${hitDescriptor}. Aggregate weight: ` +
          `${fact.aggregate_weight.toFixed(2)}.`,
      })
      .impact({
        impact_type: "session-hijack",
        scope: "ai-client",
        exploitability: "trivial",
        scenario:
          `Resource "${fact.resource_name}" carries injection phrasing in the ` +
          `${fact.hits[0]?.matched_field ?? "combined"} field. When the ` +
          `client enumerates resources, the AI reads the metadata as trusted ` +
          `context. The injected directive overrides system instructions for ` +
          `the current session — without the user ever opening the resource.`,
      })
      .factor(
        "injection_phrase_matched",
        0.1,
        `Matched ${fact.hits.length} injection-phrase catalogue entries across ` +
          `resource metadata fields. Noisy-OR aggregate ` +
          `${fact.aggregate_weight.toFixed(2)}.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0054.001",
        title: "MITRE ATLAS AML.T0054.001 — Indirect Prompt Injection",
        url: "https://atlas.mitre.org/techniques/AML.T0054.001",
        relevance:
          "I3 detects the structural precondition: attacker-controlled " +
          "content in the resource metadata surface, processed as trusted " +
          "context by the MCP client.",
      })
      .verification(stepInspectResourceMetadata(fact))
      .verification(stepCompareAgainstToolA1(fact));

    const chain = capConfidence(builder.build(), I3_CONFIDENCE_CAP);
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

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale: `I3 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ResourceMetadataInjectionRule());

export { ResourceMetadataInjectionRule };
