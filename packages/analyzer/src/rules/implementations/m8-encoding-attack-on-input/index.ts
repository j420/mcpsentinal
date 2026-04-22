/** M8 — Encoding Attack on Tool Input (v2). AST; zero regex; cap 0.80. */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherM8, type EncodingSite } from "./gather.js";
import {
  stepInspectDecode,
  stepCheckValidator,
  stepCheckSink,
} from "./verification.js";

const RULE_ID = "M8";
const OWASP = "MCP03-command-injection" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Validate tool inputs AFTER decoding. Apply allowlists / schemas / typed " +
  "parsers (zod, joi) to the decoded value before any sink. If the decode " +
  "is unnecessary, remove it — clients should never need to double-encode " +
  "payloads to reach the server.";

const REF_MITRE_T0054 = {
  id: "MITRE-AML-T0054",
  title: "MITRE ATLAS AML.T0054 — LLM Prompt Injection",
  url: "https://atlas.mitre.org/techniques/AML.T0054",
  relevance:
    "Encoding attacks bypass pre-decode input validation and WAF rules; " +
    "post-decode validation is the mandated mitigation.",
} as const;

class M8Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = "Encoding Attack on Tool Input";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherM8(context);
    return sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: EncodingSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: site.location,
        observed: site.observed,
        rationale:
          `Call to "${site.decode_name}" at this line decodes a user-controlled ` +
          `value. Encoded payloads often pass pre-decode validation (schema ` +
          `sees a safe base64 / URL-encoded string) but decode to injection ` +
          `payloads that reach a dangerous sink.`,
      })
      .propagation({
        propagation_type: "function-call",
        location: site.location,
        observed: `${site.decode_name}(user-input) — decoded value replaces the pre-validated surface`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: site.location,
        observed: `Decoded user input used without post-decode validation.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: site.enclosing_function_location ?? site.location,
        detail: `No validate / sanitize / check / verify / zod / joi call found ` +
                `in the lexical suffix of the enclosing function.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `Attacker encodes a malicious payload (command injection, path ` +
          `traversal, XSS) in base64/URL/hex encoding. Pre-decode validation ` +
          `passes. Post-decode, the raw payload reaches the dangerous sink ` +
          `unchecked.`,
      })
      .factor(
        "decode_without_validation",
        0.12,
        `${site.decode_name}() on user-derived value without post-decode validator`,
      );

    builder.reference(REF_MITRE_T0054);
    builder.verification(stepInspectDecode(site));
    builder.verification(stepCheckValidator(site));
    builder.verification(stepCheckSink(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity: "high",
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
    rationale: `M8 cap ${cap}: AST cannot prove the decoded value reaches an exploitable sink.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new M8Rule());
export { M8Rule };
