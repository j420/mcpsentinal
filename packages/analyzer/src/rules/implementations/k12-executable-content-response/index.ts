/**
 * K12 — Executable Content in Tool Response (v2).
 *
 * Emits one finding per executable construct that flows through a tool
 * response boundary without an observed sanitizer call in the enclosing
 * scope. Zero regex; confidence cap 0.88.
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
import { gatherK12, type ExecSite } from "./gather.js";
import { stepInspectExec, stepCheckSanitizer } from "./verification.js";

const RULE_ID = "K12";
const RULE_NAME = "Executable Content in Tool Response";
const OWASP = "MCP03-command-injection" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.88;

const REMEDIATION =
  "Tool responses must not contain executable constructs that the AI client " +
  "will interpret. Remove dynamic code primitives (eval, new Function, " +
  "require, import()) from the response path. For HTML-like payloads, " +
  "sanitize with DOMPurify / he / validator before emission. For JSON, " +
  "ensure fields carrying user/third-party text are strings that the client " +
  "displays as text (textContent) rather than rendered HTML. CoSAI MCP-T4 " +
  "and OWASP ASI02 treat this as a direct tool-poisoning substrate.";

const REF_COSAI_T4 = {
  id: "CoSAI-MCP-T4",
  title: "CoSAI MCP Security — T4 Tool Response Integrity",
  url: "https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy",
  relevance:
    "T4 specifies that tool responses must not carry executable content. " +
    "Embedded eval / Function / script tag / javascript: URIs violate the " +
    "control by construction.",
} as const;

class K12ExecutableContentResponseRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK12(context);
    const findings: RuleResult[] = [];
    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      for (const site of file.sites) {
        if (site.enclosingHasSanitizer) continue;
        findings.push(this.buildFinding(site));
      }
    }
    return findings.slice(0, 10);
  }

  private buildFinding(site: ExecSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `Executable construct \`${site.kind}\` in a ${site.siteType}. The ` +
          `value flows to a client consumer that may interpret it as code: ` +
          `an AI client rendering Markdown/HTML, a browser-facing response, ` +
          `or a downstream tool that eagerly evaluates the payload.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: site.location,
        observed: `Executable construct appears directly in the response path.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: site.location,
        observed: `Response carries ${site.kind} to the AI client.`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: false,
        location: site.enclosingFunctionLocation ?? site.location,
        detail:
          `No sanitizer call (escapeHtml / sanitize / DOMPurify.sanitize / ` +
          `he.encode / validator.escape / xss.inHTML / textContent / ` +
          `createTextNode) found in the enclosing function scope.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `The AI client processes the response, renders it, and the ` +
          `embedded ${site.kind} executes in the client's context. Follow-` +
          `on access to user data, credentials, and other tool handlers ` +
          `depends on the client's permission scope, but in agentic systems ` +
          `this is typically broad.`,
      })
      .factor(
        `exec_${site.kind.replace(/-/g, "_")}`,
        site.kind === "eval-call" || site.kind === "new-function" ? 0.15 : 0.10,
        `Executable construct \`${site.kind}\` observed in the response path.`,
      )
      .factor(
        "no_sanitizer_in_scope",
        0.08,
        `No sanitizer observed in the enclosing function body.`,
      );

    builder.reference(REF_COSAI_T4);
    builder.verification(stepInspectExec(site));
    builder.verification(stepCheckSanitizer(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);
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
    rationale:
      `K12 charter caps confidence at ${cap} — a runtime sanitizer layered ` +
      `between this code and the response (Express middleware, reverse proxy) ` +
      `is not visible at file scope.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new K12ExecutableContentResponseRule());

export { K12ExecutableContentResponseRule };
