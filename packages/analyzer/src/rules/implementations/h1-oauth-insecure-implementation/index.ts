/**
 * H1 — MCP OAuth 2.0 Insecure Implementation (v2)
 *
 * Orchestrator. Consumes the AST-driven OAuth-violation hits produced
 * by `gather.ts` and emits v2 RuleResult[] with evidence chains.
 *
 * Per charter: pattern-by-pattern honest confidence. Each OAuth
 * violation carries its own confidence target. The charter's global
 * cap (0.88) is applied AFTER the per-pattern assignment — so the
 * implicit-flow-literal (0.95 target) lands at 0.88 and the
 * state-validation-absence (0.72 target) lands at 0.72.
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
import { gatherH1, type H1Hit } from "./gather.js";
import {
  stepInspectPattern,
  stepInspectTaintedSource,
  stepReviewRfcBcp,
} from "./verification.js";

const RULE_ID = "H1";
const RULE_NAME = "MCP OAuth 2.0 Insecure Implementation";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0056" as const;
const CONFIDENCE_CAP = 0.88;

const REMEDIATION =
  "Bring the OAuth implementation into compliance with RFC 9700 (OAuth 2.1 BCP). " +
  "Specifically: use the authorisation-code flow with PKCE on every public " +
  "client; reject response_type=token and grant_type=password outright; validate " +
  "redirect_uri against a registered list using exact string matching; require " +
  "and validate the state parameter on every callback; clamp the scope parameter " +
  "against the client's registered capability; never store OAuth tokens in " +
  "localStorage or sessionStorage — use an HttpOnly, Secure cookie set via the " +
  "backend or (for native clients) the platform secure-enclave API.";

const REF_RFC_9700 = {
  id: "RFC-9700-OAuth-2.1-BCP",
  title: "RFC 9700 — OAuth 2.1 Security Best Current Practice",
  url: "https://datatracker.ietf.org/doc/rfc9700/",
  relevance:
    "RFC 9700 is the canonical normative reference for OAuth 2.1 security. " +
    "Every pattern H1 detects maps to a specific clause of the BCP that bans " +
    "or requires the observed behaviour.",
} as const;

class OAuthInsecureImplementationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherH1(context);
    if (gathered.mode === "absent") return [];
    return gathered.hits.map((hit) => this.buildFinding(hit));
  }

  private buildFinding(hit: H1Hit): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: hit.sourceLocation ? "user-parameter" : "file-content",
        location: hit.sourceLocation ?? hit.location,
        observed: hit.sourceObserved ?? hit.observed,
        rationale: hit.entry.rationale,
      })
      .propagation({
        propagation_type: hit.sourceLocation ? "direct-pass" : "variable-assignment",
        location: hit.location,
        observed: hit.observed,
      })
      .sink({
        sink_type: "credential-exposure",
        location: hit.location,
        observed: `${hit.entry.pattern_name} — ${hit.entry.rfc_citation} violation.`,
      })
      .impact({
        impact_type: hit.pattern === "ropc-grant-literal"
          ? "credential-theft"
          : hit.pattern === "localstorage-token-write"
            ? "session-hijack"
            : "privilege-escalation",
        scope: "user-data",
        exploitability: exploitabilityFor(hit.pattern),
        scenario: hit.entry.impact_scenario,
      })
      .factor(
        "oauth_pattern_class",
        targetAdjustment(hit.entry.confidence),
        `Pattern classified as ${hit.pattern}. ${hit.entry.rationale}`,
      );

    if (hit.pattern === "state-validation-absence") {
      builder.factor(
        "absence_proof_structural",
        -0.05,
        "State-validation absence is inferred from the handler scope — the " +
          "handler reads the OAuth authorisation code but contains no " +
          "equality comparison against a stored state value. The absence " +
          "proof is structural, not taint-based, so confidence is " +
          "deliberately lower than the other patterns.",
      );
    }

    builder.reference(REF_RFC_9700);
    builder.verification(stepInspectPattern(hit));
    const taintStep = stepInspectTaintedSource(hit);
    if (taintStep) builder.verification(taintStep);
    builder.verification(stepReviewRfcBcp(hit));

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

function exploitabilityFor(pattern: H1Hit["pattern"]): "trivial" | "moderate" | "complex" {
  switch (pattern) {
    case "implicit-flow-literal":
    case "ropc-grant-literal":
      return "trivial";
    case "localstorage-token-write":
    case "redirect-uri-from-request":
    case "scope-from-request":
      return "moderate";
    case "state-validation-absence":
      return "moderate";
  }
}

/**
 * Translate the charter's per-pattern confidence target into a factor
 * adjustment relative to the base confidence of a full source→propagation
 * →sink chain (which the builder computes at 0.70).
 */
function targetAdjustment(target: number): number {
  // The builder's base for a full chain is 0.70. The per-pattern target
  // is the eventual confidence; factor adjustment is target - base.
  return Number((target - 0.7).toFixed(2));
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `H1 charter caps confidence at ${cap}. Static OAuth pattern detection ` +
      `cannot observe runtime feature flags or middleware that may neutralise ` +
      `the pattern in production. The remaining headroom is preserved for ` +
      `that reachability uncertainty.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new OAuthInsecureImplementationRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { OAuthInsecureImplementationRule };
