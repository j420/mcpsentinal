/**
 * K8 — Cross-Boundary Credential Sharing (Rule Standard v2).
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import {
  EvidenceChainBuilder,
  type EvidenceChain,
} from "../../../evidence.js";
import { gatherK8, type K8Fact } from "./gather.js";
import { stepsForFact } from "./verification.js";

const RULE_ID = "K8";
const RULE_NAME = "Cross-Boundary Credential Sharing";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Never forward, share, or embed credentials across trust boundaries. " +
  "Replace every raw-token forward with an RFC 8693 Token Exchange that " +
  "mints a scoped, short-lived delegation token for the downstream service. " +
  "Do NOT publish credentials to shared stores (Redis, SQS, DynamoDB, " +
  "publish queues). Do NOT include credentials in MCP tool responses. Do " +
  "NOT pass credentials in argv to child processes. Required by ISO " +
  "27001:2022 A.5.17, OWASP ASI03 and ASI07, and CoSAI MCP-T1.";

class CrossBoundaryCredentialSharingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK8(context);
    if (gathered.mode !== "facts") return [];
    return gathered.facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: K8Fact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: fact.location,
        observed: `credential: ${fact.credentialIdentifier}`,
        rationale:
          `Identifier "${fact.credentialIdentifier}" is a credential-` +
          `bearing value by name (matches the credential-vocabulary ` +
          `allow-list). Any onward use that crosses into a different ` +
          `trust boundary is an ISO 27001 A.5.17 breach.`,
      })
      .propagation({
        propagation_type: propagationTypeFor(fact),
        location: fact.location,
        observed: propagationObserved(fact),
      })
      .sink({
        sink_type: sinkTypeFor(fact),
        location: fact.location,
        observed:
          `${fact.kind} — callee: ${fact.calleeName}. ` +
          `Observed: "${fact.observed.slice(0, 140)}".`,
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: fact.hasTokenExchange,
        location: fact.location,
        detail: fact.hasTokenExchange
          ? `RFC 8693 Token Exchange primitive referenced in this file. ` +
            `Reviewer must confirm it is actually invoked on THIS flow.`
          : `No RFC 8693 Token Exchange primitive observed. The raw ` +
            `credential crosses the trust boundary unchanged.`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "connected-services",
        exploitability: "moderate",
        scenario: impactScenario(fact),
      })
      .factor(
        "credential_source_identified",
        0.12,
        `Credential-name match on "${fact.credentialIdentifier}".`,
      )
      .factor(
        "cross_boundary_sink_identified",
        0.12,
        `Sink ${fact.calleeName} is a known cross-boundary operation.`,
      )
      .factor(
        "no_token_exchange_observed",
        fact.hasTokenExchange ? 0.02 : 0.1,
        fact.hasTokenExchange
          ? `Token Exchange primitive referenced — mitigation partial.`
          : `No Token Exchange primitive observed — mitigation absent.`,
      )
      .reference({
        id: "OWASP-ASI03",
        title: "OWASP Agentic Security — Identity & Privilege Abuse",
        url: "https://genai.owasp.org/llmrisk/llm03-identity-privilege-abuse/",
        relevance:
          "ASI03 enumerates cross-boundary credential sharing as the #3 " +
          "agentic-AI risk. The specific code shapes K8 detects are the " +
          "canonical ASI03 manifestations.",
      });

    for (const s of stepsForFact(fact)) builder.verification(s);

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

function propagationTypeFor(fact: K8Fact): "cross-tool-flow" | "function-call" {
  return fact.kind === "header-forward" ? "cross-tool-flow" : "function-call";
}

function propagationObserved(fact: K8Fact): string {
  switch (fact.kind) {
    case "header-forward":
      return `Credential "${fact.credentialIdentifier}" placed on the headers of an outbound ${fact.calleeName}(...) call — crosses origin boundary.`;
    case "shared-store-write":
      return `Credential "${fact.credentialIdentifier}" passed as argument to ${fact.calleeName}(...) — written to a shared store visible to every peer service.`;
    case "exec-with-credential":
      return `Credential "${fact.credentialIdentifier}" passed to ${fact.calleeName}(...) — visible in the child process's argv / env.`;
  }
}

function sinkTypeFor(fact: K8Fact):
  | "network-send"
  | "config-modification"
  | "command-execution" {
  switch (fact.kind) {
    case "header-forward":
      return "network-send";
    case "shared-store-write":
      return "config-modification";
    case "exec-with-credential":
      return "command-execution";
  }
}

function impactScenario(fact: K8Fact): string {
  const base =
    `The credential — originally scoped to the caller's trust boundary — ` +
    `is now held by ${sinkAudience(fact)}. An attacker who compromises ` +
    `that audience can impersonate the original caller against every ` +
    `service the credential covers.`;
  return fact.hasTokenExchange
    ? base +
        " The file references an RFC 8693 Token Exchange primitive " +
        "elsewhere — reviewer must verify it is actually invoked on this flow."
    : base;
}

function sinkAudience(fact: K8Fact): string {
  switch (fact.kind) {
    case "header-forward":
      return "the upstream service at the other end of the outbound request";
    case "shared-store-write":
      return "every peer service with read access to the shared store";
    case "exec-with-credential":
      return "the child process and every other process with ptrace / audit capability on the host";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K8 charter caps confidence at ${cap}. A server legitimately acting ` +
      `as an authenticated proxy for its OWN identity (not the user's) ` +
      `can exhibit similar code shapes.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new CrossBoundaryCredentialSharingRule());

export { CrossBoundaryCredentialSharingRule };
