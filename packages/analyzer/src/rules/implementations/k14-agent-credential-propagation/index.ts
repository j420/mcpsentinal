/**
 * K14 — Agent Credential Propagation via Shared State (v2).
 *
 * Emits one finding per credential identifier flowing into a cross-agent
 * shared-state writer call without an observed redactor in the enclosing
 * scope. Five-link evidence chain (source → propagation → sink →
 * mitigation → impact). Confidence cap 0.88.
 *
 * Edge-case strategies (named in CHARTER.md frontmatter):
 *   - encoder-passthrough-taint
 *   - alias-binding-resolution
 *   - cross-function-helper-walk
 *   - placeholder-literal-suppression
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
import { gatherK14, type CredentialPropagationSite } from "./gather.js";
import {
  stepInspectCredentialSource,
  stepInspectSharedStateSink,
  stepCheckRedactor,
} from "./verification.js";

const RULE_ID = "K14";
const RULE_NAME = "Agent Credential Propagation via Shared State";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0086" as const;
const CONFIDENCE_CAP = 0.88;

// Edge-case strategy labels — kept as constants so the charter
// traceability guard can find them in the implementation source.
const STRATEGY_ENCODER_PASSTHROUGH = "encoder-passthrough-taint";
const STRATEGY_ALIAS_BINDING = "alias-binding-resolution";
const STRATEGY_CROSS_FUNCTION_HELPER = "cross-function-helper-walk";
const STRATEGY_PLACEHOLDER_SUPPRESSION = "placeholder-literal-suppression";

const REMEDIATION =
  "Never write a raw credential to cross-agent shared state (vector " +
  "stores, scratchpads, working-memory tables, agent-to-agent buses). " +
  "Use a per-agent credential vault (HashiCorp Vault, AWS Secrets " +
  "Manager) and resolve credentials at the call site of each agent " +
  "rather than passing them through state. For cross-agent authorisation " +
  "use OAuth 2.0 token exchange (RFC 8693) so each agent receives a " +
  "scoped, audience-bound token. If state must reference the credential, " +
  "store an opaque reference id and resolve via the vault on read. " +
  "Required by OWASP ASI03 / ASI07 and MAESTRO L7.";

const REF_INVARIANT = {
  id: "InvariantLabs-CrossAgentMCPMemory-2026",
  title:
    "Invariant Labs — Cross-agent pollution via shared MCP memory (Jan 2026)",
  url: "https://invariantlabs.ai/blog/cross-agent-mcp-memory-pollution",
  relevance:
    "Documents the exact pattern this rule detects: a worker agent writing " +
    "an OAuth bearer token into a LangGraph shared scratchpad, after which " +
    "a downstream agent replays the token against an unrelated tool.",
} as const;

class AgentCredentialPropagationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  /** Strategy labels exposed for documentation / introspection. */
  readonly edgeCaseStrategies = [
    STRATEGY_ENCODER_PASSTHROUGH,
    STRATEGY_ALIAS_BINDING,
    STRATEGY_CROSS_FUNCTION_HELPER,
    STRATEGY_PLACEHOLDER_SUPPRESSION,
  ] as const;

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK14(context);
    const findings: RuleResult[] = [];
    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      for (const site of file.sites) {
        // placeholder-literal-suppression
        if (site.rhsIsPlaceholder) continue;
        // mitigation present in scope: emit nothing — redactor neutralises
        if (site.enclosingHasRedactor) continue;
        findings.push(this.buildFinding(site));
      }
    }
    return findings.slice(0, 10);
  }

  private buildFinding(site: CredentialPropagationSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: site.credentialSourceLocation,
        observed: `Credential binding: ${site.credentialName}`,
        rationale:
          `Identifier \`${site.credentialName}\` carries bearer authority. ` +
          `Any holder of the value can authenticate as the originating ` +
          `principal until the credential is rotated.`,
      })
      .propagation({
        propagation_type:
          site.kind === "cross-function-helper-write"
            ? "function-call"
            : site.kind === "encoder-wrapped-credential-write"
              ? "string-concatenation"
              : "cross-tool-flow",
        location: site.location,
        observed:
          `Credential flows from binding into ` +
          `\`${site.receiverName}.${site.writerMethod}(...)\` ` +
          `(strategy: ${strategyLabelFor(site)}).`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: site.location,
        observed:
          `Cross-agent shared-state write: ` +
          `${site.receiverName}.${site.writerMethod}(${site.credentialName})`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: false,
        location: site.enclosingFunctionLocation ?? site.location,
        detail:
          `No redactor call (redact / mask / scrub / vault.seal / ` +
          `kms.encrypt / cipher.encrypt) found in the enclosing function ` +
          `scope before the shared-state write.`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "other-agents",
        exploitability: "moderate",
        scenario:
          `A downstream agent reads ` +
          `${site.receiverName} and obtains \`${site.credentialName}\` ` +
          `without an explicit grant. The downstream agent now ` +
          `authenticates as the originating user against any service ` +
          `the credential authorises — typical agentic deployments give ` +
          `that scope a wide blast radius.`,
      })
      .factor(
        "credential_identifier_observed",
        0.12,
        `Identifier \`${site.credentialName}\` matches the K14 credential vocabulary.`,
      )
      .factor(
        "shared_state_sink_observed",
        0.10,
        `Receiver \`${site.receiverName}\` matches the cross-agent ` +
          `shared-state vocabulary; method \`${site.writerMethod}\` is a writer.`,
      )
      .factor(
        "no_redaction_in_scope",
        0.06,
        `No redactor call observed in the enclosing function body.`,
      );

    if (site.kind === "encoder-wrapped-credential-write") {
      builder.factor(
        STRATEGY_ENCODER_PASSTHROUGH,
        0.04,
        `Credential wrapped by an encoder pass-through (base64 / Buffer / ` +
          `JWT.sign / encodeURIComponent) — the encoded value still authorises.`,
      );
    } else if (site.kind === "alias-credential-write") {
      builder.factor(
        STRATEGY_ALIAS_BINDING,
        0.03,
        `Receiver resolved through an alias binding to \`${site.receiverName}\`.`,
      );
    } else if (site.kind === "cross-function-helper-write") {
      builder.factor(
        STRATEGY_CROSS_FUNCTION_HELPER,
        0.04,
        `Credential passed to a helper function whose body writes to shared state.`,
      );
    }

    builder.reference(REF_INVARIANT);
    builder.verification(stepInspectCredentialSource(site));
    builder.verification(stepInspectSharedStateSink(site));
    builder.verification(stepCheckRedactor(site));

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

function strategyLabelFor(site: CredentialPropagationSite): string {
  switch (site.kind) {
    case "encoder-wrapped-credential-write":
      return STRATEGY_ENCODER_PASSTHROUGH;
    case "alias-credential-write":
      return STRATEGY_ALIAS_BINDING;
    case "cross-function-helper-write":
      return STRATEGY_CROSS_FUNCTION_HELPER;
    case "direct-credential-write":
      return "direct-write";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K14 charter caps confidence at ${cap}. Runtime credential ` +
      `redaction (logging formatter, store middleware, scrubbing proxy) ` +
      `is invisible to static analysis and could neutralise the sink ` +
      `at runtime — the rule cannot prove its absence.`,
  });
  chain.confidence = cap;
  return chain;
}

// Reference the placeholder-suppression strategy constant so the charter
// traceability guard can find it in the implementation file. The strategy
// itself runs inside `analyze()` (the `if (site.rhsIsPlaceholder) continue`
// branch) — this string export documents the link.
export const _K14_PLACEHOLDER_STRATEGY = STRATEGY_PLACEHOLDER_SUPPRESSION;

registerTypedRuleV2(new AgentCredentialPropagationRule());

export { AgentCredentialPropagationRule };
