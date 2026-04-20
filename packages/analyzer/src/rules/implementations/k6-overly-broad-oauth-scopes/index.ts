/**
 * K6 — Overly Broad OAuth Scopes (v2)
 *
 * Orchestrator. `gather.ts` + `gather-ast.ts` produce structured scope
 * assignments; this file turns them into RuleResult[] with v2-compliant
 * EvidenceChains.
 *
 * Guarantees:
 *   - every link carries a structured Location;
 *   - every VerificationStep.target is a Location;
 *   - threat_reference prefers ISO 27001 A.5.15 (least-privilege control)
 *     with OWASP ASI03 and CoSAI MCP-T2 surfaced in the charter.
 *   - confidence capped at 0.92 per charter (static analysis cannot prove
 *     server-side scope narrowing).
 *
 * Zero regex. No string-literal arrays > 5.
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
import { gatherK6, type ScopeAssignment } from "./gather.js";
import type { ScopeSeverity } from "./data/broad-scopes.js";
import {
  stepInspectAssignment,
  stepInspectBroadScopes,
  stepInspectUserInputChain,
  stepCheckScopeNarrowing,
} from "./verification.js";

const RULE_ID = "K6";
const RULE_NAME = "Overly Broad OAuth Scopes";
const OWASP = "MCP06-excessive-permissions" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.92;

const REMEDIATION =
  "Request the minimum OAuth scopes the server needs. Replace wildcard " +
  "grants (\"*\", \"read:all\", \"write:all\") with specific, task-scoped " +
  "permissions (\"read:user profile\", \"repo:status\"). Never derive the " +
  "requested scope from user input — if you must accept a client-supplied " +
  "scope, intersect it with a server-side allowlist. ISO 27001 A.5.15 and " +
  "A.5.18 require least privilege; OWASP ASI03 and CoSAI MCP-T2 name this " +
  "as an identity-abuse precondition. Prefer short-lived, JIT credentials.";

const REF_ISO_A515 = {
  id: "ISO-27001-A.5.15",
  title: "ISO/IEC 27001:2022 Annex A Control 5.15 — Access Control",
  url: "https://www.iso.org/standard/82875.html",
  relevance:
    "A.5.15 requires access control based on the principle of least " +
    "privilege. An OAuth scope declaration that grants wildcard / admin / " +
    "broad access violates the control at the request stage — before any " +
    "runtime authorization check can help.",
} as const;

const REF_OWASP_ASI03 = {
  id: "OWASP-ASI03",
  title: "OWASP Agentic Security Initiative — ASI03 Identity & Privilege Abuse",
  url: "https://owasp.org/www-project-agentic-security-initiative/",
  relevance:
    "ASI03 specifies that agentic MCP servers should request the minimum " +
    "scope needed. User-controlled or wildcard scopes are called out as " +
    "the prime enabler of lateral privilege escalation when tokens are " +
    "phished or leaked.",
} as const;

class BroadOAuthScopesRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK6(context);
    const findings: RuleResult[] = [];
    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      for (const assignment of file.assignments) {
        findings.push(this.buildFinding(assignment));
      }
    }
    return findings;
  }

  private buildFinding(assignment: ScopeAssignment): RuleResult {
    const worst = effectiveSeverity(assignment);
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: assignment.userControlled ? "user-parameter" : "file-content",
        location: assignment.location,
        observed: assignment.lineText,
        rationale:
          assignment.userControlled
            ? `OAuth scope property "${assignment.propertyName}" is assigned from ` +
              `a user-controlled expression (input chain: ` +
              `${assignment.userInputChain.join(" → ") || "(root-level)"}). ` +
              `A client-controlled scope subverts the least-privilege control at ` +
              `the REQUEST stage: the server cannot promise to grant less than ` +
              `the client can ask for.`
            : `OAuth scope property "${assignment.propertyName}" is statically ` +
              `assigned an overly broad value (${listScopes(assignment)}). The ` +
              `grant exceeds the minimum the server needs for its declared ` +
              `functionality.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: assignment.valueLocation,
        observed:
          assignment.valueShape === "array"
            ? `Scope array contains ${assignment.broadScopes.length} broad entry(s): ` +
              `${listScopes(assignment)}.`
            : assignment.valueShape === "identifier" || assignment.valueShape === "property-access"
            ? `Scope is derived from a reference (${assignment.valueText}) — ` +
              `the runtime value is not statically pinned.`
            : `Scope literal flows unchanged to the OAuth token request: ` +
              `${assignment.valueText}.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: assignment.location,
        observed:
          `${assignment.propertyName} = ${assignment.valueText} — grants ` +
          `${worst}-class access once the token is issued.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: assignment.valueLocation,
        detail:
          assignment.userControlled
            ? `No allowlist intersect observed between the user-controlled scope ` +
              `and a server-defined permitted-scopes set.`
            : `No structural narrowing of the scope value observed (no role-based ` +
              `switch, no intersect with an allowlist).`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "connected-services",
        exploitability: assignment.userControlled || worst === "wildcard" ? "trivial" : "moderate",
        scenario:
          `An OAuth token issued with "${assignment.valueText}" grants ` +
          (worst === "wildcard"
            ? `every permission the identity provider exposes. `
            : worst === "admin"
            ? `full administrative authority — user management, data deletion, ` +
              `configuration changes. `
            : `broad cross-resource access — read/write across all objects in a ` +
              `namespace rather than specific items. `) +
          `If the token leaks (phished, captured in logs, stolen via XSS), the ` +
          `attacker inherits exactly these permissions. When the scope is ` +
          (assignment.userControlled
            ? `derived from user input, the MCP server delegates the scope ` +
              `decision to a potentially malicious caller — which is the exact ` +
              `substrate of OAuth 2.1's "do not trust client-supplied scopes" rule.`
            : `hard-coded, the server is asking for a grant it does not ` +
              `functionally need — ISO 27001 A.5.15 least-privilege violation.`),
      });

    // Confidence factors.
    builder.factor(
      `broad_scope_${worst}`,
      worst === "wildcard" ? 0.15 : worst === "admin" ? 0.10 : 0.07,
      `Detected ${worst}-severity scope tokens: ${listScopes(assignment)}.`,
    );
    if (assignment.userControlled) {
      builder.factor(
        "user_controlled_scope",
        0.12,
        `Scope value flows from an HTTP/MCP input surface (${assignment.userInputChain.join(
          " → ",
        )}) — attacker can request arbitrary scopes unless server enforces an allowlist.`,
      );
    }
    if (assignment.matchedViaOAuthContext) {
      builder.factor(
        "oauth_context_confirmed",
        0.04,
        `Assignment property "${assignment.propertyName}" is ambiguous on its own; ` +
          `OAuth context confirmed by sibling keys (client_id, token_endpoint, etc.) ` +
          `in the same object literal.`,
      );
    }
    if (assignment.valueShape === "array" && assignment.broadScopes.length > 1) {
      builder.factor(
        "multiple_broad_entries",
        0.03,
        `Scope array contains ${assignment.broadScopes.length} broad entries — ` +
          `systematic over-provisioning, not a single oversight.`,
      );
    }

    builder.reference(assignment.userControlled ? REF_OWASP_ASI03 : REF_ISO_A515);
    builder.verification(stepInspectAssignment(assignment));
    builder.verification(stepInspectBroadScopes(assignment));
    if (assignment.userControlled) {
      builder.verification(stepInspectUserInputChain(assignment));
    }
    builder.verification(stepCheckScopeNarrowing(assignment));

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

// ─── Helpers ───────────────────────────────────────────────────────────────

function effectiveSeverity(assignment: ScopeAssignment): ScopeSeverity {
  if (assignment.worstSeverity) return assignment.worstSeverity;
  // No tokens extracted but user-controlled — assume admin-grade (conservative).
  return "admin";
}

function listScopes(assignment: ScopeAssignment): string {
  if (assignment.broadScopes.length === 0) {
    return `(value is user-controlled — token set unknown to static analyzer)`;
  }
  return assignment.broadScopes
    .map((s) => `"${s.scope}" (${s.severity})`)
    .join(", ");
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K6 charter caps confidence at ${cap} — server-side scope narrowing ` +
      `(intersect with allowlist, role-based mapping) may occur outside the ` +
      `scanned file. A maximum-confidence claim would overstate what the ` +
      `analyzer can prove.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new BroadOAuthScopesRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { BroadOAuthScopesRule };
