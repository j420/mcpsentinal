/**
 * K5 — Auto-Approve / Bypass Confirmation (Rule Standard v2).
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
import { gatherK5, type K5Fact } from "./gather.js";
import { stepsForFact } from "./verification.js";

const RULE_ID = "K5";
const RULE_NAME = "Auto-Approve / Bypass Confirmation Pattern";
const OWASP = "MCP06-excessive-permissions" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.9;

const REMEDIATION =
  "Remove every code path that bypasses human confirmation for operations " +
  "with side effects. Replace `auto_approve` / `--yolo` / `--no-confirm` " +
  "flags with an explicit approval step that cannot be disabled via an env " +
  "var or CLI flag. If a scheduled / CI mode genuinely needs to run without " +
  "interactive approval, require a short-lived, narrowly-scoped token " +
  "supplied via the MCP client's approved credential path — NOT a server-" +
  "side bypass — and log every invocation for audit. Required by EU AI Act " +
  "Art. 14, OWASP ASI09, and ISO 42001 A.9.2.";

class AutoApproveBypassRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK5(context);
    if (gathered.mode !== "facts") return [];
    return gathered.facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: K5Fact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.location,
        observed: fact.observed.slice(0, 200),
        rationale: sourceRationale(fact),
      })
      .sink({
        sink_type: "privilege-grant",
        location: fact.location,
        observed: sinkObserved(fact),
      })
      .mitigation({
        mitigation_type: "confirmation-gate",
        present: fact.hasApprovalPath,
        location: fact.location,
        detail: fact.hasApprovalPath
          ? `An honest-approval path coexists in the same file. The bypass ` +
            `is therefore a CONDITIONAL: when the flag / env-var / stub is ` +
            `reached, human oversight is removed.`
          : `No honest-approval path observed in ${fact.file}. The bypass ` +
            `is the only code path — EU AI Act Art. 14 oversight is ` +
            `structurally absent.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "ai-client",
        exploitability: fact.kind === "neutered-stub" ? "trivial" : "moderate",
        scenario:
          `A poisoned tool description or malicious argument executes a ` +
          `destructive operation (delete, overwrite, exec, send) without ` +
          `human review. Invariant Labs documents an 84.2% tool-poisoning ` +
          `success rate when auto-approve is enabled. This is the specific ` +
          `failure mode EU AI Act Art. 14 exists to prevent.`,
      })
      .factor(
        "auto_approve_signal",
        0.15,
        `Auto-approve signal observed: "${fact.tokenHit}".`,
      )
      .factor(
        "oversight_bypass_scope",
        fact.kind === "neutered-stub" ? 0.12 : 0.08,
        fact.kind === "neutered-stub"
          ? `The ${fact.tokenHit}() function is the API the rest of the ` +
              `module calls for confirmation — body neutered.`
          : `The bypass governs a conditional branch in ${fact.file}.`,
      )
      .factor(
        "no_audit_of_bypass",
        fact.hasApprovalPath ? 0.05 : 0.1,
        fact.hasApprovalPath
          ? `Bypass coexists with an honest-approval path.`
          : `No honest-approval path — the bypass is the only code path.`,
      )
      .reference({
        id: "OWASP-ASI09",
        title: "OWASP Agentic Security — Human-Agent Trust Exploitation",
        url: "https://genai.owasp.org/llmrisk/llm09-human-agent-trust-exploitation/",
        relevance:
          "ASI09 catalogues the exact failure mode K5 detects: a server / " +
          "agent code path that disables the confirmation step the user " +
          "believes is in place.",
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

function sourceRationale(fact: K5Fact): string {
  switch (fact.kind) {
    case "bypass-flag-assignment":
      return (
        `Bypass flag observed: "${fact.tokenHit}". An assignment of the ` +
        `literal \`true\` to this identifier (or an equivalent object ` +
        `property) is the canonical shape OWASP ASI09 calls out.`
      );
    case "env-var-bypass":
      return (
        `Environment-variable bypass: "${fact.tokenHit}". Gating the ` +
        `confirmation prompt on an operator-controlled env var lets the ` +
        `deployment manifest disable EU AI Act Art. 14 oversight.`
      );
    case "neutered-stub":
      return (
        `Neutered confirmation function: "${fact.tokenHit}". The API is ` +
        `preserved but the body unconditionally returns \`true\`.`
      );
  }
}

function sinkObserved(fact: K5Fact): string {
  switch (fact.kind) {
    case "bypass-flag-assignment":
      return `Destructive operations downstream of "${fact.tokenHit}" run without a human approval step.`;
    case "env-var-bypass":
      return `Env-var "${fact.tokenHit}" gates the confirmation path; when set, every destructive operation is silently approved.`;
    case "neutered-stub":
      return `Every caller of ${fact.tokenHit}() receives \`true\` — no prompt, no audit, no user decision.`;
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K5 charter caps confidence at ${cap} — a legitimate CI / headless ` +
      `test harness may set a bypass with a narrowly-scoped token.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new AutoApproveBypassRule());

export { AutoApproveBypassRule };
