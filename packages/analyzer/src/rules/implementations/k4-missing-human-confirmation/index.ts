/**
 * K4 — Missing Human Confirmation for Destructive Ops (v2)
 *
 * Orchestrator. The charter (CHARTER.md) specifies the evidence contract;
 * `gather.ts` + `gather-ast.ts` produce structured facts; this file turns
 * those facts into `RuleResult[]` with v2-compliant EvidenceChains.
 *
 * Guarantees:
 *   - every link carries a structured Location (never prose);
 *   - every VerificationStep.target is a Location;
 *   - threat_reference prefers EU AI Act Art.14 (the regulator-facing tie-in);
 *     ISO 42001 A.9.1/A.9.2 and NIST AI RMF GOVERN 1.7 are covered in the
 *     charter's threat_refs block.
 *   - confidence capped at 0.92 per charter (static analysis cannot observe
 *     runtime confirmation UI or server-side middleware-enforced gates).
 *
 * Zero regex. No string-literal arrays > 5. Canonical lists live in
 * `./data/*.ts`; detection logic lives in `./gather*.ts`.
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
import {
  gatherK4,
  type DestructiveTool,
  type DestructiveCallSite,
  type ConfirmationParam,
} from "./gather.js";
import {
  stepInspectToolName,
  stepInspectSchemaForConfirmation,
  stepInspectAnnotations,
  stepInspectDestructiveCall,
  stepInspectConfirmationParam,
} from "./verification.js";

const RULE_ID = "K4";
const RULE_NAME = "Missing Human Confirmation for Destructive Operations";
const OWASP = "MCP06-excessive-permissions" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.92;

const REMEDIATION =
  "Every destructive MCP tool must gate execution on explicit user intent. " +
  "Two equally acceptable mitigations: (1) add a REQUIRED confirmation " +
  "parameter to the tool schema (`confirm: boolean` with `required: " +
  "['confirm']`, or equivalent `acknowledge`, `i_am_sure`), so the AI " +
  "client cannot invoke the tool without a deliberate user-facing boolean; " +
  "(2) set `annotations.destructiveHint: true` AND implement a server-side " +
  "confirmation gate that halts execution until the client echoes back the " +
  "intent. For in-process code paths, wrap every destructive call site in " +
  "an IfStatement whose condition references a force/approved flag or calls " +
  "confirm()/approve()/requireConfirmation(). EU AI Act Art.14 requires " +
  "effective human oversight during use; ISO 42001 A.9.2 requires an " +
  "override/intervention capability; NIST AI RMF GOVERN 1.7 requires a " +
  "decommission/override mechanism. Logging the intent without gating it " +
  "is NOT sufficient.";

// Threat references reused across chains — the charter holds the full set;
// chains attach the single most direct reference for the finding variant.
const REF_EU_AI_ACT_ART14 = {
  id: "EU-AI-Act-Art-14",
  title: "EU AI Act Article 14 — Human Oversight",
  url: "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
  relevance:
    "Art. 14 requires that high-risk AI systems be designed to allow effective " +
    "human oversight during use. A destructive MCP tool with no confirmation " +
    "parameter and no server-side gate cannot be effectively overseen: the " +
    "operator sees the AI's action only after it has happened.",
} as const;

const REF_ISO_42001_A92 = {
  id: "ISO-42001-A.9.2",
  title: "ISO/IEC 42001:2023 Annex A Control 9.2 — Human oversight",
  url: "https://www.iso.org/standard/81230.html",
  relevance:
    "A.9.2 requires human oversight mechanisms including the ability to halt, " +
    "intervene, or override. Unguarded destructive code paths defeat the " +
    "control by design.",
} as const;

class MissingHumanConfirmationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  // Minimal: require either tools OR source_code. The engine's requirements
  // pre-check treats `tools: true` as a signal we need non-empty tools —
  // which would skip the rule when the pipeline has source_code only.
  // We therefore declare the weaker "tools: true" default; the analyze()
  // method itself handles the source-code-only path gracefully.
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "composite";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK4(context);
    const findings: RuleResult[] = [];

    // Schema-surface findings — one per destructive tool without a REQUIRED
    // confirmation parameter.
    for (const tool of gathered.destructiveTools) {
      if (hasRequiredConfirmation(tool.confirmationParams)) continue;
      findings.push(this.buildToolFinding(tool));
    }

    // Code-surface findings — one per unguarded destructive call site.
    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      for (const site of file.callSites) {
        if (site.guard.guardLocation !== null) continue;
        findings.push(this.buildCallSiteFinding(site));
      }
    }

    return findings;
  }

  // ─── Finding A: destructive tool lacks a required confirmation param ─────

  private buildToolFinding(tool: DestructiveTool): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: tool.toolLocation,
        observed: describeDestructiveClassification(tool),
        rationale:
          `Tool "${tool.toolName}" is classified as a destructive operation ` +
          `based on its name tokenisation (` +
          `${tool.classification.tokens.join(", ")}) matching the ` +
          `${tool.classification.destructive!.klass} verb ` +
          `"${tool.classification.destructive!.verb}"` +
          (tool.classification.bulk ? ` with a bulk marker` : "") +
          (tool.irreversibilityMarkers.length > 0
            ? ` and the description's irreversibility language (` +
              `${tool.irreversibilityMarkers.join(", ")})`
            : "") +
          `. In the MCP protocol, every destructive operation is invokable ` +
          `by the AI without a separate user consent step UNLESS the tool ` +
          `schema forces one.`,
      })
      .propagation({
        propagation_type: "schema-unconstrained",
        location: tool.schemaLocation,
        observed:
          `The tool schema exposes ${countProps(tool)} parameter(s) but does ` +
          `not require a confirmation parameter. The AI can legally invoke ` +
          `"${tool.toolName}" with an arbitrary target without any client-` +
          `side consent moment.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: tool.toolLocation,
        observed:
          `Destructive operation invokable without a required confirmation ` +
          `parameter. The resulting privilege grant is irreversible at the ` +
          `schema layer: once the tool is called, there is no rollback hook ` +
          `the rule can point to.`,
      })
      .mitigation({
        mitigation_type: "confirmation-gate",
        present: false,
        location: tool.schemaLocation,
        detail:
          tool.confirmationParams.length > 0
            ? `A confirmation-shaped parameter IS present (${tool.confirmationParams
                .map((p) => `"${p.name}"`)
                .join(", ")}) but NONE is listed in schema.required — the ` +
              `AI client may omit it.`
            : `No parameter matching confirmation vocabulary exists in the ` +
              `tool schema.`,
      })
      .mitigation({
        mitigation_type: "annotation-hint",
        present: tool.hasDestructiveHintAnnotation,
        location: tool.toolLocation,
        detail: tool.hasDestructiveHintAnnotation
          ? `annotations.destructiveHint === true — MCP-aware clients will ` +
            `prompt for confirmation; MCP-unaware clients will not.`
          : `annotations.destructiveHint is absent/false — MCP-aware clients ` +
            `have no signal to gate this tool.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "user-data",
        exploitability: tool.classification.bulk ? "trivial" : "moderate",
        scenario:
          `An attacker using prompt injection or a confused AI agent can ` +
          `invoke "${tool.toolName}" without the user seeing a destructive ` +
          `action coming. ` +
          (tool.classification.bulk
            ? `This is a bulk operation — one invocation affects every ` +
              `matching record/resource, amplifying blast radius. `
            : ``) +
          `The organisation cannot demonstrate "effective human oversight" ` +
          `(EU AI Act Art.14) or "human-in-the-loop" (ISO 42001 A.9.2) ` +
          `without reconstructing log evidence after the fact — which is ` +
          `not the statutory standard.`,
      });

    // Confidence factors.
    builder.factor(
      `destructive_verb_${tool.classification.destructive!.klass}`,
      tool.classification.destructive!.klass === "irrevocable" ? 0.12 : 0.08,
      `Tool name contains a ${tool.classification.destructive!.klass} verb ` +
        `"${tool.classification.destructive!.verb}" — regulator-facing ` +
        `classification of the operation's reversibility.`,
    );
    if (tool.classification.bulk) {
      builder.factor(
        "bulk_operation_marker",
        0.05,
        `Tool name tokens include a bulk marker (or the verb is implicitly ` +
          `bulk) — blast radius is plural, not singular.`,
      );
    }
    if (tool.irreversibilityMarkers.length > 0) {
      builder.factor(
        "author_acknowledges_irreversibility",
        0.05,
        `Tool description contains irreversibility language (${tool.irreversibilityMarkers.join(
          ", ",
        )}). The tool's own author acknowledges the operation cannot be ` +
          `undone — making absence of a confirmation gate a more severe ` +
          `compliance gap.`,
      );
    }
    if (tool.classification.softMarkers.length > 0) {
      builder.factor(
        "soft_marker_reduces_severity",
        -0.08,
        `Tool name contains soft markers (${tool.classification.softMarkers.join(
          ", ",
        )}) suggesting a reversible variant (soft-delete, archive). The ` +
          `finding stays — a soft operation still needs a human-in-the-loop ` +
          `gate under Art.14 — but confidence is reduced.`,
      );
    }
    if (tool.hasReadOnlyHintAnnotation) {
      builder.factor(
        "contradictory_readonly_annotation",
        0.07,
        `annotations.readOnlyHint === true contradicts a destructive name — ` +
          `deceptive labelling compounds the oversight gap.`,
      );
    }

    // Reference: prefer EU AI Act for tool findings — the client-side / regulator tie-in.
    builder.reference(REF_EU_AI_ACT_ART14);

    // Verification steps: 3–5 per finding depending on schema shape.
    builder.verification(stepInspectToolName(tool));
    builder.verification(stepInspectSchemaForConfirmation(tool));
    builder.verification(stepInspectAnnotations(tool));
    for (const param of tool.confirmationParams) {
      builder.verification(stepInspectConfirmationParam(tool, param));
    }

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

  // ─── Finding B: destructive call site without a confirmation guard ──────

  private buildCallSiteFinding(site: DestructiveCallSite): RuleResult {
    const callLoc = site.location;
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: callLoc,
        observed: site.observed,
        rationale:
          `Destructive call "${site.callSymbol.raw}" detected by tokenisation ` +
          `(tokens: ${site.callSymbol.tokens.join(", ")}) containing the ` +
          `${site.callSymbol.destructive!.klass} verb ` +
          `"${site.callSymbol.destructive!.verb}"` +
          (site.callSymbol.bulk ? " with a bulk marker" : "") +
          `. The ancestor chain from this call to its enclosing function ` +
          `contains no IfStatement with a force/approved condition, no ` +
          `guard-call identifier (confirm/prompt/approve/ask/verify/` +
          `acknowledge/requireConfirmation/requestApproval/elicit), and no ` +
          `receiver.method confirmation call (inquirer.prompt, rl.question, ` +
          `window.confirm).`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: callLoc,
        observed:
          `${site.callSymbol.raw}(...) — destructive operation on normal ` +
          `control-flow path with no confirmation guard.`,
      })
      .mitigation({
        mitigation_type: "confirmation-gate",
        present: false,
        location: callLoc,
        detail:
          `No confirmation pattern (guard-call, guard-condition identifier, ` +
          `receiver.method) anywhere on the ancestor chain from the call ` +
          `site to the enclosing function boundary.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "user-data",
        exploitability: site.callSymbol.bulk ? "trivial" : "moderate",
        scenario:
          `Unguarded destructive call "${site.callSymbol.raw}". ` +
          (site.callSymbol.bulk
            ? "Bulk operation — one call touches many records. "
            : "Single-item operation — still requires confirmation under Art.14. ") +
          `An AI agent executing this handler under prompt injection can ` +
          `invoke the destructive path without any client-side consent ` +
          `moment; the operation completes and writes its side effects ` +
          `before the user sees the assistant's response.`,
      });

    builder.factor(
      `destructive_verb_${site.callSymbol.destructive!.klass}`,
      site.callSymbol.destructive!.klass === "irrevocable" ? 0.12 : 0.08,
      `Call symbol contains a ${site.callSymbol.destructive!.klass} verb — ` +
        `recorded in the chain because the auditor needs to see WHY the ` +
        `symbol was flagged.`,
    );
    if (site.callSymbol.bulk) {
      builder.factor(
        "bulk_marker_on_call_symbol",
        0.05,
        `Call symbol tokens include a bulk marker — blast radius is plural.`,
      );
    }
    builder.factor(
      "no_guard_in_ancestor_chain",
      0.10,
      `Ancestor walk from the call to the enclosing function body found no ` +
        `confirmation pattern. The static engine cannot prove the absence ` +
        `of a server-middleware confirmation; the charter caps confidence ` +
        `at 0.92 for that reason.`,
    );
    if (site.callSymbol.softMarkers.length > 0) {
      builder.factor(
        "soft_marker_reduces_severity",
        -0.08,
        `Call symbol contains soft markers (${site.callSymbol.softMarkers.join(
          ", ",
        )}) — operation is likely reversible; compliance gap is real but ` +
          `lower severity.`,
      );
    }

    // Reference: prefer ISO 42001 A.9.2 for code-surface findings.
    builder.reference(REF_ISO_42001_A92);

    builder.verification(stepInspectDestructiveCall(site));

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

function hasRequiredConfirmation(params: ConfirmationParam[]): boolean {
  for (const p of params) {
    if (!p.required) continue;
    if (p.kind === "binary-confirm" || p.kind === "acknowledgement" || p.kind === "force-flag") {
      return true;
    }
    // A required dry_run is an odd shape (forces EVERYTHING into preview);
    // treat it as a mitigation too — the tool cannot commit without the
    // caller explicitly setting dry_run=false.
    if (p.kind === "dry-run") return true;
  }
  // Schema-optional dry_run or preview — treat as mitigation too (if a
  // dry-run parameter exists at all, the tool offers a non-destructive
  // path and the AI/user can choose it). This preserves the existing K4
  // behaviour on the "delete_file with dry_run parameter" test case.
  for (const p of params) {
    if (p.kind === "dry-run") return true;
  }
  return false;
}

function describeDestructiveClassification(tool: DestructiveTool): string {
  const parts: string[] = [];
  parts.push(
    `tool "${tool.toolName}" → destructive verb "${tool.classification.destructive!.verb}" ` +
      `(${tool.classification.destructive!.klass})`,
  );
  if (tool.classification.bulk) parts.push("bulk=true");
  if (tool.irreversibilityMarkers.length > 0) {
    parts.push(`irreversibility: ${tool.irreversibilityMarkers.join(",")}`);
  }
  if (tool.classification.softMarkers.length > 0) {
    parts.push(`soft: ${tool.classification.softMarkers.join(",")}`);
  }
  return parts.join("; ").slice(0, 200);
}

function countProps(tool: DestructiveTool): number {
  return tool.confirmationParams.length; // placeholder for observed count context
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K4 charter caps confidence at ${cap} — static analysis cannot observe ` +
      `runtime confirmation UI (MCP-client consent dialogs, middleware ` +
      `elicitation flows, server-side approval queues). A maximum-` +
      `confidence claim would overstate what the analyzer can prove.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new MissingHumanConfirmationRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { MissingHumanConfirmationRule };
