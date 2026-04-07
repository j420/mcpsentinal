/**
 * K4 — Missing Human Confirmation for Destructive Ops (v2: Schema Inference + AST Structural)
 *
 * REPLACES the regex rule: /(?:delete|remove|drop|truncate|destroy|purge|wipe)(?:All|Many|Bulk|Batch)?\s*\([^)]*\)(?!.*(?:confirm|prompt|approve|ask|verify))/
 *
 * Old behavior: Fires on any function call named deleteAll(), removeMany(), etc.
 *   False positive: test helper deleteAllFixtures(), database migration dropOldTable()
 *   False negative: tool.execute({ action: "destroy_all" }) — action string not caught
 *
 * New behavior: Two-phase analysis:
 *   Phase 1: Schema inference — classify MCP tools as destructive based on name,
 *     description, and parameter schema. Check if tool has a confirmation parameter.
 *   Phase 2: AST structural — find destructive function calls in source code,
 *     check if they're guarded by confirmation/approval logic in the same scope.
 *
 * Why this matters for compliance:
 *   - EU AI Act Art. 14: Human oversight — destructive AI actions require human confirmation
 *   - ISO 42001 A.9.1/A.9.2: Human-in-the-loop for consequential decisions
 *   - OWASP ASI09: Human oversight bypass
 *   - NIST GOVERN 1.7: Human override capability
 */

import ts from "typescript";
import type { AnalysisContext } from "../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../base.js";
import { EvidenceChainBuilder } from "../../evidence.js";

const RULE_ID = "K4";
const RULE_NAME = "Missing Human Confirmation for Destructive Ops";
const OWASP = "ASI09-human-oversight-bypass";
const REMEDIATION =
  "Add a confirmation parameter (e.g., `confirm: boolean`, `force: boolean`) to destructive tools, " +
  "or implement a confirmation gate in the handler. For MCP tools: add a `confirm` required parameter " +
  "so the AI client must explicitly ask the user before executing. For code: wrap destructive calls " +
  "in `if (await confirmAction('Delete all records?')) { ... }` patterns. " +
  "EU AI Act Art. 14 requires human oversight for consequential AI actions.";

/** Words in tool/function names that indicate destructive operations */
const DESTRUCTIVE_VERBS = [
  "delete", "remove", "drop", "truncate", "destroy", "purge", "wipe",
  "erase", "clear", "reset", "revoke", "terminate", "kill", "shutdown",
  "uninstall", "deactivate", "disable", "ban", "block", "suspend",
];

/** Words that indicate bulk/mass operations (higher severity) */
const BULK_SUFFIXES = [
  "all", "many", "bulk", "batch", "multiple", "mass", "every",
  "recursive", "cascade", "force",
];

/** Parameter names that indicate confirmation gates */
const CONFIRMATION_PARAMS = [
  "confirm", "confirmation", "force", "approve", "approved",
  "verified", "acknowledge", "consent", "agree", "yes_i_am_sure",
  "dry_run", "dryrun", "dry-run", "preview", "simulate",
];

/** Code patterns that indicate confirmation logic in scope */
const CONFIRMATION_CODE_PATTERNS = [
  /\bconfirm\s*\(/i,
  /\bprompt\s*\(/i,
  /\bapprove\s*\(/i,
  /\bask\s*\(/i,
  /\bverify\s*\(/i,
  /\bwindow\.confirm\b/i,
  /\breadline\b/i,
  /\binquirer\b/i,
  /\bif\s*\(\s*(?:force|confirm|approved|dryRun|dry_run)\b/i,
  /\bdestructiveHint\s*:\s*true\b/i,
];

class MissingHumanConfirmationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "schema-inference";

  analyze(context: AnalysisContext): RuleResult[] {
    const findings: RuleResult[] = [];

    // ── Phase 1: Schema inference — classify tools as destructive ──
    for (const tool of context.tools) {
      const destructiveSignals = this.classifyToolDestructiveness(tool);
      if (destructiveSignals.length === 0) continue;

      const hasConfirmationParam = this.toolHasConfirmationParam(tool);
      const hasDestructiveAnnotation = this.toolHasDestructiveAnnotation(tool, context);

      if (!hasConfirmationParam) {
        findings.push(this.buildToolFinding(tool, destructiveSignals, hasDestructiveAnnotation));
      }
    }

    // ── Phase 2: AST structural — find destructive calls in source without guards ──
    if (context.source_code && !/(?:__tests?__|\.(?:test|spec)\.)/.test(context.source_code)) {
      const codeFindings = this.analyzeSourceCode(context.source_code);
      findings.push(...codeFindings);
    }

    return findings;
  }

  /** Classify a tool as destructive based on name, description, and schema */
  private classifyToolDestructiveness(
    tool: { name: string; description: string | null; input_schema: unknown },
  ): string[] {
    const signals: string[] = [];
    const nameLower = tool.name.toLowerCase();
    const descLower = (tool.description || "").toLowerCase();

    // Check tool name for destructive verbs
    for (const verb of DESTRUCTIVE_VERBS) {
      if (nameLower.includes(verb)) {
        const isBulk = BULK_SUFFIXES.some(s => nameLower.includes(s));
        signals.push(
          isBulk
            ? `tool name "${tool.name}" contains bulk destructive verb "${verb}"`
            : `tool name "${tool.name}" contains destructive verb "${verb}"`,
        );
      }
    }

    // Check description for destructive intent
    if (descLower.match(/\b(?:permanently|irreversibly|cannot be undone|destructive|dangerous)\b/)) {
      signals.push(`description warns about destructive/irreversible action: "${tool.description!.slice(0, 80)}"`);
    }

    // Check schema for path/target parameters without constraints — only if tool is ALREADY classified as destructive
    if (signals.length > 0 && tool.input_schema && typeof tool.input_schema === "object") {
      const schema = tool.input_schema as Record<string, unknown>;
      const props = (schema.properties || {}) as Record<string, unknown>;
      for (const [paramName, paramDef] of Object.entries(props)) {
        const pDef = paramDef as Record<string, unknown>;
        if (
          (paramName === "path" || paramName === "target" || paramName === "pattern") &&
          pDef.type === "string" &&
          !pDef.enum && !pDef.pattern && !pDef.maxLength
        ) {
          signals.push(
            `parameter "${paramName}" is an unconstrained string on a destructive tool — could target arbitrary resources`,
          );
        }
      }
    }

    return signals;
  }

  /** Check if tool has a confirmation-type parameter */
  private toolHasConfirmationParam(
    tool: { input_schema: unknown },
  ): boolean {
    if (!tool.input_schema || typeof tool.input_schema !== "object") return false;
    const schema = tool.input_schema as Record<string, unknown>;
    const props = (schema.properties || {}) as Record<string, unknown>;

    for (const paramName of Object.keys(props)) {
      if (CONFIRMATION_PARAMS.some(cp => paramName.toLowerCase().includes(cp))) {
        return true;
      }
    }
    return false;
  }

  /** Check if tool has destructiveHint annotation */
  private toolHasDestructiveAnnotation(
    tool: { name: string },
    context: AnalysisContext,
  ): boolean {
    // Check annotations if available in context
    const annotations = (context as unknown as Record<string, unknown>).tool_annotations as
      Record<string, Record<string, unknown>> | undefined;
    if (annotations && annotations[tool.name]) {
      return annotations[tool.name].destructiveHint === true;
    }
    return false;
  }

  /** Analyze source code for destructive function calls without confirmation guards */
  private analyzeSourceCode(source: string): RuleResult[] {
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node)) {
          const callText = node.expression.getText(sf).toLowerCase();

          // Check if this is a destructive call
          const matchedVerb = DESTRUCTIVE_VERBS.find(v => callText.includes(v));
          if (!matchedVerb) { ts.forEachChild(node, visit); return; }

          // Skip if in test/fixture code context
          const fullLine = source.substring(
            source.lastIndexOf("\n", node.getStart(sf)) + 1,
            source.indexOf("\n", node.getEnd()),
          );
          if (/test|mock|fixture|spec|__test/i.test(fullLine)) {
            ts.forEachChild(node, visit);
            return;
          }

          // Check if there's a confirmation guard in the enclosing scope
          const enclosingBlock = this.findEnclosingBlock(node, sf);
          if (enclosingBlock) {
            const blockText = enclosingBlock.getText(sf);
            const hasGuard = CONFIRMATION_CODE_PATTERNS.some(p => p.test(blockText));
            if (hasGuard) { ts.forEachChild(node, visit); return; }
          }

          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
          const isBulk = BULK_SUFFIXES.some(s => callText.includes(s));

          findings.push(this.buildCodeFinding(
            node.expression.getText(sf),
            matchedVerb,
            line,
            fullLine.trim(),
            isBulk,
          ));
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch {
      // AST parse failure — skip code analysis
    }

    return findings;
  }

  /** Walk up the AST to find the enclosing function/block for confirmation check */
  private findEnclosingBlock(node: ts.Node, _sf: ts.SourceFile): ts.Node | null {
    let current: ts.Node | undefined = node.parent;
    while (current) {
      // Return the enclosing function, method, or arrow function
      // (broader scope catches if-conditions, not just the block body)
      if (
        ts.isFunctionDeclaration(current) ||
        ts.isFunctionExpression(current) ||
        ts.isArrowFunction(current) ||
        ts.isMethodDeclaration(current) ||
        ts.isSourceFile(current)
      ) {
        return current;
      }
      current = current.parent;
    }
    return null;
  }

  /** Build finding for destructive MCP tool without confirmation parameter */
  private buildToolFinding(
    tool: { name: string; description: string | null },
    destructiveSignals: string[],
    hasDestructiveAnnotation: boolean,
  ): RuleResult {
    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "user-parameter",
      location: `tool "${tool.name}"`,
      observed: destructiveSignals[0],
      rationale:
        `Tool "${tool.name}" is classified as destructive based on ${destructiveSignals.length} signal(s): ` +
        destructiveSignals.join("; ") + ". " +
        "Destructive MCP tools should require explicit human confirmation before execution. " +
        "Without a confirmation parameter, the AI client may auto-execute this tool based on " +
        "ambiguous user intent or prompt injection.",
    });

    builder.sink({
      sink_type: "privilege-grant",
      location: `tool "${tool.name}" schema`,
      observed:
        `Tool "${tool.name}" has no confirmation parameter (e.g., confirm, force, dry_run) ` +
        `in its input schema. The AI can invoke this destructive operation without explicit user approval.`,
    });

    builder.mitigation({
      mitigation_type: "confirmation-gate",
      present: false,
      location: `tool "${tool.name}" input_schema.properties`,
      detail:
        `No parameter matching confirmation patterns (${CONFIRMATION_PARAMS.slice(0, 5).join(", ")}) ` +
        `found in tool schema. Add a required \`confirm: boolean\` parameter.`,
    });

    if (hasDestructiveAnnotation) {
      builder.mitigation({
        mitigation_type: "annotation-hint",
        present: true,
        location: `tool "${tool.name}" annotations`,
        detail: "destructiveHint: true is set — AI clients aware of annotations may prompt for confirmation",
      });
    }

    builder.impact({
      impact_type: "privilege-escalation",
      scope: "user-data",
      exploitability: "moderate",
      scenario:
        `An attacker using prompt injection or a confused AI agent could invoke "${tool.name}" ` +
        `without the user realizing a destructive action is being taken. With no confirmation gate, ` +
        `the operation executes immediately. In an MCP context, this violates the human-oversight ` +
        `principle: the user should always confirm before data is deleted, accounts are terminated, ` +
        `or resources are permanently removed.`,
    });

    builder.factor(
      "destructive_tool_name",
      destructiveSignals.length > 1 ? 0.12 : 0.08,
      `${destructiveSignals.length} independent signal(s) classify this tool as destructive`,
    );

    builder.factor(
      "no_confirmation_param",
      0.10,
      "No confirmation/force/dry_run parameter in tool schema",
    );

    if (hasDestructiveAnnotation) {
      builder.factor(
        "has_destructive_annotation",
        -0.08,
        "destructiveHint: true annotation present — partial mitigation via MCP spec",
      );
    }

    builder.reference({
      id: "EU-AI-Act-Art14",
      title: "EU AI Act Article 14 — Human Oversight",
      relevance:
        "Requires that AI systems allow human oversight and intervention. " +
        "Destructive tool invocation without confirmation bypasses this requirement.",
    });

    builder.reference({
      id: "ISO-42001-A.9.2",
      title: "ISO/IEC 42001:2023 Annex A Control 9.2 — Human-in-the-Loop",
      relevance:
        "Requires human control over AI system actions with significant consequences.",
    });

    builder.verification({
      step_type: "inspect-schema",
      instruction:
        `Check tool "${tool.name}" input_schema for a confirmation parameter. ` +
        `Verify that the tool cannot be invoked without explicit user approval.`,
      target: `tool:${tool.name}:input_schema`,
      expected_observation: "No confirm/force/dry_run parameter in schema properties",
    });

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain: builder.build(),
    };
  }

  /** Build finding for destructive code call without confirmation guard */
  private buildCodeFinding(
    callText: string,
    matchedVerb: string,
    line: number,
    lineText: string,
    isBulk: boolean,
  ): RuleResult {
    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "file-content",
      location: `line ${line}`,
      observed: lineText.slice(0, 120),
      rationale:
        `Destructive function call "${callText}" (verb: "${matchedVerb}"${isBulk ? ", bulk operation" : ""}) ` +
        `found at line ${line} without a confirmation guard in the enclosing scope. ` +
        `Checked for: confirm(), prompt(), approve(), force flag, dry_run check — none found.`,
    });

    builder.sink({
      sink_type: "privilege-grant",
      location: `line ${line}`,
      observed: `${callText}() — destructive operation without confirmation guard`,
    });

    builder.mitigation({
      mitigation_type: "confirmation-gate",
      present: false,
      location: `enclosing scope of line ${line}`,
      detail: "No confirmation pattern (confirm/prompt/approve/force check) in enclosing block",
    });

    builder.impact({
      impact_type: "privilege-escalation",
      scope: "user-data",
      exploitability: isBulk ? "trivial" : "moderate",
      scenario:
        `Unguarded destructive call "${callText}" at line ${line} can execute without user approval. ` +
        (isBulk
          ? "Bulk operation — affects multiple resources simultaneously, amplifying damage."
          : "Single-resource operation — still requires confirmation for compliance."),
    });

    builder.factor("ast_destructive_call", 0.08, `Destructive verb "${matchedVerb}" in function call`);
    builder.factor("no_guard_in_scope", 0.10, "No confirmation pattern in enclosing block");
    if (isBulk) {
      builder.factor("bulk_operation", 0.05, "Bulk/mass operation suffix increases risk");
    }

    builder.verification({
      step_type: "inspect-source",
      instruction: `Check line ${line} for destructive call "${callText}". Verify no confirmation logic exists in the enclosing function.`,
      target: `source_code:${line}`,
      expected_observation: "Destructive call without confirmation guard in scope",
    });

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain: builder.build(),
    };
  }
}

registerTypedRuleV2(new MissingHumanConfirmationRule());
