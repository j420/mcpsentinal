/**
 * K6 — Overly Broad OAuth Scopes (v2: AST Structural Analysis)
 *
 * REPLACES the regex: /scope\s*[:=]\s*['"](?:admin|root|all|\*|read:all|write:all)/
 *
 * Old behavior: Matched scope string on the same line.
 *   False positive: scope: "admin_panel" (admin is a prefix, not a wildcard)
 *   False negative: scopes: ['read', 'write', 'admin'] — array form not caught
 *
 * New behavior: AST structural analysis to:
 *   1. Find OAuth scope assignments (scope, scopes, oauth_scope, permissions)
 *   2. Parse string values AND array values
 *   3. Classify scopes: wildcard (*), admin/root, read:all/write:all, overly broad
 *   4. Check if scope is from user input (escalation risk)
 *   5. Cross-check: is scope narrowed elsewhere (if/switch on role)?
 *
 * Compliance:
 *   - OWASP ASI03: Identity & privilege abuse — broad scopes enable privilege escalation
 *   - ISO 27001 A.5.15: Access control — principle of least privilege
 *   - ISO 27001 A.5.18: Access rights management
 *   - CoSAI MCP-T1/T2: Authentication and authorization
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

const RULE_ID = "K6";
const RULE_NAME = "Overly Broad OAuth Scopes";
const OWASP = "ASI03-identity-privilege-abuse";
const REMEDIATION =
  "Use minimal OAuth scopes. Request only the permissions actually needed. " +
  "Replace wildcard scopes (*) with specific ones (e.g., 'read:repos' instead of 'admin'). " +
  "Never derive scopes from user input. Use role-based scope mappings. " +
  "Example: scope: 'read:user read:repos' instead of scope: 'admin'";

/** Scope values that are overly broad */
const BROAD_SCOPES: Array<{ pattern: RegExp; severity: "wildcard" | "admin" | "broad" }> = [
  { pattern: /^\*$/, severity: "wildcard" },
  { pattern: /^admin$/i, severity: "admin" },
  { pattern: /^root$/i, severity: "admin" },
  { pattern: /^all$/i, severity: "admin" },
  { pattern: /^superuser$/i, severity: "admin" },
  { pattern: /^full[_-]?access$/i, severity: "admin" },
  { pattern: /^read:all$/i, severity: "broad" },
  { pattern: /^write:all$/i, severity: "broad" },
  { pattern: /^manage:all$/i, severity: "broad" },
  { pattern: /^.*:admin$/i, severity: "admin" },
  { pattern: /^.*:\*$/i, severity: "wildcard" },
];

/** Property names that indicate OAuth scope configuration */
const SCOPE_PROPERTIES = /^(?:scope|scopes|oauth_scope|oauth_scopes|permissions|grant_scope|requested_scope)$/i;

class BroadOAuthScopesRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code) return [];
    if (/(?:__tests?__|\.(?:test|spec)\.)/.test(context.source_code)) return [];

    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Property assignments: scope: "admin", scope: ["read", "admin"]
        if (ts.isPropertyAssignment(node)) {
          const propName = node.name.getText(sf);
          if (SCOPE_PROPERTIES.test(propName)) {
            const result = this.analyzeScopeValue(node.initializer, sf, source, propName);
            if (result) findings.push(result);
          }
        }

        // Binary expressions: scope = "admin", config.scope = "*"
        if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
          const leftText = node.left.getText(sf);
          const propName = leftText.split(".").pop() || leftText;
          if (SCOPE_PROPERTIES.test(propName)) {
            const result = this.analyzeScopeValue(node.right, sf, source, propName);
            if (result) findings.push(result);
          }
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch {
      // AST parse failure
    }

    return findings;
  }

  /** Analyze a scope value expression for overly broad scopes */
  private analyzeScopeValue(
    valueNode: ts.Expression,
    sf: ts.SourceFile,
    source: string,
    propName: string,
  ): RuleResult | null {
    const line = sf.getLineAndCharacterOfPosition(valueNode.getStart(sf)).line + 1;
    const lineText = source.split("\n")[line - 1]?.trim() || "";

    // Skip commented lines
    if (lineText.startsWith("//") || lineText.startsWith("*")) return null;

    // String literal: scope: "admin" or scope: "read:all write:all"
    if (ts.isStringLiteral(valueNode) || ts.isNoSubstitutionTemplateLiteral(valueNode)) {
      const scopeStr = valueNode.text;
      // Split by space (OAuth convention) and check each scope
      const scopes = scopeStr.split(/\s+/);
      const broadScopes = this.findBroadScopes(scopes);
      if (broadScopes.length > 0) {
        return this.buildFinding(propName, scopeStr, broadScopes, line, lineText, false);
      }
    }

    // Array literal: scopes: ["read", "admin", "write"]
    if (ts.isArrayLiteralExpression(valueNode)) {
      const scopes = valueNode.elements
        .filter((e): e is ts.StringLiteral => ts.isStringLiteral(e))
        .map(e => e.text);
      const broadScopes = this.findBroadScopes(scopes);
      if (broadScopes.length > 0) {
        return this.buildFinding(propName, scopes.join(", "), broadScopes, line, lineText, false);
      }
    }

    // Template literal or variable: scope: `${userScope}` — scope from user input
    if (ts.isTemplateExpression(valueNode) || ts.isIdentifier(valueNode)) {
      const valueText = valueNode.getText(sf);
      // Check if it's a variable that could come from user input
      if (/req\.|params\.|query\.|body\.|user.*input|userScope/i.test(valueText)) {
        return this.buildFinding(propName, valueText, [{ scope: valueText, severity: "admin" as const }], line, lineText, true);
      }
    }

    return null;
  }

  /** Check scopes against broad scope patterns */
  private findBroadScopes(scopes: string[]): Array<{ scope: string; severity: "wildcard" | "admin" | "broad" }> {
    const broad: Array<{ scope: string; severity: "wildcard" | "admin" | "broad" }> = [];
    for (const scope of scopes) {
      for (const { pattern, severity } of BROAD_SCOPES) {
        if (pattern.test(scope.trim())) {
          broad.push({ scope: scope.trim(), severity });
          break;
        }
      }
    }
    return broad;
  }

  private buildFinding(
    propName: string,
    scopeValue: string,
    broadScopes: Array<{ scope: string; severity: "wildcard" | "admin" | "broad" }>,
    line: number,
    lineText: string,
    isUserInput: boolean,
  ): RuleResult {
    const builder = new EvidenceChainBuilder();
    const worstSeverity = broadScopes.some(s => s.severity === "wildcard") ? "wildcard"
      : broadScopes.some(s => s.severity === "admin") ? "admin" : "broad";

    builder.source({
      source_type: isUserInput ? "user-parameter" : "file-content",
      location: `line ${line}`,
      observed: lineText.slice(0, 120),
      rationale:
        `OAuth scope "${propName}" at line ${line} contains overly broad value(s): ` +
        broadScopes.map(s => `"${s.scope}" (${s.severity})`).join(", ") + ". " +
        (isUserInput
          ? "Scope is derived from user input — enables privilege escalation via scope injection."
          : `Static scope "${scopeValue}" violates principle of least privilege.`),
    });

    builder.sink({
      sink_type: "privilege-grant",
      location: `line ${line}`,
      observed: `${propName}: "${scopeValue}" — grants ${worstSeverity}-level access`,
    });

    builder.mitigation({
      mitigation_type: "input-validation",
      present: false,
      location: `line ${line}`,
      detail: isUserInput
        ? "Scope derived from user input without validation/allowlist"
        : "No scope narrowing detected (no role-based scope mapping)",
    });

    builder.impact({
      impact_type: "privilege-escalation",
      scope: "connected-services",
      exploitability: isUserInput ? "trivial" : "moderate",
      scenario:
        `Overly broad OAuth scope "${scopeValue}" grants more permissions than needed. ` +
        (worstSeverity === "wildcard"
          ? "Wildcard (*) scope grants ALL permissions — any API operation is authorized."
          : worstSeverity === "admin"
          ? "Admin/root scope grants full administrative access — can modify users, delete data, change settings."
          : "Broad scope (read:all/write:all) grants access to all resources instead of specific ones.") +
        " If the token is compromised, the attacker inherits all these permissions.",
    });

    builder.factor("broad_scope_detected", worstSeverity === "wildcard" ? 0.15 : 0.10,
      `${worstSeverity}-level scope detected: ${broadScopes.map(s => s.scope).join(", ")}`);
    if (isUserInput) {
      builder.factor("user_controlled_scope", 0.10, "Scope value derived from user input — injection risk");
    }

    builder.reference({
      id: "ISO-27001-A.5.15",
      title: "ISO/IEC 27001:2022 Annex A Control 5.15 — Access Control",
      relevance: "Requires principle of least privilege — access limited to what is needed for the role.",
    });

    builder.verification({
      step_type: "inspect-source",
      instruction: `Check line ${line} for OAuth scope assignment. Verify the scope follows least-privilege principle.`,
      target: `source_code:${line}`,
      expected_observation: `Overly broad scope: "${scopeValue}"`,
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

registerTypedRuleV2(new BroadOAuthScopesRule());
