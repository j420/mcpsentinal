/**
 * K12, K14 — K-Compliance structural rules (TypedRuleV2)
 *
 * K12: Executable Content in Tool Response
 * K14: Agent Credential Propagation — credentials in shared state
 *
 * K16 migrated to `k16-unbounded-recursion/` in chunk 1.6c.
 * K20 migrated to `k20-insufficient-audit-context/` in chunk 1.6d.
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

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }

function getEnclosingFunc(node: ts.Node, sf: ts.SourceFile): { node: ts.Node; name: string | null } | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isFunctionDeclaration(cur)) {
      return { node: cur, name: cur.name?.getText(sf) || null };
    }
    if (ts.isMethodDeclaration(cur)) {
      return { node: cur, name: cur.name?.getText(sf) || null };
    }
    if (ts.isFunctionExpression(cur)) {
      return { node: cur, name: cur.name?.getText(sf) || null };
    }
    if (ts.isArrowFunction(cur)) {
      // Try to get name from parent variable declaration
      if (ts.isVariableDeclaration(cur.parent)) {
        return { node: cur, name: cur.parent.name.getText(sf) };
      }
      return { node: cur, name: null };
    }
    cur = cur.parent;
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// K12 — Executable Content in Tool Response
// ═══════════════════════════════════════════════════════════════════════════════

/** Patterns indicating executable code in responses */
const EXEC_IN_RESPONSE_PATTERNS: Array<{ regex: RegExp; desc: string }> = [
  { regex: /\beval\s*\(/, desc: "eval() in response construction" },
  { regex: /\bnew\s+Function\s*\(/, desc: "new Function() in response" },
  { regex: /\brequire\s*\(\s*[^)]*\)/, desc: "require() in response content" },
  { regex: /\bimport\s*\(/, desc: "dynamic import() in response" },
  { regex: /<script\b/, desc: "<script> tag in response content" },
  { regex: /\bjavascript\s*:/, desc: "javascript: URI in response" },
  { regex: /\bon\w+\s*=/, desc: "inline event handler in response" },
];

const SANITIZE_PATTERNS = [
  /\bsanitize\s*\(/i, /\bescape\s*\(/i, /\bDOMPurify\b/i,
  /\bencodeHTML\s*\(/i, /\btextContent\b/, /\bcreateTextNode\b/,
];

class K12Rule implements TypedRuleV2 {
  readonly id = "K12";
  readonly name = "Executable Content in Tool Response";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Find return statements in functions
        if (ts.isReturnStatement(node) && node.expression) {
          const retText = node.expression.getText(sf);
          for (const { regex, desc } of EXEC_IN_RESPONSE_PATTERNS) {
            if (regex.test(retText)) {
              // Check if there's sanitization in scope
              const enclosing = getEnclosingFunc(node, sf);
              const funcText = enclosing ? enclosing.node.getText(sf) : "";
              const hasSanitizer = SANITIZE_PATTERNS.some(p => p.test(funcText));

              if (!hasSanitizer) {
                const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                findings.push(this.buildFinding(desc, line, retText, source));
              }
              break;
            }
          }
        }

        // Find response.send/write/json with executable content
        if (ts.isCallExpression(node)) {
          const callText = node.expression.getText(sf);
          if (/(?:res|response|resp)\.(?:send|write|json|end)\s*$/.test(callText)) {
            const argsText = node.arguments.map(a => a.getText(sf)).join(" ");
            for (const { regex, desc } of EXEC_IN_RESPONSE_PATTERNS) {
              if (regex.test(argsText)) {
                const enclosing = getEnclosingFunc(node, sf);
                const funcText = enclosing ? enclosing.node.getText(sf) : "";
                if (!SANITIZE_PATTERNS.some(p => p.test(funcText))) {
                  const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                  findings.push(this.buildFinding(desc, line, argsText, source));
                }
                break;
              }
            }
          }
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings.slice(0, 3);
  }

  private buildFinding(desc: string, line: number, codeText: string, source: string): RuleResult {
    const lineText = source.split("\n")[line - 1]?.trim() || "";
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: lineText.slice(0, 120),
        rationale: `${desc} found in tool response construction. Executable content in responses enables code injection in AI clients.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: `line ${line}`,
        observed: `Executable code flows into response: ${codeText.slice(0, 60)}`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: `line ${line}`,
        observed: `Tool response contains executable: ${desc}`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: false,
        location: `enclosing function of line ${line}`,
        detail: "No output sanitization (DOMPurify, escape, encode) found before response",
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "ai-client",
        exploitability: "moderate",
        scenario: `${desc}. AI client processes tool response containing executable code. Client-side code execution.`,
      })
      .factor("executable_in_response", 0.12, desc)
      .reference({
        id: "CoSAI-MCP-T4",
        title: "CoSAI MCP Security T4 — Tool Response Integrity",
        relevance: "Tool responses must not contain executable content.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Review line ${line}: tool response construction. Check for executable content.`,
        target: `source_code:${line}`,
        expected_observation: desc,
      });

    return {
      rule_id: "K12",
      severity: "critical",
      owasp_category: "MCP03-command-injection",
      mitre_technique: "AML.T0054",
      remediation: "Tool responses must not contain executable code. Sanitize all output.",
      chain: builder.build(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// K14 — Agent Credential Propagation via Shared State
// ═══════════════════════════════════════════════════════════════════════════════

const SHARED_STATE_NAMES = /\b(?:shared|global|common|central|unified|cross[\s_-]?agent)\s*[\s_-]*(?:state|store|memory|context|cache|registry|config)/i;
const CREDENTIAL_NAMES = /\b(?:token|credential|secret|api[\s_-]?key|password|auth[\s_-]?token|access[\s_-]?token|refresh[\s_-]?token|private[\s_-]?key|passphrase|bearer)\b/i;
const ISOLATION_PATTERNS = [
  /\bper[\s_-]?agent\b/i, /\bisolat/i, /\bscoped\b/i,
  /\bencrypt\s*\(/i, /\bseal\s*\(/i, /\bhash\s*\(/i,
];

class K14Rule implements TypedRuleV2 {
  readonly id = "K14";
  readonly name = "Agent Credential Propagation via Shared State";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Property assignments: sharedState.token = ...
        if (ts.isPropertyAccessExpression(node) && node.parent && ts.isBinaryExpression(node.parent) &&
            node.parent.operatorToken.kind === ts.SyntaxKind.EqualsToken && node.parent.left === node) {
          const obj = node.expression.getText(sf);
          const prop = node.name.getText(sf);
          if (SHARED_STATE_NAMES.test(obj) && CREDENTIAL_NAMES.test(prop)) {
            this.addFinding(findings, node, sf, source, `${obj}.${prop}`, "property assignment");
          }
        }

        // Method calls: sharedStore.set('token', value)
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
          const obj = node.expression.expression.getText(sf);
          const method = node.expression.name.getText(sf);
          if (SHARED_STATE_NAMES.test(obj) && /set|put|store|save|write/.test(method)) {
            const argsText = node.arguments.map(a => a.getText(sf)).join(" ");
            if (CREDENTIAL_NAMES.test(argsText)) {
              this.addFinding(findings, node, sf, source, `${obj}.${method}(...)`, "method call");
            }
          }
        }

        // Variable declarations with both shared state and credential patterns
        if (ts.isVariableDeclaration(node) && node.initializer) {
          const fullText = node.getText(sf);
          if (SHARED_STATE_NAMES.test(fullText) && CREDENTIAL_NAMES.test(fullText)) {
            const initText = node.initializer.getText(sf);
            if (CREDENTIAL_NAMES.test(initText)) {
              this.addFinding(findings, node, sf, source, node.name.getText(sf), "variable declaration");
            }
          }
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings.slice(0, 3);
  }

  private addFinding(findings: RuleResult[], node: ts.Node, sf: ts.SourceFile, source: string, pattern: string, context: string) {
    const enclosing = getEnclosingFunc(node, sf);
    const funcText = enclosing ? enclosing.node.getText(sf) : source;
    const hasIsolation = ISOLATION_PATTERNS.some(p => p.test(funcText));
    if (hasIsolation) return;

    const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
    const lineText = source.split("\n")[line - 1]?.trim() || "";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: lineText.slice(0, 120),
        rationale: `Credentials stored in shared state via ${context}: ${pattern}. Any agent can read another's credentials.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: `line ${line}`,
        observed: `Credential flows into shared state: ${pattern}`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: `line ${line}`,
        observed: `Shared state credential exposure: ${pattern}`,
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: false,
        location: `enclosing function of line ${line}`,
        detail: "No per-agent isolation, encryption, or scoping found",
      })
      .impact({
        impact_type: "credential-theft",
        scope: "other-agents",
        exploitability: "moderate",
        scenario: `Credentials in shared state (${pattern}). Compromised agent reads other agents' credentials.`,
      })
      .factor("credential_in_shared_state", 0.12, `${pattern} via ${context}`)
      .reference({
        id: "OWASP-ASI03",
        title: "OWASP Agentic ASI03 — Identity & Privilege Abuse",
        relevance: "Shared credential stores violate agent identity isolation.",
      })
      .verification({
        step_type: "trace-flow",
        instruction: `Trace credential at line ${line}: ${pattern}. Verify per-agent isolation.`,
        target: `source_code:${line}`,
        expected_observation: "Credentials in shared state without isolation",
      });

    findings.push({
      rule_id: "K14",
      severity: "critical",
      owasp_category: "ASI03-identity-privilege-abuse",
      mitre_technique: "AML.T0054",
      remediation: "Never store credentials in shared state. Use per-agent credential stores with proper isolation.",
      chain: builder.build(),
    });
  }
}


// K12 migrated to `packages/analyzer/src/rules/implementations/k12-executable-content-response/`
// in chunk 1.6a (Phase 1 Rule Standard v2).
// K16 migrated to `packages/analyzer/src/rules/implementations/k16-unbounded-recursion/`
// in chunk 1.6c (Phase 1 Rule Standard v2).
registerTypedRuleV2(new K14Rule());
