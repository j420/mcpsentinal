/**
 * K12, K14, K16, K20 — K-Compliance structural rules (TypedRuleV2)
 *
 * K12: Executable Content in Tool Response — AST detection of executable code in responses
 * K14: Agent Credential Propagation — credentials in shared state
 * K16: Unbounded Recursion — recursive functions without depth limits
 * K20: Insufficient Audit Context — logging without structured context
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

// ═══════════════════════════════════════════════════════════════════════════════
// K16 — Unbounded Recursion / Missing Depth Limits
// ═══════════════════════════════════════════════════════════════════════════════

const DEPTH_PATTERNS = [
  /\bdepth\b/i, /\blevel\b/i, /\bmax(?:Depth|Level|Recursion)\b/i,
  /\blimit\b/i, /\bbound\b/i, /\bguard\b/i, /\bMAX_/,
];

class K16Rule implements TypedRuleV2 {
  readonly id = "K16";
  readonly name = "Unbounded Recursion";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Check function declarations for self-recursion
        if (ts.isFunctionDeclaration(node) && node.name && node.body) {
          const funcName = node.name.getText(sf);
          this.checkRecursion(node, funcName, sf, source, findings);
        }

        // Check method declarations
        if (ts.isMethodDeclaration(node) && node.name && node.body) {
          const funcName = node.name.getText(sf);
          this.checkRecursion(node, funcName, sf, source, findings);
        }

        // Check variable-declared functions
        if (ts.isVariableDeclaration(node) && node.initializer &&
            (ts.isFunctionExpression(node.initializer) || ts.isArrowFunction(node.initializer))) {
          const funcName = node.name.getText(sf);
          this.checkRecursion(node.initializer, funcName, sf, source, findings);
        }

        // Check infinite loops
        if (ts.isWhileStatement(node)) {
          const cond = node.expression.getText(sf);
          if (cond === "true" || cond === "1") {
            const bodyText = node.statement.getText(sf);
            const hasExit = /\bbreak\b|\breturn\b|\bthrow\b/.test(bodyText);
            const hasTimeout = /\btimeout\b|\bsetTimeout\b|\bdeadline\b/i.test(bodyText);
            if (!hasExit && !hasTimeout) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
              findings.push(this.buildFinding("Infinite loop without exit", line, source, "while(true) without break/return/timeout"));
            }
          }
        }

        if (ts.isForStatement(node) && !node.condition) {
          const bodyText = node.statement.getText(sf);
          const hasExit = /\bbreak\b|\breturn\b|\bthrow\b/.test(bodyText);
          if (!hasExit) {
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            findings.push(this.buildFinding("Infinite for loop without exit", line, source, "for(;;) without break/return"));
          }
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings.slice(0, 3);
  }

  private checkRecursion(funcNode: ts.Node, funcName: string, sf: ts.SourceFile, source: string, findings: RuleResult[]) {
    let hasSelfCall = false;

    const checkCalls = (n: ts.Node): void => {
      if (ts.isCallExpression(n)) {
        const callText = n.expression.getText(sf);
        if (callText === funcName || callText.endsWith(`.${funcName}`)) {
          hasSelfCall = true;
        }
      }
      ts.forEachChild(n, checkCalls);
    };
    ts.forEachChild(funcNode, checkCalls);

    if (!hasSelfCall) return;

    // Check if function has depth limiting
    const funcText = funcNode.getText(sf);
    const hasDepthCheck = DEPTH_PATTERNS.some(p => p.test(funcText));
    if (hasDepthCheck) return;

    const line = sf.getLineAndCharacterOfPosition(funcNode.getStart(sf)).line + 1;
    findings.push(this.buildFinding(
      `Recursive function "${funcName}" without depth limit`, line, source,
      `${funcName}() calls itself without depth/level/limit parameter`,
    ));
  }

  private buildFinding(desc: string, line: number, source: string, detail: string): RuleResult {
    const lineText = source.split("\n")[line - 1]?.trim() || "";
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: lineText.slice(0, 120),
        rationale: `${desc}. Unbounded recursion causes stack overflow; infinite loops cause CPU exhaustion.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: `line ${line}`,
        observed: detail,
      })
      .mitigation({
        mitigation_type: "rate-limit",
        present: false,
        location: `function at line ${line}`,
        detail: "No depth limit, max recursion, or timeout guard found",
      })
      .impact({
        impact_type: "denial-of-service",
        scope: "server-host",
        exploitability: "moderate",
        scenario: `${desc}. Stack overflow or CPU exhaustion crashes the server.`,
      })
      .factor("unbounded_recursion", 0.10, detail)
      .reference({
        id: "OWASP-ASI08",
        title: "OWASP Agentic ASI08 — Denial of Service",
        relevance: "Unbounded recursion/loops are a primary DoS vector.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Check line ${line}: "${lineText.slice(0, 60)}". Add depth limit parameter.`,
        target: `source_code:${line}`,
        expected_observation: desc,
      });

    return {
      rule_id: "K16",
      severity: "high",
      owasp_category: "MCP07-insecure-config",
      mitre_technique: null,
      remediation: "Add recursion depth limits. Add timeout/circuit breakers to all loops.",
      chain: builder.build(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// K20 — Insufficient Audit Context in Logging
// ═══════════════════════════════════════════════════════════════════════════════

/** Audit-relevant event keywords in log messages */
const AUDIT_EVENT_KEYWORDS = /\b(?:request|handling|processing|received|creating|deleting|updating|authenticat|authoriz|login|logout|access|denied|granted|failed|error|reject)\b/i;

/** Structured logging context patterns */
const STRUCTURED_CONTEXT = [
  /\bcorrelationId\b/i, /\brequestId\b/i, /\buserId\b/i,
  /\btraceId\b/i, /\bspanId\b/i, /\bsessionId\b/i,
  /\baction\b/i, /\bresource\b/i,
];

/** Structured logger libraries — if imported, the file likely has structured logging */
const STRUCTURED_LOGGERS = /\b(?:pino|winston|bunyan|log4js|structured|correlationId|requestId)\b/i;

class K20Rule implements TypedRuleV2 {
  readonly id = "K20";
  readonly name = "Insufficient Audit Context in Logging";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;

    // Skip if file uses structured logger
    if (STRUCTURED_LOGGERS.test(source)) return [];

    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node)) {
          const callText = node.expression.getText(sf);

          // console.log("request...") — no structured context
          if (/^console\.(?:log|info|warn|error)$/.test(callText)) {
            if (node.arguments.length >= 1 && ts.isStringLiteral(node.arguments[0])) {
              const msg = node.arguments[0].text;
              if (AUDIT_EVENT_KEYWORDS.test(msg)) {
                // Check if any argument provides structured context
                const hasContext = node.arguments.length > 1 &&
                  node.arguments.slice(1).some(a => {
                    const t = a.getText(sf);
                    return STRUCTURED_CONTEXT.some(p => p.test(t));
                  });
                if (!hasContext) {
                  const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                  findings.push(this.buildFinding(line, callText, msg, source));
                }
              }
            }
          }

          // logger.info("message") without object context — string-only logging
          if (/^(?:logger|log)\.(?:info|warn|error|debug)$/.test(callText)) {
            if (node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])) {
              const msg = node.arguments[0].text;
              if (AUDIT_EVENT_KEYWORDS.test(msg)) {
                const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                findings.push(this.buildFinding(line, callText, msg, source));
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

  private buildFinding(line: number, callText: string, msg: string, source: string): RuleResult {
    const lineText = source.split("\n")[line - 1]?.trim() || "";
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: lineText.slice(0, 120),
        rationale:
          `Audit event "${msg.slice(0, 40)}" logged via ${callText}() without structured context. ` +
          `Missing request ID, user ID, or action context makes audit trails unusable for incident investigation.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: `line ${line}`,
        observed: `Unstructured audit log: ${callText}("${msg.slice(0, 40)}")`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "connected-services",
        exploitability: "complex",
        scenario:
          `Audit event logged without correlation ID or user context. During incident investigation, ` +
          `this log entry cannot be correlated with the request, user, or session that triggered it.`,
      })
      .factor("unstructured_audit_log", 0.05, `${callText}() with string-only audit message, no structured context`)
      .reference({
        id: "ISO-27001-A.8.15",
        title: "ISO 27001 A.8.15 — Logging",
        relevance: "Audit logs must contain sufficient context for investigation.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Review line ${line}: ${callText}("${msg.slice(0, 30)}"). Add { requestId, userId, action } context.`,
        target: `source_code:${line}`,
        expected_observation: "Audit log without structured context",
      });

    return {
      rule_id: "K20",
      severity: "medium",
      owasp_category: "MCP09-logging-monitoring",
      mitre_technique: null,
      remediation: "Use structured logging with request ID, user ID, action, and timestamp in every log entry.",
      chain: builder.build(),
    };
  }
}

// Register all rules
registerTypedRuleV2(new K12Rule());
registerTypedRuleV2(new K14Rule());
registerTypedRuleV2(new K16Rule());
registerTypedRuleV2(new K20Rule());
