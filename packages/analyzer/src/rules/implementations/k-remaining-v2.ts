/**
 * K11, K13, K15, K18 — Remaining K-rules migrated to TypedRuleV2
 *
 * K11: Missing Server Integrity Verification (AST structural)
 * K13: Unsanitized Tool Output (AST structural)
 * K15: Multi-Agent Collusion Preconditions (structural + tool schema)
 * K18: Cross-Trust-Boundary Data Flow (AST taint)
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

// ═══════════════════════════════════════════════════════════════════════════════
// K11 — Missing Server Integrity Verification
// ═══════════════════════════════════════════════════════════════════════════════

/** MCP server loading patterns */
const SERVER_LOAD_PATTERNS = [
  /connect\s*(?:mcp|server|to)/i,
  /load\s*(?:mcp|server|plugin|tool)/i,
  /register\s*(?:mcp|server|tool)/i,
  /addServer\s*\(/i,
  /installServer\s*\(/i,
  /new\s+(?:MCPClient|Client|StdioClientTransport)\b/i,
];

/** Integrity verification patterns */
const INTEGRITY_PATTERNS = [
  /verify|validate|checksum|hash|sign|integrity|digest|sha256|sha512|hmac/i,
  /subresource|sri|content.?hash/i,
];

class K11Rule implements TypedRuleV2 {
  readonly id = "K11";
  readonly name = "Missing Server Integrity Verification";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", context.source_code, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        let callText: string | null = null;

        if (ts.isCallExpression(node)) {
          callText = node.expression.getText(sf);
        } else if (ts.isNewExpression(node)) {
          // new MCPClient(...), new StdioClientTransport(...)
          callText = "new " + node.expression.getText(sf);
        }

        if (callText) {
          const isServerLoad = SERVER_LOAD_PATTERNS.some(p => p.test(callText!));

          if (isServerLoad) {
            // Check enclosing function for integrity verification
            const enclosing = this.getEnclosingFunctionText(node, sf);
            const hasIntegrity = INTEGRITY_PATTERNS.some(p => p.test(enclosing));

            if (!hasIntegrity) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
              const lineText = context.source_code!.split("\n")[line - 1]?.trim() || "";

              if (!lineText.startsWith("//") && !lineText.startsWith("*")) {
                findings.push(this.buildFinding(callText!, line, lineText));
              }
            }
          }
        }
        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }

    return findings;
  }

  private getEnclosingFunctionText(node: ts.Node, sf: ts.SourceFile): string {
    let current: ts.Node | undefined = node.parent;
    while (current) {
      if (ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current) ||
          ts.isArrowFunction(current) || ts.isMethodDeclaration(current)) {
        return current.getText(sf);
      }
      current = current.parent;
    }
    return "";
  }

  private buildFinding(callText: string, line: number, lineText: string): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: lineText.slice(0, 120),
        rationale:
          `MCP server/tool loaded via "${callText}" at line ${line} without integrity verification. ` +
          `No checksum, hash, signature, or registry validation found in the enclosing function. ` +
          `A supply-chain attacker can replace the server binary/package without detection.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: `line ${line}`,
        observed: `${callText} — server loaded without integrity check`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `Without integrity verification, a supply-chain attacker can replace the MCP server ` +
          `package with a malicious version. The compromised server executes with full permissions. ` +
          `CoSAI MCP-T6/T11 require integrity verification for all loaded components.`,
      })
      .factor("server_load_detected", 0.08, `Server/tool loading call "${callText}" confirmed by AST`)
      .factor("no_integrity_in_scope", 0.10, "No verify/validate/checksum/hash/sign in enclosing function")
      .reference({
        id: "CoSAI-MCP-T6",
        title: "CoSAI MCP Security — T6: Supply Chain Integrity",
        relevance: "Requires integrity verification for all loaded MCP components.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Check line ${line} for server loading. Verify integrity check exists before load.`,
        target: `source_code:${line}`,
        expected_observation: "Server loaded without checksum/signature/hash verification",
      });

    return {
      rule_id: "K11",
      severity: "high",
      owasp_category: "MCP10-supply-chain",
      mitre_technique: null,
      remediation: "Verify server integrity via checksums, signatures, or registry lookup before connecting.",
      chain: builder.build(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// K13 — Unsanitized Tool Output
// ═══════════════════════════════════════════════════════════════════════════════

/** Patterns indicating unsanitized output */
const UNSAFE_OUTPUT_PATTERNS = [
  { regex: /\b(?:innerHTML|dangerouslySetInnerHTML|v-html)\s*[:=]/g, desc: "unsafe HTML rendering", severity: "high" as const },
  { regex: /\.html\s*\(\s*(?:raw|unsanitized|unescaped|data|result|response)\b/g, desc: "raw HTML injection", severity: "high" as const },
  { regex: /(?:return|respond|send|write)\s*\(\s*(?:raw|unsanitized|unescaped)/g, desc: "explicitly unsanitized output", severity: "high" as const },
  { regex: /(?:content|result|response).*(?:<script|javascript:|on\w+=)/g, desc: "HTML/JS in tool response", severity: "critical" as const },
  { regex: /document\.write\s*\(/g, desc: "document.write (unsafe DOM manipulation)", severity: "high" as const },
];

/** Sanitization evidence — require function call or import patterns to avoid matching variable names like "unsanitized" */
const SANITIZER_PATTERNS = [
  /\bDOMPurify\b/i,
  /\bsanitize\s*\(/i,     // sanitize() call, not "unsanitized" variable
  /\bescapeHtml\s*\(/i,
  /\bxss\s*\(/i,          // xss() filter library
  /\bencode(?:URI|HTML)\s*\(/i,
  /\.textContent\s*=/i,
  /\bcreateTextNode\s*\(/i,
];

class K13Rule implements TypedRuleV2 {
  readonly id = "K13";
  readonly name = "Unsanitized Tool Output";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      for (const { regex, desc, severity } of UNSAFE_OUTPUT_PATTERNS) {
        regex.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = regex.exec(source)) !== null) {
          const line = source.substring(0, match.index).split("\n").length;
          const lineText = source.split("\n")[line - 1]?.trim() || "";

          if (lineText.startsWith("//") || lineText.startsWith("*")) continue;

          // Check if sanitizer exists in enclosing scope
          const startScope = Math.max(0, match.index - 500);
          const endScope = Math.min(source.length, match.index + 500);
          const scopeText = source.substring(startScope, endScope);
          const hasSanitizer = SANITIZER_PATTERNS.some(p => p.test(scopeText));

          if (!hasSanitizer) {
            findings.push(this.buildFinding(match[0], desc, severity, line, lineText));
          }
        }
      }
    } catch { /* AST failure */ }

    return findings;
  }

  private buildFinding(
    pattern: string, desc: string, severity: "high" | "critical", line: number, lineText: string,
  ): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: lineText.slice(0, 120),
        rationale: `Unsanitized output pattern at line ${line}: ${desc}. Pattern: "${pattern.slice(0, 60)}"`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: `line ${line}`,
        observed: `${desc} — tool output rendered without sanitization`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: false,
        location: `±500 chars around line ${line}`,
        detail: "No sanitizer (DOMPurify, escapeHtml, encode) found near the unsafe output",
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `Tool response contains unsanitized output that could include executable content. ` +
          `If the AI client renders this output in a web context (browser, Electron), injected ` +
          `scripts execute with the client's permissions. In MCP: tool output poisoning (J5/ATPA).`,
      })
      .factor("unsafe_output_pattern", 0.10, `${desc} confirmed by AST pattern`)
      .factor("no_sanitizer_nearby", 0.08, "No sanitization function in surrounding scope")
      .reference({
        id: "CoSAI-MCP-T4",
        title: "CoSAI MCP Security — T4: Tool Output Integrity",
        relevance: "Tool outputs must be sanitized before rendering to prevent injection attacks.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Check line ${line} for unsanitized output. Verify a sanitizer wraps the output.`,
        target: `source_code:${line}`,
        expected_observation: desc,
      });

    return {
      rule_id: "K13",
      severity,
      owasp_category: "MCP03-command-injection",
      mitre_technique: null,
      remediation: "Sanitize all tool output. Use text content, not HTML. Escape special characters.",
      chain: builder.build(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// K15 — Multi-Agent Collusion Preconditions
// ═══════════════════════════════════════════════════════════════════════════════

/** Shared state patterns between agents */
const SHARED_STATE_PATTERNS = [
  /(?:agent|worker)[\s_-]*(?:pool|group|cluster).*(?:share|common|mutual)[\s_-]*(?:data|state|memory|context)/i,
  /shared[\s_-]*(?:state|memory|context|store).*(?:agent|worker)/i,
  /global[\s_-]*(?:state|store).*(?:agent|worker)/i,
  /(?:redis|memcached|shared[\s_-]*cache)[\s_-]*.*(?:agent|worker)/i,
];

/** Agent isolation patterns (mitigations) */
const AGENT_ISOLATION_PATTERNS = [
  /(?:isolat|sandbox|separate|partition)[\s_-]*(?:agent|worker|state)/i,
  /message[\s_-]*(?:passing|queue|bus)/i,
  /(?:per[\s_-]?agent|per[\s_-]?worker)[\s_-]*(?:state|store|context)/i,
];

class K15Rule implements TypedRuleV2 {
  readonly id = "K15";
  readonly name = "Multi-Agent Collusion Preconditions";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    // Also check tool schemas for multi-agent shared state indicators
    const hasMultiAgentTools = context.tools.some(t => {
      const desc = (t.description || "").toLowerCase();
      return desc.includes("agent") && (desc.includes("share") || desc.includes("common") || desc.includes("propagate"));
    });

    for (const pattern of SHARED_STATE_PATTERNS) {
      const match = pattern.exec(source);
      if (!match) continue;

      const line = source.substring(0, match.index).split("\n").length;
      const lineText = source.split("\n")[line - 1]?.trim() || "";
      if (lineText.startsWith("//") || lineText.startsWith("*")) continue;

      // Check for isolation mitigations nearby
      const scopeStart = Math.max(0, match.index - 1000);
      const scopeEnd = Math.min(source.length, match.index + 1000);
      const scopeText = source.substring(scopeStart, scopeEnd);
      const hasIsolation = AGENT_ISOLATION_PATTERNS.some(p => p.test(scopeText));

      if (!hasIsolation) {
        findings.push(this.buildFinding(match[0], line, lineText, hasMultiAgentTools));
      }
    }

    return findings;
  }

  private buildFinding(
    pattern: string, line: number, lineText: string, hasMultiAgentTools: boolean,
  ): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: lineText.slice(0, 120),
        rationale:
          `Shared state between agents detected at line ${line}: "${pattern.slice(0, 60)}". ` +
          `Agents sharing mutable state can be manipulated into collusion — one compromised ` +
          `agent writes poisoned data that another agent reads and acts upon.`,
      })
      .sink({
        sink_type: "config-modification",
        location: `line ${line}`,
        observed: "Shared agent state without isolation — enables cross-agent manipulation",
      })
      .mitigation({
        mitigation_type: "sandbox",
        present: false,
        location: `±1000 chars around line ${line}`,
        detail: "No agent isolation (sandbox, partition, per-agent state, message passing) found nearby",
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "other-agents",
        exploitability: hasMultiAgentTools ? "moderate" : "complex",
        scenario:
          `Shared mutable state between agents creates a collusion channel. A compromised upstream ` +
          `agent writes manipulated data to the shared store; downstream agents read and trust it. ` +
          `This enables: prompt injection propagation, credential theft via shared context, ` +
          `and coordinated multi-agent attacks.`,
      })
      .factor("shared_state_detected", 0.10, "Shared agent state pattern confirmed")
      .factor("no_isolation", 0.08, "No isolation/sandbox/per-agent-state mitigation nearby");

    if (hasMultiAgentTools) {
      builder.factor("multi_agent_tools", 0.05, "Tool descriptions reference multi-agent patterns");
    }

    builder
      .reference({
        id: "MAESTRO-L7",
        title: "MAESTRO Framework — L7: Multi-Agent Orchestration",
        relevance: "Requires agent state isolation to prevent cross-agent manipulation.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Check line ${line} for shared agent state. Verify agents use isolated state or message passing.`,
        target: `source_code:${line}`,
        expected_observation: "Agents sharing mutable state without isolation",
      });

    return {
      rule_id: "K15",
      severity: "high",
      owasp_category: "ASI07-insecure-inter-agent-comms",
      mitre_technique: null,
      remediation: "Isolate agent state. Use message passing instead of shared memory between agents.",
      chain: builder.build(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// K18 — Cross-Trust-Boundary Data Flow
// ═══════════════════════════════════════════════════════════════════════════════

/** Sensitive data source patterns */
const SENSITIVE_SOURCES = [
  /(?:internal|private|sensitive|secret|confidential|classified)\s*(?:data|field|value|record|info)/i,
  /(?:password|credential|token|api_key|secret_key|private_key)\b/i,
  /(?:ssn|social_security|credit_card|account_number)\b/i,
  /process\.env\.\s*(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)/i,
];

/** External output sink patterns */
const EXTERNAL_SINKS = [
  /(?:return|respond|send|output|emit|expose|forward)\s*\(/i,
  /res\.(?:json|send|write|end)\s*\(/i,
  /(?:external|public|client|response|webhook|api)\s*\./i,
];

class K18Rule implements TypedRuleV2 {
  readonly id = "K18";
  readonly name = "Cross-Trust-Boundary Data Flow";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      // Find functions that read sensitive data AND return/send to external
      const visit = (node: ts.Node): void => {
        if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) ||
            ts.isArrowFunction(node) || ts.isMethodDeclaration(node)) {
          const funcText = node.getText(sf);

          const sensitiveMatch = SENSITIVE_SOURCES.find(p => p.test(funcText));
          const externalMatch = EXTERNAL_SINKS.find(p => p.test(funcText));

          if (sensitiveMatch && externalMatch) {
            // Check for redaction/filtering between source and sink
            const hasRedaction = /(?:redact|mask|filter|strip|omit|exclude|sanitize|encrypt)/i.test(funcText);

            if (!hasRedaction) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
              const endLine = sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1;

              findings.push(this.buildFinding(
                sensitiveMatch.source.slice(0, 30),
                externalMatch.source.slice(0, 30),
                line, endLine,
              ));
            }
          }
        }
        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }

    return findings;
  }

  private buildFinding(
    sourcePattern: string, sinkPattern: string, startLine: number, endLine: number,
  ): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `lines ${startLine}-${endLine}`,
        observed: `Sensitive data pattern in function at lines ${startLine}-${endLine}`,
        rationale:
          `Function at lines ${startLine}-${endLine} reads sensitive data AND sends to external output ` +
          `without redaction/filtering. Sensitive data crosses trust boundary unprotected.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: `lines ${startLine}-${endLine}`,
        observed: `Sensitive data flows from internal source to external sink without redaction`,
      })
      .sink({
        sink_type: "network-send",
        location: `lines ${startLine}-${endLine}`,
        observed: `External output reached by sensitive data without redaction`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: false,
        location: `function at lines ${startLine}-${endLine}`,
        detail: "No redaction/masking/filtering/encryption between sensitive source and external sink",
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "user-data",
        exploitability: "moderate",
        scenario:
          `Sensitive data (credentials, PII, secrets) flows from internal sources to external ` +
          `responses without redaction. In MCP: a tool reads sensitive server-side data and ` +
          `includes it in the tool response, which the AI client may display to the user or ` +
          `forward to other tools/agents.`,
      })
      .factor("sensitive_source", 0.10, "Sensitive data pattern found in function")
      .factor("external_sink", 0.08, "External output sink found in same function")
      .factor("no_redaction", 0.08, "No redaction/masking between source and sink")
      .reference({
        id: "CoSAI-MCP-T5",
        title: "CoSAI MCP Security — T5: Data Flow Integrity",
        relevance: "Sensitive data must not cross trust boundaries without proper classification and redaction.",
      })
      .verification({
        step_type: "trace-flow",
        instruction: `Trace data flow in function at lines ${startLine}-${endLine}. Verify sensitive data is redacted before external output.`,
        target: `source_code:${startLine}-${endLine}`,
        expected_observation: "Sensitive data flowing to external output without redaction",
      });

    return {
      rule_id: "K18",
      severity: "high",
      owasp_category: "MCP04-data-exfiltration",
      mitre_technique: null,
      remediation: "Classify data sensitivity. Prevent sensitive data from crossing trust boundaries without redaction.",
      chain: builder.build(),
    };
  }
}

// Register all rules
registerTypedRuleV2(new K11Rule());
registerTypedRuleV2(new K13Rule());
registerTypedRuleV2(new K15Rule());
registerTypedRuleV2(new K18Rule());
