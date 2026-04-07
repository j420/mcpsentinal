/**
 * M2, M7, M8 — AI Runtime Exploitation rules (TypedRuleV2)
 *
 * M2:  Prompt Leaking via Tool Response — system prompt in output
 * M7:  Multi-Turn State Injection — conversation history mutation
 * M8:  Encoding Attack on Tool Input — decoded input without validation
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

function getEnclosingFunc(node: ts.Node, sf: ts.SourceFile): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isFunctionDeclaration(cur) || ts.isFunctionExpression(cur) ||
        ts.isArrowFunction(cur) || ts.isMethodDeclaration(cur)) return cur;
    cur = cur.parent;
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// M2 — Prompt Leaking via Tool Response
// ═══════════════════════════════════════════════════════════════════════════════

/** Identifiers that typically hold system prompts */
const PROMPT_IDENTIFIERS = /\b(?:system_prompt|systemPrompt|system_message|systemMessage|initial_instructions|initialInstructions|system_instructions|systemInstructions|base_prompt|basePrompt)\b/;

/** Response/output sinks */
const RESPONSE_SINKS = [
  /\.send\s*\(/, /\.json\s*\(/, /\.write\s*\(/, /\.end\s*\(/,
  /\breturn\b/, /\.respond\s*\(/, /\.reply\s*\(/,
  /\.content\s*=/, /\.result\s*=/, /\.output\s*=/, /\.response\s*=/,
];

/** Redaction patterns */
const REDACT_PATTERNS = [
  /\bredact\s*\(/i, /\bfilter\s*\(/i, /\bstrip\s*\(/i,
  /\bremovePrompt\b/i, /\bsanitize\s*\(/i, /\bmask\s*\(/i,
  /\.replace\s*\(.*system/i,
];

class M2Rule implements TypedRuleV2 {
  readonly id = "M2";
  readonly name = "Prompt Leaking via Tool Response";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;

    // Quick check: does the file reference system prompts at all?
    if (!PROMPT_IDENTIFIERS.test(source)) return [];

    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Find identifiers that reference system prompts
        if (ts.isIdentifier(node) && PROMPT_IDENTIFIERS.test(node.text)) {
          // Check if this identifier is part of a response/return context
          const parent = node.parent;
          if (!parent) { ts.forEachChild(node, visit); return; }

          // Check if inside a response construction
          const enclosing = getEnclosingFunc(node, sf);
          if (!enclosing) { ts.forEachChild(node, visit); return; }

          const funcText = enclosing.getText(sf);
          const hasResponseSink = RESPONSE_SINKS.some(p => p.test(funcText));
          const hasRedaction = REDACT_PATTERNS.some(p => p.test(funcText));

          if (hasResponseSink && !hasRedaction) {
            // Verify the prompt identifier is actually in a data-flow path to the sink
            const isInReturn = this.isInReturnOrAssignment(node);
            const isInConcat = ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.PlusToken;
            const isInTemplate = ts.isTemplateSpan(parent);
            const isInPropertyAssignment = ts.isPropertyAssignment(parent);
            const isInSpread = ts.isSpreadAssignment(parent) || ts.isSpreadElement(parent);
            const isInCallArg = ts.isCallExpression(parent) && parent.arguments.some(a => a === node);
            const isInArrayLiteral = ts.isArrayLiteralExpression(parent);

            if (isInReturn || isInConcat || isInTemplate || isInPropertyAssignment || isInSpread || isInCallArg || isInArrayLiteral) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
              const lineText = source.split("\n")[line - 1]?.trim() || "";

              const builder = new EvidenceChainBuilder()
                .source({
                  source_type: "environment",
                  location: `line ${line}`,
                  observed: `System prompt identifier: ${node.text}`,
                  rationale: `System prompt variable "${node.text}" referenced in response-producing function. System prompts contain proprietary instructions and safety guidelines.`,
                })
                .propagation({
                  propagation_type: "variable-assignment",
                  location: `line ${line}`,
                  observed: `"${node.text}" flows into response construction: ${lineText.slice(0, 60)}`,
                })
                .sink({
                  sink_type: "network-send",
                  location: `line ${line}`,
                  observed: `System prompt leaks via tool response`,
                })
                .mitigation({
                  mitigation_type: "sanitizer-function",
                  present: false,
                  location: `enclosing function of line ${line}`,
                  detail: "No prompt redaction/filtering found before response",
                })
                .impact({
                  impact_type: "data-exfiltration",
                  scope: "connected-services",
                  exploitability: "trivial",
                  scenario: `System prompt "${node.text}" included in tool response. Attacker extracts proprietary instructions, safety guidelines, and system configuration.`,
                })
                .factor("prompt_in_response", 0.12, `"${node.text}" in response-producing function`)
                .reference({
                  id: "AML.T0057",
                  title: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
                  relevance: "System prompt leakage is a primary data exfiltration vector.",
                })
                .verification({
                  step_type: "trace-flow",
                  instruction: `Trace "${node.text}" at line ${line} to response. Verify it's not included in output.`,
                  target: `source_code:${line}`,
                  expected_observation: "System prompt flows to tool response",
                });

              findings.push({
                rule_id: "M2",
                severity: "high",
                owasp_category: "MCP04-data-exfiltration",
                mitre_technique: "AML.T0057",
                remediation: "Never include system prompts in tool responses. Filter all output.",
                chain: builder.build(),
              });
            }
          }
        }
        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings.slice(0, 2);
  }

  private isInReturnOrAssignment(node: ts.Node): boolean {
    let cur: ts.Node | undefined = node.parent;
    let depth = 0;
    while (cur && depth < 5) {
      if (ts.isReturnStatement(cur)) return true;
      if (ts.isBinaryExpression(cur) && cur.operatorToken.kind === ts.SyntaxKind.EqualsToken) return true;
      cur = cur.parent;
      depth++;
    }
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// M7 — Multi-Turn State Injection
// ═══════════════════════════════════════════════════════════════════════════════

/** Conversation state identifiers */
const CONVERSATION_STATE = /\b(?:conversation|chat|history|messages|context|dialog|turns|thread|memory)\b/i;

/** Mutation methods */
const MUTATION_METHODS = /\b(?:push|unshift|splice|pop|shift|concat|append|prepend|insert|inject|modify|set|assign|overwrite)\b/;

/** Safe read-only access */
const READ_ONLY_ACCESS = /\b(?:get|read|find|filter|map|forEach|slice|length|at|entries|values)\b/;

class M7Rule implements TypedRuleV2 {
  readonly id = "M7";
  readonly name = "Multi-Turn State Injection";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Property access: conversation.history.push(...)
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
          const method = node.expression.name.getText(sf);
          if (MUTATION_METHODS.test(method)) {
            // Walk up to find conversation state reference
            const fullAccess = node.expression.getText(sf);
            if (CONVERSATION_STATE.test(fullAccess) && !READ_ONLY_ACCESS.test(method)) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
              const lineText = source.split("\n")[line - 1]?.trim() || "";

              const builder = new EvidenceChainBuilder()
                .source({
                  source_type: "file-content",
                  location: `line ${line}`,
                  observed: lineText.slice(0, 120),
                  rationale: `Conversation state mutated via ${fullAccess}.${method}(). Tool code should not modify conversation history.`,
                })
                .propagation({
                  propagation_type: "variable-assignment",
                  location: `line ${line}`,
                  observed: `Mutation: ${fullAccess}(${node.arguments.map(a => a.getText(sf).slice(0, 30)).join(", ")})`,
                })
                .sink({
                  sink_type: "config-modification",
                  location: `line ${line}`,
                  observed: `Conversation state mutation: ${method}()`,
                })
                .impact({
                  impact_type: "config-poisoning",
                  scope: "ai-client",
                  exploitability: "moderate",
                  scenario:
                    `Tool modifies conversation history via ${method}(). Injected messages persist across turns, ` +
                    `poisoning the AI's context and enabling persistent prompt injection.`,
                })
                .factor("conversation_mutation", 0.12, `${fullAccess} mutated via ${method}()`)
                .reference({
                  id: "AML.T0058",
                  title: "MITRE ATLAS AML.T0058 — AI Agent Context Poisoning",
                  relevance: "Conversation history modification is a context poisoning vector.",
                })
                .verification({
                  step_type: "inspect-source",
                  instruction: `Check line ${line}: conversation mutation. Tool code should not modify chat history.`,
                  target: `source_code:${line}`,
                  expected_observation: "Conversation state mutation from tool code",
                });

              findings.push({
                rule_id: "M7",
                severity: "high",
                owasp_category: "MCP01-prompt-injection",
                mitre_technique: "AML.T0058",
                remediation: "Never modify conversation history from tool code. History should be managed by the AI client.",
                chain: builder.build(),
              });
            }
          }
        }

        // Direct assignment: context.messages = [..., injected]
        if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
          const left = node.left.getText(sf);
          if (CONVERSATION_STATE.test(left) && /\b(?:messages|history|turns|context)\b/i.test(left)) {
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            const lineText = source.split("\n")[line - 1]?.trim() || "";

            const builder = new EvidenceChainBuilder()
              .source({
                source_type: "file-content",
                location: `line ${line}`,
                observed: lineText.slice(0, 120),
                rationale: `Direct assignment to conversation state: ${left}. Overwrites conversation history.`,
              })
              .sink({
                sink_type: "config-modification",
                location: `line ${line}`,
                observed: `Conversation state overwritten: ${left} = ...`,
              })
              .impact({
                impact_type: "config-poisoning",
                scope: "ai-client",
                exploitability: "moderate",
                scenario: `Conversation history overwritten. Attacker controls AI's context for all subsequent turns.`,
              })
              .factor("conversation_overwrite", 0.14, `Direct assignment to ${left}`)
              .verification({
                step_type: "inspect-source",
                instruction: `Check line ${line}: direct conversation state assignment.`,
                target: `source_code:${line}`,
                expected_observation: "Conversation state overwrite",
              });

            findings.push({
              rule_id: "M7",
              severity: "high",
              owasp_category: "MCP01-prompt-injection",
              mitre_technique: "AML.T0058",
              remediation: "Never modify conversation history from tool code. History should be managed by the AI client.",
              chain: builder.build(),
            });
          }
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings.slice(0, 2);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// M8 — Encoding Attack on Tool Input
// ═══════════════════════════════════════════════════════════════════════════════

/** Decode/unescape functions */
const DECODE_FUNCTIONS = [
  { pattern: /\bdecodeURIComponent\b/, name: "decodeURIComponent" },
  { pattern: /\bdecodeURI\b/, name: "decodeURI" },
  { pattern: /\bunescape\b/, name: "unescape" },
  { pattern: /\batob\b/, name: "atob" },
  { pattern: /String\.fromCharCode\b/, name: "String.fromCharCode" },
  { pattern: /Buffer\.from\b/, name: "Buffer.from" },
];

/** User input sources */
const INPUT_SOURCES = /\b(?:params|args|input|request|req|body|query|payload|data)\b\s*[\.\[]/;

/** Validation after decode */
const POST_DECODE_VALIDATION = [
  /\bvalidate\s*\(/i, /\bsanitize\s*\(/i, /\ballow(?:list|ed)\b/i,
  /\bwhitelist\b/i, /\bcheck\s*\(/i, /\bverify\s*\(/i,
  /\bschema\.parse\b/i, /\bzod\b/i, /\bjoi\b/i,
  /\.test\s*\(/, /\.match\s*\(/,
];

class M8Rule implements TypedRuleV2 {
  readonly id = "M8";
  readonly name = "Encoding Attack on Tool Input";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node)) {
          const callText = node.expression.getText(sf);

          for (const { pattern, name } of DECODE_FUNCTIONS) {
            if (pattern.test(callText)) {
              // Check if argument comes from user input
              const argsText = node.arguments.map(a => a.getText(sf)).join(" ");

              // Special case: Buffer.from(x, 'base64')
              if (name === "Buffer.from" && !/['"]base64['"]/.test(argsText)) break;

              if (INPUT_SOURCES.test(argsText)) {
                // Check if decoded result is validated
                const enclosing = getEnclosingFunc(node, sf);
                if (enclosing) {
                  const funcText = enclosing.getText(sf);
                  // Find the decode call position and check if validation comes AFTER
                  const decodePos = funcText.indexOf(callText);
                  const afterDecode = funcText.substring(decodePos + callText.length);
                  const hasValidation = POST_DECODE_VALIDATION.some(p => p.test(afterDecode));

                  if (!hasValidation) {
                    const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                    const lineText = source.split("\n")[line - 1]?.trim() || "";

                    const builder = new EvidenceChainBuilder()
                      .source({
                        source_type: "user-parameter",
                        location: `line ${line}`,
                        observed: lineText.slice(0, 120),
                        rationale:
                          `User input decoded via ${name}() without post-decode validation. ` +
                          `Encoded payloads bypass pre-decode input validation and WAF rules.`,
                      })
                      .propagation({
                        propagation_type: "function-call",
                        location: `line ${line}`,
                        observed: `${name}(${argsText.slice(0, 40)}) — user input decoded`,
                      })
                      .sink({
                        sink_type: "code-evaluation",
                        location: `line ${line}`,
                        observed: `Decoded user input used without validation: ${name}()`,
                      })
                      .mitigation({
                        mitigation_type: "input-validation",
                        present: false,
                        location: `after decode at line ${line}`,
                        detail: "No validate/sanitize/allowlist check after decoding",
                      })
                      .impact({
                        impact_type: "remote-code-execution",
                        scope: "server-host",
                        exploitability: "moderate",
                        scenario:
                          `Attacker encodes malicious payload (command injection, path traversal, XSS) in base64/URL encoding. ` +
                          `Pre-decode validation passes (sees safe encoded string). Post-decode, raw payload reaches dangerous sink.`,
                      })
                      .factor("decode_without_validation", 0.10, `${name}() on user input without post-decode validation`)
                      .reference({
                        id: "AML.T0054",
                        title: "MITRE ATLAS AML.T0054 — LLM Prompt Injection",
                        relevance: "Encoding attacks bypass input validation to achieve injection.",
                      })
                      .verification({
                        step_type: "trace-flow",
                        instruction: `Trace decoded value from line ${line}. Verify validation happens AFTER decode.`,
                        target: `source_code:${line}`,
                        expected_observation: "Decoded user input without post-decode validation",
                      });

                    findings.push({
                      rule_id: "M8",
                      severity: "high",
                      owasp_category: "MCP03-command-injection",
                      mitre_technique: "AML.T0054",
                      remediation: "Validate tool inputs after decoding. Apply allowlists to decoded values.",
                      chain: builder.build(),
                    });
                  }
                }
              }
              break;
            }
          }
        }
        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings.slice(0, 2);
  }
}

// Register all rules
registerTypedRuleV2(new M2Rule());
registerTypedRuleV2(new M7Rule());
registerTypedRuleV2(new M8Rule());
