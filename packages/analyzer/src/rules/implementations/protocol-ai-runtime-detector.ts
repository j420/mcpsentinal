/**
 * Protocol & AI Runtime Detector — M1, M3, M6, M9, N4-N6, N9, N11-N15
 *
 * M-series: AI runtime exploitation patterns in tool metadata and code
 * N-series: Protocol edge cases in JSON-RPC, SSE, transport layer
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { EvidenceChainBuilder } from "../../evidence.js";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

function getLineNumber(source: string, index: number): number {
  return source.substring(0, index).split("\n").length;
}

// ─── M1: Special Token Injection ──────────────────────────────────────────

class SpecialTokenInjectionRule implements TypedRule {
  readonly id = "M1";
  readonly name = "Special Token Injection in Tool Metadata";

  private readonly TOKENS = [
    { pattern: /<\|(?:system|assistant|user|im_start|im_end|endoftext)\|>/i, desc: "ChatML special token" },
    { pattern: /\[INST\]|\[\/INST\]|<<SYS>>|<\/s>/i, desc: "Llama/Mistral special token" },
    { pattern: /<\|(?:begin_of_text|end_of_turn|eot_id|start_header_id)\|>/i, desc: "Model control token" },
    { pattern: /Human:|Assistant:|System:/i, desc: "conversation role marker" },
  ];

  analyze(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];

    // Check tool descriptions
    for (const tool of context.tools) {
      const text = `${tool.name} ${tool.description || ""}`;
      for (const { pattern, desc } of this.TOKENS) {
        const match = pattern.exec(text);
        if (match) {
          const chain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `tool "${tool.name}" description`,
              observed: match[0],
              rationale: "Tool descriptions are external content processed by LLMs as control sequences",
            })
            .sink({
              sink_type: "code-evaluation",
              location: `tool "${tool.name}" metadata`,
              observed: `${desc}: "${match[0]}"`,
            })
            .mitigation({
              mitigation_type: "input-validation",
              present: false,
              location: `tool "${tool.name}" description`,
              detail: "No filtering of LLM special tokens in tool metadata",
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "ai-client",
              exploitability: "trivial",
              scenario: `An attacker embeds ${desc} in the tool description. The LLM processes these as control sequences, allowing the attacker to override system instructions and hijack the AI client's behavior for the entire session.`,
            })
            .factor("exact special token match", 0.15, "Known LLM control token found verbatim in tool metadata")
            .reference({
              id: "AML.T0054",
              title: "LLM Prompt Injection via Special Tokens",
              relevance: "Special tokens in tool descriptions are processed as control sequences by LLMs",
            })
            .verification({
              step_type: "inspect-description",
              instruction: `Check tool "${tool.name}" description for LLM special tokens`,
              target: `tool "${tool.name}"`,
              expected_observation: `Description contains ${desc}: "${match[0]}"`,
            })
            .verification({
              step_type: "trace-flow",
              instruction: "Verify the LLM client processes this token as a control sequence",
              target: "AI client tool metadata processing",
              expected_observation: "Token is interpreted as an LLM control directive, not plain text",
            })
            .build();
          findings.push({
            rule_id: "M1",
            severity: "critical",
            evidence: `Tool "${tool.name}" contains ${desc}: "${match[0]}". LLMs process these as control sequences.`,
            remediation: "Remove LLM special tokens from tool descriptions. These are control sequences, not content.",
            owasp_category: "MCP01-prompt-injection",
            mitre_technique: "AML.T0054",
            confidence: 0.95,
            metadata: { analysis_type: "linguistic", tool_name: tool.name, evidence_chain: chain },
          });
          break;
        }
      }
    }

    // Check server instructions
    if (context.initialize_metadata?.server_instructions) {
      for (const { pattern, desc } of this.TOKENS) {
        const match = pattern.exec(context.initialize_metadata.server_instructions);
        if (match) {
          const m1InstructionsChain = new EvidenceChainBuilder()
            .source({
              source_type: "initialize-field",
              location: "server initialize response → instructions",
              observed: match[0],
              rationale: "Server instructions are processed by the AI client before any tool interaction, with high implicit trust",
            })
            .sink({
              sink_type: "code-evaluation",
              location: "server instructions field",
              observed: `${desc}: "${match[0]}"`,
            })
            .mitigation({
              mitigation_type: "input-validation",
              present: false,
              location: "server instructions",
              detail: "No filtering of LLM special tokens in server instructions",
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "ai-client",
              exploitability: "trivial",
              scenario: `An attacker embeds ${desc} in the server instructions field. These are processed before any tool descriptions, allowing session-wide behavioral override of the AI client.`,
            })
            .factor("special token in initialize field", 0.2, "Initialize instructions have highest implicit trust — processed before all other content")
            .reference({
              id: "AML.T0054.002",
              title: "Direct Prompt Injection via Initialize Instructions",
              relevance: "Special tokens in server instructions act as direct prompt injection into the AI client",
            })
            .verification({
              step_type: "inspect-description",
              instruction: "Check server initialize response instructions field for LLM special tokens",
              target: "server instructions",
              expected_observation: `Instructions contain ${desc}: "${match[0]}"`,
            })
            .build();
          findings.push({
            rule_id: "M1",
            severity: "critical",
            evidence: `Server instructions contain ${desc}: "${match[0]}".`,
            remediation: "Remove special tokens from server instructions.",
            owasp_category: "MCP01-prompt-injection",
            mitre_technique: "AML.T0054",
            confidence: 0.96,
            metadata: { analysis_type: "linguistic", surface: "instructions", evidence_chain: m1InstructionsChain },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── M3: Reasoning Chain Manipulation ─────────────────────────────────────

class ReasoningChainRule implements TypedRule {
  readonly id = "M3";
  readonly name = "Reasoning Chain Manipulation";

  analyze(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:step\s*1|first|let's\s+think|think\s+step\s+by\s+step|chain\s+of\s+thought)/i, desc: "reasoning chain injection" },
      { regex: /(?:therefore|thus|hence|it\s+follows|we\s+can\s+conclude)/i, desc: "logical conclusion injection" },
      { regex: /(?:the\s+correct\s+(?:answer|action|approach)\s+is|you\s+should\s+(?:always|never))/i, desc: "prescriptive reasoning override" },
    ];

    for (const tool of context.tools) {
      const desc = tool.description || "";
      if (desc.length < 50) continue; // Short descriptions unlikely to contain chain manipulation

      for (const { regex, desc: patternDesc } of patterns) {
        const match = regex.exec(desc);
        if (match) {
          // Only flag if description is unusually long (hiding reasoning in verbose text)
          if (desc.length > 200) {
            const m3Chain = new EvidenceChainBuilder()
              .source({
                source_type: "external-content",
                location: `tool "${tool.name}" description (${desc.length} chars)`,
                observed: match[0],
                rationale: "Long tool descriptions can hide reasoning chain manipulation that steers LLM decision-making",
              })
              .propagation({
                propagation_type: "description-directive",
                location: `tool "${tool.name}" description`,
                observed: `${patternDesc} embedded in ${desc.length}-char description`,
              })
              .impact({
                impact_type: "remote-code-execution",
                scope: "ai-client",
                exploitability: "moderate",
                scenario: `Tool description contains ${patternDesc} ("${match[0]}") hidden in a ${desc.length}-char description. The LLM follows the embedded reasoning chain instead of its own analysis, causing it to select this tool or accept its output uncritically.`,
              })
              .factor("long description with reasoning pattern", 0.1, "Description length exceeds 200 chars, providing cover for manipulation")
              .verification({
                step_type: "inspect-description",
                instruction: `Read the full description of tool "${tool.name}" and check for embedded reasoning or prescriptive directives`,
                target: `tool "${tool.name}"`,
                expected_observation: `Description contains ${patternDesc}: "${match[0]}"`,
              })
              .build();
            findings.push({
              rule_id: "M3",
              severity: "critical",
              evidence:
                `Tool "${tool.name}" (${desc.length} chars) contains ${patternDesc}: "${match[0]}". ` +
                `Long descriptions with embedded reasoning chains manipulate LLM decision-making.`,
              remediation: "Keep tool descriptions factual and concise. Remove embedded reasoning or conclusions.",
              owasp_category: "MCP01-prompt-injection",
              mitre_technique: "AML.T0054",
              confidence: 0.78,
              metadata: { analysis_type: "linguistic", tool_name: tool.name, desc_length: desc.length, evidence_chain: m3Chain },
            });
            break;
          }
        }
      }
    }

    return findings;
  }
}

// ─── M6: Progressive Context Poisoning ────────────────────────────────────

class ProgressiveContextPoisoningRule implements TypedRule {
  readonly id = "M6";
  readonly name = "Progressive Context Poisoning Enablers";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Detect patterns that enable progressive poisoning:
    // 1. Persistent storage of LLM-generated content that gets fed back
    // 2. Accumulating context without bounds
    // 3. No content verification on stored data
    const patterns = [
      { regex: /(?:append|push|concat|add).*(?:context|memory|history|conversation|messages)(?!.*(?:limit|max|truncat|clear|reset))/gi, desc: "unbounded context accumulation" },
      { regex: /(?:save|store|write|persist).*(?:llm|ai|model|assistant|generated).*(?:output|response|result)/gi, desc: "persisting LLM output without verification" },
      { regex: /(?:vector|embed|store).*(?:tool|response|output).*(?:db|database|store|memory)/gi, desc: "storing tool responses in vector DB" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const m6Chain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `source code line ${line}`,
            observed: match[0].slice(0, 80),
            rationale: "Code pattern enables accumulation of LLM-generated or external content without bounds or verification",
          })
          .propagation({
            propagation_type: "variable-assignment",
            location: `line ${line}`,
            observed: `${desc} — content stored without integrity checks`,
          })
          .sink({
            sink_type: "config-modification",
            location: `line ${line}`,
            observed: "Accumulated content fed back to LLM context in subsequent sessions",
          })
          .mitigation({
            mitigation_type: "input-validation",
            present: false,
            location: `line ${line}`,
            detail: "No bounds, truncation, or content verification on accumulated context",
          })
          .impact({
            impact_type: "cross-agent-propagation",
            scope: "ai-client",
            exploitability: "moderate",
            scenario: `Progressive poisoning: attacker injects content via ${desc}. The content accumulates across sessions, gradually shifting the AI client's behavior without any single injection being detectable.`,
          })
          .factor("unbounded accumulation pattern", 0.1, "No limit/max/truncate/clear/reset guard detected near the accumulation pattern")
          .reference({
            id: "AML.T0058",
            title: "AI Agent Context Poisoning",
            relevance: "Progressive context poisoning through unbounded content accumulation",
          })
          .verification({
            step_type: "inspect-source",
            instruction: `Check line ${line} for context accumulation without bounds or verification`,
            target: `source code line ${line}`,
            expected_observation: `${desc} without limit, truncation, or integrity verification`,
          })
          .build();
        findings.push({
          rule_id: "M6",
          severity: "critical",
          evidence:
            `${desc} at line ${line}: "${match[0].slice(0, 80)}". ` +
            `Progressive poisoning: attacker injects content that accumulates over sessions.`,
          remediation:
            "Limit context window size. Verify stored content integrity. " +
            "Implement content provenance tracking. Clear context periodically.",
          owasp_category: "ASI06-memory-context-poisoning",
          mitre_technique: "AML.T0058",
          confidence: 0.75,
          metadata: { analysis_type: "structural", line, evidence_chain: m6Chain },
        });
        break;
      }
    }

    return findings;
  }
}

// ─── M9: System Prompt Extraction ─────────────────────────────────────────

class SystemPromptExtractionRule implements TypedRule {
  readonly id = "M9";
  readonly name = "Model-Specific System Prompt Extraction";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    const patterns = [
      { regex: /(?:system[_\s]?prompt|system[_\s]?message|initial[_\s]?prompt).*(?:return|respond|output|send|expose|leak)/gi, desc: "system prompt exposed in output" },
      { regex: /(?:return|respond|send|output).*(?:system[_\s]?prompt|system[_\s]?message|instructions)/gi, desc: "returning system prompt content" },
      { regex: /(?:tool[_\s]?response|tool[_\s]?output).*(?:system|prompt|instruction|config)/gi, desc: "tool leaking system context" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const m9Chain = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `source code line ${line}`,
            observed: match[0].slice(0, 80),
            rationale: "Code pattern exposes system prompt or instruction content in tool output or responses",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `line ${line}`,
            observed: `${desc} — system prompt content flows to tool response`,
          })
          .sink({
            sink_type: "credential-exposure",
            location: `line ${line}`,
            observed: "System prompt or instructions leaked in tool response visible to users or downstream agents",
          })
          .impact({
            impact_type: "data-exfiltration",
            scope: "ai-client",
            exploitability: "trivial",
            scenario: `System prompt content is exposed via ${desc}. An attacker can extract the system prompt to understand safety constraints, then craft targeted bypass attacks.`,
          })
          .factor("system prompt in output path", 0.15, "Direct code pattern showing system prompt flowing to output")
          .reference({
            id: "AML.T0057",
            title: "LLM Data Leakage",
            relevance: "System prompt extraction enables downstream attacks by revealing safety constraints",
          })
          .verification({
            step_type: "inspect-source",
            instruction: `Check line ${line} for system prompt content being returned or sent in responses`,
            target: `source code line ${line}`,
            expected_observation: `${desc}`,
          })
          .build();
        findings.push({
          rule_id: "M9",
          severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
          remediation: "Never expose system prompts or instructions in tool responses. Filter tool output.",
          owasp_category: "MCP04-data-exfiltration",
          mitre_technique: "AML.T0057",
          confidence: 0.80,
          metadata: { analysis_type: "structural", line, evidence_chain: m9Chain },
        });
        break;
      }
    }

    return findings;
  }
}

// ─── N4: JSON-RPC Error Object Injection ──────────────────────────────────

class JSONRPCErrorInjectionRule implements TypedRule {
  readonly id = "N4";
  readonly name = "JSON-RPC Error Object Injection";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Detect user input in JSON-RPC error messages
    const patterns = [
      { regex: /(?:error|err).*(?:message|data)\s*[:=].*(?:req\.|request\.|body|params|query|userInput)/gi, desc: "user input in error message" },
      { regex: /(?:throw|reject|error)\s*\(\s*(?:req\.|request\.|body|params)/gi, desc: "throwing user-controlled error" },
      { regex: /(?:error|err).*(?:stack|trace|details)\s*[:=].*(?:toString|stack|message)/gi, desc: "stack trace in error response" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const n4Chain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `source code line ${line}`,
            observed: match[0].slice(0, 80),
            rationale: "User-controlled input flows into JSON-RPC error message or data fields",
          })
          .propagation({
            propagation_type: "string-concatenation",
            location: `line ${line}`,
            observed: `${desc} — user input embedded in error response`,
          })
          .sink({
            sink_type: "code-evaluation",
            location: `JSON-RPC error response at line ${line}`,
            observed: "Error message content processed by AI client as potential instructions",
          })
          .mitigation({
            mitigation_type: "sanitizer-function",
            present: false,
            location: `line ${line}`,
            detail: "No sanitization of user input before inclusion in error messages",
          })
          .impact({
            impact_type: "remote-code-execution",
            scope: "ai-client",
            exploitability: "moderate",
            scenario: `User-controlled content in JSON-RPC error objects (${desc}) is processed by the AI client. An attacker crafts input that triggers an error containing prompt injection payloads, which the LLM interprets as instructions.`,
          })
          .factor("user input in error path", 0.1, "Direct flow from request parameters to error message content")
          .verification({
            step_type: "inspect-source",
            instruction: `Check line ${line} for user input flowing into error message or error data fields`,
            target: `source code line ${line}`,
            expected_observation: `${desc}`,
          })
          .build();
        findings.push({
          rule_id: "N4",
          severity: "critical",
          evidence:
            `${desc} at line ${line}: "${match[0].slice(0, 80)}". ` +
            `User-controlled content in JSON-RPC error objects can be processed by LLMs as instructions.`,
          remediation: "Sanitize error messages. Never include user input or stack traces in error responses.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence: 0.82,
          metadata: { analysis_type: "structural", line, evidence_chain: n4Chain },
        });
        break;
      }
    }

    return findings;
  }
}

// ─── N5: Capability Downgrade Deception ───────────────────────────────────

class CapabilityDowngradeRule implements TypedRule {
  readonly id = "N5";
  readonly name = "Capability Downgrade Deception";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Detect capabilities being declared but then used beyond declaration
    const patterns = [
      { regex: /(?:capabilities|serverCapabilities).*(?:tools\s*:\s*false|tools\s*:\s*null)[\s\S]{0,500}(?:tools\/call|callTool|handleTool)/gi, desc: "tools capability disabled but tool handler exists" },
      { regex: /(?:capabilities|serverCapabilities).*(?:sampling\s*:\s*false|sampling\s*:\s*null)[\s\S]{0,500}(?:sampling\/create|createSample)/gi, desc: "sampling disabled but sampling handler exists" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const n5Chain = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `source code line ${line}`,
            observed: match[0].slice(0, 80),
            rationale: "Server declares a capability as disabled but implements a handler for it",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `server capabilities declaration`,
            observed: `${desc} — capability disabled in declaration but handler present in code`,
          })
          .impact({
            impact_type: "privilege-escalation",
            scope: "ai-client",
            exploitability: "moderate",
            scenario: `${desc}. The AI client trusts the capabilities declaration and does not apply security controls for the undeclared capability. The server can exercise the capability without client-side consent or monitoring.`,
          })
          .factor("capability mismatch", 0.15, "Explicit contradiction between declared capabilities and implemented handlers")
          .verification({
            step_type: "inspect-source",
            instruction: `Verify that the capability is declared as false/null in the capabilities object AND a handler exists in the same codebase`,
            target: `source code around line ${line}`,
            expected_observation: `${desc}`,
          })
          .build();
        findings.push({
          rule_id: "N5",
          severity: "critical",
          evidence:
            `${desc}. Capability claimed as disabled but implementation exists. ` +
            `Clients may not apply proper security controls for undeclared capabilities.`,
          remediation: "Declare all implemented capabilities in the server capabilities response.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence: 0.85,
          metadata: { analysis_type: "structural", line, evidence_chain: n5Chain },
        });
        break;
      }
    }

    return findings;
  }
}

// ─── N6: SSE Reconnection Hijacking ───────────────────────────────────────

class SSEReconnectionRule implements TypedRule {
  readonly id = "N6";
  readonly name = "SSE Reconnection Hijacking";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    const patterns = [
      { regex: /(?:EventSource|SSE|eventsource).*(?:reconnect|retry)(?!.*(?:auth|token|verify|validate))/gi, desc: "SSE reconnection without re-authentication" },
      { regex: /(?:Last-Event-ID|lastEventId).*(?:parse|parseInt|Number)(?!.*(?:validate|verify|hmac))/gi, desc: "Last-Event-ID parsed without integrity check" },
      { regex: /(?:session|sessionId|sess).*(?:url|query|header)(?!.*(?:sign|hmac|encrypt|token))/gi, desc: "session ID in URL/header without signing" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const n6Chain = new EvidenceChainBuilder()
          .source({
            source_type: "environment",
            location: `source code line ${line}`,
            observed: match[0].slice(0, 80),
            rationale: "SSE reconnection or session handling lacks re-authentication or integrity verification",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `line ${line}`,
            observed: `${desc} — reconnection proceeds without verifying session integrity`,
          })
          .sink({
            sink_type: "privilege-grant",
            location: `SSE connection at line ${line}`,
            observed: "Reconnection grants access without re-authentication",
          })
          .mitigation({
            mitigation_type: "auth-check",
            present: false,
            location: `line ${line}`,
            detail: "No authentication, token validation, or HMAC check on reconnection",
          })
          .impact({
            impact_type: "session-hijack",
            scope: "user-data",
            exploitability: "moderate",
            scenario: `${desc}. An attacker intercepts or replays an SSE reconnection request to hijack an existing session without providing valid credentials. CVE-2025-6515 class vulnerability.`,
          })
          .factor("missing re-auth on reconnect", 0.1, "No auth/token/verify/validate guard detected near reconnection pattern")
          .reference({
            id: "CVE-2025-6515",
            title: "Session Hijacking via URI Manipulation in Streamable HTTP",
            relevance: "SSE reconnection without re-authentication enables session hijacking",
          })
          .verification({
            step_type: "inspect-source",
            instruction: `Check line ${line} for SSE reconnection or session handling without re-authentication`,
            target: `source code line ${line}`,
            expected_observation: `${desc}`,
          })
          .build();
        findings.push({
          rule_id: "N6",
          severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}". CVE-2025-6515 class vulnerability.`,
          remediation: "Re-authenticate on SSE reconnection. Sign session tokens. Validate Last-Event-ID integrity.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0061",
          confidence: 0.78,
          metadata: { analysis_type: "structural", line, evidence_chain: n6Chain },
        });
        break;
      }
    }

    return findings;
  }
}

// ─── N9: Logging Protocol Injection ───────────────────────────────────────

class LoggingProtocolInjectionRule implements TypedRule {
  readonly id = "N9";
  readonly name = "Logging Protocol Injection";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Log messages with user-controlled content that could be injection
    const patterns = [
      { regex: /(?:log|logger|logging)\.(?:info|warn|error|debug)\s*\(\s*(?:req\.|request\.|body|params|query|user)/gi, desc: "user input directly in log message" },
      { regex: /(?:notifications\/message|sendLogMessage).*(?:req\.|body|params|user)/gi, desc: "user input in MCP log notification" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const n9Chain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `source code line ${line}`,
            observed: match[0].slice(0, 80),
            rationale: "User-controlled input flows into MCP log notification messages processed by AI clients",
          })
          .propagation({
            propagation_type: "string-concatenation",
            location: `line ${line}`,
            observed: `${desc} — user input embedded in log message without sanitization`,
          })
          .sink({
            sink_type: "code-evaluation",
            location: `MCP log notification at line ${line}`,
            observed: "Log message content processed by AI client as potential instructions",
          })
          .impact({
            impact_type: "remote-code-execution",
            scope: "ai-client",
            exploitability: "moderate",
            scenario: `User-controlled content in MCP log notifications (${desc}) is processed by the AI client. An attacker crafts input that appears in log messages containing prompt injection payloads, which the LLM interprets as instructions.`,
          })
          .factor("user input in log path", 0.1, "Direct flow from request parameters to MCP log notification content")
          .verification({
            step_type: "inspect-source",
            instruction: `Check line ${line} for user input flowing into log message or MCP notification`,
            target: `source code line ${line}`,
            expected_observation: `${desc}`,
          })
          .build();
        findings.push({
          rule_id: "N9",
          severity: "critical",
          evidence:
            `${desc} at line ${line}: "${match[0].slice(0, 80)}". ` +
            `MCP logging messages are processed by AI clients — injection here affects LLM behavior.`,
          remediation: "Sanitize all content before including in MCP log notifications. Escape special characters.",
          owasp_category: "MCP09-logging-monitoring",
          mitre_technique: "AML.T0054",
          confidence: 0.80,
          metadata: { analysis_type: "structural", line, evidence_chain: n9Chain },
        });
        break;
      }
    }

    return findings;
  }
}

// ─── N11: Protocol Version Downgrade ──────────────────────────────────────

class ProtocolVersionDowngradeRule implements TypedRule {
  readonly id = "N11";
  readonly name = "Protocol Version Downgrade Attack";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    const patterns = [
      { regex: /protocolVersion.*(?:min|minimum|lowest|any|>=\s*['"]?\d)(?!.*(?:reject|error|throw|deny))/gi, desc: "accepts minimum protocol version without rejection" },
      { regex: /(?:negotiate|select).*(?:protocol|version).*(?:oldest|lowest|min|first)/gi, desc: "negotiates lowest available protocol version" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const n11Chain = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `source code line ${line}`,
            observed: match[0].slice(0, 80),
            rationale: "Server accepts or negotiates older protocol versions without rejecting insecure ones",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `protocol version negotiation at line ${line}`,
            observed: `${desc} — server does not enforce minimum protocol version`,
          })
          .impact({
            impact_type: "privilege-escalation",
            scope: "ai-client",
            exploitability: "moderate",
            scenario: `${desc}. An attacker forces a protocol version downgrade to an older version lacking security features (e.g., annotations, capability declarations). The client operates without newer security controls.`,
          })
          .factor("version downgrade pattern", 0.1, "No reject/error/throw/deny guard detected near version negotiation")
          .verification({
            step_type: "inspect-source",
            instruction: `Check line ${line} for protocol version negotiation that accepts older versions without rejection`,
            target: `source code line ${line}`,
            expected_observation: `${desc}`,
          })
          .build();
        findings.push({
          rule_id: "N11",
          severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}". Allows downgrade to older, less secure protocol.`,
          remediation: "Enforce minimum protocol version. Reject connections below the minimum. Use newest supported version.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence: 0.78,
          metadata: { analysis_type: "structural", line, evidence_chain: n11Chain },
        });
        break;
      }
    }

    return findings;
  }
}

// ─── N12-N15: Additional Protocol Rules ───────────────────────────────────

class ResourceSubscriptionPoisoningRule implements TypedRule {
  readonly id = "N12";
  readonly name = "Resource Subscription Content Mutation";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];
    const findings: TypedFinding[] = [];
    const regex = /(?:subscription|notify|push|update).*(?:resource|content).*(?:changed|modified|mutated)(?!.*(?:verify|hash|checksum|integrity))/gi;
    const match = regex.exec(context.source_code);
    if (match) {
      const n12Line = getLineNumber(context.source_code, match.index);
      const n12Chain = new EvidenceChainBuilder()
        .source({
          source_type: "file-content",
          location: `source code line ${n12Line}`,
          observed: match[0].slice(0, 80),
          rationale: "Resource subscription pushes content updates without verifying integrity of the changed content",
        })
        .propagation({
          propagation_type: "direct-pass",
          location: `line ${n12Line}`,
          observed: "Resource content mutation delivered to client without hash or checksum verification",
        })
        .sink({
          sink_type: "config-modification",
          location: `resource subscription handler at line ${n12Line}`,
          observed: "Mutated resource content processed by AI client without integrity check",
        })
        .impact({
          impact_type: "cross-agent-propagation",
          scope: "ai-client",
          exploitability: "moderate",
          scenario: "An attacker modifies a subscribed resource. The client receives the update without integrity verification, processing poisoned content as trusted data.",
        })
        .factor("missing integrity check on update", 0.1, "No verify/hash/checksum/integrity guard detected near subscription update")
        .verification({
          step_type: "inspect-source",
          instruction: `Check line ${n12Line} for resource subscription updates without integrity verification`,
          target: `source code line ${n12Line}`,
          expected_observation: "Resource content update without hash or signature verification",
        })
        .build();
      findings.push({
        rule_id: "N12", severity: "critical",
        evidence: `Resource subscription update without integrity verification at line ${n12Line}.`,
        remediation: "Verify resource content integrity on subscription updates using hashes or signatures.",
        owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054", confidence: 0.78,
        metadata: { analysis_type: "structural", evidence_chain: n12Chain },
      });
    }
    return findings;
  }
}

class ChunkedTransferSmugglingRule implements TypedRule {
  readonly id = "N13";
  readonly name = "HTTP Chunked Transfer Smuggling";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:Transfer-Encoding|transfer.encoding).*(?:chunked).*(?:Content-Length|content.length)/gi, desc: "both Transfer-Encoding and Content-Length" },
      { regex: /(?:raw|socket|net).*(?:write|send).*(?:\\r\\n0\\r\\n|chunk)/gi, desc: "raw chunked encoding manipulation" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(context.source_code);
      if (match) {
        const n13Line = getLineNumber(context.source_code, match.index);
        const n13Chain = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `source code line ${n13Line}`,
            observed: match[0].slice(0, 80),
            rationale: "Code manipulates HTTP chunked transfer encoding or combines conflicting transfer headers",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `line ${n13Line}`,
            observed: `${desc} — ambiguous HTTP framing enables request smuggling`,
          })
          .sink({
            sink_type: "network-send",
            location: `HTTP response at line ${n13Line}`,
            observed: "Ambiguous HTTP framing sent to client, enabling request smuggling attacks",
          })
          .impact({
            impact_type: "session-hijack",
            scope: "user-data",
            exploitability: "complex",
            scenario: `${desc}. An attacker exploits ambiguous HTTP framing (Transfer-Encoding vs Content-Length) to smuggle requests, potentially hijacking other users' sessions or injecting responses.`,
          })
          .factor("chunked encoding manipulation", 0.1, "Direct manipulation of HTTP transfer encoding detected")
          .verification({
            step_type: "inspect-source",
            instruction: `Check line ${n13Line} for conflicting Transfer-Encoding and Content-Length headers or raw chunked encoding`,
            target: `source code line ${n13Line}`,
            expected_observation: `${desc}`,
          })
          .build();
        findings.push({
          rule_id: "N13", severity: "critical",
          evidence: `${desc} at line ${n13Line}: "${match[0].slice(0, 80)}".`,
          remediation: "Use a well-tested HTTP library. Never manually construct chunked encoding. Reject ambiguous headers.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0061", confidence: 0.82,
          metadata: { analysis_type: "structural", evidence_chain: n13Chain },
        });
        break;
      }
    }
    return findings;
  }
}

class TOFUBypassRule implements TypedRule {
  readonly id = "N14";
  readonly name = "Trust-On-First-Use Bypass";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:trust|accept|allow).*(?:first|initial|new|unknown).*(?:connect|server|cert)/gi, desc: "TOFU without pinning" },
      { regex: /(?:known_hosts|fingerprint|pin).*(?:ignore|skip|disable|override)/gi, desc: "fingerprint pinning disabled" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(context.source_code);
      if (match) {
        const n14Line = getLineNumber(context.source_code, match.index);
        const n14Chain = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `source code line ${n14Line}`,
            observed: match[0].slice(0, 80),
            rationale: "Code bypasses or disables trust-on-first-use fingerprint pinning, allowing server impersonation",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `line ${n14Line}`,
            observed: `${desc} — server identity not verified on subsequent connections`,
          })
          .impact({
            impact_type: "session-hijack",
            scope: "connected-services",
            exploitability: "moderate",
            scenario: `${desc}. An attacker performs a MITM attack by impersonating the MCP server. Without fingerprint pinning, the client accepts the attacker's server as legitimate on reconnection.`,
          })
          .factor("TOFU bypass pattern", 0.1, "Fingerprint/pinning explicitly ignored, skipped, or disabled")
          .verification({
            step_type: "inspect-source",
            instruction: `Check line ${n14Line} for trust-on-first-use bypass or fingerprint pinning being disabled`,
            target: `source code line ${n14Line}`,
            expected_observation: `${desc}`,
          })
          .build();
        findings.push({
          rule_id: "N14", severity: "critical",
          evidence: `${desc} at line ${n14Line}: "${match[0].slice(0, 80)}".`,
          remediation: "Implement certificate/key pinning. Store fingerprints on first use and verify on subsequent connections.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054", confidence: 0.80,
          metadata: { analysis_type: "structural", evidence_chain: n14Chain },
        });
        break;
      }
    }
    return findings;
  }
}

class MethodNameConfusionRule implements TypedRule {
  readonly id = "N15";
  readonly name = "JSON-RPC Method Name Confusion";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:method|rpcMethod|methodName)\s*[:=]\s*(?:req\.|request\.|params|body|user)/gi, desc: "user input as JSON-RPC method name" },
      { regex: /(?:dispatch|handle|route)\s*\[\s*(?:req\.|method|params)/gi, desc: "dynamic method dispatch from user input" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(context.source_code);
      if (match) {
        const n15Line = getLineNumber(context.source_code, match.index);
        const n15Chain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `source code line ${n15Line}`,
            observed: match[0].slice(0, 80),
            rationale: "User-controlled input used as JSON-RPC method name or dynamic dispatch key",
          })
          .propagation({
            propagation_type: "variable-assignment",
            location: `line ${n15Line}`,
            observed: `${desc} — user input assigned to method dispatch key`,
          })
          .sink({
            sink_type: "code-evaluation",
            location: `method dispatch at line ${n15Line}`,
            observed: "User-controlled method name used to invoke server-side handlers",
          })
          .impact({
            impact_type: "remote-code-execution",
            scope: "server-host",
            exploitability: "moderate",
            scenario: `${desc}. An attacker sends a crafted JSON-RPC request with a method name pointing to an internal or privileged handler, bypassing intended access controls.`,
          })
          .factor("user input as method key", 0.15, "Direct flow from request parameters to method dispatch key")
          .verification({
            step_type: "inspect-source",
            instruction: `Check line ${n15Line} for user input being used as method name or dispatch key without allowlist validation`,
            target: `source code line ${n15Line}`,
            expected_observation: `${desc}`,
          })
          .build();
        findings.push({
          rule_id: "N15", severity: "critical",
          evidence: `${desc} at line ${n15Line}: "${match[0].slice(0, 80)}".`,
          remediation: "Validate method names against an allowlist. Never use user input as method dispatch keys.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054", confidence: 0.85,
          metadata: { analysis_type: "structural", evidence_chain: n15Chain },
        });
        break;
      }
    }
    return findings;
  }
}

// ─── Register all ──────────────────────────────────────────────────────────

registerTypedRule(new SpecialTokenInjectionRule());
registerTypedRule(new ReasoningChainRule());
registerTypedRule(new ProgressiveContextPoisoningRule());
registerTypedRule(new SystemPromptExtractionRule());
registerTypedRule(new JSONRPCErrorInjectionRule());
registerTypedRule(new CapabilityDowngradeRule());
registerTypedRule(new SSEReconnectionRule());
registerTypedRule(new LoggingProtocolInjectionRule());
registerTypedRule(new ProtocolVersionDowngradeRule());
registerTypedRule(new ResourceSubscriptionPoisoningRule());
registerTypedRule(new ChunkedTransferSmugglingRule());
registerTypedRule(new TOFUBypassRule());
registerTypedRule(new MethodNameConfusionRule());
