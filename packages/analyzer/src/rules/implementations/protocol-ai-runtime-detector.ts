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
          findings.push({
            rule_id: "M1",
            severity: "critical",
            evidence: `Server instructions contain ${desc}: "${match[0]}".`,
            remediation: "Remove special tokens from server instructions.",
            owasp_category: "MCP01-prompt-injection",
            mitre_technique: "AML.T0054",
            confidence: 0.96,
            metadata: { analysis_type: "linguistic", surface: "instructions" },
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
              metadata: { analysis_type: "linguistic", tool_name: tool.name, desc_length: desc.length },
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
          metadata: { analysis_type: "structural", line },
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
        findings.push({
          rule_id: "M9",
          severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
          remediation: "Never expose system prompts or instructions in tool responses. Filter tool output.",
          owasp_category: "MCP04-data-exfiltration",
          mitre_technique: "AML.T0057",
          confidence: 0.80,
          metadata: { analysis_type: "structural", line },
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
          metadata: { analysis_type: "structural", line },
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
          metadata: { analysis_type: "structural", line },
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
        findings.push({
          rule_id: "N6",
          severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}". CVE-2025-6515 class vulnerability.`,
          remediation: "Re-authenticate on SSE reconnection. Sign session tokens. Validate Last-Event-ID integrity.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0061",
          confidence: 0.78,
          metadata: { analysis_type: "structural", line },
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
          metadata: { analysis_type: "structural", line },
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
        findings.push({
          rule_id: "N11",
          severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}". Allows downgrade to older, less secure protocol.`,
          remediation: "Enforce minimum protocol version. Reject connections below the minimum. Use newest supported version.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence: 0.78,
          metadata: { analysis_type: "structural", line },
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
      findings.push({
        rule_id: "N12", severity: "critical",
        evidence: `Resource subscription update without integrity verification at line ${getLineNumber(context.source_code, match.index)}.`,
        remediation: "Verify resource content integrity on subscription updates using hashes or signatures.",
        owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054", confidence: 0.78,
        metadata: { analysis_type: "structural" },
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
        findings.push({
          rule_id: "N13", severity: "critical",
          evidence: `${desc} at line ${getLineNumber(context.source_code, match.index)}: "${match[0].slice(0, 80)}".`,
          remediation: "Use a well-tested HTTP library. Never manually construct chunked encoding. Reject ambiguous headers.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0061", confidence: 0.82,
          metadata: { analysis_type: "structural" },
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
        findings.push({
          rule_id: "N14", severity: "critical",
          evidence: `${desc} at line ${getLineNumber(context.source_code, match.index)}: "${match[0].slice(0, 80)}".`,
          remediation: "Implement certificate/key pinning. Store fingerprints on first use and verify on subsequent connections.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054", confidence: 0.80,
          metadata: { analysis_type: "structural" },
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
        findings.push({
          rule_id: "N15", severity: "critical",
          evidence: `${desc} at line ${getLineNumber(context.source_code, match.index)}: "${match[0].slice(0, 80)}".`,
          remediation: "Validate method names against an allowlist. Never use user input as method dispatch keys.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054", confidence: 0.85,
          metadata: { analysis_type: "structural" },
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
