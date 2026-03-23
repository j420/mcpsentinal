/**
 * ProtocolAnalyzer — MCP protocol-level analysis (E1–E4, H1–H3)
 *
 * Analyzes the MCP connection and protocol surface:
 * - Transport security (TLS, auth)
 * - Initialize response injection (H2)
 * - OAuth implementation analysis (H1) via AST taint on source code
 * - Multi-agent propagation risk (H3) via tool capability analysis
 */

import type { AnalysisContext } from "../engine.js";
import type { Severity, OwaspCategory } from "@mcp-sentinel/database";
import { shannonEntropy, classifyContent } from "../rules/analyzers/entropy.js";
import { analyzeUnicode, extractTagMessage } from "../rules/analyzers/unicode.js";

export interface ProtocolFinding {
  rule_id: string;
  severity: Severity;
  evidence: string;
  remediation: string;
  owasp_category: OwaspCategory | null;
  mitre_technique: string | null;
  confidence: number;
  metadata?: Record<string, unknown>;
}

/** OAuth insecure patterns for AST-free detection in source code */
const OAUTH_PATTERNS: Array<{
  pattern: RegExp;
  issue: string;
  severity: Severity;
}> = [
  { pattern: /response_type\s*[=:]\s*['"]token['"]/g,
    issue: "Implicit grant (response_type=token) banned in OAuth 2.1 — token exposed in URL",
    severity: "critical" },
  { pattern: /grant_type\s*[=:]\s*['"]password['"]/g,
    issue: "ROPC grant (grant_type=password) — MCP server receives raw user credentials",
    severity: "critical" },
  { pattern: /localStorage\s*\.\s*setItem\s*\([^,]*token/gi,
    issue: "OAuth token stored in localStorage — XSS token theft",
    severity: "high" },
  { pattern: /sessionStorage\s*\.\s*setItem\s*\([^,]*token/gi,
    issue: "OAuth token stored in sessionStorage — XSS accessible",
    severity: "medium" },
  { pattern: /redirect_uri\s*[=:]\s*(?:req\.|request\.|params\.|query\.)/g,
    issue: "redirect_uri from user input — auth code injection",
    severity: "critical" },
  { pattern: /scope\s*[=:]\s*(?:req\.|request\.|params\.|query\.)/g,
    issue: "OAuth scope from user input — privilege escalation",
    severity: "high" },
];

/** Multi-agent propagation patterns */
const AGENTIC_SINK_PATTERNS = [
  /(?:agent|task|workflow)\s*(?:_input|_request|_message)/i,
  /(?:forward|propagate|pass)\s*(?:_to|_through)\s*(?:agent|downstream)/i,
  /(?:shared|common)\s*(?:_memory|_state|_context|_scratchpad)/i,
  /(?:write|update|set)\s*(?:_memory|_state|_vector_store|_embedding)/i,
];

export class ProtocolAnalyzer {
  analyze(context: AnalysisContext): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];

    // E1: No authentication
    if (context.connection_metadata?.auth_required === false) {
      findings.push({
        rule_id: "E1", severity: "medium",
        evidence: `[Protocol] Server does not require authentication. Any client can connect and invoke tools.`,
        remediation: "Implement authentication. For remote servers, use OAuth 2.0 (MCP Authorization spec).",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.95,
      });
    }

    // E2: Insecure transport
    if (context.connection_metadata) {
      const transport = context.connection_metadata.transport?.toLowerCase();
      if (transport === "http" || transport === "ws") {
        findings.push({
          rule_id: "E2", severity: "high",
          evidence: `[Protocol] Transport "${transport}" is unencrypted. Tool invocations and data visible to network observers.`,
          remediation: "Use HTTPS or WSS. Configure TLS with modern cipher suites.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.95,
        });
      }
    }

    // E3: Response time anomaly
    if (context.connection_metadata?.response_time_ms && context.connection_metadata.response_time_ms > 10000) {
      findings.push({
        rule_id: "E3", severity: "low",
        evidence: `[Protocol] Response time ${context.connection_metadata.response_time_ms}ms exceeds 10s threshold. May indicate resource exhaustion or malicious delay.`,
        remediation: "Investigate server performance. Set client-side timeouts.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.6,
      });
    }

    // H2: Initialize response injection
    findings.push(...this.analyzeInitializeResponse(context));

    // H1: OAuth implementation analysis
    if (context.source_code) {
      findings.push(...this.analyzeOAuth(context.source_code));
    }

    // H3: Multi-agent propagation risk
    findings.push(...this.analyzeMultiAgentRisk(context));

    return findings;
  }

  /**
   * H2: Analyze the MCP initialize response fields for injection.
   *
   * The initialize handshake (serverInfo.name, serverInfo.version, instructions)
   * is processed BEFORE tool descriptions with higher implicit trust.
   * Injection here sets behavioral rules for the entire session.
   */
  private analyzeInitializeResponse(context: AnalysisContext): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];
    const meta = context.initialize_metadata;
    if (!meta) return findings;

    const fields: Array<{ name: string; value: string | null | undefined }> = [
      { name: "server_version", value: meta.server_version },
      { name: "server_instructions", value: meta.server_instructions },
    ];

    // Also check server name from context
    if (context.server.name) {
      fields.push({ name: "server_name", value: context.server.name });
    }

    for (const field of fields) {
      if (!field.value || field.value.length < 5) continue;
      const text = field.value;

      // Entropy check — encoded content in protocol fields
      const entropy = shannonEntropy(text);
      if (entropy > 5.5 && text.length > 20) {
        const classification = classifyContent(text);
        if (classification.classification !== "natural_language" &&
            classification.classification !== "source_code") {
          findings.push({
            rule_id: "H2", severity: "critical",
            evidence:
              `[Protocol] Initialize field "${field.name}" contains ${classification.classification} content ` +
              `(entropy: ${entropy.toFixed(2)} bits/char). Encoded payloads in protocol fields are processed ` +
              `before any tool description or safety context.`,
            remediation: "Initialize response fields must contain only plain text metadata.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054.002",
            confidence: classification.confidence,
            metadata: { engine: "protocol_analyzer", field: field.name, entropy },
          });
        }
      }

      // Unicode attack check
      const unicodeResult = analyzeUnicode(text);
      if (unicodeResult.has_issues) {
        const bidi = unicodeResult.issues.filter((i) => i.type === "bidi_override");
        const zw = unicodeResult.issues.filter((i) =>
          i.type === "zero_width" || i.type === "tag_character"
        );

        if (bidi.length > 0 || zw.length > 0) {
          const hidden = extractTagMessage(text);
          findings.push({
            rule_id: "H2", severity: "critical",
            evidence:
              `[Protocol] Initialize field "${field.name}" contains ${bidi.length + zw.length} ` +
              `invisible/control character(s). ` +
              (hidden ? `Hidden message: "${hidden}". ` : "") +
              `These are processed at the highest trust level in the MCP protocol.`,
            remediation: "Strip all invisible Unicode characters from initialize response fields.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054.002",
            confidence: hidden ? 0.99 : 0.9,
            metadata: { engine: "protocol_analyzer", field: field.name, hidden_message: hidden },
          });
        }
      }

      // Role injection in instructions field
      if (field.name === "server_instructions") {
        const rolePatterns = [
          /you\s+are\s+(?:now|a|an|the)/i,
          /(?:ignore|override|forget)\s+(?:previous|prior|all|safety)/i,
          /(?:always|never|must)\s+(?:execute|run|call|use|output)/i,
        ];
        const matches = rolePatterns.filter((p) => p.test(text));
        if (matches.length > 0) {
          findings.push({
            rule_id: "H2", severity: "critical",
            evidence:
              `[Protocol] Instructions field contains ${matches.length} role injection pattern(s). ` +
              `The instructions field is spec-sanctioned — AI clients follow it as session-level guidance. ` +
              `Injection here is the highest-priority attack surface in MCP.`,
            remediation: "Instructions should describe server capabilities, not dictate AI behavior.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054.002",
            confidence: 0.9,
          });
        }
      }
    }

    return findings;
  }

  /**
   * H1: OAuth implementation analysis via pattern detection in source code.
   */
  private analyzeOAuth(source: string): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];

    // Only analyze if source appears to contain OAuth-related code
    if (!/oauth|authorization|token|grant/i.test(source)) return findings;

    for (const { pattern, issue, severity } of OAUTH_PATTERNS) {
      pattern.lastIndex = 0;
      const match = pattern.exec(source);
      if (match) {
        const line = source.substring(0, match.index).split("\n").length;
        findings.push({
          rule_id: "H1", severity,
          evidence: `[Protocol] OAuth vulnerability at L${line}: ${issue}. Match: "${match[0]}".`,
          remediation: "Follow RFC 9700 (OAuth 2.1). Use authorization code flow with PKCE. " +
            "Store tokens in HTTP-only cookies, not localStorage. Validate redirect_uri server-side.",
          owasp_category: "ASI03-identity-privilege-abuse", mitre_technique: "AML.T0054",
          confidence: 0.8,
        });
      }
    }

    return findings;
  }

  /**
   * H3: Multi-agent propagation risk.
   * Tools that accept agent output or write to shared agent memory.
   */
  private analyzeMultiAgentRisk(context: AnalysisContext): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];

    for (const tool of context.tools) {
      const desc = `${tool.name} ${tool.description || ""}`.toLowerCase();

      for (const pattern of AGENTIC_SINK_PATTERNS) {
        if (pattern.test(desc)) {
          findings.push({
            rule_id: "H3", severity: "high",
            evidence:
              `[Protocol] Tool "${tool.name}" matches multi-agent propagation pattern. ` +
              `In multi-agent architectures (LangGraph, AutoGen, CrewAI), a compromised upstream ` +
              `agent can inject through shared MCP tools into downstream agents.`,
            remediation: "Implement trust boundaries between agents. Validate inter-agent data. " +
              "Don't pass raw tool output from one agent as instructions to another.",
            owasp_category: "ASI07-insecure-inter-agent-comms", mitre_technique: "AML.T0054.001",
            confidence: 0.6,
            metadata: { engine: "protocol_analyzer", analysis: "multi_agent_risk" },
          });
          break;
        }
      }
    }

    return findings;
  }
}
