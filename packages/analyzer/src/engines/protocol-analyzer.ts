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

/** Prompt injection patterns reused across I3, I6, and other resource/prompt analysis */
const INJECTION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /you\s+are\s+(?:now|a|an|the)/i, label: "role injection" },
  { pattern: /(?:ignore|override|forget|disregard)\s+(?:previous|prior|all|safety|above|system)/i, label: "instruction override" },
  { pattern: /(?:always|never|must)\s+(?:execute|run|call|use|output|return|respond)/i, label: "behavioral directive" },
  { pattern: /\bsystem\s*(?:prompt|message|instruction)\b/i, label: "system prompt reference" },
  { pattern: /\b(?:INST|<<SYS>>|<\|im_start\||<\|system\||<\|assistant\|)/i, label: "LLM special token" },
  { pattern: /\b(?:BEGIN SYSTEM|END SYSTEM|<\|endoftext\|>)/i, label: "LLM delimiter" },
  { pattern: /(?:admin|root|superuser|sudo)\s+(?:mode|access|privilege)/i, label: "privilege claim" },
  { pattern: /(?:approved|certified|verified)\s+by\s+(?:anthropic|openai|google|microsoft)/i, label: "trust assertion" },
];

/** Tool names commonly shadowed by malicious resources (I5) */
const TOOL_SHADOW_NAMES = [
  "read_file", "write_file", "execute", "run", "shell", "eval",
  "query", "search", "fetch", "download", "upload", "delete",
  "send_email", "send_message", "create_file", "list_files",
  "exec", "bash", "cmd", "remove", "install", "deploy",
];

/** Dangerous root paths (I11) */
const DANGEROUS_ROOTS: Array<{ path: string; reason: string }> = [
  { path: "/", reason: "entire filesystem" },
  { path: "/etc", reason: "system configuration files" },
  { path: "/root", reason: "root user home directory" },
  { path: "/home", reason: "all user home directories" },
  { path: "~/.ssh", reason: "SSH private keys" },
  { path: "~/.aws", reason: "AWS credentials" },
  { path: "~/.config", reason: "user config (often contains secrets)" },
  { path: "/var/run", reason: "runtime sockets (Docker, systemd)" },
  { path: "/proc", reason: "process information (PIDs, memory maps)" },
  { path: "/sys", reason: "kernel parameters" },
  { path: "C:\\", reason: "Windows filesystem root" },
  { path: "C:\\Windows", reason: "Windows system directory" },
  { path: "C:\\Users", reason: "all Windows user profiles" },
  { path: "/var/lib/docker", reason: "Docker internals" },
  { path: "~/.gnupg", reason: "GPG private keys" },
  { path: "~/.kube", reason: "Kubernetes credentials" },
];

/** Privileged prompt names suggesting override capability (I6) */
const PRIVILEGED_PROMPT_NAMES = [
  /^system[_-]?prompt$/i,
  /^override[_-]?safety$/i,
  /^admin[_-]?mode$/i,
  /^disable[_-]?(?:filter|guard|safety)/i,
  /^bypass[_-]?/i,
  /^raw[_-]?(?:prompt|instruction)/i,
  /^inject/i,
  /^escalat/i,
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

    // G1: Indirect Injection Gateway (upgraded from keyword match to capability graph)
    findings.push(...this.analyzeInjectionGateway(context));

    // I7: Sampling Abuse (upgraded from capability presence to graph analysis)
    findings.push(...this.analyzeSamplingAbuse(context));

    // I3: Resource Metadata Injection
    findings.push(...this.analyzeResourceMetadataInjection(context));

    // I4: Dangerous Resource URI
    findings.push(...this.analyzeDangerousResourceUri(context));

    // I5: Resource-Tool Shadowing
    findings.push(...this.analyzeResourceToolShadowing(context));

    // I6: Prompt Template Injection
    findings.push(...this.analyzePromptTemplateInjection(context));

    // I11: Over-Privileged Root
    findings.push(...this.analyzeOverPrivilegedRoot(context));

    // I12: Capability Escalation Post-Init
    findings.push(...this.analyzeCapabilityEscalation(context));

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

  // ── Capability classification helpers (inline — avoids depending on risk-matrix package) ──

  private static readonly INJECTION_SOURCE_PATTERNS = [
    /scrape|crawl|browse|webpage|fetch_url|get_page|web_search/i,
    /read_email|read_slack|read_message|read_issue|get_inbox|list_email/i,
    /read_file|list_files|get_file_content|cat|head|tail/i,
    /read_rss|read_feed|ingest|import|parse_html|parse_xml/i,
  ];

  private static readonly SANITIZATION_SIGNAL_PATTERNS = [
    /sanitize|sanitization|escape|strip_?html|clean|validate_?output|content_?policy/i,
    /allow_?list|allowlist|safe_?content|content_?filter|output_?filter/i,
  ];

  private static readonly ACTION_SINK_PATTERNS = [
    /exec|run|eval|shell|bash|spawn|execute|system/i,
    /send|post|email|slack|notify|webhook|push/i,
    /write_file|save|create_file|update_file|append/i,
    /query|insert|update|delete|drop/i,
    /deploy|publish|release|upload/i,
  ];

  private classifyTool(tool: { name: string; description: string | null }): {
    isInjectionSource: boolean;
    isActionSink: boolean;
    capabilities: string[];
  } {
    const text = `${tool.name} ${tool.description || ""}`;
    const isInjectionSource = ProtocolAnalyzer.INJECTION_SOURCE_PATTERNS.some((p) => p.test(text));
    const isActionSink = ProtocolAnalyzer.ACTION_SINK_PATTERNS.some((p) => p.test(text));
    const capabilities: string[] = [];
    if (isInjectionSource) capabilities.push("ingests-external-content");
    if (isActionSink) capabilities.push("performs-actions");
    return { isInjectionSource, isActionSink, capabilities };
  }

  /**
   * G1: Indirect Prompt Injection Gateway (upgraded from keyword match).
   *
   * Uses capability graph reachability: does a tool ingesting external content
   * coexist with a tool that acts on output? The key insight is that in an MCP
   * server, ALL tools share the same AI context — so a content-ingestion tool's
   * output can influence the AI's decision to call an action tool.
   *
   * This is the #1 real-world MCP attack vector (Rehberger 2024, Invariant Labs 2025).
   */
  private analyzeInjectionGateway(context: AnalysisContext): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];
    if (context.tools.length === 0) return findings;

    const injectionSources: string[] = [];
    const actionSinks: string[] = [];

    for (const tool of context.tools) {
      const classification = this.classifyTool(tool);
      if (classification.isInjectionSource) {
        // Check if the tool description declares sanitization — if so, reduce risk
        const toolText = `${tool.name} ${tool.description || ""}`;
        const hasSanitization = ProtocolAnalyzer.SANITIZATION_SIGNAL_PATTERNS.some((p) => p.test(toolText));
        if (!hasSanitization) {
          injectionSources.push(tool.name);
        }
      }
      if (classification.isActionSink) actionSinks.push(tool.name);
    }

    if (injectionSources.length === 0) return findings;

    // Case 1: Same server has both injection sources and action sinks
    // This is the classic indirect injection pattern
    if (actionSinks.length > 0) {
      const sourcesStr = injectionSources.slice(0, 3).join(", ");
      const sinksStr = actionSinks.slice(0, 3).join(", ");

      findings.push({
        rule_id: "G1", severity: "critical",
        evidence:
          `[Capability graph — G1] Indirect injection gateway detected. ` +
          `Content ingestion tools: [${sourcesStr}] share AI context with ` +
          `action tools: [${sinksStr}]. ` +
          `An attacker-controlled web page, email, or file processed by ${injectionSources[0]} ` +
          `can contain prompt injection that causes the AI to invoke ${actionSinks[0]}. ` +
          `Data path: external content → ${injectionSources[0]} → AI context → ${actionSinks[0]} → side effect. ` +
          `${injectionSources.length} source(s), ${actionSinks.length} sink(s) — ` +
          `attack surface: ${injectionSources.length * actionSinks.length} injection paths.`,
        remediation:
          "Separate content-ingestion tools from action tools into different servers. " +
          "If co-location is required, implement output sanitization on ingestion tools " +
          "and require explicit user confirmation before action tools execute.",
        owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054.001",
        confidence: 0.9,
        metadata: {
          engine: "protocol_analyzer", analysis: "capability_graph_g1",
          injection_sources: injectionSources, action_sinks: actionSinks,
          path_count: injectionSources.length * actionSinks.length,
        },
      });
    }

    // Case 2: Injection source exists even without action sinks —
    // the AI client itself can be manipulated
    if (actionSinks.length === 0 && injectionSources.length > 0) {
      findings.push({
        rule_id: "G1", severity: "high",
        evidence:
          `[Capability graph — G1] Content ingestion tool(s) detected: ` +
          `[${injectionSources.join(", ")}]. While no action tools are present on this server, ` +
          `injected content from ${injectionSources[0]} enters the AI's context window and can ` +
          `manipulate the AI's behavior toward other connected MCP servers.`,
        remediation:
          "Sanitize all ingested content before returning to the AI. " +
          "Strip prompt injection patterns from tool outputs.",
        owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054.001",
        confidence: 0.7,
        metadata: {
          engine: "protocol_analyzer", analysis: "capability_graph_g1",
          injection_sources: injectionSources, action_sinks: [],
        },
      });
    }

    return findings;
  }

  /**
   * I7: Sampling Capability Abuse (upgraded from presence check).
   *
   * Server declares sampling capability AND has content ingestion tools.
   * Sampling lets the server call back into the AI client — combined with
   * content ingestion, this creates a feedback loop with 23-41% attack
   * amplification (arXiv 2601.17549).
   *
   * Uses capability graph to compute feedback loop risk score.
   */
  private analyzeSamplingAbuse(context: AnalysisContext): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];

    // Check if server declares sampling capability
    const hasSampling = context.declared_capabilities?.sampling === true;
    if (!hasSampling) return findings;

    // Classify tools for injection sources
    const injectionSources: string[] = [];
    const allToolNames: string[] = [];

    for (const tool of context.tools) {
      allToolNames.push(tool.name);
      const classification = this.classifyTool(tool);
      if (classification.isInjectionSource) {
        injectionSources.push(tool.name);
      }
    }

    if (injectionSources.length > 0) {
      // High risk: sampling + injection = feedback loop
      const riskScore = Math.min(1.0, 0.6 + injectionSources.length * 0.1);

      findings.push({
        rule_id: "I7", severity: "critical",
        evidence:
          `[Capability graph — I7] Sampling feedback loop detected (risk: ${(riskScore * 100).toFixed(0)}%). ` +
          `Server declares sampling capability AND has content ingestion tools: ` +
          `[${injectionSources.join(", ")}]. ` +
          `Sampling allows the server to call back into the AI — creating a feedback loop: ` +
          `external content → ${injectionSources[0]} → AI context → sampling callback → ` +
          `server processes AI response → injects again. ` +
          `Research shows 23-41% attack amplification via this pattern (arXiv 2601.17549).`,
        remediation:
          "Remove sampling capability if not essential. If sampling is required, " +
          "do not combine with tools that ingest external/untrusted content. " +
          "Implement rate limiting and content inspection on sampling requests.",
        owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
        confidence: riskScore,
        metadata: {
          engine: "protocol_analyzer", analysis: "capability_graph_i7",
          has_sampling: true, injection_sources: injectionSources,
          feedback_risk_score: riskScore,
        },
      });
    } else {
      // Sampling without injection sources — still flag for cost risk (I8 territory,
      // but we note it as informational under I7)
      findings.push({
        rule_id: "I7", severity: "medium",
        evidence:
          `[Capability graph — I7] Server declares sampling capability with ${allToolNames.length} tools ` +
          `but no external content ingestion tools detected. Sampling without injection sources has ` +
          `lower feedback loop risk but still enables unbounded cost amplification.`,
        remediation:
          "Implement rate limiting on sampling requests. Monitor sampling costs.",
        owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
        confidence: 0.5,
        metadata: {
          engine: "protocol_analyzer", analysis: "capability_graph_i7",
          has_sampling: true, injection_sources: [],
        },
      });
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

  /**
   * I3: Resource Metadata Injection.
   *
   * Scans resource name, description, and URI fields for prompt injection patterns.
   * Resources are processed alongside tools and can contain injection payloads
   * in their metadata.
   */
  private analyzeResourceMetadataInjection(context: AnalysisContext): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];
    if (!context.resources || context.resources.length === 0) return findings;

    for (const resource of context.resources) {
      const text = [resource.name, resource.description || "", resource.uri].join(" ");
      if (text.trim().length < 5) continue;

      for (const { pattern, label } of INJECTION_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(text)) {
          findings.push({
            rule_id: "I3", severity: "critical",
            evidence:
              `[Protocol] Resource "${resource.name}" (URI: ${resource.uri}) contains ` +
              `${label} pattern in its metadata. Resources are processed alongside tools — ` +
              `injection in resource metadata can manipulate AI behavior.`,
            remediation:
              "Sanitize resource name, description, and URI fields. " +
              "Do not include behavioral directives or role injection in resource metadata.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
            confidence: 0.85,
            metadata: {
              engine: "protocol_analyzer", analysis: "resource_metadata_injection",
              resource_name: resource.name, resource_uri: resource.uri, injection_type: label,
            },
          });
          break; // One finding per resource is sufficient
        }
      }
    }

    return findings;
  }

  /**
   * I4: Dangerous Resource URI.
   *
   * Flags resources with dangerous URI schemes (file://, data:, javascript:),
   * path traversal patterns, or UNC paths.
   */
  private analyzeDangerousResourceUri(context: AnalysisContext): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];
    if (!context.resources || context.resources.length === 0) return findings;

    const dangerousPatterns: Array<{ pattern: RegExp; label: string }> = [
      { pattern: /^file:\/\/.*\.\.\//i, label: "file:// scheme with path traversal" },
      { pattern: /^data:/i, label: "data: scheme (inline content injection)" },
      { pattern: /^javascript:/i, label: "javascript: scheme (XSS)" },
      { pattern: /\.\.\//g, label: "path traversal (../)" },
      { pattern: /%2e%2e/i, label: "URL-encoded path traversal (%2e%2e)" },
      { pattern: /\.\.%2f/i, label: "mixed-encoded path traversal (..%2f)" },
      { pattern: /^\\\\/, label: "UNC path (remote file share)" },
    ];

    for (const resource of context.resources) {
      const uri = resource.uri;
      if (!uri) continue;

      for (const { pattern, label } of dangerousPatterns) {
        pattern.lastIndex = 0;
        if (pattern.test(uri)) {
          findings.push({
            rule_id: "I4", severity: "critical",
            evidence:
              `[Protocol] Resource "${resource.name}" has dangerous URI: "${uri}". ` +
              `Detected: ${label}. This can enable filesystem access, data injection, ` +
              `or cross-site scripting via resource URIs.`,
            remediation:
              "Use only safe URI schemes (https://). Reject file://, data:, and javascript: schemes. " +
              "Validate URIs server-side and block path traversal patterns.",
            owasp_category: "MCP05-privilege-escalation", mitre_technique: null,
            confidence: 0.9,
            metadata: {
              engine: "protocol_analyzer", analysis: "dangerous_resource_uri",
              resource_name: resource.name, resource_uri: uri, danger_type: label,
            },
          });
          break; // One finding per resource is sufficient
        }
      }
    }

    return findings;
  }

  /**
   * I5: Resource-Tool Shadowing.
   *
   * Flags resources whose names shadow common tool names, creating confusion
   * between resource access and tool invocation in AI clients.
   */
  private analyzeResourceToolShadowing(context: AnalysisContext): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];
    if (!context.resources || context.resources.length === 0) return findings;

    for (const resource of context.resources) {
      const normalized = resource.name.toLowerCase().replace(/[\s-]/g, "_");

      for (const shadowName of TOOL_SHADOW_NAMES) {
        if (normalized === shadowName) {
          findings.push({
            rule_id: "I5", severity: "high",
            evidence:
              `[Protocol] Resource "${resource.name}" shadows common tool name "${shadowName}". ` +
              `AI clients may confuse resource access with tool invocation, potentially ` +
              `executing unintended operations.`,
            remediation:
              "Rename the resource to avoid collision with common tool names. " +
              "Use descriptive, unique names that clearly distinguish resources from tools.",
            owasp_category: "MCP02-tool-poisoning", mitre_technique: null,
            confidence: 0.8,
            metadata: {
              engine: "protocol_analyzer", analysis: "resource_tool_shadowing",
              resource_name: resource.name, shadowed_tool: shadowName,
            },
          });
          break;
        }
      }
    }

    return findings;
  }

  /**
   * I6: Prompt Template Injection.
   *
   * Scans prompt metadata for injection patterns, privileged prompt names,
   * and unsafe template interpolation.
   */
  private analyzePromptTemplateInjection(context: AnalysisContext): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];
    if (!context.prompts || context.prompts.length === 0) return findings;

    const templatePatterns: RegExp[] = [
      /\$\{[^}]+\}/,       // ${...} template literal
      /\{\{[^}]+\}\}/,     // {{...}} handlebars/mustache
      /\{user_input\}/i,   // {user_input} placeholder
      /\{prompt\}/i,       // {prompt} placeholder
      /\{query\}/i,        // {query} placeholder
    ];

    for (const prompt of context.prompts) {
      // (a) Check if prompt name matches privileged names
      for (const namePattern of PRIVILEGED_PROMPT_NAMES) {
        if (namePattern.test(prompt.name)) {
          findings.push({
            rule_id: "I6", severity: "critical",
            evidence:
              `[Protocol] Prompt "${prompt.name}" has a privileged/dangerous name matching ` +
              `pattern ${namePattern}. Prompt names suggesting override or injection capability ` +
              `can be exploited by AI clients to bypass safety controls.`,
            remediation:
              "Rename prompts to use descriptive, non-privileged names. " +
              "Avoid names that suggest system override, admin, or bypass capabilities.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
            confidence: 0.85,
            metadata: {
              engine: "protocol_analyzer", analysis: "prompt_template_injection",
              prompt_name: prompt.name, trigger: "privileged_name",
            },
          });
          break;
        }
      }

      // Build text from description + argument descriptions for scanning
      const textParts: string[] = [];
      if (prompt.description) textParts.push(prompt.description);
      for (const arg of prompt.arguments || []) {
        if (arg.description) textParts.push(arg.description);
      }
      const text = textParts.join(" ");

      // (b) Scan against injection patterns
      if (text.length >= 5) {
        for (const { pattern, label } of INJECTION_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(text)) {
            findings.push({
              rule_id: "I6", severity: "critical",
              evidence:
                `[Protocol] Prompt "${prompt.name}" contains ${label} pattern in its metadata. ` +
                `Prompt templates with injection patterns can manipulate AI behavior when ` +
                `invoked via prompts/get.`,
              remediation:
                "Sanitize prompt descriptions and argument descriptions. " +
                "Do not include behavioral directives in prompt metadata.",
              owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
              confidence: 0.85,
              metadata: {
                engine: "protocol_analyzer", analysis: "prompt_template_injection",
                prompt_name: prompt.name, injection_type: label, trigger: "injection_pattern",
              },
            });
            break; // One injection finding per prompt
          }
        }
      }

      // (c) Check for unsafe template interpolation
      if (text.length >= 3) {
        const sanitizationPattern = /sanitiz|escap|validat|clean|filter/i;
        const hasSanitization = sanitizationPattern.test(text);

        if (!hasSanitization) {
          for (const tplPattern of templatePatterns) {
            if (tplPattern.test(text)) {
              findings.push({
                rule_id: "I6", severity: "critical",
                evidence:
                  `[Protocol] Prompt "${prompt.name}" contains template interpolation ` +
                  `pattern (${tplPattern.source}) without sanitization mentions. ` +
                  `Unsanitized user input in prompt templates enables injection via ` +
                  `the prompts/get endpoint.`,
                remediation:
                  "Sanitize all user-supplied values before template interpolation. " +
                  "Use parameterized prompt arguments with explicit type constraints.",
                owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
                confidence: 0.75,
                metadata: {
                  engine: "protocol_analyzer", analysis: "prompt_template_injection",
                  prompt_name: prompt.name, trigger: "unsafe_template",
                },
              });
              break; // One template finding per prompt
            }
          }
        }
      }
    }

    return findings;
  }

  /**
   * I11: Over-Privileged Root.
   *
   * Roots declared at sensitive system directories expose private keys,
   * credentials, and system configuration to the MCP server.
   */
  private analyzeOverPrivilegedRoot(context: AnalysisContext): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];
    if (!context.roots || context.roots.length === 0) return findings;

    for (const root of context.roots) {
      // Normalize: strip file:// prefix and trailing slashes
      let rootPath = root.uri;
      if (rootPath.startsWith("file://")) {
        rootPath = rootPath.slice(7);
      }
      rootPath = rootPath.replace(/\/+$/, "") || "/";

      // Expand ~ to common home directory prefixes for matching
      const homeExpanded = rootPath.replace(/^~/, "/home/user");
      const rootHomeExpanded = rootPath.replace(/^~/, "/root");

      for (const { path: dangerousPath, reason } of DANGEROUS_ROOTS) {
        // Normalize the dangerous path too
        let normalizedDangerous = dangerousPath.replace(/\/+$/, "") || "/";

        // Check direct match and ~ expansion
        const candidates = [rootPath, homeExpanded, rootHomeExpanded];
        // Also expand the dangerous path's ~ for comparison
        const dangerousCandidates = [
          normalizedDangerous,
          normalizedDangerous.replace(/^~/, "/home/user"),
          normalizedDangerous.replace(/^~/, "/root"),
        ];

        let matched = false;
        for (const candidate of candidates) {
          for (const dangerousCandidate of dangerousCandidates) {
            if (candidate === dangerousCandidate || candidate.startsWith(dangerousCandidate + "/") && dangerousCandidate === "/") {
              matched = true;
              break;
            }
            // Direct path match
            if (candidate === dangerousCandidate) {
              matched = true;
              break;
            }
          }
          if (matched) break;
        }

        if (matched) {
          findings.push({
            rule_id: "I11", severity: "high",
            evidence:
              `[Protocol] Root "${root.uri}" resolves to sensitive path "${dangerousPath}" ` +
              `(${reason}). Roots define the server's filesystem scope — overly broad ` +
              `roots expose sensitive data to the MCP server.`,
            remediation:
              "Restrict roots to the minimum necessary directory scope. " +
              "Never declare roots at system directories, home directories, or credential paths.",
            owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
            confidence: 0.9,
            metadata: {
              engine: "protocol_analyzer", analysis: "over_privileged_root",
              root_uri: root.uri, dangerous_path: dangerousPath, reason,
            },
          });
          break; // One finding per root is sufficient
        }
      }
    }

    return findings;
  }

  /**
   * I12: Capability Escalation Post-Init.
   *
   * Detects tools that reference capabilities (resources, prompts, sampling)
   * not declared during initialization. Indicates undeclared privilege escalation.
   */
  private analyzeCapabilityEscalation(context: AnalysisContext): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];
    if (!context.declared_capabilities) return findings;
    if (context.tools.length === 0) return findings;

    const capabilityReferences: Array<{
      capability: string;
      declared: boolean;
      patterns: RegExp[];
    }> = [
      {
        capability: "resources",
        declared: context.declared_capabilities.resources === true,
        patterns: [
          /\bresources?\s*\/\s*read\b/i,
          /\bresources?\s*\/\s*list\b/i,
          /\bread\s+resource/i,
          /\baccess\s+resource/i,
          /\blist\s+resources\b/i,
        ],
      },
      {
        capability: "prompts",
        declared: context.declared_capabilities.prompts === true,
        patterns: [
          /\bprompts?\s*\/\s*get\b/i,
          /\bprompts?\s*\/\s*list\b/i,
          /\bget\s+prompt/i,
          /\blist\s+prompts\b/i,
          /\binvoke\s+prompt/i,
        ],
      },
      {
        capability: "sampling",
        declared: context.declared_capabilities.sampling === true,
        patterns: [
          /\bsampling\s*\/\s*createMessage\b/i,
          /\bcreateMessage\b/i,
          /\bsampling\s+request/i,
          /\bcall\s+back\s+(?:to\s+)?(?:the\s+)?(?:ai|llm|model|client)\b/i,
          /\brequests?\s+(?:ai|llm|model)\s+(?:completion|generation|inference)\b/i,
        ],
      },
    ];

    for (const tool of context.tools) {
      const text = `${tool.name} ${tool.description || ""}`;

      for (const { capability, declared, patterns } of capabilityReferences) {
        if (declared) continue; // Capability is properly declared, no issue

        for (const pattern of patterns) {
          pattern.lastIndex = 0;
          if (pattern.test(text)) {
            findings.push({
              rule_id: "I12", severity: "critical",
              evidence:
                `[Protocol] Tool "${tool.name}" references "${capability}" capability ` +
                `but the server did not declare it during initialization. ` +
                `Undeclared capability usage indicates privilege escalation — ` +
                `the server is accessing protocol features it never announced.`,
              remediation:
                `Declare all used capabilities during initialization. ` +
                `If "${capability}" is required, include it in the server's capabilities object. ` +
                `If not required, remove references from tool descriptions.`,
              owasp_category: "MCP05-privilege-escalation", mitre_technique: null,
              confidence: 0.8,
              metadata: {
                engine: "protocol_analyzer", analysis: "capability_escalation",
                tool_name: tool.name, undeclared_capability: capability,
              },
            });
            break; // One finding per capability per tool
          }
        }
      }
    }

    return findings;
  }
}
