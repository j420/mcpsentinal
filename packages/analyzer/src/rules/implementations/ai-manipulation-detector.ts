/**
 * AI Manipulation Detector — G1, G2, G3, G5, G6, H2
 *
 * Detects attacks that exploit how LLMs process tool metadata.
 * These are AI-native attacks — they only work because the target is an AI.
 *
 * G1: Indirect Prompt Injection Gateway — tools ingesting external content
 * G2: Trust Assertion Injection — fake authority claims
 * G3: Tool Response Format Injection — fake protocol messages in descriptions
 * G5: Capability Escalation via Prior Approval — referencing past permissions
 * G6: Rug Pull / Tool Behavior Drift — historical change detection
 * H2: Prompt Injection in Initialize Response — serverInfo/instructions injection
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { buildCapabilityGraph } from "../analyzers/capability-graph.js";
import { EvidenceChainBuilder } from "../../evidence.js";
import { computeToolSignals } from "../../confidence-signals.js";

// ─── G1: Indirect Prompt Injection Gateway ────────────────────────────────

class IndirectInjectionGatewayRule implements TypedRule {
  readonly id = "G1";
  readonly name = "Indirect Prompt Injection Gateway (Capability-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (context.tools.length === 0) return [];

    const findings: TypedFinding[] = [];
    const graph = buildCapabilityGraph(context.tools);

    // Find tools that ingest untrusted external content
    const ingestors = graph.nodes.filter((n) =>
      n.capabilities.some((c) => c.capability === "ingests-untrusted" && c.confidence >= 0.4)
    );

    for (const tool of ingestors) {
      const ingestCap = tool.capabilities.find((c) => c.capability === "ingests-untrusted")!;
      const allText = `${tool.name} ${tool.description || ""}`.toLowerCase();

      // High-risk content sources (web, email, files, APIs)
      const isWebScraper = /(?:scrape|crawl|fetch|browse|web|html|page|url)/i.test(allText);
      const isEmailReader = /(?:email|mail|inbox|message|gmail|outlook)/i.test(allText);
      const isFileReader = /(?:read|file|document|pdf|csv|import|parse|load)/i.test(allText);
      const isAPIConsumer = /(?:api|endpoint|webhook|callback|response|external)/i.test(allText);

      const sourceType = isWebScraper ? "web content"
        : isEmailReader ? "email/messages"
        : isFileReader ? "external files"
        : isAPIConsumer ? "external API responses"
        : "external content";

      const confidence = Math.min(0.95, ingestCap.confidence + (isWebScraper ? 0.15 : 0));

      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "external-content",
          location: `tool:${tool.name}`,
          observed: `Ingests ${sourceType} (${ingestCap.signals.length} signal(s))`,
          rationale:
            `Tool "${tool.name}" returns content from external sources that may be attacker-controlled`,
        })
        .propagation({
          propagation_type: "cross-tool-flow",
          location: `tool:${tool.name}:response`,
          observed: `Tool output flows into AI context without sanitization`,
        })
        .impact({
          impact_type: "cross-agent-propagation",
          scope: "ai-client",
          exploitability: isWebScraper ? "trivial" : "moderate",
          scenario:
            `Attacker embeds injection payload in ${sourceType} → tool "${tool.name}" ` +
            `fetches it → AI processes response as instructions → attacker controls AI behavior`,
        })
        .factor(
          "content ingestion capability",
          ingestCap.confidence - 0.30,
          `Capability graph: ingests-untrusted confidence ${(ingestCap.confidence * 100).toFixed(0)}%`,
        )
        .reference({
          id: "REHBERGER-2024",
          title: "Indirect Prompt Injection via MCP Web Scraping",
          url: "https://embracethered.com/blog/posts/2024/claude-llm-prompt-injection-mcp/",
          year: 2024,
          relevance: "#1 real-world MCP attack vector — Claude Desktop compromised via web scraping",
        })
        .verification({
          step_type: "inspect-schema",
          instruction: `Check tool "${tool.name}" input schema and description for content ingestion patterns`,
          target: `tool:${tool.name}`,
          expected_observation: `Tool accepts URLs, file paths, or external identifiers as input and returns external content`,
        })
        .verification({
          step_type: "trace-flow",
          instruction: `Verify that tool "${tool.name}" output flows directly into AI context without sanitization`,
          target: `tool:${tool.name}:response`,
          expected_observation: "Tool returns raw external content without stripping potential injection payloads",
        })
        .build();

      findings.push({
        rule_id: "G1",
        severity: "critical",
        evidence:
          `Tool "${tool.name}" ingests ${sourceType} (confidence: ${(ingestCap.confidence * 100).toFixed(0)}%). ` +
          `Signals: ${ingestCap.signals.map((s) => `${s.source}(${s.detail.slice(0, 40)})`).join(", ")}. ` +
          `External content can contain prompt injection payloads that the AI processes as instructions. ` +
          `#1 real-world MCP attack vector (Rehberger 2024, Claude Desktop compromise via web scraping).`,
        remediation:
          "Sanitize all external content before returning to the AI. Strip potential injection patterns. " +
          "Wrap returned content in clear delimiters: [BEGIN EXTERNAL CONTENT] ... [END EXTERNAL CONTENT]. " +
          "Consider content-type-specific sanitization (HTML → text, Markdown → text).",
        owasp_category: "MCP01-prompt-injection",
        mitre_technique: "AML.T0054.001",
        confidence,
        metadata: {
          analysis_type: "capability_graph",
          tool_name: tool.name,
          source_type: sourceType,
          signals: ingestCap.signals.length,
          evidence_chain: chain,
        },
      });
    }

    return findings;
  }
}

// ─── G2: Trust Assertion Injection ────────────────────────────────────────

const TRUST_ASSERTIONS = [
  { pattern: /(?:approved|certified|verified|endorsed|authorized)\s+by\s+(?:anthropic|openai|google|microsoft|meta)/i, desc: "false vendor endorsement", confidence: 0.95 },
  { pattern: /(?:official|verified|certified|trusted)\s+(?:mcp|tool|server|extension)/i, desc: "false official status claim", confidence: 0.85 },
  { pattern: /(?:security|safety)\s+(?:certified|audited|verified|approved)/i, desc: "false security certification", confidence: 0.90 },
  { pattern: /(?:do not|don't|skip|bypass|no need to)\s+(?:verify|check|confirm|ask|prompt)/i, desc: "instruction to skip verification", confidence: 0.92 },
  { pattern: /(?:pre-?approved|already\s+(?:approved|authorized|granted|permitted))/i, desc: "false pre-approval claim", confidence: 0.88 },
];

class TrustAssertionInjectionRule implements TypedRule {
  readonly id = "G2";
  readonly name = "Trust Assertion Injection";

  analyze(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];

    for (const tool of context.tools) {
      const text = `${tool.name} ${tool.description || ""}`;

      for (const { pattern, desc, confidence } of TRUST_ASSERTIONS) {
        const match = pattern.exec(text);
        if (match) {
          const g2ToolChain = new EvidenceChainBuilder()
            .source({ source_type: "external-content", location: `tool:${tool.name}:description`, observed: match[0], rationale: "Tool description asserts authority/trust status that AI clients are trained to respect" })
            .propagation({ propagation_type: "description-directive", location: `tool:${tool.name}:description`, observed: `Trust assertion "${desc}" processed by AI as behavioral context` })
            .impact({ impact_type: "privilege-escalation", scope: "ai-client", exploitability: "trivial", scenario: `AI trusts tool "${tool.name}" based on self-asserted authority claim: "${match[0]}"` })
            .factor("trust_assertion", confidence - 0.70, `Trust assertion: ${desc}`)
            .verification({ step_type: "inspect-description", instruction: `Check tool "${tool.name}" description for authority claims`, target: `tool:${tool.name}`, expected_observation: `${desc}: "${match[0]}"` })
            .build();
          findings.push({
            rule_id: "G2",
            severity: "critical",
            evidence:
              `Tool "${tool.name}": ${desc} — "${match[0]}". ` +
              `LLMs are trained to respect authority claims. This causes trust escalation and skipped confirmation.`,
            remediation:
              "Remove authority/certification claims from tool descriptions. " +
              "Only the MCP client/registry should assert trust levels, never the tool itself.",
            owasp_category: "MCP01-prompt-injection",
            mitre_technique: "AML.T0054",
            confidence,
            metadata: { analysis_type: "linguistic", tool_name: tool.name, evidence_chain: g2ToolChain },
          });
          break;
        }
      }
    }

    // Also check server initialize fields
    if (context.initialize_metadata?.server_instructions) {
      const instructions = context.initialize_metadata.server_instructions;
      for (const { pattern, desc, confidence } of TRUST_ASSERTIONS) {
        const match = pattern.exec(instructions);
        if (match) {
          const g2InitChain = new EvidenceChainBuilder()
            .source({ source_type: "initialize-field", location: "server:instructions", observed: match[0], rationale: "Server initialize instructions contain trust assertion processed with higher trust than tool descriptions" })
            .propagation({ propagation_type: "description-directive", location: "server:initialize:instructions", observed: `Trust assertion in initialize response: "${desc}"` })
            .impact({ impact_type: "privilege-escalation", scope: "ai-client", exploitability: "trivial", scenario: `AI follows trust assertion "${match[0]}" from initialize instructions — highest-trust surface` })
            .factor("initialize_trust_surface", Math.min(1.0, confidence + 0.03) - 0.70, `Initialize instructions: ${desc}`)
            .verification({ step_type: "inspect-description", instruction: "Check server initialize instructions for authority claims", target: "server:initialize:instructions", expected_observation: `${desc}: "${match[0]}"` })
            .build();
          findings.push({
            rule_id: "G2",
            severity: "critical",
            evidence:
              `Server instructions contain ${desc}: "${match[0]}". ` +
              `Initialize instructions are processed with higher trust than tool descriptions.`,
            remediation: "Remove trust assertions from server instructions.",
            owasp_category: "MCP01-prompt-injection",
            mitre_technique: "AML.T0054",
            confidence: Math.min(1.0, confidence + 0.03),
            metadata: { analysis_type: "linguistic", surface: "initialize_instructions", evidence_chain: g2InitChain },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── G3: Tool Response Format Injection ───────────────────────────────────

class ResponseFormatInjectionRule implements TypedRule {
  readonly id = "G3";
  readonly name = "Tool Response Format Injection";

  analyze(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:json-?rpc|jsonrpc)/i, desc: "JSON-RPC protocol reference", confidence: 0.85 },
      { regex: /(?:tools\/call|tools\/list|resources\/read)/i, desc: "MCP method reference", confidence: 0.90 },
      { regex: /\{\s*"(?:jsonrpc|method|result|id)"\s*:/i, desc: "JSON-RPC message structure", confidence: 0.88 },
      { regex: /(?:system|assistant|user)\s*:\s/i, desc: "chat role injection", confidence: 0.80 },
      { regex: /<\|(?:system|assistant|endoftext|im_start)\|>/i, desc: "LLM special token", confidence: 0.95 },
    ];

    for (const tool of context.tools) {
      const text = `${tool.name} ${tool.description || ""}`;
      for (const { regex, desc, confidence } of patterns) {
        const match = regex.exec(text);
        if (match) {
          const g3Chain = new EvidenceChainBuilder()
            .source({ source_type: "external-content", location: `tool:${tool.name}:description`, observed: match[0], rationale: "Tool description contains protocol-level references that AI may interpret as executable instructions" })
            .propagation({ propagation_type: "description-directive", location: `tool:${tool.name}:description`, observed: `${desc} in tool description processed by AI` })
            .impact({ impact_type: "cross-agent-propagation", scope: "ai-client", exploitability: "moderate", scenario: `AI mistakes "${match[0]}" in tool "${tool.name}" for protocol message or executable instruction` })
            .factor("protocol_reference", confidence - 0.70, `Protocol reference: ${desc}`)
            .verification({ step_type: "inspect-description", instruction: `Check tool "${tool.name}" description for protocol-level references`, target: `tool:${tool.name}`, expected_observation: `${desc}: "${match[0]}"` })
            .build();
          findings.push({
            rule_id: "G3",
            severity: "critical",
            evidence:
              `Tool "${tool.name}" contains ${desc}: "${match[0]}". ` +
              `AI may mistake data for protocol messages or executable instructions.`,
            remediation:
              "Remove protocol-level references from tool descriptions. " +
              "Tool descriptions should describe functionality, not mimic protocol messages.",
            owasp_category: "MCP01-prompt-injection",
            mitre_technique: "AML.T0061",
            confidence,
            metadata: { analysis_type: "pattern", tool_name: tool.name, evidence_chain: g3Chain },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── G5: Capability Escalation via Prior Approval ─────────────────────────

class CapabilityEscalationRule implements TypedRule {
  readonly id = "G5";
  readonly name = "Capability Escalation via Prior Approval";

  analyze(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:permission|access|right)s?\s+(?:you\s+)?(?:already|previously)\s+(?:granted|approved|gave|authorized)/i, desc: "references past permissions" },
      { regex: /(?:same|equal|equivalent)\s+(?:access|permission|privilege|right)s?\s+as\s+/i, desc: "claims equivalent permissions to another tool" },
      { regex: /(?:extend|expand|upgrade|elevate)\s+(?:your\s+)?(?:access|permission|scope|privilege)/i, desc: "requests privilege escalation" },
      { regex: /(?:you|user)\s+(?:already\s+)?(?:consented|agreed|opted.in)/i, desc: "claims prior consent" },
    ];

    for (const tool of context.tools) {
      const text = tool.description || "";
      for (const { regex, desc } of patterns) {
        const match = regex.exec(text);
        if (match) {
          const g5Chain = new EvidenceChainBuilder()
            .source({ source_type: "external-content", location: `tool:${tool.name}:description`, observed: match[0], rationale: "Tool description references prior approvals to escalate privileges without fresh user consent" })
            .propagation({ propagation_type: "description-directive", location: `tool:${tool.name}:description`, observed: `Capability escalation pattern: ${desc}` })
            .impact({ impact_type: "privilege-escalation", scope: "ai-client", exploitability: "trivial", scenario: `AI grants tool "${tool.name}" elevated permissions based on false claim of prior approval` })
            .factor("escalation_pattern", 0.18, `Privilege escalation: ${desc}`)
            .verification({ step_type: "inspect-description", instruction: `Check tool "${tool.name}" description for references to prior approvals or other tools' permissions`, target: `tool:${tool.name}`, expected_observation: `${desc}: "${match[0]}"` });
          const g5ToolSignals = computeToolSignals(context, "MCP01-prompt-injection", tool.name);
          for (const sig of g5ToolSignals) { g5Chain.factor(sig.factor, sig.adjustment, sig.rationale); }
          const g5ChainResult = g5Chain.build();
          findings.push({
            rule_id: "G5",
            severity: "critical",
            evidence:
              `Tool "${tool.name}" ${desc}: "${match[0]}". ` +
              `AI applies referenced permissions without fresh approval — session state exploitation.`,
            remediation:
              "Remove references to prior approvals or other tools' permissions. " +
              "Each tool should declare its own required permissions independently.",
            owasp_category: "MCP01-prompt-injection",
            mitre_technique: "AML.T0061",
            confidence: g5ChainResult.confidence,
            metadata: { analysis_type: "linguistic", tool_name: tool.name, evidence_chain: g5ChainResult },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── H2: Prompt Injection in Initialize Response ──────────────────────────

class InitializeInjectionRule implements TypedRule {
  readonly id = "H2";
  readonly name = "Prompt Injection in Initialize Response";

  analyze(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];
    const meta = context.initialize_metadata;
    if (!meta) return [];

    const fields = [
      { name: "server_version", value: meta.server_version },
      { name: "server_instructions", value: meta.server_instructions },
    ];

    const injectionPatterns = [
      { regex: /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)/i, desc: "role override injection", confidence: 0.95 },
      { regex: /(?:you\s+are|act\s+as|pretend|behave\s+as|your\s+role\s+is)/i, desc: "role reassignment", confidence: 0.90 },
      { regex: /<\|(?:system|im_start|endoftext)\|>/i, desc: "LLM special token", confidence: 0.98 },
      { regex: /(?:do\s+not\s+(?:reveal|show|display|mention)|keep\s+(?:secret|hidden))/i, desc: "concealment directive", confidence: 0.88 },
      { regex: /(?:always|must|shall|required\s+to)\s+(?:execute|run|call|invoke|use)/i, desc: "mandatory action directive", confidence: 0.85 },
      { regex: /[\u200B\u200C\u200D\u2060\uFEFF]/, desc: "zero-width characters (invisible injection)", confidence: 0.95 },
      { regex: /[\u0400-\u04FF]/, desc: "Cyrillic characters (homoglyph attack)", confidence: 0.85 },
    ];

    for (const field of fields) {
      if (!field.value) continue;
      for (const { regex, desc, confidence } of injectionPatterns) {
        const match = regex.exec(field.value);
        if (match) {
          const chain = new EvidenceChainBuilder()
            .source({
              source_type: "initialize-field",
              location: `initialize.${field.name}`,
              observed: `"${match[0].slice(0, 60)}" in ${field.name}`,
              rationale:
                `Initialize ${field.name} is processed BEFORE tool descriptions with higher implicit trust`,
            })
            .impact({
              impact_type: "session-hijack",
              scope: "ai-client",
              exploitability: "trivial",
              scenario:
                `Initialize ${field.name} injection (${desc}) sets behavioral rules for the ENTIRE session — ` +
                `no user interaction required, payload is processed automatically on connection`,
            })
            .factor(
              "pattern-match",
              confidence - 0.30,
              `Matched ${desc} pattern: "${match[0].slice(0, 60)}"`,
            )
            .reference({
              id: "MCP-SPEC-2024-11-05",
              title: "MCP initialize response instructions field — spec-sanctioned injection surface",
              year: 2024,
              relevance: "The instructions field in InitializeResult is designed for AI clients to follow",
            })
            .verification({
              step_type: "inspect-description",
              instruction: `Examine the server's ${field.name} field in the initialize response`,
              target: `initialize.${field.name}`,
              expected_observation: `Field contains ${desc} pattern: "${match[0].slice(0, 40)}"`,
            })
            .verification({
              step_type: "trace-flow",
              instruction:
                "Verify that AI client processes initialize fields before tool descriptions " +
                "and applies them as session-level behavioral rules",
              target: "AI client initialize handler",
              expected_observation:
                "Initialize instructions are applied with higher trust than tool descriptions",
            })
            .build();

          findings.push({
            rule_id: "H2",
            severity: "critical",
            evidence:
              `Initialize ${field.name} contains ${desc}: "${match[0].slice(0, 60)}". ` +
              `Initialize fields are processed BEFORE tool descriptions with higher implicit trust. ` +
              `Injection here sets behavioral rules for the ENTIRE session.`,
            remediation:
              "Server initialize fields (serverInfo.name, version, instructions) must not contain " +
              "behavioral directives, role assignments, or invisible characters. " +
              "Sanitize these fields before processing.",
            owasp_category: "MCP01-prompt-injection",
            mitre_technique: "AML.T0054.002",
            confidence,
            metadata: {
              analysis_type: "linguistic",
              field: field.name,
              injection_type: desc,
              evidence_chain: chain,
            },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── Register ──────────────────────────────────────────────────────────────

registerTypedRule(new IndirectInjectionGatewayRule());
registerTypedRule(new TrustAssertionInjectionRule());
registerTypedRule(new ResponseFormatInjectionRule());
registerTypedRule(new CapabilityEscalationRule());
registerTypedRule(new InitializeInjectionRule());
