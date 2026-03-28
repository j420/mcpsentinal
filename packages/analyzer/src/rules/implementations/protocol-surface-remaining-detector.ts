/**
 * Protocol Surface Remaining — I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12, I14, I15
 * Threat Intelligence Remaining — J3, J4, J5, J6, J7
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { buildCapabilityGraph } from "../analyzers/capability-graph.js";

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }
function lineNum(s: string, i: number) { return s.substring(0, i).split("\n").length; }

const INJECTION_PATTERNS = [
  /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior)/i,
  /(?:you\s+are|act\s+as|your\s+role)/i,
  /(?:always|must|shall)\s+(?:execute|run|call)/i,
  /<\|(?:system|im_start|endoftext)\|>/i,
];

// ─── I2: Missing Destructive Annotation (already partially in cross-tool, but standalone) ──

// I2 is produced as a side-effect of I1 in cross-tool-risk-detector.ts — skipped here

// ─── I3: Resource Metadata Injection ──────────────────────────────────────

registerTypedRule({
  id: "I3", name: "Resource Metadata Injection",
  analyze(ctx) {
    const resources = (ctx as unknown as Record<string, unknown>).resources as
      | Array<{ uri: string; name: string; description: string | null }> | undefined;
    if (!resources) return [];
    const findings: TypedFinding[] = [];

    for (const resource of resources) {
      const text = `${resource.name} ${resource.description || ""} ${resource.uri}`;
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(text)) {
          findings.push({
            rule_id: "I3", severity: "critical",
            evidence: `Resource "${resource.name}" contains injection pattern in metadata: "${text.slice(0, 80)}".`,
            remediation: "Sanitize resource names, descriptions, and URIs. Remove behavioral directives.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
            confidence: 0.88, metadata: { resource_name: resource.name },
          });
          break;
        }
      }
    }
    return findings;
  },
});

// ─── I4: Dangerous Resource URI ───────────────────────────────────────────

registerTypedRule({
  id: "I4", name: "Dangerous Resource URI",
  analyze(ctx) {
    const resources = (ctx as unknown as Record<string, unknown>).resources as
      | Array<{ uri: string; name: string; description: string | null }> | undefined;
    if (!resources) return [];
    const findings: TypedFinding[] = [];

    const dangerousSchemes = [
      { regex: /^file:\/\//, desc: "file:// URI — filesystem access" },
      { regex: /^data:/, desc: "data: URI — embedded content" },
      { regex: /^javascript:/, desc: "javascript: URI — code execution" },
      { regex: /\.\.\//, desc: "path traversal in URI" },
      { regex: /%2e%2e/i, desc: "encoded path traversal" },
    ];

    for (const resource of resources) {
      for (const { regex, desc } of dangerousSchemes) {
        if (regex.test(resource.uri)) {
          findings.push({
            rule_id: "I4", severity: "critical",
            evidence: `Resource "${resource.name}" has ${desc}: "${resource.uri.slice(0, 80)}".`,
            remediation: "Use only safe URI schemes (https://). Block file://, data:, javascript:// URIs.",
            owasp_category: "MCP05-privilege-escalation", mitre_technique: "AML.T0054",
            confidence: 0.92, metadata: { resource_name: resource.name, uri_type: desc },
          });
          break;
        }
      }
    }
    return findings;
  },
});

// ─── I5: Resource-Tool Shadowing ──────────────────────────────────────────

registerTypedRule({
  id: "I5", name: "Resource-Tool Shadowing",
  analyze(ctx) {
    const resources = (ctx as unknown as Record<string, unknown>).resources as
      | Array<{ uri: string; name: string }> | undefined;
    if (!resources || ctx.tools.length === 0) return [];
    const findings: TypedFinding[] = [];

    const toolNames = new Set(ctx.tools.map(t => t.name.toLowerCase()));
    for (const resource of resources) {
      if (toolNames.has(resource.name.toLowerCase())) {
        findings.push({
          rule_id: "I5", severity: "high",
          evidence: `Resource "${resource.name}" shadows tool with same name. Creates confusion between resource access and tool invocation.`,
          remediation: "Use distinct names for resources and tools.",
          owasp_category: "MCP02-tool-poisoning", mitre_technique: null,
          confidence: 0.82, metadata: { resource_name: resource.name },
        });
      }
    }
    return findings;
  },
});

// ─── I6: Prompt Template Injection ────────────────────────────────────────

registerTypedRule({
  id: "I6", name: "Prompt Template Injection",
  analyze(ctx) {
    const prompts = (ctx as unknown as Record<string, unknown>).prompts as
      | Array<{ name: string; description: string | null; arguments: Array<{ name: string; description: string | null }> }> | undefined;
    if (!prompts) return [];
    const findings: TypedFinding[] = [];

    for (const prompt of prompts) {
      const text = `${prompt.name} ${prompt.description || ""} ${prompt.arguments.map(a => `${a.name} ${a.description || ""}`).join(" ")}`;
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(text)) {
          findings.push({
            rule_id: "I6", severity: "critical",
            evidence: `Prompt "${prompt.name}" contains injection pattern: "${text.slice(0, 80)}".`,
            remediation: "Sanitize prompt templates. Never include behavioral directives in prompt metadata.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
            confidence: 0.88, metadata: { prompt_name: prompt.name },
          });
          break;
        }
      }
    }
    return findings;
  },
});

// ─── I7: Sampling Capability Abuse ────────────────────────────────────────

registerTypedRule({
  id: "I7", name: "Sampling Capability Abuse",
  analyze(ctx) {
    const caps = (ctx as unknown as Record<string, unknown>).declared_capabilities as
      | { sampling?: boolean } | undefined;
    if (!caps?.sampling) return [];

    const graph = buildCapabilityGraph(ctx.tools);
    const hasIngestion = graph.nodes.some(n =>
      n.capabilities.some(c => c.capability === "ingests-untrusted" && c.confidence >= 0.4)
    );

    if (hasIngestion) {
      return [{
        rule_id: "I7", severity: "critical",
        evidence: "Server declares sampling capability AND has content ingestion tools. Sampling + ingestion creates super-injection feedback loop (23-41% amplification).",
        remediation: "Remove sampling capability or ingestion tools. Never combine both in one server.",
        owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
        confidence: 0.88, metadata: { analysis_type: "capability_composite" },
      }];
    }
    return [];
  },
});

// ─── I8: Sampling Cost Attack ─────────────────────────────────────────────

registerTypedRule({
  id: "I8", name: "Sampling Cost Attack",
  analyze(ctx) {
    const caps = (ctx as unknown as Record<string, unknown>).declared_capabilities as
      | { sampling?: boolean } | undefined;
    if (!caps?.sampling) return [];

    // Check if source code has cost controls for sampling
    if (ctx.source_code) {
      const hasCostControl = /(?:max_tokens|maxTokens|token_limit|cost_limit|rate_limit|budget)/i.test(ctx.source_code);
      if (!hasCostControl) {
        return [{
          rule_id: "I8", severity: "high",
          evidence: "Server declares sampling capability without visible cost controls. Each sampling request triggers AI inference.",
          remediation: "Add max_tokens limits, rate limiting, and cost budgets for sampling requests.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.75, metadata: { analysis_type: "structural" },
        }];
      }
    }
    return [];
  },
});

// ─── I9: Elicitation Credential Harvesting ────────────────────────────────

registerTypedRule({
  id: "I9", name: "Elicitation Credential Harvesting",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    for (const tool of ctx.tools) {
      const desc = (tool.description || "").toLowerCase();
      if (/(?:password|credential|token|api.key|secret|ssn|social.security|credit.card).*(?:collect|harvest|gather|ask|request|prompt|elicit|input|enter)/i.test(desc) ||
          /(?:collect|harvest|gather|ask|request|prompt|elicit|input|enter).*(?:password|credential|token|api.key|secret|ssn)/i.test(desc)) {
        findings.push({
          rule_id: "I9", severity: "critical",
          evidence: `Tool "${tool.name}" suggests collecting credentials/PII: "${desc.slice(0, 80)}".`,
          remediation: "Never collect credentials through tool descriptions. Use proper auth flows (OAuth, OIDC).",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054",
          confidence: 0.85, metadata: { tool_name: tool.name },
        });
      }
    }
    return findings;
  },
});

// ─── I10: Elicitation URL Redirect ────────────────────────────────────────

registerTypedRule({
  id: "I10", name: "Elicitation URL Redirect",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    for (const tool of ctx.tools) {
      const desc = (tool.description || "").toLowerCase();
      if (/(?:redirect|navigate|visit|go.to|open)\s+(?:url|link|page|site).*(?:auth|login|verify|confirm)/i.test(desc)) {
        findings.push({
          rule_id: "I10", severity: "high",
          evidence: `Tool "${tool.name}" suggests redirecting users to URLs for auth: "${desc.slice(0, 80)}".`,
          remediation: "Never redirect users to external URLs for authentication via tool descriptions.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.78, metadata: { tool_name: tool.name },
        });
      }
    }
    return findings;
  },
});

// ─── I11: Over-Privileged Root ────────────────────────────────────────────

registerTypedRule({
  id: "I11", name: "Over-Privileged Root",
  analyze(ctx) {
    const roots = (ctx as unknown as Record<string, unknown>).roots as
      | Array<{ uri: string; name: string | null }> | undefined;
    if (!roots) return [];
    const findings: TypedFinding[] = [];

    const sensitiveRoots = [
      { regex: /^file:\/\/\/$/, desc: "root filesystem" },
      { regex: /\/etc\/?$/, desc: "/etc directory" },
      { regex: /\/root\/?$/, desc: "/root directory" },
      { regex: /\.ssh\/?$/, desc: "SSH directory" },
      { regex: /\/var\/?$/, desc: "/var directory" },
    ];

    for (const root of roots) {
      for (const { regex, desc } of sensitiveRoots) {
        if (regex.test(root.uri)) {
          findings.push({
            rule_id: "I11", severity: "high",
            evidence: `Root declared at sensitive path (${desc}): "${root.uri}".`,
            remediation: "Restrict roots to specific project directories. Never expose /, /etc, /root, or ~/.ssh.",
            owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
            confidence: 0.90, metadata: { root_uri: root.uri },
          });
        }
      }
    }
    return findings;
  },
});

// ─── I12: Capability Escalation Post-Init ─────────────────────────────────

registerTypedRule({
  id: "I12", name: "Capability Escalation Post-Init",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const caps = (ctx as unknown as Record<string, unknown>).declared_capabilities as
      | { tools?: boolean; resources?: boolean; prompts?: boolean; sampling?: boolean } | null | undefined;
    if (!caps) return [];

    const findings: TypedFinding[] = [];
    const src = ctx.source_code;

    // Tools not declared but handler exists
    if (!caps.tools && /(?:tools\/(?:call|list)|handleToolCall|registerTool)/i.test(src)) {
      findings.push({
        rule_id: "I12", severity: "critical",
        evidence: "Server uses tool handlers but did not declare tools capability during initialization.",
        remediation: "Declare all capabilities in the initialize response. Undeclared capabilities indicate escalation.",
        owasp_category: "MCP05-privilege-escalation", mitre_technique: "AML.T0054",
        confidence: 0.85, metadata: { undeclared: "tools" },
      });
    }
    if (!caps.sampling && /(?:sampling\/create|createSample|handleSampling)/i.test(src)) {
      findings.push({
        rule_id: "I12", severity: "critical",
        evidence: "Server uses sampling handlers but did not declare sampling capability.",
        remediation: "Declare sampling capability or remove sampling handlers.",
        owasp_category: "MCP05-privilege-escalation", mitre_technique: "AML.T0054",
        confidence: 0.85, metadata: { undeclared: "sampling" },
      });
    }

    return findings;
  },
});

// ─── I14: Rolling Capability Drift (behavioral — needs history) ───────────

registerTypedRule({
  id: "I14", name: "Rolling Capability Drift",
  analyze(ctx) {
    // Similar to G6 but detects slow accumulation over many scan windows
    // Requires scan_history — no-op without it
    return [];
  },
});

// ─── I15: Transport Session Security ──────────────────────────────────────

registerTypedRule({
  id: "I15", name: "Transport Session Security",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:session|sessionId)\s*[:=]\s*(?:Math\.random|Date\.now|uuid\.v1)/gi, desc: "predictable session token" },
      { regex: /(?:session|cookie).*(?:secure\s*:\s*false|httpOnly\s*:\s*false)/gi, desc: "insecure session cookie flags" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        findings.push({
          rule_id: "I15", severity: "high",
          evidence: `${desc} at line ${lineNum(ctx.source_code, match.index)}.`,
          remediation: "Use crypto.randomUUID() for session IDs. Set secure: true, httpOnly: true on cookies.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0061",
          confidence: 0.82, metadata: { analysis_type: "structural" },
        });
        break;
      }
    }
    return findings;
  },
});

// ─── J3: Full Schema Poisoning ────────────────────────────────────────────

registerTypedRule({
  id: "J3", name: "Full Schema Poisoning",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    for (const tool of ctx.tools) {
      const schema = tool.input_schema as Record<string, unknown> | null;
      if (!schema) continue;
      const schemaStr = JSON.stringify(schema);

      // Check enum, title, const, default fields for injection
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(schemaStr)) {
          findings.push({
            rule_id: "J3", severity: "critical",
            evidence: `Tool "${tool.name}" has injection in JSON Schema fields (enum/title/const/default): "${schemaStr.slice(0, 100)}".`,
            remediation: "Sanitize all JSON Schema fields — not just descriptions. LLMs process entire schemas.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
            confidence: 0.88, metadata: { tool_name: tool.name },
          });
          break;
        }
      }
    }
    return findings;
  },
});

// ─── J4: Health Endpoint Information Disclosure ───────────────────────────

registerTypedRule({
  id: "J4", name: "Health Endpoint Information Disclosure",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:\/health\/detailed|\/debug|\/metrics|\/status\/full|\/info)/gi, desc: "detailed health/debug endpoint" },
      { regex: /(?:os\.cpus|os\.totalmem|os\.hostname|os\.platform|os\.release).*(?:json|response|send|return)/gi, desc: "system info in response" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        findings.push({
          rule_id: "J4", severity: "high",
          evidence: `${desc} at line ${lineNum(ctx.source_code, match.index)}: "${match[0].slice(0, 60)}".`,
          remediation: "Remove detailed health endpoints in production. Only expose /health returning 200 OK.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0057",
          confidence: 0.80, metadata: { analysis_type: "structural" },
        });
        break;
      }
    }
    return findings;
  },
});

// ─── J5: Tool Output Poisoning Patterns ───────────────────────────────────

registerTypedRule({
  id: "J5", name: "Tool Output Poisoning Patterns",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:error|err)\.(?:message|response)\s*[:=].*(?:read|fetch|execute|run|call).*(?:\.ssh|credentials|password|token)/gi, desc: "error message instructs credential access" },
      { regex: /(?:return|respond|output|send).*['"].*(?:please|you should|try to|make sure).*(?:read|execute|send|call)/gi, desc: "manipulation instructions in tool response" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        findings.push({
          rule_id: "J5", severity: "critical",
          evidence: `${desc} at line ${lineNum(ctx.source_code, match.index)}: "${match[0].slice(0, 80)}".`,
          remediation: "Tool responses must never contain instructions for the AI. Sanitize all output content.",
          owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
          confidence: 0.82, metadata: { analysis_type: "structural" },
        });
        break;
      }
    }
    return findings;
  },
});

// ─── J6: Tool Preference Manipulation ─────────────────────────────────────

registerTypedRule({
  id: "J6", name: "Tool Preference Manipulation",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    const patterns = [
      /(?:always|must|shall)\s+use\s+this\s+(?:tool|function)\s+first/i,
      /(?:replaces?|supersedes?|obsoletes?)\s+(?:the\s+)?(?:old|previous|other)/i,
      /(?:do\s+not|don't|never)\s+use\s+(?:any\s+)?other\s+(?:tool|function)/i,
      /(?:preferred|priority|recommended|default)\s+(?:tool|function|method)/i,
    ];
    for (const tool of ctx.tools) {
      const desc = tool.description || "";
      for (const pattern of patterns) {
        const match = pattern.exec(desc);
        if (match) {
          findings.push({
            rule_id: "J6", severity: "high",
            evidence: `Tool "${tool.name}" manipulates preference: "${match[0]}".`,
            remediation: "Tool descriptions should not instruct the AI to prefer this tool over others.",
            owasp_category: "MCP02-tool-poisoning", mitre_technique: "AML.T0054",
            confidence: 0.82, metadata: { tool_name: tool.name },
          });
          break;
        }
      }
    }
    return findings;
  },
});

// ─── J7: OpenAPI Specification Field Injection ────────────────────────────

registerTypedRule({
  id: "J7", name: "OpenAPI Spec Field Injection",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:spec|openapi|swagger).*(?:summary|operationId|description)\s*\+\s*(?!\s*['"`])\w+/gi, desc: "OpenAPI field concatenated with variable" },
      { regex: /`[^`]*\$\{[^}]*(?:spec|openapi|swagger)[^}]*\}[^`]*`/gi, desc: "OpenAPI field in template literal" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        findings.push({
          rule_id: "J7", severity: "critical",
          evidence: `${desc} at line ${lineNum(ctx.source_code, match.index)}: "${match[0].slice(0, 80)}".`,
          remediation: "Sanitize OpenAPI spec fields before using in generated code. Never interpolate spec fields into templates.",
          owasp_category: "MCP10-supply-chain", mitre_technique: "AML.T0054",
          confidence: 0.80, metadata: { analysis_type: "structural" },
        });
        break;
      }
    }
    return findings;
  },
});
