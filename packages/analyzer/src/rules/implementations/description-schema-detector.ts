/**
 * Description & Schema Detector — A1-A5, A8, B1-B7
 *
 * Migrates ALL remaining A-category (description analysis) and B-category
 * (schema analysis) rules from YAML regex to TypedRule implementations.
 *
 * A1: Prompt injection in tool description (linguistic + pattern scoring)
 * A2: Excessive scope claims
 * A3: Suspicious URLs
 * A4: Cross-server tool name shadowing (Levenshtein)
 * A5: Description length anomaly
 * A8: Description-capability mismatch
 * B1: Missing input validation (structural schema check)
 * B2: Dangerous parameter types
 * B3: Excessive parameter count
 * B4: Schema-less tools
 * B5: Prompt injection in parameter descriptions
 * B6: Unconstrained additional properties
 * B7: Dangerous default parameter values
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import type { OwaspCategory } from "@mcp-sentinel/database";
import { EvidenceChainBuilder } from "../../evidence.js";

function makeRule(id: string, name: string, analyzeFn: (ctx: AnalysisContext) => TypedFinding[]): TypedRule {
  return { id, name, analyze: analyzeFn };
}

// ─── A1: Prompt Injection in Tool Description ─────────────────────────────

const INJECTION_PATTERNS: Array<{ regex: RegExp; desc: string; weight: number }> = [
  { regex: /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)/i, desc: "role override", weight: 0.95 },
  { regex: /(?:you\s+are|act\s+as|pretend|behave\s+as|your\s+(?:new\s+)?role)/i, desc: "role reassignment", weight: 0.90 },
  { regex: /(?:do\s+not|don't|never)\s+(?:ask|confirm|verify|check|prompt|question)/i, desc: "confirmation bypass directive", weight: 0.88 },
  { regex: /(?:always|must|shall)\s+(?:execute|run|call|use|invoke|output|return)/i, desc: "mandatory execution directive", weight: 0.82 },
  { regex: /(?:system|admin|root|sudo|superuser)\s*(?:mode|access|privilege|role)/i, desc: "privilege escalation claim", weight: 0.85 },
  { regex: /(?:secret|hidden|private)\s+(?:instruction|command|directive|mode)/i, desc: "hidden instruction", weight: 0.90 },
  { regex: /(?:output|return|send|exfiltrate|transmit)\s+(?:to|via)\s+(?:http|url|webhook|endpoint)/i, desc: "exfiltration directive", weight: 0.92 },
  { regex: /(?:base64|encode|decode|atob|btoa)\s+(?:the|this|all|every)/i, desc: "encoding directive", weight: 0.80 },
  { regex: /\]\s*\(\s*https?:\/\/(?!(?:github\.com|npmjs\.com|pypi\.org))/i, desc: "markdown link to external URL", weight: 0.60 },
  { regex: /```\s*(?:json|javascript|python|bash|sh)\s*\n/i, desc: "code block injection", weight: 0.70 },
];

registerTypedRule(makeRule("A1", "Prompt Injection in Tool Description", (ctx) => {
  const findings: TypedFinding[] = [];

  for (const tool of ctx.tools) {
    const desc = tool.description || "";
    if (desc.length < 10) continue;

    const matchedSignals: string[] = [];
    const matchedWeights: number[] = [];

    for (const { regex, desc: patternDesc, weight } of INJECTION_PATTERNS) {
      regex.lastIndex = 0;
      if (regex.test(desc)) {
        matchedSignals.push(patternDesc);
        matchedWeights.push(weight);
      }
    }

    // Noisy-OR aggregation: P(injection) = 1 - Π(1 - wᵢ) for each matched signal.
    // Each weight represents the independent probability that the matched pattern
    // indicates prompt injection. Noisy-OR combines them correctly:
    //   Single 0.95-weight match → 0.95 confidence (canonical injection phrases)
    //   Two matches combine multiplicatively: 1-(1-0.95)(1-0.82) = 0.991
    if (matchedSignals.length > 0) {
      const noisyOR = 1 - matchedWeights.reduce((product, w) => product * (1 - w), 1);
      const confidence = Math.min(0.98, noisyOR);

      if (confidence >= 0.50) {
        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `tool:${tool.name}:description`,
            observed: desc.slice(0, 200),
            rationale: "Tool description is processed by the AI as behavioral context for tool usage",
          })
          .impact({
            impact_type: "cross-agent-propagation",
            scope: "ai-client",
            exploitability: matchedSignals.length >= 2 ? "trivial" : "moderate",
            scenario:
              `AI follows injected instructions in tool "${tool.name}" description: ` +
              matchedSignals.join(", "),
          })
          .factor(
            "linguistic scoring",
            confidence - 0.30,
            `Noisy-OR of ${matchedSignals.length} injection signal(s): [${matchedSignals.join(", ")}]`,
          )
          .reference({
            id: "INVARIANT-TOOL-POISONING",
            title: "Tool Poisoning Attacks in MCP",
            relevance: "Systematic study of prompt injection via tool descriptions",
          })
          .verification({
            step_type: "inspect-description",
            instruction: `Examine tool "${tool.name}" description for behavioral directives`,
            target: `tool:${tool.name}`,
            expected_observation:
              `Description contains injection pattern(s): ${matchedSignals.join(", ")}`,
          })
          .build();

        findings.push({
          rule_id: "A1",
          severity: confidence >= 0.80 ? "critical" : confidence >= 0.60 ? "high" : "medium",
          evidence:
            `Tool "${tool.name}" description (${desc.length} chars) contains ${matchedSignals.length} injection signal(s): ` +
            `[${matchedSignals.join(", ")}]. Combined confidence: ${(confidence * 100).toFixed(0)}%.`,
          remediation:
            "Remove behavioral directives from tool descriptions. Descriptions should only explain " +
            "what the tool does, not instruct the AI how to behave.",
          owasp_category: "MCP01-prompt-injection",
          mitre_technique: "AML.T0054",
          confidence,
          metadata: {
            analysis_type: "linguistic_scoring",
            tool_name: tool.name,
            signals: matchedSignals,
            evidence_chain: chain,
          },
        });
      }
    }
  }

  return findings;
}));

// ─── A2: Excessive Scope Claims ───────────────────────────────────────────

const SCOPE_CLAIMS = [
  /(?:full|complete|unrestricted|unlimited|all)\s+(?:access|control|permission|privilege)/i,
  /(?:read|write|delete|modify)\s+(?:any|all|every)\s+(?:file|data|resource|record)/i,
  /(?:root|admin|superuser|god)\s+(?:access|mode|privilege)/i,
];

registerTypedRule(makeRule("A2", "Excessive Scope Claims", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    const desc = tool.description || "";
    for (const pattern of SCOPE_CLAIMS) {
      const match = pattern.exec(desc);
      if (match) {
        findings.push({
          rule_id: "A2", severity: "high",
          evidence: `Tool "${tool.name}" claims excessive scope: "${match[0]}".`,
          remediation: "Scope tool access to specific directories/resources. Avoid 'all' or 'unrestricted' claims.",
          owasp_category: "MCP06-excessive-permissions", mitre_technique: "AML.T0054",
          confidence: 0.82, metadata: { tool_name: tool.name },
        });
        break;
      }
    }
  }
  return findings;
}));

// ─── A3: Suspicious URLs ──────────────────────────────────────────────────

const SUSPICIOUS_URL_PATTERNS = [
  { regex: /https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|buff\.ly)\//i, desc: "URL shortener" },
  { regex: /https?:\/\/[^/]*(?:ngrok|serveo|localtunnel|bore\.digital|localhost\.run)\./i, desc: "tunneling service" },
  { regex: /https?:\/\/[^/]*(?:webhook\.site|requestbin|hookbin|pipedream)\./i, desc: "webhook/canary service" },
  { regex: /https?:\/\/[^/]*\.(?:tk|ml|ga|cf|gq|top|xyz|buzz|click|link|work)\//i, desc: "suspicious TLD" },
  { regex: /[a-z0-9]{20,}\.(?:com|net|org|io)/i, desc: "high-entropy domain (possible DGA)" },
];

registerTypedRule(makeRule("A3", "Suspicious URLs in Description", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    const desc = tool.description || "";
    for (const { regex, desc: urlDesc } of SUSPICIOUS_URL_PATTERNS) {
      const match = regex.exec(desc);
      if (match) {
        findings.push({
          rule_id: "A3", severity: "medium",
          evidence: `Tool "${tool.name}" contains ${urlDesc}: "${match[0].slice(0, 60)}".`,
          remediation: "Remove suspicious URLs from tool descriptions. Use only well-known domains.",
          owasp_category: "MCP04-data-exfiltration", mitre_technique: "AML.T0057",
          confidence: 0.80, metadata: { tool_name: tool.name, url_type: urlDesc },
        });
        break;
      }
    }
  }
  return findings;
}));

// ─── A4: Cross-Server Tool Name Shadowing ─────────────────────────────────

const COMMON_TOOL_NAMES = new Set([
  "read_file", "write_file", "list_files", "delete_file", "search_files",
  "read_directory", "create_directory", "move_file", "copy_file",
  "execute_command", "run_script", "run_code", "exec",
  "fetch_url", "http_request", "web_search", "browse",
  "query_database", "sql_query", "read_database",
  "send_email", "send_message", "notify", "alert",
  "get_weather", "get_time", "get_location",
  "create_file", "edit_file", "replace_in_file",
  "list_tools", "get_tool", "call_tool",
  "git_clone", "git_commit", "git_push", "git_pull",
  "read_resource", "write_resource", "subscribe",
  "create_image", "analyze_image", "generate_text",
  "memory_store", "memory_retrieve", "memory_search",
  "bash", "shell", "terminal", "repl",
  "search", "find", "grep", "read", "write", "delete", "update", "create",
  "get", "set", "list", "put", "post", "patch", "remove",
]);

registerTypedRule(makeRule("A4", "Cross-Server Tool Name Shadowing", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    const normalized = tool.name.toLowerCase().replace(/[-_\s]+/g, "_");
    if (COMMON_TOOL_NAMES.has(normalized)) {
      findings.push({
        rule_id: "A4", severity: "high",
        evidence: `Tool "${tool.name}" shadows common tool name "${normalized}". May confuse AI into using this instead of a trusted tool.`,
        remediation: "Use a unique, namespaced tool name (e.g., 'myserver_read_file' instead of 'read_file').",
        owasp_category: "MCP02-tool-poisoning", mitre_technique: "AML.T0054",
        confidence: 0.78, metadata: { tool_name: tool.name, shadowed_name: normalized },
      });
    }
  }
  return findings;
}));

// ─── A5: Description Length Anomaly ───────────────────────────────────────

registerTypedRule(makeRule("A5", "Description Length Anomaly", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    const desc = tool.description || "";
    if (desc.length > 1000) {
      findings.push({
        rule_id: "A5", severity: "low",
        evidence: `Tool "${tool.name}" has unusually long description (${desc.length} chars). Long descriptions can hide injection payloads.`,
        remediation: "Keep tool descriptions concise (<500 chars). Move detailed docs to external references.",
        owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
        confidence: Math.min(0.80, 0.40 + (desc.length - 1000) / 5000),
        metadata: { tool_name: tool.name, length: desc.length },
      });
    }
  }
  return findings;
}));

// ─── A8: Description-Capability Mismatch ──────────────────────────────────

const READ_ONLY_CLAIMS = /(?:read[\s-]?only|just\s+reads?|only\s+reads?|safe|non[\s-]?destructive|no\s+side[\s-]?effects)/i;
const WRITE_PARAMS = /(?:delete|remove|write|create|update|modify|overwrite|drop|truncate|kill|terminate|execute|run|send|post|put|patch)/i;

registerTypedRule(makeRule("A8", "Description-Capability Mismatch", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    const desc = tool.description || "";
    if (!READ_ONLY_CLAIMS.test(desc)) continue;

    const schema = tool.input_schema as Record<string, unknown> | null;
    const params = Object.keys((schema?.properties || {}) as Record<string, unknown>);
    const writeParams = params.filter(p => WRITE_PARAMS.test(p));

    if (writeParams.length > 0) {
      findings.push({
        rule_id: "A8", severity: "high",
        evidence:
          `Tool "${tool.name}" claims "${desc.match(READ_ONLY_CLAIMS)?.[0]}" but has write parameters: [${writeParams.join(", ")}].`,
        remediation: "Update description to accurately reflect capabilities. Remove false read-only claims.",
        owasp_category: "MCP02-tool-poisoning", mitre_technique: "AML.T0054",
        confidence: 0.85, metadata: { tool_name: tool.name, write_params: writeParams },
      });
    }
  }
  return findings;
}));

// ─── B1: Missing Input Validation ─────────────────────────────────────────

registerTypedRule(makeRule("B1", "Missing Input Validation", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    const schema = tool.input_schema as Record<string, unknown> | null;
    if (!schema?.properties) continue;

    const props = schema.properties as Record<string, Record<string, unknown>>;
    const unconstrained: string[] = [];

    for (const [name, prop] of Object.entries(props)) {
      if (prop.type === "string" && !prop.maxLength && !prop.enum && !prop.pattern && !prop.format) {
        unconstrained.push(name);
      }
      if (prop.type === "number" && prop.minimum === undefined && prop.maximum === undefined) {
        unconstrained.push(name);
      }
    }

    if (unconstrained.length > 0) {
      findings.push({
        rule_id: "B1", severity: "medium",
        evidence: `Tool "${tool.name}" has ${unconstrained.length} unconstrained parameter(s): [${unconstrained.join(", ")}].`,
        remediation: "Add maxLength, enum, pattern, or format constraints to string parameters. Add min/max to numbers.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.70, metadata: { tool_name: tool.name, unconstrained },
      });
    }
  }
  return findings;
}));

// ─── B2: Dangerous Parameter Types ────────────────────────────────────────

const DANGEROUS_PARAM_NAMES = /^(?:command|cmd|shell|exec|script|sql|query|code|eval|path|file_path|url|uri|template)$/i;

registerTypedRule(makeRule("B2", "Dangerous Parameter Types", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    const schema = tool.input_schema as Record<string, unknown> | null;
    if (!schema?.properties) continue;

    const props = Object.keys(schema.properties as Record<string, unknown>);
    const dangerous = props.filter(p => DANGEROUS_PARAM_NAMES.test(p));

    if (dangerous.length > 0) {
      findings.push({
        rule_id: "B2", severity: "high",
        evidence: `Tool "${tool.name}" has dangerous parameter name(s): [${dangerous.join(", ")}].`,
        remediation: "Add strict validation (enum, pattern, maxLength) to parameters that accept commands, paths, SQL, or code.",
        owasp_category: "MCP03-command-injection", mitre_technique: "AML.T0054",
        confidence: 0.75, metadata: { tool_name: tool.name, dangerous_params: dangerous },
      });
    }
  }
  return findings;
}));

// ─── B3: Excessive Parameter Count ────────────────────────────────────────

registerTypedRule(makeRule("B3", "Excessive Parameter Count", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    const schema = tool.input_schema as Record<string, unknown> | null;
    const count = Object.keys((schema?.properties || {}) as Record<string, unknown>).length;
    if (count > 15) {
      findings.push({
        rule_id: "B3", severity: "low",
        evidence: `Tool "${tool.name}" has ${count} parameters (threshold: 15). Excessive params increase attack surface.`,
        remediation: "Reduce parameter count. Group related parameters into nested objects.",
        owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
        confidence: 0.70, metadata: { tool_name: tool.name, param_count: count },
      });
    }
  }
  return findings;
}));

// ─── B4: Schema-less Tools ────────────────────────────────────────────────

registerTypedRule(makeRule("B4", "Schema-less Tools", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    if (!tool.input_schema) {
      findings.push({
        rule_id: "B4", severity: "medium",
        evidence: `Tool "${tool.name}" has no input schema. AI will guess parameter types.`,
        remediation: "Add a JSON Schema with typed properties for all parameters.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.90, metadata: { tool_name: tool.name },
      });
    }
  }
  return findings;
}));

// ─── B5: Prompt Injection in Parameter Descriptions ───────────────────────

registerTypedRule(makeRule("B5", "Prompt Injection in Parameter Description", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    const schema = tool.input_schema as Record<string, unknown> | null;
    if (!schema?.properties) continue;

    const props = schema.properties as Record<string, Record<string, unknown>>;
    for (const [paramName, prop] of Object.entries(props)) {
      const paramDesc = (prop.description || "") as string;
      if (paramDesc.length < 10) continue;

      for (const { regex, desc: patternDesc, weight } of INJECTION_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(paramDesc)) {
          findings.push({
            rule_id: "B5", severity: "critical",
            evidence:
              `Tool "${tool.name}", parameter "${paramName}" description contains ${patternDesc}: ` +
              `"${paramDesc.slice(0, 100)}". Parameter descriptions are a secondary injection surface.`,
            remediation: "Remove behavioral directives from parameter descriptions. Use only factual type/format info.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
            confidence: Math.min(0.95, weight),
            metadata: { tool_name: tool.name, param_name: paramName },
          });
          break;
        }
      }
    }
  }
  return findings;
}));

// ─── B6: Unconstrained Additional Properties ─────────────────────────────

registerTypedRule(makeRule("B6", "Unconstrained Additional Properties", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    const schema = tool.input_schema as Record<string, unknown> | null;
    if (!schema) continue;

    if (schema.additionalProperties === true || (schema.additionalProperties === undefined && schema.properties)) {
      findings.push({
        rule_id: "B6", severity: "medium",
        evidence: `Tool "${tool.name}" allows additional properties (not set to false). Arbitrary input accepted.`,
        remediation: "Set additionalProperties: false in the tool schema to reject unknown parameters.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.75, metadata: { tool_name: tool.name },
      });
    }
  }
  return findings;
}));

// ─── B7: Dangerous Default Parameter Values ──────────────────────────────

const DANGEROUS_DEFAULTS: Array<{ pattern: RegExp; desc: string }> = [
  { pattern: /^\/$/,                    desc: "root filesystem path" },
  { pattern: /^\*$/,                    desc: "wildcard glob" },
  { pattern: /^true$/i,                desc: "boolean true" }, // context-dependent — only dangerous for specific param names
];

const DANGEROUS_DEFAULT_PARAMS = /(?:overwrite|recursive|force|delete|remove|disable_ssl|read_only|allow_all|skip_validation)/i;

registerTypedRule(makeRule("B7", "Dangerous Default Parameter Values", (ctx) => {
  const findings: TypedFinding[] = [];
  for (const tool of ctx.tools) {
    const schema = tool.input_schema as Record<string, unknown> | null;
    if (!schema?.properties) continue;

    const props = schema.properties as Record<string, Record<string, unknown>>;
    for (const [name, prop] of Object.entries(props)) {
      if (prop.default === undefined) continue;
      const defaultVal = String(prop.default);

      // Check: dangerous default value on security-sensitive parameter
      if (DANGEROUS_DEFAULT_PARAMS.test(name) && /^true$/i.test(defaultVal)) {
        findings.push({
          rule_id: "B7", severity: "high",
          evidence: `Tool "${tool.name}", parameter "${name}" defaults to "${defaultVal}". Dangerous default on security-sensitive parameter.`,
          remediation: `Change default of "${name}" to false/null. Require explicit opt-in for destructive operations.`,
          owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
          confidence: 0.85, metadata: { tool_name: tool.name, param_name: name, default_value: defaultVal },
        });
      }

      // Check: path defaults to root
      if (/path|dir|directory|folder/i.test(name) && /^\/$/.test(defaultVal)) {
        findings.push({
          rule_id: "B7", severity: "high",
          evidence: `Tool "${tool.name}", parameter "${name}" defaults to "/". Root filesystem access by default.`,
          remediation: "Default to a specific, restricted directory instead of root.",
          owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
          confidence: 0.90, metadata: { tool_name: tool.name, param_name: name },
        });
      }
    }
  }
  return findings;
}));
