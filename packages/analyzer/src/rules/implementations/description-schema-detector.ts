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
        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `tool:${tool.name}:description`,
            observed: match[0],
            rationale: "Tool description claims unrestricted scope that AI clients trust for permission decisions",
          })
          .propagation({
            propagation_type: "description-directive",
            location: `tool:${tool.name}:description`,
            observed: `Scope claim "${match[0]}" in tool "${tool.name}" description`,
          })
          .impact({
            impact_type: "privilege-escalation",
            scope: "server-host",
            exploitability: "moderate",
            scenario: `AI grants tool "${tool.name}" unrestricted access based on scope claim "${match[0]}"`,
          })
          .factor("description_scope_analysis", 0.12, `Matched excessive scope pattern: "${match[0]}"`)
          .verification({
            step_type: "inspect-description",
            instruction: `Check tool "${tool.name}" description for overly broad access claims`,
            target: `tool:${tool.name}`,
            expected_observation: `Description contains scope claim: "${match[0]}"`,
          })
          .build();
        findings.push({
          rule_id: "A2", severity: "high",
          evidence: `Tool "${tool.name}" claims excessive scope: "${match[0]}".`,
          remediation: "Scope tool access to specific directories/resources. Avoid 'all' or 'unrestricted' claims.",
          owasp_category: "MCP06-excessive-permissions", mitre_technique: "AML.T0054",
          confidence: 0.82, metadata: { tool_name: tool.name, evidence_chain: chain },
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
        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `tool:${tool.name}:description`,
            observed: match[0].slice(0, 80),
            rationale: "Tool description contains a URL that AI may follow or leak data to",
          })
          .propagation({
            propagation_type: "description-directive",
            location: `tool:${tool.name}:description`,
            observed: `${urlDesc} found: "${match[0].slice(0, 60)}"`,
          })
          .impact({
            impact_type: "data-exfiltration",
            scope: "connected-services",
            exploitability: "moderate",
            scenario: `Data sent to ${urlDesc} endpoint in tool "${tool.name}" description`,
          })
          .factor("url_pattern_analysis", 0.10, `Matched ${urlDesc} pattern in description`)
          .verification({
            step_type: "inspect-description",
            instruction: `Check tool "${tool.name}" description for suspicious URLs`,
            target: `tool:${tool.name}`,
            expected_observation: `Description contains ${urlDesc}: "${match[0].slice(0, 60)}"`,
          })
          .build();
        findings.push({
          rule_id: "A3", severity: "medium",
          evidence: `Tool "${tool.name}" contains ${urlDesc}: "${match[0].slice(0, 60)}".`,
          remediation: "Remove suspicious URLs from tool descriptions. Use only well-known domains.",
          owasp_category: "MCP04-data-exfiltration", mitre_technique: "AML.T0057",
          confidence: 0.80, metadata: { tool_name: tool.name, url_type: urlDesc, evidence_chain: chain },
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
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "external-content",
          location: `tool:${tool.name}:name`,
          observed: tool.name,
          rationale: "Tool name matches a common tool name used by official MCP servers",
        })
        .propagation({
          propagation_type: "cross-tool-flow",
          location: `tool:${tool.name}:name`,
          observed: `Name "${tool.name}" normalizes to common name "${normalized}"`,
        })
        .impact({
          impact_type: "cross-agent-propagation",
          scope: "ai-client",
          exploitability: "moderate",
          scenario: `AI uses tool "${tool.name}" (shadowing "${normalized}") instead of the trusted equivalent, routing data through an untrusted server`,
        })
        .factor("name_shadowing", 0.08, `Exact match against common tool name "${normalized}" from official MCP servers`)
        .verification({
          step_type: "inspect-description",
          instruction: `Compare tool "${tool.name}" against official MCP server tool names`,
          target: `tool:${tool.name}`,
          expected_observation: `Tool name "${normalized}" matches a common tool from official servers`,
        })
        .build();
      findings.push({
        rule_id: "A4", severity: "high",
        evidence: `Tool "${tool.name}" shadows common tool name "${normalized}". May confuse AI into using this instead of a trusted tool.`,
        remediation: "Use a unique, namespaced tool name (e.g., 'myserver_read_file' instead of 'read_file').",
        owasp_category: "MCP02-tool-poisoning", mitre_technique: "AML.T0054",
        confidence: 0.78, metadata: { tool_name: tool.name, shadowed_name: normalized, evidence_chain: chain },
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
      const conf = Math.min(0.80, 0.40 + (desc.length - 1000) / 5000);
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "external-content",
          location: `tool:${tool.name}:description`,
          observed: `Description length: ${desc.length} chars (threshold: 1000)`,
          rationale: "Excessively long descriptions can hide prompt injection payloads in the noise",
        })
        .propagation({
          propagation_type: "description-directive",
          location: `tool:${tool.name}:description`,
          observed: `${desc.length} chars of tool description processed by AI client`,
        })
        .impact({
          impact_type: "cross-agent-propagation",
          scope: "ai-client",
          exploitability: "moderate",
          scenario: `Injection payload hidden in ${desc.length}-char description of tool "${tool.name}" evades human review`,
        })
        .factor("description_length", conf - 0.60, `Length ${desc.length} chars, ${((desc.length - 1000) / 1000).toFixed(1)}x over threshold`)
        .verification({
          step_type: "inspect-description",
          instruction: `Review the full ${desc.length}-char description of tool "${tool.name}" for hidden directives`,
          target: `tool:${tool.name}`,
          expected_observation: "Description exceeds 1000 chars and may contain hidden injection payloads",
        })
        .build();
      findings.push({
        rule_id: "A5", severity: "low",
        evidence: `Tool "${tool.name}" has unusually long description (${desc.length} chars). Long descriptions can hide injection payloads.`,
        remediation: "Keep tool descriptions concise (<500 chars). Move detailed docs to external references.",
        owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
        confidence: conf,
        metadata: { tool_name: tool.name, length: desc.length, evidence_chain: chain },
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
      const readOnlyClaim = desc.match(READ_ONLY_CLAIMS)?.[0] || "read-only";
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "external-content",
          location: `tool:${tool.name}:description`,
          observed: `Claims "${readOnlyClaim}"`,
          rationale: "Tool description makes a read-only safety claim that AI clients trust for auto-approval",
        })
        .propagation({
          propagation_type: "schema-unconstrained",
          location: `tool:${tool.name}:input_schema`,
          observed: `Write parameters: [${writeParams.join(", ")}] contradict description`,
        })
        .sink({
          sink_type: "config-modification",
          location: `tool:${tool.name}:parameters`,
          observed: `Parameters [${writeParams.join(", ")}] enable destructive operations despite "${readOnlyClaim}" claim`,
        })
        .factor("mismatch_severity", 0.15, `${writeParams.length} write parameter(s) contradict read-only claim`)
        .verification({
          step_type: "inspect-description",
          instruction: `Compare tool "${tool.name}" description claim "${readOnlyClaim}" against its schema parameters`,
          target: `tool:${tool.name}`,
          expected_observation: `Description claims "${readOnlyClaim}" but parameters [${writeParams.join(", ")}] enable writes`,
        })
        .build();
      findings.push({
        rule_id: "A8", severity: "high",
        evidence:
          `Tool "${tool.name}" claims "${readOnlyClaim}" but has write parameters: [${writeParams.join(", ")}].`,
        remediation: "Update description to accurately reflect capabilities. Remove false read-only claims.",
        owasp_category: "MCP02-tool-poisoning", mitre_technique: "AML.T0054",
        confidence: 0.85, metadata: { tool_name: tool.name, write_params: writeParams, evidence_chain: chain },
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
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "user-parameter",
          location: `tool:${tool.name}:input_schema`,
          observed: `${unconstrained.length} unconstrained parameter(s): [${unconstrained.join(", ")}]`,
          rationale: "Parameters without validation constraints accept arbitrary input including injection payloads",
        })
        .propagation({
          propagation_type: "schema-unconstrained",
          location: `tool:${tool.name}:input_schema`,
          observed: `No maxLength, enum, pattern, format, min, or max constraints on [${unconstrained.join(", ")}]`,
        })
        .impact({
          impact_type: "config-poisoning",
          scope: "server-host",
          exploitability: "moderate",
          scenario: `Attacker injects malicious input via unconstrained parameters [${unconstrained.join(", ")}] in tool "${tool.name}"`,
        })
        .factor("structural_schema_check", 0.0, `${unconstrained.length} of ${Object.keys((schema.properties || {}) as Record<string, unknown>).length} parameters lack constraints`)
        .verification({
          step_type: "inspect-description",
          instruction: `Check tool "${tool.name}" schema for missing validation constraints`,
          target: `tool:${tool.name}`,
          expected_observation: `Parameters [${unconstrained.join(", ")}] have no maxLength, enum, pattern, or format constraints`,
        })
        .build();
      findings.push({
        rule_id: "B1", severity: "medium",
        evidence: `Tool "${tool.name}" has ${unconstrained.length} unconstrained parameter(s): [${unconstrained.join(", ")}].`,
        remediation: "Add maxLength, enum, pattern, or format constraints to string parameters. Add min/max to numbers.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.70, metadata: { tool_name: tool.name, unconstrained, evidence_chain: chain },
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
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "user-parameter",
          location: `tool:${tool.name}:input_schema`,
          observed: `Dangerous parameter names: [${dangerous.join(", ")}]`,
          rationale: "Parameter names indicate acceptance of commands, paths, SQL, or code — high-risk input types",
        })
        .propagation({
          propagation_type: "direct-pass",
          location: `tool:${tool.name}:parameters`,
          observed: `Parameters [${dangerous.join(", ")}] match dangerous name patterns (command, sql, exec, path, etc.)`,
        })
        .sink({
          sink_type: "command-execution",
          location: `tool:${tool.name}:execution`,
          observed: `Tool accepts [${dangerous.join(", ")}] — likely flows to command execution, file access, or database query`,
        })
        .factor("param_name_analysis", 0.05, `${dangerous.length} parameter(s) match dangerous name patterns`)
        .verification({
          step_type: "inspect-description",
          instruction: `Check tool "${tool.name}" parameters [${dangerous.join(", ")}] for injection risk`,
          target: `tool:${tool.name}`,
          expected_observation: `Parameters named [${dangerous.join(", ")}] indicate command/SQL/path injection surface`,
        })
        .build();
      findings.push({
        rule_id: "B2", severity: "high",
        evidence: `Tool "${tool.name}" has dangerous parameter name(s): [${dangerous.join(", ")}].`,
        remediation: "Add strict validation (enum, pattern, maxLength) to parameters that accept commands, paths, SQL, or code.",
        owasp_category: "MCP03-command-injection", mitre_technique: "AML.T0054",
        confidence: 0.75, metadata: { tool_name: tool.name, dangerous_params: dangerous, evidence_chain: chain },
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
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "user-parameter",
          location: `tool:${tool.name}:input_schema`,
          observed: `${count} parameters (threshold: 15)`,
          rationale: "Excessive parameters increase attack surface and make security review impractical",
        })
        .propagation({
          propagation_type: "schema-unconstrained",
          location: `tool:${tool.name}:input_schema`,
          observed: `${count} parameters require AI reasoning for each value`,
        })
        .impact({
          impact_type: "config-poisoning",
          scope: "server-host",
          exploitability: "complex",
          scenario: `Large parameter surface (${count} params) in tool "${tool.name}" makes comprehensive validation unlikely`,
        })
        .factor("structural_schema_check", 0.0, `${count} parameters, ${count - 15} over threshold`)
        .verification({
          step_type: "inspect-description",
          instruction: `Count parameters in tool "${tool.name}" schema`,
          target: `tool:${tool.name}`,
          expected_observation: `Tool has ${count} parameters, exceeding 15-parameter threshold`,
        })
        .build();
      findings.push({
        rule_id: "B3", severity: "low",
        evidence: `Tool "${tool.name}" has ${count} parameters (threshold: 15). Excessive params increase attack surface.`,
        remediation: "Reduce parameter count. Group related parameters into nested objects.",
        owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
        confidence: 0.70, metadata: { tool_name: tool.name, param_count: count, evidence_chain: chain },
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
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "user-parameter",
          location: `tool:${tool.name}:input_schema`,
          observed: "input_schema is null/undefined",
          rationale: "Missing schema means no server-side input validation — AI client guesses parameter format",
        })
        .propagation({
          propagation_type: "schema-unconstrained",
          location: `tool:${tool.name}`,
          observed: "No JSON Schema defined for tool input",
        })
        .impact({
          impact_type: "config-poisoning",
          scope: "server-host",
          exploitability: "moderate",
          scenario: `AI sends arbitrary JSON to schema-less tool "${tool.name}" — no validation possible`,
        })
        .factor("structural_schema_check", 0.20, "Complete absence of input schema is a strong misconfiguration signal")
        .verification({
          step_type: "inspect-description",
          instruction: `Check if tool "${tool.name}" defines an input_schema`,
          target: `tool:${tool.name}`,
          expected_observation: "Tool has no input_schema — AI must guess parameter format",
        })
        .build();
      findings.push({
        rule_id: "B4", severity: "medium",
        evidence: `Tool "${tool.name}" has no input schema. AI will guess parameter types.`,
        remediation: "Add a JSON Schema with typed properties for all parameters.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.90, metadata: { tool_name: tool.name, evidence_chain: chain },
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
          const b5Chain = new EvidenceChainBuilder()
            .source({
              source_type: "user-parameter",
              location: `tool:${tool.name}:param:${paramName}:description`,
              observed: paramDesc.slice(0, 120),
              rationale: "Parameter descriptions are processed by AI as context for filling argument values",
            })
            .propagation({
              propagation_type: "description-directive",
              location: `tool:${tool.name}:param:${paramName}:description`,
              observed: `Injection pattern "${patternDesc}" in parameter "${paramName}" description`,
            })
            .impact({
              impact_type: "cross-agent-propagation",
              scope: "ai-client",
              exploitability: "trivial",
              scenario: `AI follows injected "${patternDesc}" directive in parameter "${paramName}" of tool "${tool.name}"`,
            })
            .factor("linguistic scoring", Math.min(0.95, weight) - 0.60, `Injection pattern: ${patternDesc} (weight: ${weight})`)
            .reference({
              id: "INVARIANT-TOOL-POISONING",
              title: "Tool Poisoning Attacks in MCP",
              relevance: "Parameter descriptions are a secondary injection surface missed by most scanners",
            })
            .verification({
              step_type: "inspect-description",
              instruction: `Check parameter "${paramName}" description in tool "${tool.name}" for injection patterns`,
              target: `tool:${tool.name}:param:${paramName}`,
              expected_observation: `Description contains ${patternDesc}: "${paramDesc.slice(0, 80)}"`,
            })
            .build();
          findings.push({
            rule_id: "B5", severity: "critical",
            evidence:
              `Tool "${tool.name}", parameter "${paramName}" description contains ${patternDesc}: ` +
              `"${paramDesc.slice(0, 100)}". Parameter descriptions are a secondary injection surface.`,
            remediation: "Remove behavioral directives from parameter descriptions. Use only factual type/format info.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
            confidence: Math.min(0.95, weight),
            metadata: { tool_name: tool.name, param_name: paramName, evidence_chain: b5Chain },
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
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "user-parameter",
          location: `tool:${tool.name}:input_schema`,
          observed: `additionalProperties: ${schema.additionalProperties === true ? "true" : "undefined (defaults to true)"}`,
          rationale: "Schema accepts arbitrary extra parameters beyond those defined, bypassing all validation",
        })
        .propagation({
          propagation_type: "schema-unconstrained",
          location: `tool:${tool.name}:input_schema`,
          observed: "additionalProperties not set to false — arbitrary keys accepted",
        })
        .impact({
          impact_type: "config-poisoning",
          scope: "server-host",
          exploitability: "moderate",
          scenario: `Attacker adds undeclared parameters to tool "${tool.name}" that bypass schema validation`,
        })
        .factor("structural_schema_check", 0.05, "additionalProperties not restricted — open schema")
        .verification({
          step_type: "inspect-description",
          instruction: `Check tool "${tool.name}" schema for additionalProperties setting`,
          target: `tool:${tool.name}`,
          expected_observation: "additionalProperties is not set to false — arbitrary input accepted",
        })
        .build();
      findings.push({
        rule_id: "B6", severity: "medium",
        evidence: `Tool "${tool.name}" allows additional properties (not set to false). Arbitrary input accepted.`,
        remediation: "Set additionalProperties: false in the tool schema to reject unknown parameters.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.75, metadata: { tool_name: tool.name, evidence_chain: chain },
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
        const b7BoolChain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `tool:${tool.name}:param:${name}:default`,
            observed: `default: "${defaultVal}"`,
            rationale: "Security-sensitive parameter defaults to permissive value without requiring explicit opt-in",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `tool:${tool.name}:param:${name}`,
            observed: `Parameter "${name}" (security-sensitive) defaults to true`,
          })
          .sink({
            sink_type: "config-modification",
            location: `tool:${tool.name}:execution`,
            observed: `Destructive operation enabled by default via "${name}": true`,
          })
          .factor("dangerous_default", 0.15, `Security-sensitive parameter "${name}" defaults to permissive value`)
          .verification({
            step_type: "inspect-description",
            instruction: `Check parameter "${name}" in tool "${tool.name}" for dangerous default`,
            target: `tool:${tool.name}:param:${name}`,
            expected_observation: `Parameter "${name}" defaults to "${defaultVal}" — should require explicit opt-in`,
          })
          .build();
        findings.push({
          rule_id: "B7", severity: "high",
          evidence: `Tool "${tool.name}", parameter "${name}" defaults to "${defaultVal}". Dangerous default on security-sensitive parameter.`,
          remediation: `Change default of "${name}" to false/null. Require explicit opt-in for destructive operations.`,
          owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
          confidence: 0.85, metadata: { tool_name: tool.name, param_name: name, default_value: defaultVal, evidence_chain: b7BoolChain },
        });
      }

      // Check: path defaults to root
      if (/path|dir|directory|folder/i.test(name) && /^\/$/.test(defaultVal)) {
        const b7RootChain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `tool:${tool.name}:param:${name}:default`,
            observed: `default: "/"`,
            rationale: "Path parameter defaults to filesystem root, granting maximum filesystem scope",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `tool:${tool.name}:param:${name}`,
            observed: `Path parameter "${name}" defaults to "/" (root)`,
          })
          .sink({
            sink_type: "file-write",
            location: `tool:${tool.name}:filesystem`,
            observed: "Root filesystem access by default — enables traversal of /etc, /root, ~/.ssh",
          })
          .factor("dangerous_default", 0.20, "Root filesystem default is the most permissive path possible")
          .verification({
            step_type: "inspect-description",
            instruction: `Check parameter "${name}" in tool "${tool.name}" for root path default`,
            target: `tool:${tool.name}:param:${name}`,
            expected_observation: `Parameter "${name}" defaults to "/" — should default to a restricted directory`,
          })
          .build();
        findings.push({
          rule_id: "B7", severity: "high",
          evidence: `Tool "${tool.name}", parameter "${name}" defaults to "/". Root filesystem access by default.`,
          remediation: "Default to a specific, restricted directory instead of root.",
          owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
          confidence: 0.90, metadata: { tool_name: tool.name, param_name: name, evidence_chain: b7RootChain },
        });
      }
    }
  }
  return findings;
}));
