/**
 * SchemaAnalyzer — Structural inference for schema/ecosystem/protocol rules (B, F, I)
 *
 * Replaces keyword-based capability classification with analysis of
 * JSON Schema STRUCTURE: parameter types, constraints, defaults, annotations.
 *
 * The schema IS the interface contract. Descriptions can lie. Schemas can't.
 * If a tool accepts { command: { type: "string" } } it CAN execute commands,
 * regardless of what the description says.
 */

import type { AnalysisContext } from "../engine.js";
import type { Severity, OwaspCategory } from "@mcp-sentinel/database";
import {
  analyzeSchema,
  analyzeToolSet,
  type SchemaAnalysisResult,
  type CrossToolPattern,
} from "../rules/analyzers/schema-inference.js";
import { buildCapabilityGraph } from "../rules/analyzers/capability-graph.js";
import { shannonEntropy } from "../rules/analyzers/entropy.js";
import { analyzeUnicode } from "../rules/analyzers/unicode.js";

export interface SchemaFinding {
  rule_id: string;
  severity: Severity;
  evidence: string;
  remediation: string;
  owasp_category: OwaspCategory | null;
  mitre_technique: string | null;
  confidence: number;
  metadata?: Record<string, unknown>;
}

export class SchemaAnalyzer {
  analyze(context: AnalysisContext): SchemaFinding[] {
    if (context.tools.length === 0) return [];
    const findings: SchemaFinding[] = [];

    // Per-tool schema analysis
    const toolResults: SchemaAnalysisResult[] = [];
    for (const tool of context.tools) {
      const result = analyzeSchema(tool.name, tool.input_schema, tool.annotations);
      toolResults.push(result);
      findings.push(...this.analyzeToolSchema(tool, result));
    }

    // Cross-tool analysis
    const toolSetResult = analyzeToolSet(context.tools);
    findings.push(...this.analyzeCrossToolPatterns(toolSetResult.cross_tool_patterns));

    // Annotation consistency (I1, I2)
    findings.push(...this.analyzeAnnotations(context.tools, toolResults));

    // Excessive tool count (E4 replacement)
    if (context.tools.length > 50) {
      findings.push({
        rule_id: "E4", severity: "medium",
        evidence: `[Schema] Server exposes ${context.tools.length} tools (threshold: 50). ` +
          `Large tool counts increase attack surface and enable consent fatigue.`,
        remediation: "Split into multiple focused servers. Group tools by capability domain.",
        owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
        confidence: 0.9,
      });
    }

    // Consent fatigue (I16): many benign + few dangerous
    const dangerous = toolResults.filter((t) => t.attack_surface_score > 0.5);
    const benign = toolResults.filter((t) => t.attack_surface_score <= 0.2);
    if (context.tools.length > 10 && dangerous.length > 0 && dangerous.length <= 3 && benign.length > 8) {
      findings.push({
        rule_id: "I16", severity: "high",
        evidence:
          `[Schema] Consent fatigue profile: ${benign.length} low-risk tools hiding ` +
          `${dangerous.length} high-risk tool(s): ${dangerous.map((d) => d.tool_name).join(", ")}. ` +
          `Users approve 10 safe tools, then auto-approve the dangerous one without scrutiny. ` +
          `84.2% success rate (Invariant Labs).`,
        remediation: "Separate high-risk tools into their own server requiring explicit approval.",
        owasp_category: "ASI09-human-oversight-bypass", mitre_technique: "AML.T0054",
        confidence: 0.75,
      });
    }

    // J3: Full schema poisoning — recursive schema walk
    findings.push(...this.detectJ3FullSchemaPoisoning(context.tools));

    return findings;
  }

  private analyzeToolSchema(
    tool: AnalysisContext["tools"][0],
    result: SchemaAnalysisResult
  ): SchemaFinding[] {
    const findings: SchemaFinding[] = [];

    // B4: No input schema
    if (!tool.input_schema || !tool.input_schema.properties) {
      findings.push({
        rule_id: "B4", severity: "medium",
        evidence: `[Schema] Tool "${tool.name}" has no input schema. Cannot validate inputs.`,
        remediation: "Define a JSON Schema for all tool parameters with type constraints.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.95,
      });
      return findings;
    }

    // B1: Missing input validation — per parameter
    const unconstrained = result.parameters.filter(
      (p) => p.constraints.has_enum === false &&
             p.constraints.has_pattern === false &&
             p.constraints.has_max_length === false &&
             p.constraints.is_boolean === false &&
             p.constraints.is_number === false &&
             p.semantic_type !== "boolean_flag" &&
             p.semantic_type !== "numeric_value"
    );
    if (unconstrained.length > 0) {
      findings.push({
        rule_id: "B1", severity: "medium",
        evidence:
          `[Schema] Tool "${tool.name}" — ${unconstrained.length}/${result.parameters.length} ` +
          `string parameter(s) lack constraints: ${unconstrained.map((p) => p.evidence).join("; ")}. ` +
          `Overall constraint density: ${(result.overall_constraint_density * 100).toFixed(0)}%.`,
        remediation: "Add enum, pattern, or maxLength constraints to string parameters.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.8,
      });
    }

    // B2: Dangerous parameter types — from semantic classification
    const dangerousParams = result.parameters.filter((p) => p.risk_contribution > 0.7);
    for (const param of dangerousParams) {
      findings.push({
        rule_id: "B2", severity: "high",
        evidence:
          `[Schema] Tool "${tool.name}", parameter "${param.name}" classified as ` +
          `${param.semantic_type} with risk ${(param.risk_contribution * 100).toFixed(0)}%. ` +
          `${param.evidence}.`,
        remediation: `Add constraints to "${param.name}": enum for known values, pattern for format validation, maxLength for size limits.`,
        owasp_category: "MCP03-command-injection", mitre_technique: null,
        confidence: 0.8,
      });
    }

    // B3: Excessive parameter count
    if (result.parameters.length > 15) {
      findings.push({
        rule_id: "B3", severity: "low",
        evidence: `[Schema] Tool "${tool.name}" has ${result.parameters.length} parameters (threshold: 15). Complex interfaces increase attack surface.`,
        remediation: "Split into multiple focused tools with fewer parameters each.",
        owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
        confidence: 0.9,
      });
    }

    // B6: additionalProperties allowed
    if (tool.input_schema.additionalProperties !== false && tool.input_schema.properties) {
      findings.push({
        rule_id: "B6", severity: "medium",
        evidence: `[Schema] Tool "${tool.name}" — additionalProperties not set to false. Accepts arbitrary extra fields beyond defined schema.`,
        remediation: "Set additionalProperties: false to reject unexpected input fields.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.85,
      });
    }

    // B7: Dangerous defaults — check for risky default values
    for (const [paramName, paramDef] of Object.entries(
      (tool.input_schema.properties || {}) as Record<string, Record<string, unknown>>
    )) {
      const defaultVal = paramDef.default;
      if (defaultVal === undefined) continue;

      const dangerousDefaults: Array<{ value: unknown; why: string }> = [
        { value: "/", why: "Root filesystem access" },
        { value: "*", why: "Wildcard — matches everything" },
        { value: true, why: "Dangerous when param is named overwrite/recursive/force" },
      ];

      const dangerousParamNames = /^(overwrite|recursive|force|allow_overwrite|disable_ssl|read_only)$/i;

      for (const { value, why } of dangerousDefaults) {
        if (defaultVal === value && (value !== true || dangerousParamNames.test(paramName))) {
          findings.push({
            rule_id: "B7", severity: "high",
            evidence: `[Schema] Tool "${tool.name}", parameter "${paramName}" defaults to ${JSON.stringify(value)} — ${why}.`,
            remediation: `Remove or change the default value for "${paramName}". Defaults should follow least-privilege.`,
            owasp_category: "MCP07-insecure-config", mitre_technique: null,
            confidence: 0.85,
          });
        }
      }
    }

    return findings;
  }

  private analyzeCrossToolPatterns(patterns: CrossToolPattern[]): SchemaFinding[] {
    const findings: SchemaFinding[] = [];

    for (const pattern of patterns) {
      switch (pattern.type) {
        case "lethal_trifecta":
          findings.push({
            rule_id: "F1", severity: "critical",
            evidence: `[Schema structural] ${pattern.evidence}`,
            remediation: "Separate data access and network capabilities into isolated servers. Score capped at 40.",
            owasp_category: "MCP04-data-exfiltration", mitre_technique: "AML.T0054",
            confidence: pattern.confidence,
            metadata: { engine: "schema_analyzer", analysis: "cross_tool_trifecta" },
          });
          break;
        case "credential_exposure":
          findings.push({
            rule_id: "F3", severity: "critical",
            evidence: `[Schema structural] ${pattern.evidence}`,
            remediation: "Isolate credential handling from network-facing tools.",
            owasp_category: "MCP04-data-exfiltration", mitre_technique: "AML.T0057",
            confidence: pattern.confidence,
          });
          break;
        case "unrestricted_access":
          findings.push({
            rule_id: "F2", severity: "critical",
            evidence: `[Schema structural] ${pattern.evidence}`,
            remediation: "Add constraints to command/code parameters.",
            owasp_category: "MCP03-command-injection", mitre_technique: "AML.T0054",
            confidence: pattern.confidence,
          });
          break;
      }
    }

    return findings;
  }

  /**
   * I1/I2: Annotation consistency — compare declared annotations against
   * structurally inferred capabilities.
   */
  private analyzeAnnotations(
    tools: AnalysisContext["tools"],
    results: SchemaAnalysisResult[]
  ): SchemaFinding[] {
    const findings: SchemaFinding[] = [];

    for (let i = 0; i < tools.length; i++) {
      const tool = tools[i];
      const result = results[i];
      if (!tool.annotations) continue;

      // I1: readOnlyHint=true but schema has destructive capabilities
      if (tool.annotations.readOnlyHint === true) {
        const destructiveParams = result.parameters.filter(
          (p) => p.semantic_type === "shell_command" ||
                 p.semantic_type === "code_expression" ||
                 p.semantic_type === "filesystem_path"
        );
        const destructiveCaps = result.capabilities.filter(
          (c) => c.capability === "code_execution" ||
                 c.capability === "destructive_operation" ||
                 c.capability === "filesystem_access"
        );

        if (destructiveParams.length > 0 || destructiveCaps.length > 0) {
          findings.push({
            rule_id: "I1", severity: "critical",
            evidence:
              `[Annotation deception] Tool "${tool.name}" declares readOnlyHint: true ` +
              `but schema analysis found ${destructiveParams.length} destructive parameter(s) ` +
              `and ${destructiveCaps.length} destructive capability(s). ` +
              `Parameters: ${destructiveParams.map((p) => `${p.name} (${p.semantic_type})`).join(", ")}. ` +
              `AI clients trust readOnlyHint for auto-approval — this bypasses user consent.`,
            remediation: "Remove readOnlyHint: true or remove destructive parameters. Annotations must match actual capabilities.",
            owasp_category: "MCP02-tool-poisoning", mitre_technique: "AML.T0054",
            confidence: 0.9,
            metadata: {
              engine: "schema_analyzer", analysis: "annotation_deception",
              declared: { readOnlyHint: true },
              inferred_capabilities: destructiveCaps.map((c) => c.capability),
            },
          });
        }
      }

      // I2: Missing destructiveHint on tools with destructive capabilities
      if (tool.annotations.destructiveHint !== true) {
        const destructiveCaps = result.capabilities.filter(
          (c) => c.capability === "code_execution" || c.capability === "destructive_operation"
        );
        if (destructiveCaps.length > 0) {
          findings.push({
            rule_id: "I2", severity: "high",
            evidence:
              `[Annotation gap] Tool "${tool.name}" has destructive capabilities ` +
              `(${destructiveCaps.map((c) => c.capability).join(", ")}) but does not declare ` +
              `destructiveHint: true. AI clients may auto-execute this tool without user confirmation.`,
            remediation: "Add destructiveHint: true to the tool's annotations.",
            owasp_category: "MCP02-tool-poisoning", mitre_technique: null,
            confidence: Math.max(...destructiveCaps.map((c) => c.confidence)),
          });
        }
      }
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // J3: Full Schema Poisoning — CyberArk FSP Attack Detection
  // ---------------------------------------------------------------------------
  //
  // Recursively walks every string value in JSON Schema trees (input_schema +
  // output_schema) looking for injection payloads hidden in fields that LLMs
  // process as reasoning context: title, const, default, enum, examples,
  // allOf/anyOf/oneOf compositions, and $ref targets.
  // ---------------------------------------------------------------------------

  /** LLM special tokens that manipulate model behaviour when embedded in schema fields. */
  private static readonly SPECIAL_TOKENS = [
    "<|endoftext|>", "<|im_start|>", "<|im_end|>", "<|system|>",
    "<|user|>", "<|assistant|>", "[INST]", "[/INST]",
    "<<SYS>>", "<</SYS>>", "<think>", "</think>",
  ];

  /** Prompt injection patterns — imperative verbs + role injection. */
  private static readonly INJECTION_PATTERNS: RegExp[] = [
    /ignore\s+(?:previous|all|prior|safety)/i,
    /you\s+are\s+(?:now|a|an|the)/i,
    /(?:always|never|must)\s+(?:execute|run|call|output)/i,
    /(?:override|replace|forget)\s+(?:all|previous|instructions)/i,
    /(?:system|admin|root)\s+(?:access|privilege|permission)/i,
    /(?:read|send|fetch|download)\s+(?:~\/|\/etc\/|\.ssh|\.env|credentials)/i,
  ];

  /** Shell / code injection patterns dangerous in default and const values. */
  private static readonly SHELL_INJECTION_IN_DEFAULTS: RegExp[] = [
    /;\s*(?:rm|cat|curl|wget|nc|bash|sh|python|node)\s/,
    /\|\s*(?:bash|sh|python|node)/,
    /\$\(.*\)/,   // command substitution
    /`[^`]*`/,    // backtick execution
  ];

  /** Maximum recursion depth to prevent infinite loops from circular $ref. */
  private static readonly MAX_DEPTH = 20;

  /** Maximum number of string values to inspect per tool to bound runtime. */
  private static readonly MAX_STRINGS_PER_TOOL = 500;

  /**
   * Walk input_schema and output_schema of every tool, checking every reachable
   * string value for injection signals.
   */
  private detectJ3FullSchemaPoisoning(
    tools: AnalysisContext["tools"],
  ): SchemaFinding[] {
    const findings: SchemaFinding[] = [];

    for (const tool of tools) {
      const schemas: Array<{ schema: Record<string, unknown>; label: string }> = [];
      if (tool.input_schema) schemas.push({ schema: tool.input_schema, label: "input_schema" });
      if (tool.output_schema) schemas.push({ schema: tool.output_schema, label: "output_schema" });

      for (const { schema, label } of schemas) {
        const visited = new Set<unknown>();
        let stringsChecked = 0;

        const checkString = (value: string, jsonPath: string, fieldType: string): void => {
          if (stringsChecked >= SchemaAnalyzer.MAX_STRINGS_PER_TOOL) return;
          stringsChecked++;

          const signals: string[] = [];
          let maxConfidence = 0;

          // 1. Prompt injection patterns
          for (const pat of SchemaAnalyzer.INJECTION_PATTERNS) {
            if (pat.test(value)) {
              signals.push(`injection pattern match: ${pat.source}`);
              maxConfidence = Math.max(maxConfidence, 0.9);
            }
          }

          // 2. LLM special tokens
          const lowerVal = value.toLowerCase();
          for (const token of SchemaAnalyzer.SPECIAL_TOKENS) {
            if (lowerVal.includes(token.toLowerCase())) {
              signals.push(`LLM special token: ${token}`);
              maxConfidence = Math.max(maxConfidence, 0.95);
            }
          }

          // 3. High entropy (encoded / obfuscated payloads)
          if (value.length >= 16) {
            const entropy = shannonEntropy(value);
            if (entropy > 5.5) {
              signals.push(`high entropy ${entropy.toFixed(2)} bits/char (threshold 5.5)`);
              maxConfidence = Math.max(maxConfidence, 0.7);
            }
          }

          // 4. Unicode attacks (zero-width, bidi override, homoglyphs)
          const unicodeResult = analyzeUnicode(value);
          if (unicodeResult.has_issues) {
            const issueTypes = [...new Set(unicodeResult.issues.map((i) => i.type))];
            signals.push(`Unicode issues: ${issueTypes.join(", ")} (${unicodeResult.suspicious_codepoint_count} suspicious codepoints)`);
            maxConfidence = Math.max(maxConfidence, 0.85);
          }

          // 5. Shell / code injection in default and const values
          if (fieldType === "default" || fieldType === "const") {
            for (const pat of SchemaAnalyzer.SHELL_INJECTION_IN_DEFAULTS) {
              if (pat.test(value)) {
                signals.push(`shell injection in ${fieldType}: ${pat.source}`);
                maxConfidence = Math.max(maxConfidence, 0.95);
              }
            }
          }

          if (signals.length === 0) return;

          findings.push({
            rule_id: "J3",
            severity: "critical",
            evidence:
              `[Schema deep] Tool "${tool.name}", path "${label}.${jsonPath}": ` +
              `injection detected in ${fieldType}. Content: "${value.slice(0, 80)}". ` +
              `${signals.join("; ")}.`,
            remediation:
              "Remove injection payloads from JSON Schema fields. Schema title, enum, const, " +
              "default, and examples are processed by LLMs as reasoning context. All string " +
              "fields in the schema surface must contain only legitimate values.",
            owasp_category: "MCP01-prompt-injection",
            mitre_technique: "AML.T0054",
            confidence: Math.min(1.0, maxConfidence),
          });
        };

        /**
         * Recursively walk a JSON Schema node, visiting every string-valued field
         * that LLMs consume as reasoning context.
         */
        const walkSchema = (node: unknown, path: string, depth: number): void => {
          if (depth > SchemaAnalyzer.MAX_DEPTH) return;
          if (stringsChecked >= SchemaAnalyzer.MAX_STRINGS_PER_TOOL) return;
          if (node === null || node === undefined) return;
          if (typeof node !== "object") return;

          // Circular reference guard
          if (visited.has(node)) return;
          visited.add(node);

          const obj = node as Record<string, unknown>;

          // --- Scalar string fields ---

          if (typeof obj.title === "string" && obj.title.length > 0) {
            checkString(obj.title, path ? `${path}.title` : "title", "title");
          }

          if (typeof obj.description === "string" && obj.description.length > 0) {
            checkString(obj.description, path ? `${path}.description` : "description", "description");
          }

          if (typeof obj.const === "string" && (obj.const as string).length > 0) {
            checkString(obj.const as string, path ? `${path}.const` : "const", "const");
          }

          if (typeof obj.default === "string" && (obj.default as string).length > 0) {
            checkString(obj.default as string, path ? `${path}.default` : "default", "default");
          }

          // --- Enum values ---
          if (Array.isArray(obj.enum)) {
            for (let i = 0; i < obj.enum.length; i++) {
              const val = obj.enum[i];
              if (typeof val === "string" && val.length > 0) {
                checkString(val, path ? `${path}.enum[${i}]` : `enum[${i}]`, "enum");
              }
            }
          }

          // --- Examples values ---
          if (Array.isArray(obj.examples)) {
            for (let i = 0; i < obj.examples.length; i++) {
              const val = obj.examples[i];
              if (typeof val === "string" && val.length > 0) {
                checkString(val, path ? `${path}.examples[${i}]` : `examples[${i}]`, "examples");
              }
            }
          }

          // --- $ref detection (flag external refs — don't resolve) ---
          if (typeof obj.$ref === "string") {
            const ref = obj.$ref as string;
            // External $ref (http/https) can pull in attacker-controlled schemas
            if (/^https?:\/\//.test(ref)) {
              findings.push({
                rule_id: "J3",
                severity: "critical",
                evidence:
                  `[Schema deep] Tool "${tool.name}", path "${label}.${path ? path + ".$ref" : "$ref"}": ` +
                  `external $ref detected: "${ref.slice(0, 120)}". External schema references ` +
                  `can be replaced by an attacker at any time, injecting arbitrary schema content.`,
                remediation:
                  "Inline all schema definitions. Do not use external $ref URIs in tool schemas. " +
                  "External references are a supply chain risk — the target can change without notice.",
                owasp_category: "MCP01-prompt-injection",
                mitre_technique: "AML.T0054",
                confidence: 0.85,
              });
            }
            // Don't recurse into $ref — we can't resolve it statically
            return;
          }

          // --- Recurse into properties ---
          if (typeof obj.properties === "object" && obj.properties !== null) {
            const props = obj.properties as Record<string, unknown>;
            for (const [propName, propSchema] of Object.entries(props)) {
              walkSchema(
                propSchema,
                path ? `${path}.properties.${propName}` : `properties.${propName}`,
                depth + 1,
              );
            }
          }

          // --- Recurse into items (array item schema) ---
          if (obj.items !== undefined && obj.items !== null) {
            if (typeof obj.items === "object" && !Array.isArray(obj.items)) {
              walkSchema(obj.items, path ? `${path}.items` : "items", depth + 1);
            } else if (Array.isArray(obj.items)) {
              // Tuple validation: items is an array of schemas
              for (let i = 0; i < obj.items.length; i++) {
                walkSchema(
                  obj.items[i],
                  path ? `${path}.items[${i}]` : `items[${i}]`,
                  depth + 1,
                );
              }
            }
          }

          // --- Recurse into allOf / anyOf / oneOf ---
          for (const keyword of ["allOf", "anyOf", "oneOf"] as const) {
            if (Array.isArray(obj[keyword])) {
              const arr = obj[keyword] as unknown[];
              for (let i = 0; i < arr.length; i++) {
                walkSchema(
                  arr[i],
                  path ? `${path}.${keyword}[${i}]` : `${keyword}[${i}]`,
                  depth + 1,
                );
              }
            }
          }

          // --- Recurse into additionalProperties (if object schema) ---
          if (
            typeof obj.additionalProperties === "object" &&
            obj.additionalProperties !== null &&
            !Array.isArray(obj.additionalProperties)
          ) {
            walkSchema(
              obj.additionalProperties,
              path ? `${path}.additionalProperties` : "additionalProperties",
              depth + 1,
            );
          }

          // --- Recurse into patternProperties ---
          if (typeof obj.patternProperties === "object" && obj.patternProperties !== null) {
            const pp = obj.patternProperties as Record<string, unknown>;
            for (const [pattern, ppSchema] of Object.entries(pp)) {
              walkSchema(
                ppSchema,
                path ? `${path}.patternProperties["${pattern}"]` : `patternProperties["${pattern}"]`,
                depth + 1,
              );
            }
          }

          // --- Recurse into not / if / then / else ---
          for (const keyword of ["not", "if", "then", "else"] as const) {
            if (typeof obj[keyword] === "object" && obj[keyword] !== null) {
              walkSchema(
                obj[keyword],
                path ? `${path}.${keyword}` : keyword,
                depth + 1,
              );
            }
          }

          // --- Recurse into definitions / $defs ---
          for (const keyword of ["definitions", "$defs"] as const) {
            if (typeof obj[keyword] === "object" && obj[keyword] !== null) {
              const defs = obj[keyword] as Record<string, unknown>;
              for (const [defName, defSchema] of Object.entries(defs)) {
                walkSchema(
                  defSchema,
                  path ? `${path}.${keyword}.${defName}` : `${keyword}.${defName}`,
                  depth + 1,
                );
              }
            }
          }
        };

        walkSchema(schema, "", 0);
      }
    }

    return findings;
  }
}
