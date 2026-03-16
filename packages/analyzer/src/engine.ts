import type { DetectionRule, FindingInput } from "@mcp-sentinel/database";
import pino from "pino";

// Log to stderr so that stdout is clean for callers that parse it (e.g. CLI --json mode)
const logger = pino({ name: "analyzer:engine" }, process.stderr);

export interface AnalysisContext {
  server: {
    id: string;
    name: string;
    description: string | null;
    github_url: string | null;
  };
  tools: Array<{
    name: string;
    description: string | null;
    input_schema: Record<string, unknown> | null;
  }>;
  source_code: string | null;
  dependencies: Array<{
    name: string;
    version: string | null;
    has_known_cve: boolean;
    cve_ids: string[];
    last_updated: Date | null;
  }>;
  connection_metadata: {
    auth_required: boolean;
    transport: string;
    response_time_ms: number;
  } | null;
  // H2: Fields from the MCP initialize response (serverInfo.name is in server.name)
  initialize_metadata?: {
    server_version?: string | null;
    server_instructions?: string | null;
  };
  // Category I: Protocol surface data
  resources?: Array<{
    uri: string;
    name: string;
    description?: string | null;
    mimeType?: string | null;
  }>;
  prompts?: Array<{
    name: string;
    description?: string | null;
    arguments?: Array<{
      name: string;
      description?: string | null;
      required?: boolean;
    }>;
  }>;
  roots?: Array<{
    uri: string;
    name?: string | null;
  }>;
  declared_capabilities?: {
    tools?: boolean;
    resources?: boolean;
    prompts?: boolean;
    sampling?: boolean;
    logging?: boolean;
  } | null;
}

export class AnalysisEngine {
  constructor(private rules: DetectionRule[]) {}

  analyze(context: AnalysisContext): FindingInput[] {
    const findings: FindingInput[] = [];

    for (const rule of this.rules) {
      try {
        const ruleFindings = this.runRule(rule, context);
        findings.push(...ruleFindings);
      } catch (err) {
        logger.error(
          { rule: rule.id, server: context.server.id, err },
          "Rule execution error"
        );
      }
    }

    logger.info(
      {
        server: context.server.id,
        rules_run: this.rules.length,
        findings: findings.length,
      },
      "Analysis complete"
    );

    return findings;
  }

  private runRule(
    rule: DetectionRule,
    context: AnalysisContext
  ): FindingInput[] {
    switch (rule.detect.type) {
      case "regex":
        return this.runRegexRule(rule, context);
      case "schema-check":
        return this.runSchemaCheckRule(rule, context);
      case "behavioral":
        return this.runBehavioralRule(rule, context);
      case "composite":
        return this.runCompositeRule(rule, context);
      default:
        return [];
    }
  }

  private runRegexRule(
    rule: DetectionRule,
    context: AnalysisContext
  ): FindingInput[] {
    const findings: FindingInput[] = [];
    const patterns = rule.detect.patterns || [];
    const excludePatterns = rule.detect.exclude_patterns || [];

    const textsToScan = this.getTextsForContext(rule.detect.context, context);

    for (const { text, location } of textsToScan) {
      if (!text) continue;

      // Check exclude patterns first
      const excluded = excludePatterns.some((ep: string) => {
        try {
          return new RegExp(ep, "i").test(text);
        } catch {
          return text.includes(ep);
        }
      });
      if (excluded) continue;

      for (const rawPattern of patterns) {
        // Strip inline (?i) flag — engine already passes "gi" to RegExp
        const pattern = rawPattern.replace(/^\(\?i\)/, "");
        try {
          const regex = new RegExp(pattern, "gi");
          const match = regex.exec(text);
          if (match) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Pattern "${pattern}" matched in ${location}: "${match[0]}" (at position ${match.index})`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
            break; // One finding per text per rule
          }
        } catch (err) {
          logger.warn({ rule: rule.id, pattern, err }, "Invalid regex pattern");
        }
      }
    }

    return findings;
  }

  private runSchemaCheckRule(
    rule: DetectionRule,
    context: AnalysisContext
  ): FindingInput[] {
    const findings: FindingInput[] = [];
    const conditions = rule.detect.conditions || {};

    switch (conditions.check) {
      case "no_input_schema":
        for (const tool of context.tools) {
          if (!tool.input_schema || Object.keys(tool.input_schema).length === 0) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Tool "${tool.name}" has no input schema defined`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;

      case "parameter_count_exceeds": {
        const threshold = (conditions.threshold as number) || 15;
        for (const tool of context.tools) {
          const props = tool.input_schema?.properties as Record<string, unknown> | undefined;
          if (props && Object.keys(props).length > threshold) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Tool "${tool.name}" has ${Object.keys(props).length} parameters (threshold: ${threshold})`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "parameter_missing_constraints": {
        const missingAnyOf = (conditions.missing_any_of as string[]) || [];
        for (const tool of context.tools) {
          const props = tool.input_schema?.properties as Record<string, Record<string, unknown>> | undefined;
          if (!props) continue;

          for (const [paramName, paramDef] of Object.entries(props)) {
            const paramType = paramDef.type as string;
            const appliesToTypes = (conditions.applies_to_types as string[]) || ["string"];
            if (!appliesToTypes.includes(paramType)) continue;

            const hasConstraint = missingAnyOf.some((c) => c in paramDef);
            if (!hasConstraint) {
              findings.push({
                rule_id: rule.id,
                severity: rule.severity,
                evidence: `Tool "${tool.name}", parameter "${paramName}" (type: ${paramType}) has no validation constraints (missing: ${missingAnyOf.join(", ")})`,
                remediation: rule.remediation,
                owasp_category: rule.owasp,
                mitre_technique: rule.mitre,
              });
            }
          }
        }
        break;
      }

      case "tool_count_exceeds": {
        const threshold = (conditions.threshold as number) || 50;
        if (context.tools.length > threshold) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server has ${context.tools.length} tools (threshold: ${threshold})`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "dependency_count_exceeds": {
        const threshold = (conditions.threshold as number) || 50;
        if (context.dependencies.length > threshold) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server has ${context.dependencies.length} dependencies (threshold: ${threshold})`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "additional_properties_allowed": {
        // B6: additionalProperties: true (or not set to false) is a security risk
        for (const tool of context.tools) {
          if (!tool.input_schema) continue;
          const schema = tool.input_schema as Record<string, unknown>;
          // Flag if additionalProperties is explicitly true, or if properties exist but
          // additionalProperties is not explicitly false
          const hasProps = schema.properties && Object.keys(schema.properties as object).length > 0;
          const additionalProps = schema.additionalProperties;
          if (hasProps && additionalProps !== false) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Tool "${tool.name}" schema has additionalProperties: ${JSON.stringify(additionalProps ?? "not set")} — arbitrary extra parameters are accepted`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "description_length_anomaly": {
        // A5: Flag tools with excessively long descriptions that may hide injection payloads
        const minLength = (conditions.description_min_length as number) || 2000;
        for (const tool of context.tools) {
          const desc = tool.description || "";
          if (desc.length >= minLength) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Tool "${tool.name}" has a ${desc.length}-character description (threshold: ${minLength}) — excessively long descriptions may hide prompt injection payloads`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "dangerous_parameter_defaults": {
        // B7: detect dangerous default values in schemas
        const dangerousDefaults = (conditions.dangerous_defaults as Array<{
          pattern?: string;
          context?: string;
          key?: string;
          value?: unknown;
        }>) || [];

        for (const tool of context.tools) {
          const props = tool.input_schema?.properties as Record<string, Record<string, unknown>> | undefined;
          if (!props) continue;

          for (const [paramName, paramDef] of Object.entries(props)) {
            if (!("default" in paramDef)) continue;
            const defaultVal = paramDef.default;

            for (const rule_ of dangerousDefaults) {
              // Pattern-based: match string defaults against regex
              if (rule_.pattern && typeof defaultVal === "string") {
                try {
                  if (new RegExp(rule_.pattern).test(defaultVal)) {
                    findings.push({
                      rule_id: rule.id,
                      severity: rule.severity,
                      evidence: `Tool "${tool.name}", parameter "${paramName}" has dangerous default value "${defaultVal}" (${rule_.context || rule_.pattern})`,
                      remediation: rule.remediation,
                      owasp_category: rule.owasp,
                      mitre_technique: rule.mitre,
                    });
                    break;
                  }
                } catch { /* invalid pattern */ }
              }
              // Key+value based: match parameter name and boolean default
              if (rule_.key && rule_.value !== undefined) {
                const keyPattern = new RegExp(rule_.key, "i");
                if (keyPattern.test(paramName) && defaultVal === rule_.value) {
                  findings.push({
                    rule_id: rule.id,
                    severity: rule.severity,
                    evidence: `Tool "${tool.name}", parameter "${paramName}" defaults to ${JSON.stringify(defaultVal)} — this is a dangerous default that grants broad permissions`,
                    remediation: rule.remediation,
                    owasp_category: rule.owasp,
                    mitre_technique: rule.mitre,
                  });
                  break;
                }
              }
            }
          }
        }
        break;
      }
    }

    return findings;
  }

  private runBehavioralRule(
    rule: DetectionRule,
    context: AnalysisContext
  ): FindingInput[] {
    const findings: FindingInput[] = [];
    const conditions = rule.detect.conditions || {};
    const meta = context.connection_metadata;

    if (!meta) return findings;

    switch (conditions.check) {
      case "connection_no_auth":
        if (!meta.auth_required) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: "Server does not require authentication for connections",
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;

      case "connection_transport": {
        const insecure = (conditions.insecure_transports as string[]) || ["http", "ws"];
        if (insecure.includes(meta.transport)) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server uses insecure transport: ${meta.transport}`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "response_time_exceeds": {
        const threshold = (conditions.threshold_ms as number) || 10000;
        if (meta.response_time_ms > threshold) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server response time ${meta.response_time_ms}ms exceeds threshold ${threshold}ms`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "tool_behavior_drift": {
        // G6: Rug pull detection — requires historical context stored in connection_metadata.
        // The scanner pipeline is expected to embed prior_tool_count and prior_tool_names
        // into connection_metadata when historical data is available.
        const metaExt = meta as typeof meta & {
          prior_tool_count?: number;
          prior_tool_names?: string[];
          prior_description_hashes?: Record<string, string>;
        };

        const increaseThreshold = (conditions.tool_count_increase_threshold as number) || 5;
        const decreaseThreshold = (conditions.tool_count_decrease_threshold as number) || 3;
        const criticalPatterns = (conditions.critical_capability_patterns as string[]) || [];

        if (metaExt.prior_tool_count !== undefined) {
          const currentCount = context.tools.length;
          const delta = currentCount - metaExt.prior_tool_count;

          if (delta > increaseThreshold) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Server tool count increased by ${delta} tools since last scan (${metaExt.prior_tool_count} → ${currentCount}) — rug pull signal`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          } else if (-delta > decreaseThreshold) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Server tool count decreased by ${-delta} tools since last scan (${metaExt.prior_tool_count} → ${currentCount}) — tool removal after trust established`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }

        // Check if any new tools have dangerous capability profiles
        if (metaExt.prior_tool_names) {
          const priorNames = new Set(metaExt.prior_tool_names);
          const newTools = context.tools.filter((t) => !priorNames.has(t.name));

          for (const newTool of newTools) {
            const toolText = `${newTool.name} ${newTool.description || ""}`.toLowerCase();
            const isDangerous = criticalPatterns.some((p) => {
              try { return new RegExp(p, "i").test(toolText); } catch { return false; }
            });

            if (isDangerous) {
              findings.push({
                rule_id: rule.id,
                severity: rule.severity,
                evidence: `New tool "${newTool.name}" added since last scan matches dangerous capability patterns — server behavior drift detected`,
                remediation: rule.remediation,
                owasp_category: rule.owasp,
                mitre_technique: rule.mitre,
              });
            }
          }
        }
        break;
      }
    }

    return findings;
  }

  private runCompositeRule(
    rule: DetectionRule,
    context: AnalysisContext
  ): FindingInput[] {
    const findings: FindingInput[] = [];
    const conditions = rule.detect.conditions || {};

    switch (conditions.check) {
      case "dependency_cve_audit": {
        const vulnDeps = context.dependencies.filter((d) => d.has_known_cve);
        for (const dep of vulnDeps) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Dependency "${dep.name}@${dep.version}" has known CVEs: ${dep.cve_ids.join(", ")}`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "dependency_last_update": {
        const thresholdMonths = (conditions.threshold_months as number) || 12;
        const cutoff = new Date();
        cutoff.setMonth(cutoff.getMonth() - thresholdMonths);

        for (const dep of context.dependencies) {
          if (dep.last_updated && dep.last_updated < cutoff) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Dependency "${dep.name}@${dep.version}" last updated ${dep.last_updated.toISOString()} (over ${thresholdMonths} months ago)`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "dependency_name_similarity": {
        // D3: typosquatting detection via Levenshtein distance
        const knownPackages = (conditions.known_packages as string[]) || [];
        const similarityThreshold = (conditions.similarity_threshold as number) || 0.85;

        for (const dep of context.dependencies) {
          for (const known of knownPackages) {
            if (dep.name === known) continue; // exact match is fine
            const sim = this.stringSimilarity(dep.name, known);
            if (sim >= similarityThreshold) {
              findings.push({
                rule_id: rule.id,
                severity: rule.severity,
                evidence: `Dependency "${dep.name}" is suspiciously similar to "${known}" (similarity: ${(sim * 100).toFixed(1)}%) — possible typosquat`,
                remediation: rule.remediation,
                owasp_category: rule.owasp,
                mitre_technique: rule.mitre,
              });
            }
          }
        }
        break;
      }

      case "lethal_trifecta": {
        const capabilities = new Set<string>();
        for (const tool of context.tools) {
          const desc = `${tool.name} ${tool.description || ""}`.toLowerCase();
          if (
            desc.match(/read|query|get|fetch|database|file|credential|secret/)
          ) {
            capabilities.add("reads-data");
          }
          if (desc.match(/web|scrape|browse|crawl|external|api|url/)) {
            capabilities.add("ingests-untrusted");
          }
          if (desc.match(/send|post|email|webhook|notify|upload|http/)) {
            capabilities.add("sends-network");
          }
        }

        if (
          capabilities.has("reads-data") &&
          capabilities.has("ingests-untrusted") &&
          capabilities.has("sends-network")
        ) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence:
              "Server exhibits the lethal trifecta: reads private data, ingests untrusted content, and can communicate externally",
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "capability_risk_profile": {
        const highRiskCombos =
          (conditions.high_risk_combinations as string[][]) || [];
        const toolCaps = this.classifyToolCapabilities(context.tools);

        for (const combo of highRiskCombos) {
          if (combo.every((cap) => toolCaps.has(cap))) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Server combines high-risk capabilities: ${combo.join(" + ")}`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "data_flow_analysis": {
        const sourcePatterns = (conditions.source_tools as string[]) || [];
        const sinkPatterns = (conditions.sink_tools as string[]) || [];

        const hasSources = context.tools.some((t) =>
          sourcePatterns.some((p) => t.name.toLowerCase().includes(p))
        );
        const hasSinks = context.tools.some((t) =>
          sinkPatterns.some((p) => t.name.toLowerCase().includes(p))
        );

        if (hasSources && hasSinks) {
          const sourceTools = context.tools
            .filter((t) => sourcePatterns.some((p) => t.name.toLowerCase().includes(p)))
            .map((t) => t.name);
          const sinkTools = context.tools
            .filter((t) => sinkPatterns.some((p) => t.name.toLowerCase().includes(p)))
            .map((t) => t.name);
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server contains data-reading tools [${sourceTools.join(", ")}] and data-sending tools [${sinkTools.join(", ")}], creating potential exfiltration paths`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "tool_name_shadows_common": {
        const commonNames = (conditions.common_tool_names as string[]) || [];
        for (const tool of context.tools) {
          if (commonNames.includes(tool.name.toLowerCase())) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Tool "${tool.name}" shadows a common tool name used by well-known MCP servers`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "spec_compliance": {
        // F4: Check that server metadata meets MCP spec requirements
        const requiredFields = (conditions.required_fields as string[]) || [];
        const recommendedFields = (conditions.recommended_fields as string[]) || [];
        const missing: string[] = [];
        const serverMeta = context.server as Record<string, unknown>;

        for (const field of requiredFields) {
          if (!serverMeta[field]) missing.push(`required:${field}`);
        }
        for (const field of recommendedFields) {
          if (!serverMeta[field]) missing.push(`recommended:${field}`);
        }

        // Check tool descriptions
        if (recommendedFields.includes("tool_descriptions")) {
          const toolsWithoutDesc = context.tools.filter((t) => !t.description || t.description.trim().length < 10);
          if (toolsWithoutDesc.length > 0) {
            missing.push(`tool_descriptions missing on: ${toolsWithoutDesc.map((t) => t.name).join(", ")}`);
          }
        }

        if (missing.length > 0) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server fails MCP spec compliance checks: ${missing.join("; ")}`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "description_capability_mismatch": {
        // A8: Description claims read-only but parameters suggest write operations
        const readonlyClaimPatterns = (conditions.readonly_claim_patterns as string[]) || [];
        const writeParamPatterns = (conditions.write_parameter_patterns as string[]) || [];

        for (const tool of context.tools) {
          const desc = `${tool.description || ""}`;
          const claimsReadOnly = readonlyClaimPatterns.some((p) => {
            try { return new RegExp(p, "i").test(desc); } catch { return false; }
          });

          if (!claimsReadOnly) continue;

          const props = tool.input_schema?.properties as Record<string, Record<string, unknown>> | undefined;
          if (!props) continue;

          const writeParams = Object.keys(props).filter((paramName) =>
            writeParamPatterns.some((p) => {
              try { return new RegExp(p, "i").test(paramName); } catch { return false; }
            })
          );

          if (writeParams.length > 0) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Tool "${tool.name}" describes itself as read-only/non-destructive but has write-capable parameters: [${writeParams.join(", ")}]`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "known_malicious_package": {
        // D5: Check against known malicious package name list
        const maliciousPackages = (conditions.malicious_packages as string[]) || [];
        for (const dep of context.dependencies) {
          if (maliciousPackages.includes(dep.name.toLowerCase())) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Dependency "${dep.name}@${dep.version}" is on the known malicious packages list — this package has been confirmed malicious or is a known typosquat`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "weak_crypto_deps": {
        // D6: Check for known weak/deprecated cryptographic dependencies
        const weakPackages = (conditions.weak_packages as Array<{
          name: string;
          max_version?: string;
          reason: string;
        }>) || [];

        for (const dep of context.dependencies) {
          for (const weak of weakPackages) {
            if (dep.name.toLowerCase() !== weak.name.toLowerCase()) continue;

            // If max_version specified, only flag if dep version is <= max_version
            if (weak.max_version && dep.version) {
              if (!this.versionLessThanOrEqual(dep.version, weak.max_version)) continue;
            }

            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Dependency "${dep.name}@${dep.version || "unknown"}" uses weak/deprecated cryptography: ${weak.reason}`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
            break;
          }
        }
        break;
      }

      case "dependency_confusion_risk": {
        // D7: Detect dependency confusion risk signals
        const signals = (conditions.signals as Array<{
          pattern?: string;
          description: string;
        }>) || [];

        for (const dep of context.dependencies) {
          for (const signal of signals) {
            if (!signal.pattern) continue;
            try {
              if (new RegExp(signal.pattern).test(dep.name)) {
                // Additional check: version suspiciously high (attacker trick)
                if (dep.version && /^[0-9]{3,}\./.test(dep.version)) {
                  findings.push({
                    rule_id: rule.id,
                    severity: rule.severity,
                    evidence: `Dependency "${dep.name}@${dep.version}" has a suspiciously high version number — classic dependency confusion attack signature (${signal.description})`,
                    remediation: rule.remediation,
                    owasp_category: rule.owasp,
                    mitre_technique: rule.mitre,
                  });
                  break;
                }
              }
            } catch { /* invalid regex */ }
          }
        }
        break;
      }

      case "namespace_squatting": {
        // F5: Detect servers impersonating official namespaces
        const protectedNamespaces = (conditions.protected_namespaces as Array<{
          pattern: string;
          owner: string;
          verified_github_orgs: string[];
        }>) || [];
        const knownServerNames = (conditions.known_server_names as string[]) || [];

        const serverName = context.server.name.toLowerCase();
        const githubUrl = context.server.github_url?.toLowerCase() || "";

        for (const ns of protectedNamespaces) {
          try {
            if (!new RegExp(ns.pattern).test(serverName)) continue;

            // Check if the server's GitHub org matches a verified org
            const isVerified = ns.verified_github_orgs.some((org) =>
              githubUrl.includes(`github.com/${org}/`) ||
              githubUrl.includes(`github.com/${org.toLowerCase()}/`)
            );

            if (!isVerified) {
              findings.push({
                rule_id: rule.id,
                severity: rule.severity,
                evidence: `Server name "${context.server.name}" matches protected namespace pattern for "${ns.owner}" but is not from a verified GitHub org (expected: ${ns.verified_github_orgs.join(", ")})`,
                remediation: rule.remediation,
                owasp_category: rule.owasp,
                mitre_technique: rule.mitre,
              });
              break;
            }
          } catch { /* invalid regex */ }
        }

        // Check for high-similarity matches to known official server names
        for (const knownName of knownServerNames) {
          if (serverName === knownName) continue;
          const sim = this.stringSimilarity(serverName, knownName);
          if (sim >= 0.85) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Server name "${context.server.name}" is suspiciously similar to known official server "${knownName}" (similarity: ${(sim * 100).toFixed(1)}%)`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "circular_data_loop": {
        // F6: Detect write+read on same data store — persistent prompt injection vector
        const writePatterns = (conditions.write_tool_patterns as string[]) || [];
        const readPatterns = (conditions.read_tool_patterns as string[]) || [];
        const storeIndicators = (conditions.store_indicators as string[]) || [];

        const writeTools: string[] = [];
        const readTools: string[] = [];

        for (const tool of context.tools) {
          const text = `${tool.name} ${tool.description || ""}`.toLowerCase();
          const hasStore = storeIndicators.some((p) => {
            try { return new RegExp(p, "i").test(text); } catch { return false; }
          });
          if (!hasStore) continue;

          const isWrite = writePatterns.some((p) => {
            try { return new RegExp(p, "i").test(text); } catch { return false; }
          });
          const isRead = readPatterns.some((p) => {
            try { return new RegExp(p, "i").test(text); } catch { return false; }
          });

          if (isWrite) writeTools.push(tool.name);
          if (isRead) readTools.push(tool.name);
        }

        if (writeTools.length > 0 && readTools.length > 0) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server has write tools [${writeTools.join(", ")}] and read tools [${readTools.join(", ")}] operating on the same data store — circular data loop enables persistent prompt injection`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "indirect_injection_gateway": {
        // G1: Tools that ingest untrusted external content without declared sanitization
        // This is the #1 real-world MCP attack vector (Rehberger / Invariant Labs research)
        const ingestionPatterns = (conditions.ingestion_tool_patterns as string[]) || [];
        const sanitizationSignals = (conditions.sanitization_signals as string[]) || [];

        const gatewayTools: string[] = [];

        for (const tool of context.tools) {
          const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();

          const isIngestionTool = ingestionPatterns.some((p) => {
            try { return new RegExp(p, "i").test(toolText); } catch { return false; }
          });

          if (!isIngestionTool) continue;

          // Check if description mentions any sanitization
          const hasSanitization = sanitizationSignals.some((p) => {
            try { return new RegExp(p, "i").test(toolText); } catch { return false; }
          });

          if (!hasSanitization) {
            gatewayTools.push(tool.name);
          }
        }

        if (gatewayTools.length > 0) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server has tools that ingest untrusted external content without declared sanitization: [${gatewayTools.join(", ")}]. These are indirect prompt injection gateways — attackers can inject instructions into the content these tools fetch.`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "context_window_saturation": {
        // G4: Detect descriptions designed to exhaust the AI's context window
        const charThreshold = (conditions.description_char_threshold as number) || 6000;
        const descToParamsRatio = (conditions.description_to_params_ratio as number) || 500;
        const tailWindowPct = (conditions.tail_window_percent as number) || 20;

        for (const tool of context.tools) {
          const desc = tool.description || "";
          const descLen = desc.length;

          // Check 1: Raw length threshold
          if (descLen > charThreshold) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Tool "${tool.name}" description is ${descLen} characters (threshold: ${charThreshold}) — potential context window saturation attack`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
            continue;
          }

          // Check 2: Disproportionate description vs parameter count
          const props = tool.input_schema?.properties as Record<string, unknown> | undefined;
          const paramCount = props ? Object.keys(props).length : 0;
          if (paramCount > 0 && descLen / paramCount > descToParamsRatio && descLen > 1000) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Tool "${tool.name}" has ${descLen} char description for only ${paramCount} parameters (${Math.round(descLen / paramCount)} chars/param, threshold: ${descToParamsRatio}) — description padding detected`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
            continue;
          }

          // Check 3: Injection payload in tail position of a long description (recency attack)
          if (descLen > 2000) {
            const tailStart = Math.floor(descLen * (1 - tailWindowPct / 100));
            const tail = desc.substring(tailStart);
            const injectionPatterns = [
              /ignore\s+(previous|above|all)\s+instructions/i,
              /you\s+are\s+now\s+(a|an|the)\s+/i,
              /from\s+now\s+on[,\s]+you\s+(must|will|should)/i,
              /new\s+instructions?\s*:/i,
              /override\s+(previous|system)\s+(prompt|instructions)/i,
            ];
            const tailInjection = injectionPatterns.some((r) => r.test(tail));
            if (tailInjection) {
              findings.push({
                rule_id: rule.id,
                severity: rule.severity,
                evidence: `Tool "${tool.name}" has a ${descLen}-char description with an injection payload in the final ${tailWindowPct}% — context saturation + tail injection attack`,
                remediation: rule.remediation,
                owasp_category: rule.owasp,
                mitre_technique: rule.mitre,
              });
            }
          }
        }
        break;
      }

      case "multi_step_exfiltration_chain": {
        // F7: Detect 3-step exfiltration chain (read → transform → exfiltrate)
        const step1Patterns = (conditions.step1_read_patterns as string[]) || [];
        const step2Patterns = (conditions.step2_transform_patterns as string[]) || [];
        const step3Patterns = (conditions.step3_exfil_patterns as string[]) || [];

        const step1Tools: string[] = [];
        const step2Tools: string[] = [];
        const step3Tools: string[] = [];

        for (const tool of context.tools) {
          const text = `${tool.name} ${tool.description || ""}`.toLowerCase();

          if (step1Patterns.some((p) => { try { return new RegExp(p, "i").test(text); } catch { return false; } })) {
            step1Tools.push(tool.name);
          }
          if (step2Patterns.some((p) => { try { return new RegExp(p, "i").test(text); } catch { return false; } })) {
            step2Tools.push(tool.name);
          }
          if (step3Patterns.some((p) => { try { return new RegExp(p, "i").test(text); } catch { return false; } })) {
            step3Tools.push(tool.name);
          }
        }

        const requiresAll = conditions.requires_all_steps !== false;
        const chainComplete = requiresAll
          ? step1Tools.length > 0 && step2Tools.length > 0 && step3Tools.length > 0
          : step1Tools.length > 0 && step3Tools.length > 0;

        if (chainComplete) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server provides a complete multi-step exfiltration chain — Step 1 (read): [${step1Tools.join(", ")}] → Step 2 (transform): [${step2Tools.join(", ")}] → Step 3 (exfiltrate): [${step3Tools.join(", ")}]`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "multi_agent_propagation_risk": {
        // H3: Detect MCP tools that form propagation vectors in multi-agent architectures.
        //
        // Agentic AI systems (LangGraph, AutoGen, CrewAI) use MCP as the integration
        // layer between agents. A compromised upstream agent can inject malicious
        // instructions through shared MCP tools to ALL downstream agents — without any
        // single tool call appearing suspicious in isolation.
        //
        // We flag two categories:
        // 1. Agentic input sinks: tools explicitly designed to receive output FROM other
        //    agents, without declaring trust boundary or input validation.
        // 2. Shared memory writers: tools that write to cross-agent state (vector stores,
        //    working memory, scratchpads) — the transmission medium for cross-agent injection.
        const agenticInputPatterns = (conditions.agentic_input_patterns as string[]) || [];
        const sharedMemoryPatterns = (conditions.shared_memory_patterns as string[]) || [];
        const trustBoundarySignals = (conditions.trust_boundary_signals as string[]) || [];

        const propagationSinkTools: string[] = [];
        const sharedMemoryTools: string[] = [];

        for (const tool of context.tools) {
          const toolText = `${tool.name} ${tool.description || ""}`;

          const isAgenticInputSink = agenticInputPatterns.some((p) => {
            try { return new RegExp(p, "i").test(toolText); } catch { return false; }
          });

          if (isAgenticInputSink) {
            // Only flag if there is no explicit trust boundary declaration
            const hasTrustBoundary = trustBoundarySignals.some((p) => {
              try { return new RegExp(p, "i").test(toolText); } catch { return false; }
            });
            if (!hasTrustBoundary) {
              propagationSinkTools.push(tool.name);
            }
          }

          const isSharedMemoryWriter = sharedMemoryPatterns.some((p) => {
            try { return new RegExp(p, "i").test(toolText); } catch { return false; }
          });
          if (isSharedMemoryWriter) {
            sharedMemoryTools.push(tool.name);
          }
        }

        if (propagationSinkTools.length > 0 || sharedMemoryTools.length > 0) {
          const evidenceParts: string[] = [];
          if (propagationSinkTools.length > 0) {
            evidenceParts.push(
              `agentic input sinks without trust boundaries: [${propagationSinkTools.join(", ")}]`
            );
          }
          if (sharedMemoryTools.length > 0) {
            evidenceParts.push(
              `shared agent memory/state tools (cross-agent infection vectors): [${sharedMemoryTools.join(", ")}]`
            );
          }
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Multi-agent propagation risk — ${evidenceParts.join("; ")}. A compromised upstream agent can propagate injected instructions to downstream agents through these tools without any individual call appearing suspicious.`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "annotation_deception": {
        // I1: readOnlyHint=true on tools with destructive capability signals
        const destructivePatterns = (conditions.destructive_patterns as string[]) || [
          "delete", "remove", "drop", "destroy", "kill", "terminate", "wipe", "purge",
          "truncate", "overwrite", "format", "reset", "revoke",
        ];
        for (const tool of context.tools) {
          const ann = (tool as Record<string, unknown>).annotations as Record<string, unknown> | null;
          if (!ann || ann.readOnlyHint !== true) continue;

          const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();
          const matchedPattern = destructivePatterns.find((p) => toolText.includes(p));
          if (matchedPattern) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Tool "${tool.name}" has readOnlyHint=true but name/description contains destructive signal "${matchedPattern}" — annotation deception bypasses client confirmation dialogs`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "missing_destructive_annotation": {
        // I2: Tools with destructive capability but no destructiveHint
        const destructiveSignals = (conditions.destructive_signals as string[]) || [
          "delete", "remove", "drop", "destroy", "execute", "exec", "run", "shell",
          "command", "write", "modify", "update", "create", "send", "post", "put",
        ];
        for (const tool of context.tools) {
          const ann = (tool as Record<string, unknown>).annotations as Record<string, unknown> | null;
          if (ann?.destructiveHint === true) continue; // properly annotated

          const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();
          const matchedSignal = destructiveSignals.find((s) => toolText.includes(s));
          if (matchedSignal) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Tool "${tool.name}" has destructive capability signal "${matchedSignal}" but no destructiveHint annotation — clients may skip confirmation`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "dangerous_resource_uri": {
        // I4: Dangerous URI schemes or path traversal in resource URIs
        const dangerousSchemes = (conditions.dangerous_schemes as string[]) || [
          "ftp:", "gopher:", "data:", "javascript:", "file:///etc", "file:///root",
          "file:///home", "file:///proc", "file:///sys", "file:///dev",
          "file:///var/log", "file:///tmp",
        ];
        const traversalPatterns = ["../", "..\\", "%2e%2e", "%252e%252e"];
        const resources = context.resources || [];

        for (const resource of resources) {
          const uri = resource.uri.toLowerCase();

          // Check dangerous schemes/paths
          const dangerousMatch = dangerousSchemes.find((s) => uri.startsWith(s));
          if (dangerousMatch) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Resource URI "${resource.uri}" uses dangerous path/scheme "${dangerousMatch}" — potential local file inclusion or sensitive data exposure`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
            continue;
          }

          // Check path traversal
          const traversalMatch = traversalPatterns.find((p) => uri.includes(p));
          if (traversalMatch) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Resource URI "${resource.uri}" contains path traversal pattern "${traversalMatch}"`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "resource_tool_shadowing": {
        // I5: Resources named identically to well-known tools
        const knownToolNames = (conditions.known_tool_names as string[]) || [
          "read_file", "write_file", "execute_command", "list_directory",
          "search", "query", "fetch", "get", "create", "delete",
        ];
        const resources = context.resources || [];

        for (const resource of resources) {
          const rName = resource.name.toLowerCase();
          const matchedTool = knownToolNames.find((t) => rName === t || rName.includes(t));
          if (matchedTool) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Resource "${resource.name}" (${resource.uri}) shadows well-known tool name "${matchedTool}" — may confuse AI client about data source`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "sampling_abuse": {
        // I7: Sampling capability + indirect injection gateway = super injection loop
        const caps = context.declared_capabilities;
        if (!caps?.sampling) break;

        // Check if server also has tools that ingest external content (G1 pattern)
        const ingestionPatterns = (conditions.ingestion_patterns as string[]) || [
          "fetch", "scrape", "browse", "crawl", "download", "read_url",
          "get_page", "http", "web", "email", "inbox", "message",
          "slack", "discord", "issue", "comment", "rss", "feed",
        ];

        for (const tool of context.tools) {
          const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();
          const matchedPattern = ingestionPatterns.find((p) => toolText.includes(p));
          if (matchedPattern) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Server declares sampling capability AND has tool "${tool.name}" matching ingestion pattern "${matchedPattern}" — sampling + external content ingestion creates weaponized inference loop (23-41% attack amplification per "Breaking the Protocol" paper)`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
            break; // One finding per server
          }
        }

        // Even without ingestion tools, sampling alone is notable
        if (findings.length === 0) {
          findings.push({
            rule_id: rule.id,
            severity: "high" as const,
            evidence: `Server declares sampling capability — can request client LLM to generate arbitrary text. Risk: covert tool invocation, data exfiltration via generated output, resource theft`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "sampling_cost_risk": {
        // I8: Sampling without cost controls
        const caps = context.declared_capabilities;
        if (!caps?.sampling) break;

        findings.push({
          rule_id: rule.id,
          severity: rule.severity,
          evidence: `Server declares sampling capability with no cost disclosure mechanism — can silently drain client API credits by requesting expensive model inference`,
          remediation: rule.remediation,
          owasp_category: rule.owasp,
          mitre_technique: rule.mitre,
        });
        break;
      }

      case "over_privileged_root": {
        // I11: Roots declaring access to sensitive system directories
        const sensitiveRoots = (conditions.sensitive_paths as string[]) || [
          "file:///", "file:///etc", "file:///root", "file:///home",
          "file:///var", "file:///proc", "file:///sys", "file:///dev",
          "file:///tmp", "file:///usr", "file:///opt",
        ];
        const roots = context.roots || [];

        for (const root of roots) {
          const uri = root.uri.toLowerCase();
          const matched = sensitiveRoots.find((s) => {
            if (s === "file:///") return uri === "file:///" || uri === "file:///";
            return uri.startsWith(s);
          });
          if (matched) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Server declares filesystem root at "${root.uri}" ${root.name ? `("${root.name}")` : ""} — over-privileged access to sensitive system directory. CVE-2025-53109/53110 demonstrated root boundary bypass in Anthropic's filesystem server.`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "consent_fatigue_profile": {
        // I16: Many benign tools + few dangerous = consent fatigue exploitation
        const totalTools = context.tools.length;
        const minTotalTools = (conditions.min_total_tools as number) || 30;
        if (totalTools < minTotalTools) break;

        const dangerousPatterns = (conditions.dangerous_patterns as string[]) || [
          "exec", "shell", "command", "delete", "drop", "send", "email",
          "webhook", "post", "write_file", "remove",
        ];

        let dangerousCount = 0;
        const dangerousTools: string[] = [];
        for (const tool of context.tools) {
          const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();
          if (dangerousPatterns.some((p) => toolText.includes(p))) {
            dangerousCount++;
            dangerousTools.push(tool.name);
          }
        }

        const dangerousRatio = dangerousCount / totalTools;
        const maxDangerousRatio = (conditions.max_dangerous_ratio as number) || 0.15;

        if (dangerousCount > 0 && dangerousRatio <= maxDangerousRatio) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server has ${totalTools} tools with only ${dangerousCount} having dangerous capabilities (${dangerousTools.join(", ")}) — ${(dangerousRatio * 100).toFixed(1)}% dangerous ratio creates consent fatigue risk. 84.2% tool poisoning success when auto-approve is enabled (Invariant Labs).`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "capability_escalation_post_init": {
        // I12: Detects servers using capabilities they didn't declare during initialize
        const caps = context.declared_capabilities;
        if (!caps) break;

        // Check if server has tools but didn't declare tools capability
        if (context.tools.length > 0 && !caps.tools) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server has ${context.tools.length} tools but did not declare tools capability during initialization — undeclared capability escalation`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }

        // Check if server has resources but didn't declare resources capability
        if ((context.resources?.length ?? 0) > 0 && !caps.resources) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server exposes ${context.resources!.length} resources but did not declare resources capability during initialization — undeclared capability escalation`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }

        // Check if server has prompts but didn't declare prompts capability
        if ((context.prompts?.length ?? 0) > 0 && !caps.prompts) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server exposes ${context.prompts!.length} prompts but did not declare prompts capability during initialization — undeclared capability escalation`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }

      case "rolling_capability_drift": {
        // I14: Gradual capability addition over multiple scans
        // This requires historical data embedded in connection_metadata by the pipeline
        const metaExt = context.connection_metadata as typeof context.connection_metadata & {
          prior_scan_tool_counts?: number[];
        };
        if (!metaExt?.prior_scan_tool_counts) break;

        const counts = metaExt.prior_scan_tool_counts;
        const windowScans = (conditions.window_scans as number) || 4;
        const cumulativeThreshold = (conditions.cumulative_threshold as number) || 5;

        if (counts.length >= windowScans) {
          const windowStart = counts[counts.length - windowScans];
          const windowEnd = context.tools.length;
          const cumulativeDelta = windowEnd - windowStart;

          if (cumulativeDelta >= cumulativeThreshold) {
            findings.push({
              rule_id: rule.id,
              severity: rule.severity,
              evidence: `Server tool count grew by ${cumulativeDelta} over ${windowScans} scan periods (${windowStart} → ${windowEnd}) — gradual capability drift below G6 per-scan threshold but significant cumulative growth`,
              remediation: rule.remediation,
              owasp_category: rule.owasp,
              mitre_technique: rule.mitre,
            });
          }
        }
        break;
      }

      case "cross_config_lethal_trifecta": {
        // I13: Detects lethal trifecta distributed across multiple servers in a config
        // This rule only fires in CLI mode where multi-server context is available.
        // The CLI assembles a combined tool list across all servers in the config.
        // In registry mode, this check is skipped (tools only from one server).
        const caps = this.classifyToolCapabilities(context.tools);
        const hasPrivateData = caps.has("reads-data") || caps.has("accesses-filesystem") || caps.has("manages-credentials");
        const hasUntrustedContent = caps.has("sends-network") || context.tools.some((t) => {
          const text = `${t.name} ${t.description || ""}`.toLowerCase();
          return /fetch|scrape|browse|crawl|download|web|http|email|inbox|rss|feed/.test(text);
        });
        const hasExternalComms = caps.has("sends-network");

        if (hasPrivateData && hasUntrustedContent && hasExternalComms) {
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Cross-config lethal trifecta detected: private data access + untrusted content ingestion + external communication capabilities are present across the combined tool set`,
            remediation: rule.remediation,
            owasp_category: rule.owasp,
            mitre_technique: rule.mitre,
          });
        }
        break;
      }
    }

    return findings;
  }

  private getTextsForContext(
    contextType: string | undefined,
    context: AnalysisContext
  ): Array<{ text: string; location: string }> {
    switch (contextType) {
      case "tool_description":
        return context.tools.map((t) => ({
          text: `${t.name} ${t.description || ""}`,
          location: `tool:${t.name}`,
        }));

      case "parameter_description": {
        // B5: Scan parameter-level description fields — a secondary injection surface
        return context.tools.flatMap((t) => {
          const props = t.input_schema?.properties as Record<string, Record<string, unknown>> | undefined;
          if (!props) return [];
          return Object.entries(props).flatMap(([name, def]) => {
            const results: Array<{ text: string; location: string }> = [];
            // Scan the parameter's description field
            if (def.description && typeof def.description === "string") {
              results.push({
                text: def.description,
                location: `tool:${t.name}/param:${name}/description`,
              });
            }
            // Also scan parameter name + title
            if (def.title && typeof def.title === "string") {
              results.push({
                text: `${name} ${def.title}`,
                location: `tool:${t.name}/param:${name}/title`,
              });
            }
            return results;
          });
        });
      }

      case "parameter_schema":
        return context.tools.flatMap((t) => {
          const props = t.input_schema?.properties as Record<string, unknown> | undefined;
          if (!props) return [];
          return Object.entries(props).map(([name, def]) => ({
            text: `${name} ${JSON.stringify(def)}`,
            location: `tool:${t.name}/param:${name}`,
          }));
        });

      case "source_code":
        if (!context.source_code) return [];
        return [{ text: context.source_code, location: "source_code" }];

      case "metadata":
        return [
          {
            text: JSON.stringify({
              server: context.server,
              tools: context.tools.map((t) => t.name),
            }),
            location: "metadata",
          },
        ];

      // H2: Scans fields from the MCP initialize handshake response.
      // serverInfo.name is the first string an AI processes when connecting to a server —
      // processed before tool descriptions, before conversation, before any user context.
      // server_version and server_instructions (MCP spec 2025-11+) add two more surfaces.
      case "server_initialize_fields": {
        const initTexts: Array<{ text: string; location: string }> = [];
        if (context.server.name) {
          initTexts.push({
            text: context.server.name,
            location: "initialize:serverInfo.name",
          });
        }
        if (context.initialize_metadata?.server_version) {
          initTexts.push({
            text: context.initialize_metadata.server_version,
            location: "initialize:serverInfo.version",
          });
        }
        if (context.initialize_metadata?.server_instructions) {
          initTexts.push({
            text: context.initialize_metadata.server_instructions,
            location: "initialize:instructions",
          });
        }
        return initTexts;
      }

      // I3, I4, I5: Scans resource metadata fields (URI, name, description)
      case "resource_metadata": {
        const resources = context.resources || [];
        return resources.flatMap((r) => {
          const texts: Array<{ text: string; location: string }> = [];
          if (r.name) {
            texts.push({ text: r.name, location: `resource:${r.uri}/name` });
          }
          if (r.description) {
            texts.push({ text: r.description, location: `resource:${r.uri}/description` });
          }
          if (r.uri) {
            texts.push({ text: r.uri, location: `resource:${r.uri}` });
          }
          return texts;
        });
      }

      // I6: Scans prompt template metadata (name, description, argument names/descriptions)
      case "prompt_metadata": {
        const prompts = context.prompts || [];
        return prompts.flatMap((p) => {
          const texts: Array<{ text: string; location: string }> = [];
          texts.push({
            text: `${p.name} ${p.description || ""}`,
            location: `prompt:${p.name}`,
          });
          for (const arg of p.arguments || []) {
            if (arg.description) {
              texts.push({
                text: arg.description,
                location: `prompt:${p.name}/arg:${arg.name}`,
              });
            }
          }
          return texts;
        });
      }

      // I1, I2: Scans tool annotation fields for deception
      case "tool_annotations": {
        return context.tools
          .filter((t) => {
            const ann = (t as Record<string, unknown>).annotations;
            return ann && typeof ann === "object";
          })
          .map((t) => ({
            text: JSON.stringify((t as Record<string, unknown>).annotations),
            location: `tool:${t.name}/annotations`,
          }));
      }

      default:
        return [];
    }
  }

  private classifyToolCapabilities(
    tools: Array<{
      name: string;
      description: string | null;
    }>
  ): Set<string> {
    const caps = new Set<string>();

    for (const tool of tools) {
      const text = `${tool.name} ${tool.description || ""}`.toLowerCase();
      if (text.match(/exec|run|shell|command|script|eval/))
        caps.add("executes-code");
      if (text.match(/file|read|write|path|directory|fs/))
        caps.add("accesses-filesystem");
      if (text.match(/http|fetch|request|api|url|webhook|send|email/))
        caps.add("sends-network");
      if (text.match(/credential|secret|key|token|password|auth/))
        caps.add("manages-credentials");
      if (text.match(/read|query|get|fetch|search|list/))
        caps.add("reads-data");
      if (text.match(/write|create|update|delete|modify|set/))
        caps.add("writes-data");
    }

    return caps;
  }

  /**
   * Compute normalized Levenshtein similarity between two strings.
   * Returns a value between 0 (completely different) and 1 (identical).
   */
  private stringSimilarity(a: string, b: string): number {
    const longer = a.length > b.length ? a : b;
    const shorter = a.length > b.length ? b : a;
    if (longer.length === 0) return 1.0;
    const distance = this.levenshteinDistance(longer, shorter);
    return (longer.length - distance) / longer.length;
  }

  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * Simple semver comparison: returns true if version <= maxVersion.
   * Only handles major.minor.patch format.
   */
  private versionLessThanOrEqual(version: string, maxVersion: string): boolean {
    const parse = (v: string) =>
      v.replace(/[^0-9.]/g, "").split(".").map(Number);
    const [aMaj, aMin = 0, aPatch = 0] = parse(version);
    const [bMaj, bMin = 0, bPatch = 0] = parse(maxVersion);
    if (aMaj !== bMaj) return aMaj < bMaj;
    if (aMin !== bMin) return aMin < bMin;
    return aPatch <= bPatch;
  }
}
