import type { DetectionRule, FindingInput } from "@mcp-sentinel/database";
import pino from "pino";

const logger = pino({ name: "analyzer:engine" });

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
      const excluded = excludePatterns.some((ep) => {
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
          findings.push({
            rule_id: rule.id,
            severity: rule.severity,
            evidence: `Server contains both data-reading and data-sending tools, creating potential exfiltration paths`,
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
}
