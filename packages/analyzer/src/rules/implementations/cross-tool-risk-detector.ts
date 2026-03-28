/**
 * Cross-Tool Risk Detector — Deep analysis for I1, I13, I16
 *
 * Extends the graph-based approach in f1-lethal-trifecta.ts to 3 more rules
 * that require reasoning about tool COMBINATIONS, not individual tools.
 *
 * F1, F6, F7 are already covered by f1-lethal-trifecta.ts.
 * This detector adds:
 * - I1:  Annotation deception — tool claims readOnlyHint but has destructive params
 * - I13: Cross-config lethal trifecta — trifecta distributed across multiple servers
 * - I16: Consent fatigue — many benign tools hiding a few dangerous ones
 *
 * What this catches that YAML regex can't:
 * - I1:  Schema-level contradiction between annotation claims and actual capabilities
 * - I13: Risk patterns that span server boundaries in multi-server configs
 * - I16: Statistical distribution of danger across a tool set
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import {
  buildCapabilityGraph,
  type CapabilityGraphResult,
  type ToolNode,
} from "../analyzers/capability-graph.js";
import {
  analyzeToolSet,
} from "../analyzers/schema-inference.js";

// ─── I1: Annotation Deception ──────────────────────────────────────────────

const DESTRUCTIVE_PARAM_PATTERNS = [
  /delete/i, /remove/i, /drop/i, /overwrite/i, /truncate/i,
  /destroy/i, /purge/i, /wipe/i, /kill/i, /terminate/i,
  /erase/i, /reset/i, /force/i,
];

const WRITE_PARAM_PATTERNS = [
  /write/i, /create/i, /update/i, /insert/i, /modify/i,
  /append/i, /set/i, /put/i, /upload/i, /save/i,
];

class AnnotationDeceptionRule implements TypedRule {
  readonly id = "I1";
  readonly name = "Annotation Deception (Schema-Verified)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (context.tools.length === 0) return [];

    const findings: TypedFinding[] = [];

    for (const tool of context.tools) {
      const annotations = (tool as Record<string, unknown>).annotations as
        | { readOnlyHint?: boolean; destructiveHint?: boolean } | null | undefined;
      if (!annotations) continue;

      const schema = tool.input_schema as Record<string, unknown> | null;
      const props = (schema?.properties || {}) as Record<string, Record<string, unknown>>;
      const paramNames = Object.keys(props);
      const allText = `${tool.name} ${tool.description || ""} ${paramNames.join(" ")}`.toLowerCase();

      // Check: readOnlyHint=true but has destructive/write parameters
      if (annotations.readOnlyHint === true) {
        const destructiveParams = paramNames.filter((p) =>
          DESTRUCTIVE_PARAM_PATTERNS.some((pat) => pat.test(p))
        );
        const writeParams = paramNames.filter((p) =>
          WRITE_PARAM_PATTERNS.some((pat) => pat.test(p))
        );

        // Also check description for destructive intent
        const descHasDestructive = DESTRUCTIVE_PARAM_PATTERNS.some((p) =>
          p.test(tool.description || "")
        );
        const descHasWrite = WRITE_PARAM_PATTERNS.some((p) =>
          p.test(tool.description || "")
        );

        const deceptiveParams = [...destructiveParams, ...writeParams];
        const deceptiveSignals = deceptiveParams.length + (descHasDestructive ? 1 : 0) + (descHasWrite ? 1 : 0);

        if (deceptiveSignals > 0) {
          // Use schema inference for higher-confidence classification
          const schemaAnalysis = analyzeToolSet([tool]);
          const toolAnalysis = schemaAnalysis.tools[0];
          const hasDestructiveCapability = toolAnalysis?.capabilities.some(
            (c) => c.capability === "destructive_operation" || c.capability === "configuration_mutation"
          );

          const confidence = hasDestructiveCapability
            ? 0.92  // Schema inference confirms destructive capability
            : deceptiveParams.length > 0
              ? 0.80  // Parameter names suggest deception
              : 0.65; // Only description suggests deception

          findings.push({
            rule_id: "I1",
            severity: "critical",
            evidence:
              `Tool "${tool.name}" declares readOnlyHint: true but ` +
              (deceptiveParams.length > 0
                ? `has parameters suggesting write/destroy: [${deceptiveParams.join(", ")}]. `
                : `description contains destructive language. `) +
              (hasDestructiveCapability
                ? `Schema structural analysis CONFIRMS destructive capability (attack_surface: ${((toolAnalysis?.attack_surface_score || 0) * 100).toFixed(0)}%). `
                : "") +
              `AI clients trust readOnlyHint for auto-approval — this annotation bypasses user consent. ` +
              `Confidence: ${(confidence * 100).toFixed(0)}%.`,
            remediation:
              "Set readOnlyHint: false or remove it. If the tool has any write, delete, or modify " +
              "capability, it must not claim to be read-only. Set destructiveHint: true for destructive operations.",
            owasp_category: "MCP06-excessive-permissions",
            mitre_technique: "AML.T0054",
            confidence,
            metadata: {
              analysis_type: "annotation_vs_schema",
              tool_name: tool.name,
              claimed_readonly: true,
              deceptive_params: deceptiveParams,
              schema_confirms_destructive: hasDestructiveCapability,
            },
          });
        }
      }

      // Check: no destructiveHint but tool IS destructive
      if (!annotations.destructiveHint) {
        const destructiveParams = paramNames.filter((p) =>
          DESTRUCTIVE_PARAM_PATTERNS.some((pat) => pat.test(p))
        );

        if (destructiveParams.length >= 2) {
          findings.push({
            rule_id: "I2",
            severity: "high",
            evidence:
              `Tool "${tool.name}" has ${destructiveParams.length} destructive parameters ` +
              `[${destructiveParams.join(", ")}] but does not set destructiveHint: true. ` +
              `AI clients may auto-execute this tool without user confirmation.`,
            remediation:
              "Add destructiveHint: true to the tool's annotations to ensure AI clients " +
              "request user confirmation before execution.",
            owasp_category: "MCP06-excessive-permissions",
            mitre_technique: "AML.T0054",
            confidence: 0.75,
            metadata: {
              analysis_type: "missing_annotation",
              tool_name: tool.name,
              destructive_params: destructiveParams,
            },
          });
        }
      }
    }

    return findings;
  }
}

// ─── I16: Consent Fatigue Exploitation ─────────────────────────────────────

class ConsentFatigueRule implements TypedRule {
  readonly id = "I16";
  readonly name = "Consent Fatigue Exploitation (Capability Distribution)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (context.tools.length < 5) return [];

    const graph = buildCapabilityGraph(context.tools);
    const findings: TypedFinding[] = [];

    // Classify tools as benign (read-only/public) vs dangerous (exec/network/destructive)
    const dangerousCapabilities = new Set<string>([
      "executes-code", "sends-network", "manages-credentials",
      "writes-data", "destructive",
    ]);

    const benignTools: string[] = [];
    const dangerousTools: Array<{ name: string; capabilities: string[] }> = [];

    for (const node of graph.nodes) {
      const dangerousCaps = node.capabilities.filter(
        (c) => dangerousCapabilities.has(c.capability) && c.confidence >= 0.5
      );
      if (dangerousCaps.length > 0) {
        dangerousTools.push({
          name: node.name,
          capabilities: dangerousCaps.map((c) => c.capability),
        });
      } else {
        benignTools.push(node.name);
      }
    }

    // Consent fatigue: >10 benign tools hiding <3 dangerous ones
    // Ratio matters: 84.2% success rate at 10:1 (Invariant Labs)
    const ratio = benignTools.length / Math.max(dangerousTools.length, 1);

    if (benignTools.length >= 10 && dangerousTools.length > 0 && dangerousTools.length <= 3 && ratio >= 5) {
      const confidence = Math.min(0.90, 0.60 + (ratio / 50));

      findings.push({
        rule_id: "I16",
        severity: "high",
        evidence:
          `${benignTools.length} benign tools hiding ${dangerousTools.length} dangerous tool(s). ` +
          `Benign-to-dangerous ratio: ${ratio.toFixed(1)}:1. ` +
          `Dangerous tools: ${dangerousTools.map((t) => `${t.name} (${t.capabilities.join(", ")})`).join("; ")}. ` +
          `After approving ${benignTools.length} safe tools, users auto-approve without scrutiny ` +
          `(84.2% success rate per Invariant Labs research). ` +
          `Confidence: ${(confidence * 100).toFixed(0)}%.`,
        remediation:
          "Move dangerous tools to a separate server that requires explicit security review. " +
          "Tools with code execution, network access, or credential management should not be " +
          "bundled with a large number of benign tools.",
        owasp_category: "MCP06-excessive-permissions",
        mitre_technique: "AML.T0054",
        confidence,
        metadata: {
          analysis_type: "capability_distribution",
          benign_count: benignTools.length,
          dangerous_count: dangerousTools.length,
          ratio,
          dangerous_tools: dangerousTools,
        },
      });
    }

    return findings;
  }
}

// ─── I13: Cross-Config Lethal Trifecta ────────────────────────────────────

class CrossConfigTrifectaRule implements TypedRule {
  readonly id = "I13";
  readonly name = "Cross-Config Lethal Trifecta (Multi-Server Graph)";

  analyze(context: AnalysisContext): TypedFinding[] {
    // I13 needs multi-server context — AnalysisContext.tools is per-server
    // This rule activates when the scanner passes merged tool sets from multiple
    // servers in the same client config via context metadata
    const multiServerTools = (context as unknown as Record<string, unknown>).multi_server_tools as
      | Array<{ server_name: string; tools: AnalysisContext["tools"] }> | undefined;

    if (!multiServerTools || multiServerTools.length < 2) return [];

    // Merge all tools and build a unified capability graph
    const allTools = multiServerTools.flatMap((s) => s.tools);
    const graph = buildCapabilityGraph(allTools);
    const findings: TypedFinding[] = [];

    // Check for lethal trifecta distributed across servers
    const trifectaPatterns = graph.patterns.filter((p) => p.type === "lethal_trifecta");

    for (const pattern of trifectaPatterns) {
      // Determine which servers contribute which legs of the trifecta
      const serverContributions = new Map<string, string[]>();
      for (const toolName of pattern.tools_involved) {
        for (const server of multiServerTools) {
          if (server.tools.some((t) => t.name === toolName)) {
            if (!serverContributions.has(server.server_name)) {
              serverContributions.set(server.server_name, []);
            }
            serverContributions.get(server.server_name)!.push(toolName);
          }
        }
      }

      // Only flag if the trifecta spans multiple servers (F1 catches single-server)
      if (serverContributions.size >= 2) {
        const serverDetails = Array.from(serverContributions.entries())
          .map(([server, tools]) => `${server}: [${tools.join(", ")}]`)
          .join("; ");

        findings.push({
          rule_id: "I13",
          severity: "critical",
          evidence:
            `Cross-config lethal trifecta detected across ${serverContributions.size} servers. ` +
            `${pattern.description} ` +
            `Server contributions: ${serverDetails}. ` +
            `No individual server has the full trifecta — it only emerges when servers are combined. ` +
            `Score CAPPED at 40.`,
          remediation:
            "Review server combinations in your MCP client config. Remove either the server " +
            "providing private data access or the one providing external communication. " +
            "The lethal trifecta (private data + untrusted content + external comms) enables " +
            "complete data exfiltration even when distributed across servers.",
          owasp_category: "MCP04-data-exfiltration",
          mitre_technique: "AML.T0054",
          confidence: pattern.confidence * 0.9, // Slightly lower for cross-server (less certain)
          metadata: {
            analysis_type: "cross_config_graph",
            servers_involved: Array.from(serverContributions.keys()),
            server_contributions: Object.fromEntries(serverContributions),
            total_tools: allTools.length,
          },
        });
      }
    }

    return findings;
  }
}

// ─── Register ──────────────────────────────────────────────────────────────

registerTypedRule(new AnnotationDeceptionRule());
registerTypedRule(new ConsentFatigueRule());
registerTypedRule(new CrossConfigTrifectaRule());
