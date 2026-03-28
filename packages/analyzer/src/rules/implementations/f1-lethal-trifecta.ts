/**
 * F1 — Lethal Trifecta (Graph-Based Capability Analysis)
 * F7 — Multi-Step Exfiltration Chain (Graph Reachability)
 *
 * REPLACES the YAML composite rules with graph-based analysis.
 *
 * Old behavior: Keyword matching on tool names ("read" → reads-data, "send" → sends-network).
 * New behavior: Multi-signal capability classification using schema + annotations + descriptions,
 * then graph algorithms (cycle detection, reachability, centrality) to find dangerous patterns.
 *
 * Why graph analysis beats keywords:
 * - "get_weather" no longer triggers "reads-private-data" (it reads PUBLIC data)
 * - "query_database" + "send_webhook" only triggers if there's a DATA FLOW path between them
 * - Capability confidence from multiple signals (annotations, parameter types, descriptions)
 *   using noisy-OR probability model instead of boolean keyword match
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import {
  buildCapabilityGraph,
  type CapabilityGraphResult,
  type GraphPattern,
} from "../analyzers/capability-graph.js";
import {
  analyzeToolSet,
  type CrossToolPattern,
} from "../analyzers/schema-inference.js";

// --- F1: Lethal Trifecta ---

class LethalTrifectaRule implements TypedRule {
  readonly id = "F1";
  readonly name = "Lethal Trifecta (Graph-Based)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (context.tools.length === 0) return [];

    const graph = buildCapabilityGraph(context.tools);
    const findings: TypedFinding[] = [];

    // Schema structural inference — analyzes JSON Schema structure
    // (parameter types, constraints, semantic types) instead of description keywords
    const schemaAnalysis = analyzeToolSet(context.tools);

    // Schema-detected lethal trifecta (based on actual parameter types, not description text)
    for (const pattern of schemaAnalysis.cross_tool_patterns) {
      if (pattern.type === "lethal_trifecta") {
        findings.push({
          rule_id: "F1",
          severity: "critical",
          evidence:
            `[Schema structural analysis] ${pattern.evidence} ` +
            `Tool attack surfaces: ${schemaAnalysis.tools
              .map((t) => `${t.tool_name}=${(t.attack_surface_score * 100).toFixed(0)}%`)
              .join(", ")}. ` +
            `Constraint density: ${schemaAnalysis.tools
              .map((t) => `${t.tool_name}=${(t.overall_constraint_density * 100).toFixed(0)}%`)
              .join(", ")}.`,
          remediation:
            "This server combines data access and network capabilities — " +
            "confirmed by analyzing parameter schemas (not just descriptions). " +
            "Separate these capabilities into isolated servers. Score capped at 40.",
          owasp_category: "MCP04-data-exfiltration",
          mitre_technique: "AML.T0054",
          confidence: pattern.confidence,
          metadata: {
            analysis_type: "schema_structural",
            tools_involved: pattern.tools,
            per_tool_analysis: schemaAnalysis.tools.map((t) => ({
              name: t.tool_name,
              attack_surface: t.attack_surface_score,
              constraint_density: t.overall_constraint_density,
              capabilities: t.capabilities.map((c) => ({
                type: c.capability,
                confidence: c.confidence,
                evidence: c.evidence,
              })),
              parameter_profiles: t.parameters.map((p) => p.evidence),
            })),
          },
        });
      }

      if (pattern.type === "credential_exposure") {
        findings.push({
          rule_id: "F3",
          severity: "critical",
          evidence: `[Schema structural analysis] ${pattern.evidence}`,
          remediation:
            "Credential parameters should never coexist with network URL parameters. " +
            "Isolate credential management from network-facing tools.",
          owasp_category: "MCP04-data-exfiltration",
          mitre_technique: "AML.T0057",
          confidence: pattern.confidence,
        });
      }

      if (pattern.type === "unrestricted_access") {
        findings.push({
          rule_id: "F2",
          severity: "critical",
          evidence: `[Schema structural analysis] ${pattern.evidence}`,
          remediation:
            "Add constraints to command/code parameters: enum values, pattern validation, " +
            "maxLength limits. Unconstrained code execution parameters are the highest-risk surface.",
          owasp_category: "MCP03-command-injection",
          mitre_technique: "AML.T0054",
          confidence: pattern.confidence,
        });
      }
    }

    // Graph-based lethal trifecta patterns (description-based — lower confidence)
    const trifectaPatterns = graph.patterns.filter(
      (p) => p.type === "lethal_trifecta"
    );

    for (const pattern of trifectaPatterns) {
      // Skip if schema analysis already found this
      if (findings.some((f) => f.rule_id === "F1")) continue;

      findings.push({
        rule_id: "F1",
        severity: "critical",
        evidence: this.formatTrifectaEvidence(pattern, graph),
        remediation:
          "This server combines private data access, untrusted content ingestion, " +
          "and external communication — the 'lethal trifecta' for data exfiltration. " +
          "Separate these capabilities into isolated servers or add strict data flow controls. " +
          "Score capped at 40 when the lethal trifecta is present.",
        owasp_category: "MCP04-data-exfiltration",
        mitre_technique: "AML.T0054",
        confidence: pattern.confidence,
        metadata: {
          analysis_type: "capability_graph",
          tools_involved: pattern.tools_involved,
          graph_summary: {
            node_count: graph.nodes.length,
            edge_count: graph.edges.length,
            cycle_count: graph.cycles.length,
          },
          capability_details: this.extractCapabilityDetails(graph),
        },
      });
    }

    // Also report circular data loops (F6 upgrade)
    const loopPatterns = graph.patterns.filter(
      (p) => p.type === "circular_data_loop"
    );
    for (const pattern of loopPatterns) {
      findings.push({
        rule_id: "F6",
        severity: "high",
        evidence:
          `${pattern.description} ` +
          `Graph centrality of involved tools: ${pattern.tools_involved
            .map((t) => `${t}=${((graph.centrality.get(t) || 0) * 100).toFixed(0)}%`)
            .join(", ")}.`,
        remediation:
          "Break the circular data loop by making read and write operations " +
          "go through different data stores, or add integrity verification " +
          "on read to detect poisoned data.",
        owasp_category: "MCP01-prompt-injection",
        mitre_technique: "AML.T0054.001",
        confidence: pattern.confidence,
        metadata: {
          analysis_type: "cycle_detection",
          cycle: pattern.tools_involved,
        },
      });
    }

    // Report command injection chains
    const cmdPatterns = graph.patterns.filter(
      (p) => p.type === "command_injection_chain"
    );
    for (const pattern of cmdPatterns) {
      findings.push({
        rule_id: "F2",
        severity: "critical",
        evidence: pattern.description,
        remediation:
          "Untrusted input should never flow to command execution tools " +
          "without validation. Add input validation at the boundary between " +
          "untrusted ingestion and command execution.",
        owasp_category: "MCP03-command-injection",
        mitre_technique: "AML.T0054",
        confidence: pattern.confidence,
      });
    }

    // Report credential exposure paths
    const credPatterns = graph.patterns.filter(
      (p) => p.type === "credential_exposure"
    );
    for (const pattern of credPatterns) {
      findings.push({
        rule_id: "F3",
        severity: "critical",
        evidence: pattern.description,
        remediation:
          "Credentials should never be accessible to tools that can send " +
          "data externally. Isolate credential management from network-facing tools.",
        owasp_category: "MCP04-data-exfiltration",
        mitre_technique: "AML.T0057",
        confidence: pattern.confidence,
      });
    }

    return findings;
  }

  private formatTrifectaEvidence(
    pattern: GraphPattern,
    graph: CapabilityGraphResult
  ): string {
    const capDetails = this.extractCapabilityDetails(graph);
    return (
      `[Graph analysis] ${pattern.description} ` +
      `Capability classification used ${graph.nodes.reduce((sum, n) => sum + n.capabilities.reduce((s, c) => s + c.signals.length, 0), 0)} ` +
      `signals across ${graph.nodes.length} tools. ` +
      `Data flow graph: ${graph.edges.length} edges, ${graph.cycles.length} cycles. ` +
      `Private data tools: ${capDetails.private_readers.join(", ") || "none"}. ` +
      `Untrusted ingestion: ${capDetails.untrusted_ingesters.join(", ") || "none"}. ` +
      `Network senders: ${capDetails.network_senders.join(", ") || "none"}.`
    );
  }

  private extractCapabilityDetails(graph: CapabilityGraphResult) {
    return {
      private_readers: graph.nodes
        .filter((n) =>
          n.capabilities.some(
            (c) => c.capability === "reads-private-data" && c.confidence >= 0.5
          )
        )
        .map((n) => n.name),
      untrusted_ingesters: graph.nodes
        .filter((n) =>
          n.capabilities.some(
            (c) => c.capability === "ingests-untrusted" && c.confidence >= 0.5
          )
        )
        .map((n) => n.name),
      network_senders: graph.nodes
        .filter((n) =>
          n.capabilities.some(
            (c) => c.capability === "sends-network" && c.confidence >= 0.5
          )
        )
        .map((n) => n.name),
    };
  }
}

// --- F7: Multi-Step Exfiltration Chain ---

class ExfiltrationChainRule implements TypedRule {
  readonly id = "F7";
  readonly name = "Multi-Step Exfiltration Chain (Graph Reachability)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (context.tools.length < 2) return [];

    const graph = buildCapabilityGraph(context.tools);
    const findings: TypedFinding[] = [];

    const exfilPatterns = graph.patterns.filter(
      (p) => p.type === "exfiltration_chain"
    );

    for (const pattern of exfilPatterns) {
      // Compute centrality info for tools in the chain
      const centralityInfo = pattern.tools_involved.map((t) => ({
        tool: t,
        centrality: graph.centrality.get(t) || 0,
      }));

      findings.push({
        rule_id: "F7",
        severity: "critical",
        evidence:
          `[Graph reachability] ${pattern.description} ` +
          `No individual tool in the chain is dangerous; the combination enables exfiltration. ` +
          `Tool centrality scores: ${centralityInfo
            .map((c) => `${c.tool}=${(c.centrality * 100).toFixed(0)}%`)
            .join(", ")}. ` +
          `High centrality tools are critical data flow bottlenecks — ` +
          `securing them blocks the exfiltration path.`,
        remediation:
          "Break the exfiltration chain by: " +
          "(1) removing the network-sending capability from this server, " +
          "(2) adding data classification labels that prevent sensitive data from reaching network tools, " +
          "(3) requiring user confirmation before any read→send sequence.",
        owasp_category: "MCP04-data-exfiltration",
        mitre_technique: "AML.T0057",
        confidence: pattern.confidence,
        metadata: {
          analysis_type: "graph_reachability",
          chain: pattern.tools_involved,
          centrality: Object.fromEntries(
            centralityInfo.map((c) => [c.tool, c.centrality])
          ),
          graph_summary: {
            total_nodes: graph.nodes.length,
            total_edges: graph.edges.length,
            total_patterns: graph.patterns.length,
          },
        },
      });
    }

    return findings;
  }
}

// F2, F3, F6 findings are emitted by F1's analyze() as companion detections
// from the same capability graph analysis. Register stubs so the engine
// doesn't warn about missing TypedRule implementations.
class F2Stub implements TypedRule {
  readonly id = "F2";
  readonly name = "High-Risk Capability Profile (via F1)";
  analyze(): TypedFinding[] { return []; } // F1 emits F2 findings
}
class F3Stub implements TypedRule {
  readonly id = "F3";
  readonly name = "Data Flow Risk Source→Sink (via F1)";
  analyze(): TypedFinding[] { return []; } // F1 emits F3 findings
}
class F6Stub implements TypedRule {
  readonly id = "F6";
  readonly name = "Circular Data Loop (via F1)";
  analyze(): TypedFinding[] { return []; } // F1 emits F6 findings
}

registerTypedRule(new LethalTrifectaRule());
registerTypedRule(new ExfiltrationChainRule());
registerTypedRule(new F2Stub());
registerTypedRule(new F3Stub());
registerTypedRule(new F6Stub());
