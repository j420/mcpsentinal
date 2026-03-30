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
import { EvidenceChainBuilder } from "../../evidence.js";

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
        const schemaChain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `tools: ${pattern.tools.join(", ")}`,
            observed: `Schema structural analysis identified lethal trifecta across ${pattern.tools.length} tools`,
            rationale: "Parameter schemas confirm data-access + network-send capabilities coexist in same server",
          })
          .propagation({
            propagation_type: "cross-tool-flow",
            location: "server execution context",
            observed: "Cross-tool data flow via shared server context — no isolation boundary",
          })
          .sink({
            sink_type: "network-send",
            location: "external network endpoint",
            observed: "Private data readable by one tool can be exfiltrated via another tool's network capability",
          })
          .factor(
            "schema-structural",
            pattern.confidence - 0.30,
            `Schema analysis confirmed: ${pattern.evidence}`,
          )
          .factor(
            "attack-surface-score",
            Math.max(...schemaAnalysis.tools.map((t) => t.attack_surface_score)) - 0.30,
            `Highest tool attack surface: ${Math.max(...schemaAnalysis.tools.map((t) => t.attack_surface_score * 100)).toFixed(0)}%`,
          )
          .reference({
            id: "OWASP-MCP04",
            title: "OWASP MCP Top 10 — MCP04 Data Exfiltration",
            relevance: "Private data + untrusted content + external comms = lethal trifecta for exfiltration",
          })
          .verification({
            step_type: "inspect-schema",
            instruction: "Examine tool parameter schemas to confirm data-access and network-send capabilities coexist",
            target: pattern.tools.join(", "),
            expected_observation: "At least one tool reads private data AND at least one tool can send data externally",
          })
          .verification({
            step_type: "trace-flow",
            instruction: "Verify that data can flow from the private-data-reading tool to the network-sending tool within the same server session",
            target: "server tool execution context",
            expected_observation: "No isolation boundary prevents data flow between these tools",
          })
          .build();

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
            evidence_chain: schemaChain,
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
        const f3SchemaChain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `tools: ${pattern.tools.join(", ")}`,
            observed: `Schema analysis detected credential parameters coexisting with network URL parameters`,
            rationale: "Credential parameters (API keys, tokens, passwords) in the same server as network-send parameters create a direct exfiltration path",
          })
          .propagation({
            propagation_type: "cross-tool-flow",
            location: "server execution context",
            observed: "Credential values accessible in shared server memory can flow to network-sending tools",
          })
          .impact({
            impact_type: "credential-theft",
            scope: "connected-services",
            exploitability: "moderate",
            scenario: "Attacker instructs AI to read credentials via one tool and exfiltrate them via a network-capable tool in the same server",
          })
          .verification({
            step_type: "inspect-description",
            instruction: "Verify that credential-handling and network-sending tools coexist in this server",
            target: pattern.tools.join(", "),
            expected_observation: "At least one tool handles credentials AND at least one tool can send data to external endpoints",
          })
          .build();

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
          metadata: {
            analysis_type: "schema_structural",
            tools_involved: pattern.tools,
            evidence_chain: f3SchemaChain,
          },
        });
      }

      if (pattern.type === "unrestricted_access") {
        const f2SchemaChain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `tools: ${pattern.tools.join(", ")}`,
            observed: `Schema analysis detected unconstrained command/code execution parameters`,
            rationale: "Parameters that accept arbitrary commands or code without enum, pattern, or maxLength constraints enable unrestricted execution",
          })
          .propagation({
            propagation_type: "schema-unconstrained",
            location: "tool input schema",
            observed: "No schema constraints (enum, pattern, maxLength) limit the parameter value space",
          })
          .sink({
            sink_type: "command-execution",
            location: "server-side execution environment",
            observed: "Unconstrained parameters flow directly to command or code execution handlers",
          })
          .verification({
            step_type: "inspect-description",
            instruction: "Examine tool parameter schemas for missing constraints on command/code parameters",
            target: pattern.tools.join(", "),
            expected_observation: "Parameters accepting commands or code lack enum, pattern, or maxLength validation",
          })
          .build();

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
          metadata: {
            analysis_type: "schema_structural",
            tools_involved: pattern.tools,
            evidence_chain: f2SchemaChain,
          },
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

      const capDetails = this.extractCapabilityDetails(graph);
      const graphChain = new EvidenceChainBuilder()
        .source({
          source_type: "user-parameter",
          location: `tools: ${pattern.tools_involved.join(", ")}`,
          observed: `Graph analysis: ${graph.nodes.length} tools, ${graph.edges.length} edges, ${graph.cycles.length} cycles`,
          rationale: "Capability graph identifies coexistence of private-data, untrusted-content, and network-send capabilities",
        })
        .propagation({
          propagation_type: "cross-tool-flow",
          location: `${capDetails.private_readers.join(", ") || "private-data-reader"} → ${capDetails.network_senders.join(", ") || "network-sender"}`,
          observed: `Data flow graph with ${graph.edges.length} edges enables cross-tool data movement`,
        })
        .sink({
          sink_type: "network-send",
          location: "external network endpoint",
          observed:
            "Lethal trifecta: private data + untrusted content + external comms = " +
            "attacker-controlled content can exfiltrate private data via network tools",
        })
        .factor(
          "capability-graph",
          pattern.confidence - 0.30,
          `${graph.nodes.reduce((sum, n) => sum + n.capabilities.reduce((s, c) => s + c.signals.length, 0), 0)} signals across ${graph.nodes.length} tools`,
        )
        .reference({
          id: "OWASP-MCP04",
          title: "OWASP MCP Top 10 — MCP04 Data Exfiltration",
          relevance: "Lethal trifecta is the #1 structural risk pattern in the OWASP MCP Top 10",
        })
        .verification({
          step_type: "inspect-schema",
          instruction: "Verify tool descriptions and schemas confirm three capability categories: reads-private-data, ingests-untrusted, sends-network",
          target: pattern.tools_involved.join(", "),
          expected_observation:
            `Private data: [${capDetails.private_readers.join(", ")}], ` +
            `Untrusted: [${capDetails.untrusted_ingesters.join(", ")}], ` +
            `Network: [${capDetails.network_senders.join(", ")}]`,
        })
        .build();

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
          evidence_chain: graphChain,
          graph_summary: {
            node_count: graph.nodes.length,
            edge_count: graph.edges.length,
            cycle_count: graph.cycles.length,
          },
          capability_details: capDetails,
        },
      });
    }

    // Also report circular data loops (F6 upgrade)
    const loopPatterns = graph.patterns.filter(
      (p) => p.type === "circular_data_loop"
    );
    for (const pattern of loopPatterns) {
      const f6Chain = new EvidenceChainBuilder()
        .source({
          source_type: "external-content",
          location: `tools: ${pattern.tools_involved.join(", ")}`,
          observed: `Cycle detection found circular data loop: ${pattern.tools_involved.join(" → ")} → ${pattern.tools_involved[0]}`,
          rationale: "Write+read on the same data store enables persistent prompt injection — attacker poisons stored content once, AI executes it on every subsequent read",
        })
        .propagation({
          propagation_type: "cross-tool-flow",
          location: `cycle: ${pattern.tools_involved.join(" → ")}`,
          observed: `Graph centrality: ${pattern.tools_involved.map((t) => `${t}=${((graph.centrality.get(t) || 0) * 100).toFixed(0)}%`).join(", ")}`,
        })
        .impact({
          impact_type: "config-poisoning",
          scope: "ai-client",
          exploitability: "moderate",
          scenario: "Attacker writes poisoned content to a data store via one tool; AI reads it back via another tool in the same cycle, executing the injected instructions persistently across sessions",
        })
        .verification({
          step_type: "inspect-description",
          instruction: "Verify that tools in the cycle can both write to and read from the same data store",
          target: pattern.tools_involved.join(", "),
          expected_observation: "At least one tool writes data that another tool in the cycle reads back, forming a persistent injection loop",
        })
        .build();

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
          evidence_chain: f6Chain,
        },
      });
    }

    // Report command injection chains
    const cmdPatterns = graph.patterns.filter(
      (p) => p.type === "command_injection_chain"
    );
    for (const pattern of cmdPatterns) {
      const f2GraphChain = new EvidenceChainBuilder()
        .source({
          source_type: "external-content",
          location: `tools: ${pattern.tools_involved.join(", ")}`,
          observed: `Graph analysis detected command injection chain: ${pattern.description}`,
          rationale: "Untrusted content ingestion tools feed data to command execution tools without validation boundary",
        })
        .propagation({
          propagation_type: "cross-tool-flow",
          location: `data flow: ${pattern.tools_involved.join(" → ")}`,
          observed: "Capability graph edge connects untrusted-content-ingestion to command-execution without sanitization",
        })
        .sink({
          sink_type: "command-execution",
          location: "server-side execution environment",
          observed: "Untrusted input reaches command execution tool via cross-tool data flow",
        })
        .verification({
          step_type: "inspect-description",
          instruction: "Verify that untrusted content can flow from ingestion tools to command execution tools",
          target: pattern.tools_involved.join(", "),
          expected_observation: "Data path exists from content ingestion to command execution without input validation",
        })
        .build();

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
        metadata: {
          analysis_type: "capability_graph",
          tools_involved: pattern.tools_involved,
          evidence_chain: f2GraphChain,
        },
      });
    }

    // Report credential exposure paths
    const credPatterns = graph.patterns.filter(
      (p) => p.type === "credential_exposure"
    );
    for (const pattern of credPatterns) {
      const f3GraphChain = new EvidenceChainBuilder()
        .source({
          source_type: "user-parameter",
          location: `tools: ${pattern.tools_involved.join(", ")}`,
          observed: `Graph analysis detected credential exposure path: ${pattern.description}`,
          rationale: "Credential-handling tools coexist with network-sending tools, enabling credential exfiltration via cross-tool data flow",
        })
        .propagation({
          propagation_type: "cross-tool-flow",
          location: `data flow: ${pattern.tools_involved.join(" → ")}`,
          observed: "Capability graph connects credential-access nodes to network-send nodes",
        })
        .impact({
          impact_type: "credential-theft",
          scope: "connected-services",
          exploitability: "moderate",
          scenario: "Attacker instructs AI to access credentials via one tool and send them to an external endpoint via a network-capable tool in the same server",
        })
        .verification({
          step_type: "inspect-description",
          instruction: "Verify that credential-handling and network-sending capabilities coexist with a data flow path between them",
          target: pattern.tools_involved.join(", "),
          expected_observation: "Graph edge connects a credential-access tool to a network-send tool",
        })
        .build();

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
        metadata: {
          analysis_type: "capability_graph",
          tools_involved: pattern.tools_involved,
          evidence_chain: f3GraphChain,
        },
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

      const f7Chain = new EvidenceChainBuilder()
        .source({
          source_type: "user-parameter",
          location: `tools: ${pattern.tools_involved.join(", ")}`,
          observed: `Graph reachability analysis found ${pattern.tools_involved.length}-step exfiltration chain`,
          rationale: "No individual tool in the chain is dangerous; the combination of read → transform → send enables multi-step data exfiltration",
        })
        .propagation({
          propagation_type: "cross-tool-flow",
          location: `chain: ${pattern.tools_involved.join(" → ")}`,
          observed: `Tool centrality: ${centralityInfo.map((c) => `${c.tool}=${(c.centrality * 100).toFixed(0)}%`).join(", ")} — high centrality tools are data flow bottlenecks`,
        })
        .sink({
          sink_type: "network-send",
          location: "external network endpoint",
          observed: "Final tool in the chain sends data to an external endpoint, completing the exfiltration path",
        })
        .factor(
          "chain-length",
          (pattern.tools_involved.length - 2) * 0.1,
          `${pattern.tools_involved.length}-step chain: longer chains are harder to detect but still exploitable`,
        )
        .verification({
          step_type: "inspect-description",
          instruction: "Trace the data flow through each tool in the chain to confirm read → transform → send sequence",
          target: pattern.tools_involved.join(", "),
          expected_observation: "First tool reads sensitive data, intermediate tools transform/encode it, last tool sends it externally",
        })
        .build();

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
          evidence_chain: f7Chain,
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
