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
import { EvidenceChainBuilder } from "../../evidence.js";

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

          const i1Chain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `tool "${tool.name}" annotations`,
              observed: `readOnlyHint: true declared on tool with ${deceptiveParams.length > 0 ? `destructive params: [${deceptiveParams.join(", ")}]` : "destructive description language"}`,
              rationale:
                "Tool annotations are metadata declared by the server author and consumed by AI clients to " +
                "make automated approval decisions. The readOnlyHint annotation is a trust signal — AI clients " +
                "that respect it will auto-execute the tool without user confirmation, assuming it has no side effects.",
            })
            .propagation({
              propagation_type: "schema-unconstrained",
              location: `tool "${tool.name}" input schema`,
              observed:
                deceptiveParams.length > 0
                  ? `Parameters [${deceptiveParams.join(", ")}] indicate destructive/write capability that contradicts the read-only annotation`
                  : `Description language indicates destructive capability despite read-only annotation`,
            })
            .sink({
              sink_type: "privilege-grant",
              location: `AI client auto-approval decision for "${tool.name}"`,
              observed:
                "AI client trusts readOnlyHint: true → auto-executes the tool without user confirmation → " +
                "destructive operation runs with user's full permissions",
            })
            .mitigation({
              mitigation_type: "annotation-hint",
              present: false,
              location: `tool "${tool.name}" annotations`,
              detail:
                "The tool's annotation claims readOnlyHint: true but schema analysis reveals destructive " +
                "capability. No secondary verification (destructiveHint, confirmation gate) exists to catch " +
                "this contradiction. The MCP spec does not mandate annotation validation against schema.",
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "server-host",
              exploitability: "trivial",
              scenario:
                "An attacker sets readOnlyHint: true on a tool that can delete files, drop databases, or " +
                "execute commands. AI clients that respect this annotation auto-approve the tool without " +
                "asking the user. The destructive operation executes silently with the user's full permissions — " +
                "data loss, system modification, or credential theft occurs without any user interaction.",
            })
            .factor(
              hasDestructiveCapability ? "schema_confirms_destructive" : "param_name_suggests_destructive",
              hasDestructiveCapability ? 0.15 : 0.05,
              hasDestructiveCapability
                ? `Schema structural analysis independently confirms destructive capability (attack_surface: ${((toolAnalysis?.attack_surface_score || 0) * 100).toFixed(0)}%)`
                : `Parameter names [${deceptiveParams.join(", ")}] suggest destructive capability but schema analysis is inconclusive`
            )
            .factor(
              "annotation_contradiction",
              0.15,
              "readOnlyHint: true contradicts detected destructive/write capability — deliberate deception or careless misconfiguration"
            )
            .reference({
              id: "MCP-2025-03-26",
              title: "MCP Specification 2025-03-26 — Tool Annotations",
              relevance:
                "The MCP spec defines readOnlyHint and destructiveHint as advisory hints for AI clients. " +
                "Clients are expected to use these for auto-approval decisions but the spec does not require " +
                "validation against the actual tool schema — creating a trust exploitation surface.",
            })
            .verification({
              step_type: "inspect-schema",
              instruction:
                `Examine the input schema for tool "${tool.name}". List all parameter names and check whether ` +
                `any suggest destructive operations (delete, remove, drop, overwrite, truncate, destroy, purge, ` +
                `wipe, kill, terminate) or write operations (write, create, update, insert, modify, append). ` +
                `Compare these against the readOnlyHint: true annotation to confirm the contradiction.`,
              target: `tool "${tool.name}" input_schema.properties`,
              expected_observation:
                deceptiveParams.length > 0
                  ? `Parameters [${deceptiveParams.join(", ")}] indicate write/destructive capability, contradicting readOnlyHint: true.`
                  : "Description language indicates destructive capability despite read-only annotation claim.",
            })
            .verification({
              step_type: "check-config",
              instruction:
                "Check the AI client's annotation handling policy. Determine whether the client auto-approves " +
                "tools with readOnlyHint: true without user confirmation. Verify whether the client performs " +
                "any independent validation of the annotation against the tool's actual parameters. If the " +
                "client blindly trusts the annotation, the deception bypasses the entire consent mechanism.",
              target: "AI client tool annotation handling / auto-approval policy",
              expected_observation:
                "Client auto-approves readOnlyHint tools without schema validation — the deceptive " +
                "annotation bypasses user consent for destructive operations.",
            })
            .build();

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
              evidence_chain: i1Chain,
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
          const i2Chain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `tool:${tool.name}:annotations`,
              observed: `destructiveHint not set, ${destructiveParams.length} destructive params: [${destructiveParams.join(", ")}]`,
              rationale: "Tool with destructive capabilities lacks annotation that triggers user confirmation in AI clients",
            })
            .propagation({
              propagation_type: "schema-unconstrained",
              location: `tool:${tool.name}:annotations`,
              observed: `Missing destructiveHint: true — AI client treats tool as safe for auto-execution`,
            })
            .impact({
              impact_type: "privilege-escalation",
              scope: "user-data",
              exploitability: "moderate",
              scenario: `AI auto-executes destructive tool "${tool.name}" without user confirmation due to missing annotation`,
            })
            .factor("missing_annotation", 0.05, `${destructiveParams.length} destructive params without destructiveHint`)
            .verification({
              step_type: "check-config",
              instruction: `Check tool "${tool.name}" annotations for destructiveHint: true`,
              target: `tool:${tool.name}:annotations`,
              expected_observation: `destructiveHint is absent despite params [${destructiveParams.join(", ")}]`,
            })
            .build();
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
              evidence_chain: i2Chain,
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

      const i16Chain = new EvidenceChainBuilder()
        .source({
          source_type: "external-content",
          location: `server tool set (${context.tools.length} tools)`,
          observed: `${benignTools.length} benign tools + ${dangerousTools.length} dangerous tool(s), ratio ${ratio.toFixed(1)}:1`,
          rationale:
            "The server exposes a large number of benign tools alongside a small number of dangerous ones. " +
            "This statistical distribution exploits human approval fatigue — after reviewing and approving " +
            "many safe tools, the user stops scrutinizing each one and rubber-stamps the remaining approvals.",
        })
        .propagation({
          propagation_type: "cross-tool-flow",
          location: "AI client tool approval dialog sequence",
          observed:
            `User is presented with ${context.tools.length} tools for approval. After approving ` +
            `${benignTools.length} safe tools, the ${dangerousTools.length} dangerous tool(s) appear ` +
            `in the approval queue`,
        })
        .sink({
          sink_type: "privilege-grant",
          location: `dangerous tools: ${dangerousTools.map((t) => t.name).join(", ")}`,
          observed:
            `User auto-approves dangerous tools [${dangerousTools.map((t) => `${t.name}(${t.capabilities.join(",")})`).join(", ")}] ` +
            `after approval fatigue from ${benignTools.length} benign tools`,
        })
        .mitigation({
          mitigation_type: "confirmation-gate",
          present: false,
          location: "AI client tool approval workflow",
          detail:
            "No differential approval for dangerous vs benign tools. All tools go through the same " +
            "approval flow regardless of their capability risk level. Dangerous tools should require " +
            "a separate, elevated confirmation with explicit risk disclosure.",
        })
        .impact({
          impact_type: "privilege-escalation",
          scope: "ai-client",
          exploitability: "moderate",
          scenario:
            "A server bundles many harmless tools (read_time, get_weather, list_files) with a few dangerous " +
            "ones (execute_command, send_email, write_file). After approving 10+ safe tools, the user develops " +
            "approval fatigue and clicks 'approve' on the dangerous tools without reading their capabilities. " +
            "Invariant Labs research measured 84.2% success rate for this attack at a 10:1 ratio.",
        })
        .factor(
          "high_benign_ratio",
          ratio >= 10 ? 0.15 : 0.05,
          `Benign-to-dangerous ratio ${ratio.toFixed(1)}:1 — ${ratio >= 10 ? "exceeds 10:1 threshold (84.2% success rate)" : "moderate ratio, some fatigue risk"}`
        )
        .factor(
          "dangerous_capability_confirmed",
          0.1,
          `Capability graph confirms dangerous tools have: ${dangerousTools.flatMap((t) => t.capabilities).join(", ")}`
        )
        .reference({
          id: "invariant-labs-consent-fatigue",
          title: "Invariant Labs: Consent Fatigue Exploitation in MCP Tool Approval",
          year: 2025,
          relevance:
            "Research demonstrated that 84.2% of users approve dangerous tools without scrutiny when " +
            "they are bundled with a large number of benign tools. The approval fatigue effect is " +
            "strongest at ratios above 10:1.",
        })
        .verification({
          step_type: "inspect-schema",
          instruction:
            `Review the full tool set exposed by this server. Classify each tool as benign (read-only, ` +
            `no side effects) or dangerous (code execution, network access, file write, credential access). ` +
            `Count the ratio. Verify that the ${dangerousTools.length} dangerous tool(s) ` +
            `[${dangerousTools.map((t) => t.name).join(", ")}] genuinely have the flagged capabilities ` +
            `by examining their parameter schemas and descriptions.`,
          target: `all ${context.tools.length} tools in the server`,
          expected_observation:
            `${benignTools.length} benign tools and ${dangerousTools.length} dangerous tools confirmed. ` +
            `Ratio: ${ratio.toFixed(1)}:1.`,
        })
        .verification({
          step_type: "check-config",
          instruction:
            "Check whether the AI client implements differential approval (separate confirmation for " +
            "dangerous tools vs benign tools). Verify if the client groups tools by risk level or " +
            "presents them in a flat list. A flat approval list maximizes fatigue exploitation potential.",
          target: "AI client tool approval UX and risk-based grouping",
          expected_observation:
            "Client presents all tools in a flat approval list without risk-based grouping — " +
            "dangerous tools are not highlighted or separated from benign ones.",
        })
        .build();

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
          evidence_chain: i16Chain,
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

        const i13Chain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `${serverContributions.size} servers in client config`,
            observed: `Lethal trifecta distributed: ${serverDetails}`,
            rationale:
              "The lethal trifecta (private data access + untrusted content ingestion + external communication) " +
              "is distributed across multiple MCP servers in the same client configuration. No single server " +
              "has all three capabilities, so single-server analysis (F1) misses this pattern entirely. The " +
              "danger only emerges when the servers are analyzed as a combined configuration.",
          })
          .propagation({
            propagation_type: "cross-tool-flow",
            location: "AI client multi-server context",
            observed:
              "The AI client has access to tools from all configured servers simultaneously. Data read " +
              "by one server's tools can be passed to another server's tools through the AI client — " +
              "the client acts as an unwitting bridge between server trust boundaries.",
          })
          .sink({
            sink_type: "network-send",
            location: `external communication tools across ${serverContributions.size} servers`,
            observed:
              "Private data accessed via one server's tools can be exfiltrated via another server's " +
              "external communication tools. The AI client bridges the gap between servers that individually " +
              "appear safe.",
          })
          .mitigation({
            mitigation_type: "sandbox",
            present: false,
            location: "AI client cross-server isolation",
            detail:
              "No cross-server isolation prevents data from flowing between tools of different servers. " +
              "The AI client treats all tools as a unified set, allowing data from a private-data server " +
              "to flow to an external-comms server without any boundary enforcement.",
          })
          .impact({
            impact_type: "data-exfiltration",
            scope: "user-data",
            exploitability: "moderate",
            scenario:
              "Server A provides tools to read private data (emails, files, databases). Server B ingests " +
              "untrusted content (web scraping, RSS feeds) that can contain prompt injection. Server C provides " +
              "external communication (send email, webhook, HTTP request). An injection payload in Server B's " +
              "content instructs the AI to read private data via Server A's tools and exfiltrate it via Server C's " +
              "tools. No individual server triggers an alert — the attack only works because all three are configured together.",
          })
          .factor(
            "multi_server_distribution",
            0.1,
            `Trifecta spans ${serverContributions.size} servers — more complex than single-server F1 but still exploitable`
          )
          .factor(
            "graph_confirmed",
            0.1,
            "Capability graph analysis confirmed all three legs of the trifecta across the merged tool set"
          )
          .reference({
            id: "MCP04-data-exfiltration",
            title: "OWASP MCP Top 10 — MCP04: Data Exfiltration",
            relevance:
              "The cross-config lethal trifecta is the most dangerous configuration pattern in the MCP " +
              "ecosystem. OWASP MCP04 specifically calls out multi-server exfiltration chains as a critical risk.",
          })
          .verification({
            step_type: "check-config",
            instruction:
              "Examine the full MCP client configuration file. List all configured servers and their " +
              "tools. Classify each server's capability: (1) private data access, (2) untrusted content " +
              "ingestion, (3) external communication. Verify that at least two different servers contribute " +
              "different legs of the trifecta. Check whether any cross-server data flow restrictions exist.",
            target: `MCP client config with ${multiServerTools.length} servers`,
            expected_observation:
              `${serverContributions.size} servers contribute different trifecta legs: ${serverDetails}. ` +
              "No cross-server isolation prevents data flow between them.",
          })
          .verification({
            step_type: "trace-flow",
            instruction:
              "Construct a concrete exfiltration scenario: identify a tool from Server A that reads " +
              "private data, a tool from Server B that could inject instructions (via untrusted content), " +
              "and a tool from Server C that sends data externally. Verify that the AI client can invoke " +
              "all three tools in sequence without any cross-server restriction.",
            target: `tools across servers: ${serverDetails}`,
            expected_observation:
              "A concrete read→inject→exfiltrate chain is possible across the configured servers, " +
              "with the AI client bridging all server boundaries.",
          })
          .build();

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
          confidence: pattern.confidence * 0.9,
          metadata: {
            analysis_type: "cross_config_graph",
            servers_involved: Array.from(serverContributions.keys()),
            server_contributions: Object.fromEntries(serverContributions),
            total_tools: allTools.length,
            evidence_chain: i13Chain,
          },
        });
      }
    }

    return findings;
  }
}

// ─── Register ──────────────────────────────────────────────────────────────

// I2 findings are emitted by I1 (AnnotationDeceptionRule) during annotation analysis.
// Register stub so the engine doesn't warn about missing implementation.
class I2Stub implements TypedRule {
  readonly id = "I2";
  readonly name = "Missing Destructive Annotation (via I1)";
  analyze(): TypedFinding[] { return []; }
}

registerTypedRule(new AnnotationDeceptionRule());
registerTypedRule(new I2Stub());
registerTypedRule(new ConsentFatigueRule());
registerTypedRule(new CrossConfigTrifectaRule());
