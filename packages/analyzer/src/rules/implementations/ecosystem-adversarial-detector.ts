/**
 * Ecosystem & Adversarial Remaining — F2-F4, F5, F6, G6, H1, H3
 *
 * F2: High-Risk Capability Profile
 * F3: Data Flow Risk Source→Sink
 * F4: MCP Spec Non-Compliance
 * F5: Official Namespace Squatting (Levenshtein)
 * F6: Circular Data Loop (already partially in f1, this covers YAML fallback)
 * G6: Rug Pull / Tool Behavior Drift (historical diff)
 * H1: MCP OAuth 2.0 Insecure Implementation
 * H3: Multi-Agent Propagation Risk
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { buildCapabilityGraph } from "../analyzers/capability-graph.js";
import { damerauLevenshtein } from "../analyzers/similarity.js";
import { EvidenceChainBuilder } from "../../evidence.js";
import { computeToolSignals, computeCodeSignals } from "../../confidence-signals.js";

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }
function lineNum(s: string, i: number) { return s.substring(0, i).split("\n").length; }

// F2 and F3 are already handled by f1-lethal-trifecta.ts (graph-based implementation)
// F4 migrated to f4-mcp-spec-non-compliance/ in Phase 1 Chunk 1.26.

// ─── F5: Official Namespace Squatting ─────────────────────────────────────

const OFFICIAL_NAMES = [
  "anthropic", "openai", "google", "microsoft", "aws", "github",
  "stripe", "cloudflare", "vercel", "supabase", "firebase", "atlas",
];

registerTypedRule({
  id: "F5", name: "Official Namespace Squatting (Levenshtein)",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    const serverName = (ctx.server.name || "").toLowerCase();

    for (const official of OFFICIAL_NAMES) {
      if (serverName.includes(official)) {
        // Direct match — only flag if it's not actually from the official source
        const githubUrl = ctx.server.github_url || "";
        const isOfficial = githubUrl.includes(`github.com/${official}`);
        if (!isOfficial) {
          const f5DirectChain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `server:${ctx.server.name}`,
              observed: `Server name "${ctx.server.name}" contains "${official}"`,
              rationale: "Server name impersonates an official vendor namespace, misleading AI clients and users",
            })
            .propagation({
              propagation_type: "cross-tool-flow",
              location: `server:${ctx.server.name}:github_url`,
              observed: `GitHub URL "${ctx.server.github_url || "(none)"}" is not under github.com/${official}`,
            })
            .impact({
              impact_type: "cross-agent-propagation",
              scope: "ai-client",
              exploitability: "trivial",
              scenario: `AI trusts server "${ctx.server.name}" as official ${official} product due to namespace match`,
            })
            .factor("namespace_match", 0.20, `Direct substring match: "${official}" in server name`)
            .verification({
              step_type: "inspect-description",
              instruction: `Verify whether "${ctx.server.name}" is an official ${official} server`,
              target: `server:${ctx.server.name}`,
              expected_observation: `Server uses "${official}" namespace but GitHub URL does not match`,
            })
          const f5DirectSignals = computeToolSignals(ctx, "MCP10-supply-chain", ctx.server.name || "");
          for (const sig of f5DirectSignals) {
            f5DirectChain.factor(sig.factor, sig.adjustment, sig.rationale);
          }
          const f5DirectBuilt = f5DirectChain.build();
          findings.push({
            rule_id: "F5", severity: "critical",
            evidence: `Server name "${ctx.server.name}" contains official namespace "${official}" but is not from ${official}'s GitHub.`,
            remediation: "Do not use official vendor names in server names unless you are the vendor.",
            owasp_category: "MCP10-supply-chain", mitre_technique: "AML.T0054",
            confidence: f5DirectBuilt.confidence, metadata: { server_name: ctx.server.name, impersonated: official, evidence_chain: f5DirectBuilt },
          });
        }
      }

      // Levenshtein similarity for typosquats
      const distance = damerauLevenshtein(serverName, official);
      if (distance > 0 && distance <= 2 && !serverName.includes(official)) {
        const f5LevenChain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `server:${ctx.server.name}`,
            observed: `Server name "${ctx.server.name}" is ${distance} edit(s) from "${official}"`,
            rationale: "Server name is suspiciously similar to an official vendor name — typosquatting pattern",
          })
          .propagation({
            propagation_type: "cross-tool-flow",
            location: `server:${ctx.server.name}:name`,
            observed: `Damerau-Levenshtein distance: ${distance} from "${official}"`,
          })
          .impact({
            impact_type: "cross-agent-propagation",
            scope: "ai-client",
            exploitability: distance === 1 ? "trivial" : "moderate",
            scenario: `AI selects typosquat "${ctx.server.name}" instead of official "${official}" server`,
          })
          .factor("levenshtein_similarity", distance === 1 ? 0.22 : 0.10, `Edit distance ${distance} from "${official}"`)
          .verification({
            step_type: "inspect-description",
            instruction: `Compare server name "${ctx.server.name}" against official name "${official}"`,
            target: `server:${ctx.server.name}`,
            expected_observation: `Name is ${distance} edit(s) from "${official}" — likely typosquat`,
          })
        const f5LevenSignals = computeToolSignals(ctx, "MCP10-supply-chain", ctx.server.name || "");
        for (const sig of f5LevenSignals) {
          f5LevenChain.factor(sig.factor, sig.adjustment, sig.rationale);
        }
        const f5LevenBuilt = f5LevenChain.build();
        findings.push({
          rule_id: "F5", severity: "critical",
          evidence: `Server name "${ctx.server.name}" is ${distance} edit(s) from official "${official}" (typosquat risk).`,
          remediation: "Rename server to avoid confusion with official vendor names.",
          owasp_category: "MCP10-supply-chain", mitre_technique: "AML.T0054",
          confidence: f5LevenBuilt.confidence,
          metadata: { server_name: ctx.server.name, target: official, distance, evidence_chain: f5LevenBuilt },
        });
      }
    }
    return findings;
  },
});

// ─── G6: Rug Pull / Tool Behavior Drift ──────────────────────────────────

registerTypedRule({
  id: "G6", name: "Rug Pull / Tool Behavior Drift",
  analyze(ctx) {
    // G6 requires historical data — previous scan results
    // When no history is available, flag based on tool count / capability heuristics
    const findings: TypedFinding[] = [];

    // Check if scan_history is available via context metadata
    const history = (ctx as unknown as Record<string, unknown>).scan_history as
      | Array<{ tool_count: number; tool_names: string[]; scan_date: string }> | undefined;

    if (!history || history.length < 2) return findings;

    const current = history[history.length - 1];
    const previous = history[history.length - 2];

    const toolCountDelta = current.tool_count - previous.tool_count;
    const newTools = current.tool_names.filter(t => !previous.tool_names.includes(t));

    if (toolCountDelta > 5 || newTools.length > 3) {
      // Check if new tools are dangerous
      const dangerousNewTools = newTools.filter(t =>
        /(?:exec|run|shell|command|delete|remove|send|upload|write|admin)/i.test(t)
      );

      if (dangerousNewTools.length > 0) {
        const g6Chain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `server:${ctx.server.name}:tools`,
            observed: `${newTools.length} new tools added: [${newTools.slice(0, 5).join(", ")}${newTools.length > 5 ? "..." : ""}]`,
            rationale: "Sudden tool additions after stable scan history indicate possible rug pull / behavior drift",
          })
          .propagation({
            propagation_type: "cross-tool-flow",
            location: `server:${ctx.server.name}:scan_history`,
            observed: `Tool count: ${previous.tool_count} → ${current.tool_count} (delta: +${toolCountDelta})`,
          })
          .sink({
            sink_type: "command-execution",
            location: `server:${ctx.server.name}:new_tools`,
            observed: `Dangerous new tools: [${dangerousNewTools.join(", ")}]`,
          })
          .factor("temporal_drift", 0.18, `${dangerousNewTools.length} dangerous tools added in single scan window`)
          .verification({
            step_type: "inspect-description",
            instruction: `Compare current tool list against previous scan for server "${ctx.server.name}"`,
            target: `server:${ctx.server.name}`,
            expected_observation: `New dangerous tools [${dangerousNewTools.join(", ")}] appeared since last scan`,
          })
        const g6Signals = computeToolSignals(ctx, "MCP02-tool-poisoning", dangerousNewTools[0] || "");
        for (const sig of g6Signals) {
          g6Chain.factor(sig.factor, sig.adjustment, sig.rationale);
        }
        const g6Built = g6Chain.build();
        findings.push({
          rule_id: "G6", severity: "critical",
          evidence:
            `Tool behavior drift: ${newTools.length} new tools since last scan, including dangerous: [${dangerousNewTools.join(", ")}]. ` +
            `Total tools: ${previous.tool_count} → ${current.tool_count}. Possible rug pull.`,
          remediation: "Investigate sudden tool additions. Review new dangerous tools. Consider reverting to previous version.",
          owasp_category: "MCP02-tool-poisoning", mitre_technique: "AML.T0054",
          confidence: g6Built.confidence, metadata: { new_tools: newTools, dangerous_new: dangerousNewTools, delta: toolCountDelta, evidence_chain: g6Built },
        });
      }
    }

    return findings;
  },
});

// ─── H1: MCP OAuth 2.0 Insecure Implementation ───────────────────────────

registerTypedRule({
  id: "H1", name: "MCP OAuth 2.0 Insecure Implementation",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const src = ctx.source_code;

    const oauthPatterns: Array<{ regex: RegExp; desc: string; confidence: number }> = [
      // redirect_uri from user input
      { regex: /redirect_uri\s*[:=]\s*(?:req\.|request\.|params|body|query)/gi, desc: "redirect_uri from user input → auth code injection", confidence: 0.92 },
      // Implicit flow (banned in OAuth 2.1)
      { regex: /response_type\s*[:=]\s*['"]token['"]/gi, desc: "implicit flow (response_type=token) — banned in OAuth 2.1", confidence: 0.95 },
      // ROPC grant
      { regex: /grant_type\s*[:=]\s*['"]password['"]/gi, desc: "ROPC grant (grant_type=password) — server receives raw credentials", confidence: 0.90 },
      // Token in localStorage
      { regex: /localStorage\.setItem\s*\([^)]*(?:token|access_token|refresh_token)/gi, desc: "token stored in localStorage (XSS-accessible)", confidence: 0.88 },
      // Missing state validation
      { regex: /(?:state|csrf).*(?:skip|ignore|disable|bypass|false)/gi, desc: "OAuth state parameter not validated", confidence: 0.82 },
      // Scope from user input
      { regex: /scope\s*[:=]\s*(?:req\.|request\.|params|body|query)/gi, desc: "OAuth scope from user input → privilege escalation", confidence: 0.90 },
    ];

    for (const { regex, desc, confidence } of oauthPatterns) {
      regex.lastIndex = 0;
      const match = regex.exec(src);
      if (match) {
        const h1Chain = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${lineNum(src, match.index)}`,
            observed: match[0].slice(0, 80),
            rationale: "OAuth implementation pattern detected in source code that violates RFC 9700 / OAuth 2.1",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `line ${lineNum(src, match.index)}`,
            observed: `OAuth vulnerability: ${desc}`,
          })
          .sink({
            sink_type: "credential-exposure",
            location: `line ${lineNum(src, match.index)}`,
            observed: `${desc}: "${match[0].slice(0, 60)}"`,
          })
          .factor("oauth_pattern", confidence - 0.70, `OAuth pattern: ${desc}`)
          .verification({
            step_type: "inspect-description",
            instruction: `Review OAuth implementation at line ${lineNum(src, match.index)} for RFC 9700 compliance`,
            target: `source:line ${lineNum(src, match.index)}`,
            expected_observation: desc,
          });
        const matchLineNum = lineNum(src, match.index);
        const srcLines = src.split("\n");
        const h1CodeSignals = computeCodeSignals({
          matchText: match[0],
          lineText: srcLines[matchLineNum - 1] || match[0],
          matchLine: matchLineNum,
          sourceCode: src,
          context: ctx,
          owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of h1CodeSignals) {
          h1Chain.factor(sig.factor, sig.adjustment, sig.rationale);
        }
        const h1Built = h1Chain.build();
        findings.push({
          rule_id: "H1", severity: "critical",
          evidence: `OAuth vulnerability: ${desc} at line ${matchLineNum}: "${match[0].slice(0, 60)}".`,
          remediation: "Follow RFC 9700. Use authorization code flow with PKCE. Never use implicit flow or ROPC.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0055",
          confidence: h1Built.confidence, metadata: { analysis_type: "structural", vulnerability: desc, evidence_chain: h1Built },
        });
      }
    }
    return findings;
  },
});

// ─── H3: Multi-Agent Propagation Risk ─────────────────────────────────────

registerTypedRule({
  id: "H3", name: "Multi-Agent Propagation Risk",
  analyze(ctx) {
    if (ctx.tools.length === 0) return [];
    const findings: TypedFinding[] = [];

    // Detect tools that accept output from other agents
    for (const tool of ctx.tools) {
      const desc = (tool.description || "").toLowerCase();
      const schema = tool.input_schema as Record<string, unknown> | null;
      const params = Object.keys((schema?.properties || {}) as Record<string, unknown>);

      const acceptsAgentInput = /(?:agent|upstream|previous|chain|pipeline|workflow)\s*(?:output|result|response|input)/i.test(desc) ||
        params.some(p => /(?:agent|upstream|previous)[\s_]?(?:output|result|response)/i.test(p));

      if (acceptsAgentInput) {
        const h3Chain = new EvidenceChainBuilder()
          .source({
            source_type: "agent-output",
            location: `tool:${tool.name}`,
            observed: `Tool accepts agent/upstream/pipeline output via description or parameters`,
            rationale: "Tool ingests output from other agents without declared trust boundaries",
          })
          .propagation({
            propagation_type: "cross-tool-flow",
            location: `tool:${tool.name}:description`,
            observed: `Agent input sink detected in tool "${tool.name}" description or parameters`,
          })
          .impact({
            impact_type: "cross-agent-propagation",
            scope: "other-agents",
            exploitability: "moderate",
            scenario: `Compromised upstream agent injects instructions through tool "${tool.name}" into downstream agents`,
          })
          .factor("agent_input_sink", 0.08, "Tool accepts agent output without trust boundary declaration")
          .verification({
            step_type: "inspect-description",
            instruction: `Check tool "${tool.name}" for inter-agent data flow without sanitization`,
            target: `tool:${tool.name}`,
            expected_observation: "Tool accepts agent output/result/response without trust boundary",
          })
        const h3Signals = computeToolSignals(ctx, "ASI07-insecure-inter-agent-comms", tool.name);
        for (const sig of h3Signals) {
          h3Chain.factor(sig.factor, sig.adjustment, sig.rationale);
        }
        const h3Built = h3Chain.build();
        findings.push({
          rule_id: "H3", severity: "high",
          evidence:
            `Tool "${tool.name}" accepts agent output without trust boundary declaration. ` +
            `Compromised upstream agent can propagate injected instructions downstream.`,
          remediation: "Validate and sanitize all inter-agent data. Declare trust boundaries explicitly.",
          owasp_category: "ASI07-insecure-inter-agent-comms", mitre_technique: "AML.T0059",
          confidence: h3Built.confidence, metadata: { tool_name: tool.name, evidence_chain: h3Built },
        });
      }
    }
    return findings;
  },
});
