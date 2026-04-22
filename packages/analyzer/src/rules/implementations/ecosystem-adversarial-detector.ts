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

// F5 migrated to f5-official-namespace-squatting/ in Phase 1 Chunk 1.26.

// G6 migrated to g6-rug-pull-tool-drift/ in Phase 1 Chunk 1.26.

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
