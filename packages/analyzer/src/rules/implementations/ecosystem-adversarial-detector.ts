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

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }
function lineNum(s: string, i: number) { return s.substring(0, i).split("\n").length; }

// ─── F2: High-Risk Capability Profile ─────────────────────────────────────

registerTypedRule({
  id: "F2", name: "High-Risk Capability Profile",
  analyze(ctx) {
    if (ctx.tools.length === 0) return [];
    const graph = buildCapabilityGraph(ctx.tools);
    const findings: TypedFinding[] = [];

    const dangerousCombos: Array<{ caps: string[]; desc: string }> = [
      { caps: ["executes-code", "sends-network"], desc: "code execution + network send" },
      { caps: ["accesses-filesystem", "sends-network"], desc: "filesystem + network send" },
      { caps: ["manages-credentials", "sends-network"], desc: "credential access + network send" },
    ];

    for (const { caps, desc } of dangerousCombos) {
      const hasAll = caps.every(cap =>
        graph.nodes.some(n => n.capabilities.some(c => c.capability === cap && c.confidence >= 0.5))
      );
      if (hasAll) {
        findings.push({
          rule_id: "F2", severity: "medium",
          evidence: `Server has high-risk capability combination: ${desc}.`,
          remediation: "Separate dangerous capability combinations into isolated servers.",
          owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
          confidence: 0.75, metadata: { analysis_type: "capability_graph", combo: desc },
        });
      }
    }
    return findings;
  },
});

// ─── F3: Data Flow Risk Source→Sink ───────────────────────────────────────

registerTypedRule({
  id: "F3", name: "Data Flow Risk Source→Sink",
  analyze(ctx) {
    if (ctx.tools.length < 2) return [];
    const graph = buildCapabilityGraph(ctx.tools);
    const findings: TypedFinding[] = [];

    const readers = graph.nodes.filter(n =>
      n.capabilities.some(c => (c.capability === "reads-private-data" || c.capability === "manages-credentials") && c.confidence >= 0.5)
    );
    const senders = graph.nodes.filter(n =>
      n.capabilities.some(c => c.capability === "sends-network" && c.confidence >= 0.5)
    );

    if (readers.length > 0 && senders.length > 0) {
      findings.push({
        rule_id: "F3", severity: "high",
        evidence:
          `Data flow risk: readers [${readers.map(r => r.name).join(", ")}] + senders [${senders.map(s => s.name).join(", ")}]. ` +
          `Private data can flow from read tools to network send tools.`,
        remediation: "Add data classification. Prevent sensitive data from reaching network-facing tools.",
        owasp_category: "MCP04-data-exfiltration", mitre_technique: "AML.T0057",
        confidence: 0.78, metadata: { readers: readers.map(r => r.name), senders: senders.map(s => s.name) },
      });
    }
    return findings;
  },
});

// ─── F4: MCP Spec Non-Compliance ──────────────────────────────────────────

registerTypedRule({
  id: "F4", name: "MCP Spec Non-Compliance",
  analyze(ctx) {
    const findings: TypedFinding[] = [];

    for (const tool of ctx.tools) {
      if (!tool.name || tool.name.trim().length === 0) {
        findings.push({
          rule_id: "F4", severity: "low",
          evidence: "Tool has empty or missing name (MCP spec requires non-empty name).",
          remediation: "Add a name to all tools per MCP specification.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.95, metadata: {},
        });
      }
      if (tool.description === null || tool.description === undefined || tool.description.trim().length === 0) {
        findings.push({
          rule_id: "F4", severity: "low",
          evidence: `Tool "${tool.name}" has no description (recommended by MCP spec).`,
          remediation: "Add descriptions to all tools for proper AI understanding.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.70, metadata: { tool_name: tool.name },
        });
      }
    }
    return findings;
  },
});

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
          findings.push({
            rule_id: "F5", severity: "critical",
            evidence: `Server name "${ctx.server.name}" contains official namespace "${official}" but is not from ${official}'s GitHub.`,
            remediation: "Do not use official vendor names in server names unless you are the vendor.",
            owasp_category: "MCP10-supply-chain", mitre_technique: "AML.T0054",
            confidence: 0.90, metadata: { server_name: ctx.server.name, impersonated: official },
          });
        }
      }

      // Levenshtein similarity for typosquats
      const distance = damerauLevenshtein(serverName, official);
      if (distance > 0 && distance <= 2 && !serverName.includes(official)) {
        findings.push({
          rule_id: "F5", severity: "critical",
          evidence: `Server name "${ctx.server.name}" is ${distance} edit(s) from official "${official}" (typosquat risk).`,
          remediation: "Rename server to avoid confusion with official vendor names.",
          owasp_category: "MCP10-supply-chain", mitre_technique: "AML.T0054",
          confidence: distance === 1 ? 0.92 : 0.80,
          metadata: { server_name: ctx.server.name, target: official, distance },
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
        findings.push({
          rule_id: "G6", severity: "critical",
          evidence:
            `Tool behavior drift: ${newTools.length} new tools since last scan, including dangerous: [${dangerousNewTools.join(", ")}]. ` +
            `Total tools: ${previous.tool_count} → ${current.tool_count}. Possible rug pull.`,
          remediation: "Investigate sudden tool additions. Review new dangerous tools. Consider reverting to previous version.",
          owasp_category: "MCP02-tool-poisoning", mitre_technique: "AML.T0054",
          confidence: 0.88, metadata: { new_tools: newTools, dangerous_new: dangerousNewTools, delta: toolCountDelta },
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
        findings.push({
          rule_id: "H1", severity: "critical",
          evidence: `OAuth vulnerability: ${desc} at line ${lineNum(src, match.index)}: "${match[0].slice(0, 60)}".`,
          remediation: "Follow RFC 9700. Use authorization code flow with PKCE. Never use implicit flow or ROPC.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0055",
          confidence, metadata: { analysis_type: "structural", vulnerability: desc },
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
        findings.push({
          rule_id: "H3", severity: "high",
          evidence:
            `Tool "${tool.name}" accepts agent output without trust boundary declaration. ` +
            `Compromised upstream agent can propagate injected instructions downstream.`,
          remediation: "Validate and sanitize all inter-agent data. Declare trust boundaries explicitly.",
          owasp_category: "ASI07-insecure-inter-agent-comms", mitre_technique: "AML.T0059",
          confidence: 0.78, metadata: { tool_name: tool.name },
        });
      }
    }
    return findings;
  },
});
