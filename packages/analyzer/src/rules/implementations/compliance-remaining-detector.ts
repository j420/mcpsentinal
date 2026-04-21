/**
 * Compliance Remaining — K1, K4, K6, K7, K11-K20 (minus those already migrated)
 * Plus remaining stragglers: L3, L8, L10, L14, L15, M2, M4, M5, M7, M8,
 * N1-N3, N7, N8, N10, O4, O6, O8, O10, P8-P10, Q10, Q12, Q14, Q15
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import type { OwaspCategory } from "@mcp-sentinel/database";
import { EvidenceChainBuilder } from "../../evidence.js";
import { computeCodeSignals, computeToolSignals } from "../../confidence-signals.js";

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }
function lineNum(s: string, i: number) { return s.substring(0, i).split("\n").length; }

type RCfg = {
  id: string; name: string;
  source: "code" | "tools" | "metadata" | "deps" | "conn";
  patterns: Array<{ regex: RegExp; desc: string }>;
  severity: "critical" | "high" | "medium" | "low";
  owasp: OwaspCategory; mitre: string | null; remediation: string;
  confidence: number;
  excludePatterns?: RegExp[];
};

function sinkTypeForOwasp(owasp: string): "command-execution" | "code-evaluation" | "network-send" | "credential-exposure" | "config-modification" | "privilege-grant" | "file-write" {
  if (owasp.includes("injection") || owasp.includes("command")) return "command-execution";
  if (owasp.includes("exfiltration")) return "network-send";
  if (owasp.includes("privilege") || owasp.includes("permission")) return "privilege-grant";
  if (owasp.includes("supply") || owasp.includes("chain")) return "code-evaluation";
  if (owasp.includes("logging") || owasp.includes("monitor")) return "credential-exposure";
  if (owasp.includes("config") || owasp.includes("insecure")) return "config-modification";
  return "code-evaluation";
}

function impactTypeForOwasp(owasp: string): "remote-code-execution" | "data-exfiltration" | "credential-theft" | "denial-of-service" | "privilege-escalation" | "config-poisoning" {
  if (owasp.includes("injection") || owasp.includes("command")) return "remote-code-execution";
  if (owasp.includes("exfiltration")) return "data-exfiltration";
  if (owasp.includes("privilege") || owasp.includes("permission") || owasp.includes("identity")) return "privilege-escalation";
  if (owasp.includes("supply") || owasp.includes("chain")) return "remote-code-execution";
  if (owasp.includes("logging") || owasp.includes("config") || owasp.includes("insecure")) return "config-poisoning";
  if (owasp.includes("memory") || owasp.includes("poison")) return "config-poisoning";
  return "config-poisoning";
}

function buildRule(cfg: RCfg): TypedRule {
  return {
    id: cfg.id, name: cfg.name,
    analyze(ctx) {
      if (cfg.source === "code") {
        if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
        const findings: TypedFinding[] = [];
        for (const { regex, desc } of cfg.patterns) {
          regex.lastIndex = 0;
          const match = regex.exec(ctx.source_code);
          if (match) {
            const line = lineNum(ctx.source_code, match.index);
            const lineText = ctx.source_code.split("\n")[line - 1] || "";
            if (cfg.excludePatterns?.some(e => e.test(lineText))) continue;

            // Compute server-specific confidence signals
            const signals = computeCodeSignals({
              sourceCode: ctx.source_code,
              matchLine: line,
              matchText: match[0],
              lineText,
              context: ctx,
              owaspCategory: cfg.owasp,
            });

            const builder = new EvidenceChainBuilder()
              .source({
                source_type: "file-content",
                location: `line ${line}`,
                observed: match[0].slice(0, 100),
                rationale:
                  `Structural pattern analysis detected: ${desc}. Rule ${cfg.id} (${cfg.name}) ` +
                  `identifies this code pattern as a compliance or security risk requiring remediation.`,
              })
              .propagation({
                propagation_type: "direct-pass",
                location: `line ${line}`,
                observed: `Pattern matched in source: ${lineText.trim().slice(0, 80)}`,
              })
              .sink({
                sink_type: sinkTypeForOwasp(cfg.owasp),
                location: `line ${line}`,
                observed: `${desc}: ${match[0].slice(0, 60)}`,
              })
              .impact({
                impact_type: impactTypeForOwasp(cfg.owasp),
                scope: "connected-services",
                exploitability: "moderate",
                scenario:
                  `The code pattern "${desc}" at line ${line} enables the attack or compliance ` +
                  `violation detected by ${cfg.id} (${cfg.name}). ${cfg.remediation}`,
              })
              .factor("structural_match", -0.05, "Structural regex pattern match — confirmed in source code but no full taint propagation");

            // Add all server-specific confidence signals
            for (const signal of signals) {
              builder.factor(signal.factor, signal.adjustment, signal.rationale);
            }

            const chain = builder
              .verification({
                step_type: "inspect-source",
                instruction:
                  `Review the code at line ${line}: "${match[0].slice(0, 60)}". Verify this ` +
                  `represents a genuine ${cfg.name} risk. Check for mitigating factors: is the ` +
                  `code in a test file, behind a feature flag, or otherwise unreachable in production?`,
                target: `source_code:${line}`,
                expected_observation: `${desc} — ${cfg.name} pattern confirmed in production code.`,
              })
              .build();

            findings.push({
              rule_id: cfg.id, severity: cfg.severity,
              evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
              remediation: cfg.remediation,
              owasp_category: cfg.owasp, mitre_technique: cfg.mitre,
              confidence: chain.confidence, metadata: { analysis_type: "structural", line, evidence_chain: chain },
            });
            break;
          }
        }
        return findings;
      }
      if (cfg.source === "tools") {
        const findings: TypedFinding[] = [];
        for (const tool of ctx.tools) {
          const text = `${tool.name} ${tool.description || ""}`;
          for (const { regex, desc } of cfg.patterns) {
            regex.lastIndex = 0;
            if (regex.test(text)) {
              // Compute server-specific confidence signals for tool findings
              const signals = computeToolSignals(ctx, cfg.owasp, tool.name);

              const builder = new EvidenceChainBuilder()
                .source({
                  source_type: "external-content",
                  location: `tool: ${tool.name}`,
                  observed: text.slice(0, 100),
                  rationale:
                    `Tool metadata analysis detected: ${desc}. Rule ${cfg.id} (${cfg.name}) ` +
                    `identifies this pattern in tool name or description as a security risk.`,
                })
                .propagation({
                  propagation_type: "direct-pass",
                  location: `tool: ${tool.name}`,
                  observed: `Pattern detected in tool metadata: ${desc}`,
                })
                .sink({
                  sink_type: sinkTypeForOwasp(cfg.owasp),
                  location: `tool: ${tool.name}`,
                  observed: `${desc} in tool "${tool.name}"`,
                })
                .impact({
                  impact_type: impactTypeForOwasp(cfg.owasp),
                  scope: "connected-services",
                  exploitability: "moderate",
                  scenario:
                    `Tool "${tool.name}" exhibits the pattern detected by ${cfg.id} (${cfg.name}): ` +
                    `${desc}. ${cfg.remediation}`,
                });

              // Add all server-specific confidence signals
              for (const signal of signals) {
                builder.factor(signal.factor, signal.adjustment, signal.rationale);
              }

              const chain = builder
                .verification({
                  step_type: "inspect-description",
                  instruction:
                    `Review tool "${tool.name}" name and description for the pattern: ${desc}. ` +
                    `Determine if this is a legitimate tool behavior or a security risk.`,
                  target: `tool: ${tool.name}`,
                  expected_observation: `${desc} — ${cfg.name} pattern confirmed in tool metadata.`,
                })
                .build();

              findings.push({
                rule_id: cfg.id, severity: cfg.severity,
                evidence: `Tool "${tool.name}": ${desc}.`,
                remediation: cfg.remediation,
                owasp_category: cfg.owasp, mitre_technique: cfg.mitre,
                confidence: chain.confidence, metadata: { tool_name: tool.name, evidence_chain: chain },
              });
              break;
            }
          }
        }
        return findings;
      }
      return [];
    },
  };
}

// ─── K-remaining ───────────────────────────────────────────────────────────

const K_RULES: RCfg[] = [
  // K1 migrated to TypedRuleV2 — see k1-absent-structured-logging/
  // K4 migrated to TypedRuleV2 — see k4-missing-human-confirmation/
  // K6 migrated to TypedRuleV2 — see k6-overly-broad-oauth-scopes/
  // K7 migrated to TypedRuleV2 — see k7-long-lived-tokens/
  // K9 migrated to TypedRuleV2 — see k9-dangerous-post-install-hooks/
  // K11 migrated to TypedRuleV2 — see k11-missing-server-integrity-verification/
  // K12 migrated to TypedRuleV2 — see k12-executable-content-response/
  // K13 migrated to TypedRuleV2 — see k13-unsanitized-tool-output/
  // K14 migrated to TypedRuleV2 — see k14-agent-credential-propagation/
  // K15 migrated to TypedRuleV2 — see k15-multi-agent-collusion-preconditions/
  // K16 migrated to TypedRuleV2 — see k16-unbounded-recursion/
  // K17 migrated to TypedRuleV2 — see k17-missing-timeout/
  // K18 migrated to TypedRuleV2 — see k18-cross-trust-boundary-data-flow/
  // K19 migrated to TypedRuleV2 — see docker-k8s-crypto-v2.ts
  // K20 migrated to TypedRuleV2 — see k20-insufficient-audit-context/
];

// ─── L/M/N/O/P/Q remaining stragglers ─────────────────────────────────────

const STRAGGLER_RULES: RCfg[] = [
  // L3 migrated to TypedRuleV2 — see docker-k8s-crypto-v2.ts
  // L8 migrated to TypedRuleV2 — see l-supply-chain-v2.ts
  // L10 migrated to TypedRuleV2 — see l-supply-chain-v2.ts
  // L15 migrated to TypedRuleV2 — see l-supply-chain-v2.ts
  // M2 migrated to TypedRuleV2 — see m-runtime-v2.ts
  // M4 migrated to TypedRuleV2 — see m4-tool-squatting.ts
  // M5 migrated to TypedRuleV2 — see m5-context-window-flooding.ts
  // M7 migrated to TypedRuleV2 — see m-runtime-v2.ts
  // M8 migrated to TypedRuleV2 — see m-runtime-v2.ts
  // N1 migrated to TypedRuleV2 — see jsonrpc-protocol-v2.ts
  // N2 migrated to TypedRuleV2 — see jsonrpc-protocol-v2.ts
  // N3 migrated to TypedRuleV2 — see jsonrpc-protocol-v2.ts
  // N7 migrated to TypedRuleV2 — see jsonrpc-protocol-v2.ts
  // N8 migrated to TypedRuleV2 — see jsonrpc-protocol-v2.ts
  // N10 migrated to TypedRuleV2 — see jsonrpc-protocol-v2.ts
  // O4 migrated to TypedRuleV2 — see o4-q10-v2.ts
  { id: "O6", name: "Clipboard / Pasteboard Access", source: "code",
    patterns: [
      { regex: /(?:clipboard|pasteboard|pbcopy|pbpaste|xclip|xsel).*(?:read|write|get|set|copy|paste)/gi, desc: "clipboard access (data leakage vector)" },
    ],
    severity: "high", owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
    remediation: "MCP servers should not access the clipboard. Remove clipboard read/write operations.",
    confidence: 0.82,
  },
  { id: "O8", name: "Screenshot / Screen Capture", source: "code",
    patterns: [
      { regex: /(?:screenshot|screen.?capture|screen.?grab|captureScreen|desktopCapturer)/gi, desc: "screen capture capability" },
    ],
    severity: "high", owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
    remediation: "MCP servers should not capture screenshots. This is a significant data exfiltration vector.",
    confidence: 0.85,
  },
  { id: "O10", name: "Keylogging / Input Monitoring", source: "code",
    patterns: [
      { regex: /(?:keylog|keypress|keydown|keyup|input.?monitor|keyboard.?hook)/gi, desc: "keyboard/input monitoring" },
    ],
    severity: "high", owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
    remediation: "MCP servers must not monitor keyboard input. Remove all input capture code.",
    confidence: 0.90,
  },
  // P8 migrated to TypedRuleV2 — see docker-k8s-crypto-v2.ts
  // P9 migrated to TypedRuleV2 — see docker-k8s-crypto-v2.ts
  // P10 migrated to TypedRuleV2 — see docker-k8s-crypto-v2.ts
  // Q10 migrated to TypedRuleV2 — see o4-q10-v2.ts
  { id: "Q12", name: "Browser Extension ↔ MCP Bridge", source: "code",
    patterns: [
      { regex: /(?:chrome|browser)\.runtime\.(?:sendMessage|connect|sendNativeMessage).*(?:mcp|tool|server)/gi, desc: "browser extension to MCP bridge" },
    ],
    severity: "high", owasp: "MCP05-privilege-escalation", mitre: null,
    remediation: "Don't bridge browser extension APIs to MCP servers without sandboxing and permission checks.",
    confidence: 0.78,
  },
  { id: "Q14", name: "Cross-Language Serialization Mismatch", source: "code",
    patterns: [
      { regex: /(?:serialize|marshal|encode).*(?:python|ruby|java|php).*(?:deserialize|unmarshal|decode).*(?:javascript|node|typescript)/gi, desc: "cross-language serialization without type validation" },
    ],
    severity: "high", owasp: "MCP03-command-injection", mitre: "AML.T0054",
    remediation: "Use language-neutral serialization (JSON, protobuf). Validate types after deserialization.",
    confidence: 0.72,
  },
  { id: "Q15", name: "Agentic Workflow Persistence Hijacking", source: "code",
    patterns: [
      { regex: /(?:checkpoint|snapshot|persist|save)\s*(?:workflow|state|progress).*(?:file|disk|db|store)(?!.*(?:encrypt|sign|verify|hash))/gi, desc: "workflow state persisted without integrity protection" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Sign or encrypt persisted workflow state. Verify integrity on resume.",
    confidence: 0.72,
  },
];

// Register all
for (const cfg of [...K_RULES, ...STRAGGLER_RULES]) {
  registerTypedRule(buildRule(cfg));
}
