/**
 * Advanced Supply Chain Detector — L7, K3, K5, K8
 *
 * Originally housed L1, L2, L6, L13 as well. Those four rules were
 * migrated to Rule Standard v2 in Phase 1, Chunk 1.9 and now live in
 * their own directories:
 *
 *   L1  → packages/analyzer/src/rules/implementations/l1-github-actions-tag-poisoning/
 *   L2  → packages/analyzer/src/rules/implementations/l2-malicious-build-plugin/
 *   L6  → packages/analyzer/src/rules/implementations/l6-config-symlink-attack/
 *   L13 → packages/analyzer/src/rules/implementations/l13-build-credential-file-theft/
 *
 * The remaining rules in this file are legacy v1 TypedRule
 * implementations pending their own Phase 1 migration chunks:
 *
 * L7:  Transitive MCP Delegation — MCP client inside MCP server (import resolution)
 * K3:  Audit Log Tampering — read→filter→write on log files
 * K5:  Auto-Approve / Bypass Confirmation — confirmation skip patterns
 * K8:  Cross-Boundary Credential Sharing — credentials flowing across trust boundaries
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { analyzeASTTaint } from "../analyzers/taint-ast.js";
import { analyzeTaint } from "../analyzers/taint.js";
import { EvidenceChainBuilder } from "../../evidence.js";
import { computeCodeSignals } from "../../confidence-signals.js";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

function getLineNumber(source: string, index: number): number {
  return source.substring(0, index).split("\n").length;
}

// ─── L1: GitHub Actions Tag Poisoning (MIGRATED) ─────────────────────────

// MIGRATED to packages/analyzer/src/rules/implementations/l1-github-actions-tag-poisoning/
// (Phase 1, Chunk 1.9). The v2 rule auto-registers itself; this file no longer
// contains the L1 class.

// ─── L2: Malicious Build Plugin (MIGRATED) ───────────────────────────────

// MIGRATED to packages/analyzer/src/rules/implementations/l2-malicious-build-plugin/
// (Phase 1, Chunk 1.9). The v2 rule auto-registers itself; this file no longer
// contains the L2 class.

// ─── L6: Config Symlink Attack (MIGRATED) ────────────────────────────────

// MIGRATED to packages/analyzer/src/rules/implementations/l6-config-symlink-attack/
// (Phase 1, Chunk 1.9). The v2 rule auto-registers itself; this file no longer
// contains the L6 class.

// ─── L7: Transitive MCP Delegation ────────────────────────────────────────

class TransitiveMCPDelegationRule implements TypedRule {
  readonly id = "L7";
  readonly name = "Transitive MCP Delegation (Import-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Detect MCP client imports inside what appears to be an MCP server
    const hasServerImport = /(?:import|require).*(?:@modelcontextprotocol\/sdk.*server|McpServer|Server)/i.test(source);
    const hasClientImport = /(?:import|require).*(?:@modelcontextprotocol\/sdk.*client|Client|StdioClientTransport|SSEClientTransport|StreamableHTTPClientTransport)/i.test(source);

    if (hasServerImport && hasClientImport) {
      const l7DelegationChain = new EvidenceChainBuilder()
        .source({
          source_type: "file-content",
          location: "import statements",
          observed: "Both MCP Server and MCP Client imports present in the same module",
          rationale: "A module that imports both MCP server and client SDK acts as a proxy/bridge, creating a transitive delegation path where upstream server responses flow through to downstream clients.",
        })
        .propagation({
          propagation_type: "cross-tool-flow",
          location: "MCP server → MCP client bridge",
          observed: "Server receives requests, forwards them via client to upstream MCP server, relays responses back",
        })
        .impact({
          impact_type: "cross-agent-propagation",
          scope: "other-agents",
          exploitability: "moderate",
          scenario: "A compromised upstream MCP server injects malicious tool descriptions or responses through this proxy server to downstream AI clients, bypassing per-server trust boundaries.",
        })
        .factor("dual_import", 0.12, "Both server and client SDK imports confirmed — strong indicator of MCP proxy pattern")
        .verification({
          step_type: "inspect-source",
          instruction: "Search the file for import/require statements of @modelcontextprotocol/sdk. Confirm both Server and Client classes are imported in the same module.",
          target: "import statements at top of file",
          expected_observation: "Both McpServer/Server and Client/StdioClientTransport imports present",
        });

      const l7DualSignals = computeCodeSignals({
        sourceCode: source,
        matchLine: 1,
        matchText: "import @modelcontextprotocol/sdk server + client",
        lineText: (source.split("\n")[0] || ""),
        context,
        owaspCategory: "MCP06-excessive-permissions",
      });
      for (const sig of l7DualSignals) l7DelegationChain.factor(sig.factor, sig.adjustment, sig.rationale);
      const l7DelegationBuilt = l7DelegationChain.build();

      findings.push({
        rule_id: "L7",
        severity: "critical",
        evidence:
          `MCP client imported inside MCP server code. ` +
          `This server acts as both server AND client — transitive delegation. ` +
          `Compromised upstream server can inject through this proxy to downstream clients.`,
        remediation:
          "MCP servers should not contain MCP client code. If proxying is required, " +
          "declare it explicitly in server metadata and implement trust boundary validation.",
        owasp_category: "MCP06-excessive-permissions",
        mitre_technique: "AML.T0054",
        confidence: l7DelegationBuilt.confidence,
        metadata: { analysis_type: "import_resolution", evidence_chain: l7DelegationBuilt },
      });
    }

    // Detect proxy/delegation patterns
    const proxyPatterns = [
      { regex: /(?:proxy|forward|delegate|relay|bridge).*(?:mcp|tool|request).*(?:server|client|upstream)/gi, desc: "MCP proxy/delegation pattern" },
      { regex: /(?:tools\/call|callTool|invokeTool).*(?:client|remote|upstream|backend)/gi, desc: "remote tool invocation via client" },
      { regex: /(?:auth|token|credential).*(?:forward|pass|proxy|propagate).*(?:server|upstream)/gi, desc: "credential forwarding to upstream" },
    ];

    for (const { regex, desc } of proxyPatterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const l7ProxyChain = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${line}: "${match[0].slice(0, 80)}"`,
            observed: match[0].slice(0, 100),
            rationale: "Code contains proxy/delegation/forwarding patterns that route MCP requests or credentials to upstream servers.",
          })
          .propagation({
            propagation_type: "cross-tool-flow",
            location: `line ${line}`,
            observed: `${desc} — requests or credentials forwarded across trust boundaries`,
          })
          .impact({
            impact_type: "cross-agent-propagation",
            scope: "other-agents",
            exploitability: "moderate",
            scenario: "Proxy pattern enables a compromised upstream server to inject malicious responses into downstream clients. Credential forwarding exposes tokens to untrusted upstream servers.",
          })
          .factor("proxy_pattern", 0.05, "Structural proxy/delegation pattern detected")
          .verification({
            step_type: "inspect-source",
            instruction: "Examine the proxy/delegation code at the indicated line. Verify whether upstream responses are validated before being relayed and whether credentials are scoped appropriately.",
            target: `line ${line}`,
            expected_observation: desc,
          });

        const l7ProxySignals = computeCodeSignals({
          sourceCode: source,
          matchLine: line,
          matchText: match[0].slice(0, 80),
          lineText: (source.split("\n")[line - 1] || ""),
          context,
          owaspCategory: "MCP06-excessive-permissions",
        });
        for (const sig of l7ProxySignals) l7ProxyChain.factor(sig.factor, sig.adjustment, sig.rationale);
        const l7ProxyBuilt = l7ProxyChain.build();

        findings.push({
          rule_id: "L7",
          severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
          remediation: "Declare delegation explicitly. Validate upstream responses. Don't forward credentials blindly.",
          owasp_category: "MCP06-excessive-permissions",
          mitre_technique: "AML.T0054",
          confidence: l7ProxyBuilt.confidence,
          metadata: { analysis_type: "import_resolution", line, evidence_chain: l7ProxyBuilt },
        });
        break;
      }
    }

    return findings;
  }
}

// ─── L13: Credential File Theft (MIGRATED) ───────────────────────────────

// MIGRATED to packages/analyzer/src/rules/implementations/l13-build-credential-file-theft/
// (Phase 1, Chunk 1.9). The v2 rule auto-registers itself; this file no longer
// contains the L13 class.

// ─── K3: Audit Log Tampering ──────────────────────────────────────────────

class AuditLogTamperingRule implements TypedRule {
  readonly id = "K3";
  readonly name = "Audit Log Tampering (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Detect read→modify→write on log files
    const patterns = [
      { regex: /(?:readFileSync|readFile)\s*\([^)]*(?:\.log|audit|journal)[\s\S]{0,500}(?:filter|replace|split|slice)[\s\S]{0,500}(?:writeFileSync|writeFile)/gi, desc: "read→filter→write on log file" },
      { regex: /sed\s+-i.*(?:\.log|audit|journal)/gi, desc: "in-place sed edit on log file" },
      { regex: /(?:open\s*\([^)]*(?:log|audit)[^)]*['"]r\+)/gi, desc: "read-write mode on audit file" },
      { regex: /(?:timestamp|time|date).*(?:replace|override|fake|forge|spoof)/gi, desc: "timestamp manipulation" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        // Exclude PII redaction (legitimate)
        const lineText = source.split("\n")[line - 1] || "";
        if (/(?:redact|pii|gdpr|anonymize|sanitize)/i.test(lineText)) continue;

        const k3Chain = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${line}: "${match[0].slice(0, 80)}"`,
            observed: match[0].slice(0, 100),
            rationale: "Code performs a read-modify-write operation on an audit log file, which enables tampering with forensic evidence.",
          })
          .propagation({
            propagation_type: "variable-assignment",
            location: `line ${line}`,
            observed: `Log file content is read, filtered/modified, then written back: ${desc}`,
          })
          .sink({
            sink_type: "file-write",
            location: `line ${line}`,
            observed: `Modified audit log content written back to log file — ${desc}`,
          })
          .impact({
            impact_type: "config-poisoning",
            scope: "server-host",
            exploitability: "trivial",
            scenario: "An attacker (or compromised code) modifies audit logs to remove evidence of intrusion, violating ISO 27001 A.8.15 log integrity requirements. This destroys the forensic trail needed for incident response.",
          })
          .factor("log_modification", 0.1, "Read-modify-write pattern on audit/log files indicates tampering capability")
          .verification({
            step_type: "trace-flow",
            instruction: "Search for file read followed by filter/replace/write operations on log files. Confirm this is modifying existing log entries rather than legitimate append-only logging.",
            target: `line ${line}`,
            expected_observation: `${desc} — log content modified in place`,
          });

        const k3Signals = computeCodeSignals({
          sourceCode: source,
          matchLine: line,
          matchText: match[0].slice(0, 100),
          lineText: lineText,
          context,
          owaspCategory: "MCP09-logging-monitoring",
        });
        for (const sig of k3Signals) k3Chain.factor(sig.factor, sig.adjustment, sig.rationale);
        const k3Built = k3Chain.build();

        findings.push({
          rule_id: "K3",
          severity: "critical",
          evidence:
            `${desc} at line ${line}: "${match[0].slice(0, 100)}". ` +
            `Modifying audit logs violates ISO 27001 A.8.15 (log integrity).`,
          remediation:
            "Audit logs must be append-only. Use immutable log storage (write-once media, " +
            "append-only databases). If PII redaction is needed, do it at write time, not retroactively.",
          owasp_category: "MCP09-logging-monitoring",
          mitre_technique: "AML.T0054",
          confidence: k3Built.confidence,
          metadata: { analysis_type: "structural", line, evidence_chain: k3Built },
        });
      }
    }

    return findings;
  }
}

// ─── K5: Auto-Approve / Bypass Confirmation ───────────────────────────────

class AutoApproveBypassRule implements TypedRule {
  readonly id = "K5";
  readonly name = "Auto-Approve / Bypass Confirmation (Structural)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    const patterns = [
      { regex: /auto[_\s-]?approve\s*[:=]\s*true/gi, desc: "auto-approve enabled" },
      { regex: /(?:skip|bypass|disable)[_\s-]?confirm(?:ation)?\s*[:=]\s*true/gi, desc: "confirmation bypass" },
      { regex: /(?:confirm|prompt|ask)[_\s-]?(?:user|human)\s*[:=]\s*false/gi, desc: "human confirmation disabled" },
      { regex: /force[_\s-]?(?:execute|run|approve)\s*[:=]\s*true/gi, desc: "forced execution without approval" },
      { regex: /(?:yolo|dangerously|unsafe)[_\s-]?(?:mode|allow|approve)/gi, desc: "unsafe mode pattern" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const k5Chain = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${line}: "${match[0].slice(0, 60)}"`,
            observed: match[0].slice(0, 80),
            rationale: "Code contains a flag or configuration that explicitly bypasses human confirmation for tool execution, undermining the human-in-the-loop safety requirement.",
          })
          .sink({
            sink_type: "privilege-grant",
            location: `line ${line}`,
            observed: `${desc} — operations execute without human approval`,
          })
          .impact({
            impact_type: "privilege-escalation",
            scope: "ai-client",
            exploitability: "trivial",
            scenario: "With auto-approve enabled, a compromised or poisoned tool can execute destructive operations (file deletion, credential access, network exfiltration) without any human review. This violates EU AI Act Art. 14 human oversight requirements.",
          })
          .factor("confirmation_bypass", 0.12, "Explicit auto-approve or confirmation bypass flag found in source code")
          .verification({
            step_type: "trace-flow",
            instruction: "Search for auto-approve, skip-confirm, or force-execute patterns. Verify this flag controls whether human confirmation is required before tool execution.",
            target: `line ${line}`,
            expected_observation: `${desc} — boolean flag disabling human confirmation`,
          });

        const k5Signals = computeCodeSignals({
          sourceCode: source,
          matchLine: line,
          matchText: match[0].slice(0, 60),
          lineText: (source.split("\n")[line - 1] || ""),
          context,
          owaspCategory: "ASI09-human-oversight-bypass",
        });
        for (const sig of k5Signals) k5Chain.factor(sig.factor, sig.adjustment, sig.rationale);
        const k5Built = k5Chain.build();

        findings.push({
          rule_id: "K5",
          severity: "critical",
          evidence:
            `${desc} at line ${line}: "${match[0].slice(0, 60)}". ` +
            `Bypassing human confirmation violates EU AI Act Art. 14 (human oversight) and OWASP ASI09.`,
          remediation:
            "Remove auto-approve flags. All destructive or sensitive operations must require " +
            "explicit human confirmation. Implement a proper approval workflow.",
          owasp_category: "ASI09-human-oversight-bypass",
          mitre_technique: "AML.T0054",
          confidence: k5Built.confidence,
          metadata: { analysis_type: "structural", line, evidence_chain: k5Built },
        });
      }
    }

    return findings;
  }
}

// ─── K8: Cross-Boundary Credential Sharing ────────────────────────────────

class CrossBoundaryCredentialRule implements TypedRule {
  readonly id = "K8";
  readonly name = "Cross-Boundary Credential Sharing (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];

    // Phase 1: AST taint — credentials flowing to external boundaries
    try {
      const astFlows = analyzeASTTaint(context.source_code);
      const credFlows = astFlows.filter(f =>
        f.source.category === "environment" &&
        (f.sink.category === "ssrf" || f.sink.category === "file_write") &&
        !f.sanitized
      );

      for (const flow of credFlows) {
        const isCredSource = /(?:token|secret|key|password|credential|auth|api_key)/i.test(flow.source.expression);
        if (isCredSource) {
          const k8TaintChain = new EvidenceChainBuilder()
            .source({
              source_type: "environment",
              location: `line ${flow.source.line}: "${flow.source.expression}"`,
              observed: flow.source.expression,
              rationale: "Credential (token, secret, key, password) is read from an environment variable or config, representing a trust boundary's authentication material.",
            })
            .propagation({
              propagation_type: "function-call",
              location: `line ${flow.source.line} → line ${flow.sink.line}`,
              observed: `Credential "${flow.source.expression}" propagates to external sink "${flow.sink.expression.slice(0, 50)}"`,
            })
            .sink({
              sink_type: flow.sink.category === "ssrf" ? "network-send" : "file-write",
              location: `line ${flow.sink.line}`,
              observed: `${flow.sink.category}: "${flow.sink.expression.slice(0, 80)}"`,
            })
            .impact({
              impact_type: "credential-theft",
              scope: "connected-services",
              exploitability: "moderate",
              scenario: "A credential intended for one trust boundary is forwarded to an external service or written to a shared location. An attacker controlling the destination can capture the credential and impersonate the original service.",
            })
            .factor("credential_cross_boundary", 0.12, "AST taint confirms credential flows from environment source to external sink")
            .verification({
              step_type: "trace-flow",
              instruction: "Trace the credential variable from its environment source to the network/file sink. Confirm the credential crosses a service or agent trust boundary.",
              target: `lines ${flow.source.line}–${flow.sink.line}`,
              expected_observation: "Credential variable used in HTTP request, fetch call, or file write targeting another service",
            })
            .build();

          findings.push({
            rule_id: "K8",
            severity: "critical",
            evidence:
              `[AST taint] Credential "${flow.source.expression}" (L${flow.source.line}) crosses trust boundary → ` +
              `"${flow.sink.expression.slice(0, 50)}" (L${flow.sink.line}). ` +
              `Credentials must not flow across service/agent boundaries.`,
            remediation:
              "Use scoped, short-lived tokens for cross-boundary communication. " +
              "Never share credentials between services. Implement proper service-to-service auth (mTLS, OAuth).",
            owasp_category: "ASI03-identity-privilege-abuse",
            mitre_technique: "AML.T0054",
            confidence: flow.confidence,
            metadata: { analysis_type: "ast_taint", evidence_chain: k8TaintChain },
          });
        }
      }
    } catch { /* fall through */ }

    // Phase 2: Pattern — shared credential patterns
    if (findings.length === 0) {
      const patterns = [
        { regex: /(?:shared|common|global)[_\s-]?(?:token|secret|key|credential|api_key)/gi, desc: "shared credential variable" },
        { regex: /(?:forward|pass|propagate|share)[_\s-]?(?:token|credential|auth|api_key).*(?:server|agent|service|upstream)/gi, desc: "credential forwarding to another service" },
      ];

      for (const { regex, desc } of patterns) {
        regex.lastIndex = 0;
        const match = regex.exec(context.source_code);
        if (match) {
          const line = getLineNumber(context.source_code, match.index);
          const k8StructChain = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `line ${line}: "${match[0].slice(0, 80)}"`,
              observed: match[0].slice(0, 100),
              rationale: "Code contains a pattern indicating credentials are shared or forwarded across service/agent trust boundaries.",
            })
            .sink({
              sink_type: "credential-exposure",
              location: `line ${line}`,
              observed: `${desc} — credentials exposed across trust boundary`,
            })
            .impact({
              impact_type: "credential-theft",
              scope: "connected-services",
              exploitability: "moderate",
              scenario: "Shared or forwarded credentials grant an untrusted service the same access as the original credential holder. Compromise of any service in the sharing chain compromises all services that accept the shared credential.",
            })
            .factor("shared_credential_pattern", 0.08, "Structural pattern matching shared/forwarded credential variable naming")
            .verification({
              step_type: "trace-flow",
              instruction: "Search for the shared/forwarded credential variable at the indicated line. Verify the credential is used across service or agent boundaries rather than within a single trust domain.",
              target: `line ${line}`,
              expected_observation: `${desc} — credential variable shared or forwarded to another service`,
            });

          const k8Signals = computeCodeSignals({
            sourceCode: context.source_code,
            matchLine: line,
            matchText: match[0].slice(0, 80),
            lineText: (context.source_code.split("\n")[line - 1] || ""),
            context,
            owaspCategory: "ASI03-identity-privilege-abuse",
          });
          for (const sig of k8Signals) k8StructChain.factor(sig.factor, sig.adjustment, sig.rationale);
          const k8StructBuilt = k8StructChain.build();

          findings.push({
            rule_id: "K8",
            severity: "critical",
            evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
            remediation: "Use scoped, per-service credentials. Never share API keys across trust boundaries.",
            owasp_category: "ASI03-identity-privilege-abuse",
            mitre_technique: "AML.T0054",
            confidence: k8StructBuilt.confidence,
            metadata: { analysis_type: "structural", line, evidence_chain: k8StructBuilt },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── Register ──────────────────────────────────────────────────────────────

// MIGRATED: ActionsTagPoisoningRule (L1) now self-registers via
//           implementations/l1-github-actions-tag-poisoning/index.ts
// MIGRATED: MaliciousBuildPluginRule (L2) now self-registers via
//           implementations/l2-malicious-build-plugin/index.ts
// MIGRATED: ConfigSymlinkRule (L6) now self-registers via
//           implementations/l6-config-symlink-attack/index.ts
registerTypedRule(new TransitiveMCPDelegationRule());
// MIGRATED: CredentialFileTheftRule (L13) now self-registers via
//           implementations/l13-build-credential-file-theft/index.ts
registerTypedRule(new AuditLogTamperingRule());
registerTypedRule(new AutoApproveBypassRule());
registerTypedRule(new CrossBoundaryCredentialRule());
