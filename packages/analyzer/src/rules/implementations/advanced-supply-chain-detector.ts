/**
 * Advanced Supply Chain Detector — L1, L2, L6, L7, L13, K3, K5, K8
 *
 * L1:  GitHub Actions Tag Poisoning — mutable tags, pipe-to-shell
 * L2:  Malicious Build Plugin — plugins with exec/fetch/writeFile
 * L6:  Config Symlink Attack — symlink to sensitive paths without realpath
 * L7:  Transitive MCP Delegation — MCP client inside MCP server (import resolution)
 * L13: Credential File Theft — read .npmrc/.pypirc → network exfil
 * K3:  Audit Log Tampering — read→filter→write on log files
 * K5:  Auto-Approve / Bypass Confirmation — confirmation skip patterns
 * K8:  Cross-Boundary Credential Sharing — credentials flowing across trust boundaries
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { analyzeASTTaint } from "../analyzers/taint-ast.js";
import { analyzeTaint } from "../analyzers/taint.js";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

function getLineNumber(source: string, index: number): number {
  return source.substring(0, index).split("\n").length;
}

// ─── L1: GitHub Actions Tag Poisoning ─────────────────────────────────────

class ActionsTagPoisoningRule implements TypedRule {
  readonly id = "L1";
  readonly name = "GitHub Actions Tag Poisoning (Structural)";

  private readonly SAFE_ACTIONS = new Set([
    "actions/checkout", "actions/setup-node", "actions/setup-python",
    "actions/cache", "actions/upload-artifact", "actions/download-artifact",
    "actions/github-script", "actions/labeler",
  ]);

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const lines = context.source_code.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      // uses: action@mutable-ref (not SHA)
      const usesMatch = line.match(/uses:\s*([\w-]+\/[\w-]+)@([\w.-]+)/);
      if (usesMatch) {
        const [, action, ref] = usesMatch;
        const isSafe = this.SAFE_ACTIONS.has(action);
        const isSHA = /^[0-9a-f]{40}$/.test(ref);
        const isMutableTag = /^(main|master|dev|latest|v\d+)$/.test(ref);

        if (!isSafe && !isSHA && isMutableTag) {
          findings.push({
            rule_id: "L1",
            severity: "critical",
            evidence:
              `Mutable Action ref at line ${i + 1}: ${action}@${ref}. ` +
              `Mutable tags can be force-pushed. CVE-2025-30066: tj-actions/changed-files tag poisoning.`,
            remediation:
              `Pin to SHA: uses: ${action}@<full-sha-hash>. ` +
              "Use Dependabot or Renovate to keep SHA pins updated.",
            owasp_category: "MCP10-supply-chain",
            mitre_technique: "AML.T0017",
            confidence: isMutableTag ? 0.92 : 0.75,
            metadata: { analysis_type: "structural", line: i + 1, action, ref },
          });
        }
      }

      // Pipe-to-shell: curl|bash in run step
      if (/(?:curl|wget)\s+.*\|\s*(?:bash|sh|sudo|python|node)/i.test(line)) {
        findings.push({
          rule_id: "L1",
          severity: "critical",
          evidence:
            `Pipe-to-shell at line ${i + 1}: "${line.slice(0, 80)}". ` +
            `Remote code execution — downloaded script runs without integrity verification.`,
          remediation:
            "Download the script, verify its checksum, then execute. " +
            "Better: use a versioned GitHub Action instead of curl|bash.",
          owasp_category: "MCP10-supply-chain",
          mitre_technique: "AML.T0017",
          confidence: 0.95,
          metadata: { analysis_type: "structural", line: i + 1 },
        });
      }
    }

    return findings;
  }
}

// ─── L2: Malicious Build Plugin ───────────────────────────────────────────

class MaliciousBuildPluginRule implements TypedRule {
  readonly id = "L2";
  readonly name = "Malicious Build Plugin (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];

    // Phase 1: AST taint — plugin code that executes commands or fetches URLs
    try {
      const astFlows = analyzeASTTaint(context.source_code);
      const dangerousFlows = astFlows.filter(f =>
        (f.sink.category === "command_execution" || f.sink.category === "ssrf") && !f.sanitized
      );

      // Check if these flows are within build plugin context
      const isPluginContext = /(?:rollup|vite|webpack|esbuild)[\s\S]*(?:plugin|hooks|compiler)/i.test(context.source_code);
      if (isPluginContext && dangerousFlows.length > 0) {
        for (const flow of dangerousFlows) {
          findings.push({
            rule_id: "L2",
            severity: "critical",
            evidence:
              `[AST taint] Build plugin with ${flow.sink.category}: ` +
              `"${flow.source.expression}" (L${flow.source.line}) → "${flow.sink.expression.slice(0, 50)}" (L${flow.sink.line}). ` +
              `Build plugins run with full system access during compilation.`,
            remediation:
              "Audit build plugins for network calls and command execution. " +
              "Use only well-known plugins (rollup-plugin-terser, etc.). Pin plugin versions.",
            owasp_category: "MCP10-supply-chain",
            mitre_technique: "AML.T0017",
            confidence: flow.confidence * 0.90,
            metadata: { analysis_type: "ast_taint" },
          });
        }
      }
    } catch { /* fall through */ }

    // Phase 2: Structural — build config importing from URL
    if (findings.length === 0) {
      const patterns = [
        { regex: /(?:plugins|presets).*(?:import|require)\s*\(\s*["']https?:\/\//gi, desc: "plugin loaded from URL" },
        { regex: /(?:rollup|vite|webpack|esbuild)\.config.*(?:exec|spawn|child_process)/gi, desc: "build config with exec" },
        { regex: /(?:plugin|hook|transform).*process\.env.*(?:fetch|http|axios)/gi, desc: "plugin exfiltrates env vars" },
      ];

      for (const { regex, desc } of patterns) {
        regex.lastIndex = 0;
        const match = regex.exec(context.source_code);
        if (match) {
          const line = getLineNumber(context.source_code, match.index);
          findings.push({
            rule_id: "L2",
            severity: "critical",
            evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
            remediation: "Build plugins should not make network requests or execute commands.",
            owasp_category: "MCP10-supply-chain",
            mitre_technique: "AML.T0017",
            confidence: 0.85,
            metadata: { analysis_type: "structural", line },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── L6: Config Symlink Attack ────────────────────────────────────────────

class ConfigSymlinkRule implements TypedRule {
  readonly id = "L6";
  readonly name = "Config Symlink Attack (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Detect symlink creation to sensitive paths
    const symlinkPatterns = [
      { regex: /(?:symlink|symlinkSync|os\.symlink|ln\s+-s).*(?:\/etc\/|\/root\/|~\/\.ssh|\/var\/|\/proc\/)/gi, desc: "symlink to sensitive system path" },
      { regex: /(?:symlink|symlinkSync|os\.symlink).*(?:\.claude|\.cursor|\.mcp\.json|mcp_config)/gi, desc: "symlink targeting agent config" },
    ];

    for (const { regex, desc } of symlinkPatterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        findings.push({
          rule_id: "L6",
          severity: "critical",
          evidence:
            `${desc} at line ${line}: "${match[0].slice(0, 80)}". ` +
            `CVE-2025-53109: filesystem MCP server symlink bypass.`,
          remediation:
            "Use lstat() to check for symlinks before following. Use O_NOFOLLOW flag. " +
            "Resolve real paths with realpath() and verify against allowed base directory.",
          owasp_category: "MCP05-privilege-escalation",
          mitre_technique: "AML.T0054",
          confidence: 0.90,
          metadata: { analysis_type: "structural", line },
        });
      }
    }

    // Detect file access without symlink protection (TOCTOU)
    const toctouPattern = /(?:fs\.stat|statSync|os\.stat)[\s\S]{0,200}(?:fs\.readFile|readFileSync|open)(?!.*(?:O_NOFOLLOW|NOFOLLOW|lstat|realpath))/gi;
    const toctouMatch = toctouPattern.exec(source);
    if (toctouMatch) {
      const line = getLineNumber(source, toctouMatch.index);
      findings.push({
        rule_id: "L6",
        severity: "high",
        evidence:
          `TOCTOU vulnerability at line ${line}: stat() then read() without symlink protection. ` +
          `Attacker can replace file with symlink between stat and read.`,
        remediation:
          "Use O_NOFOLLOW with open(). Or use fstat() on the file descriptor after opening.",
        owasp_category: "MCP05-privilege-escalation",
        mitre_technique: "AML.T0054",
        confidence: 0.75,
        metadata: { analysis_type: "structural", line },
      });
    }

    return findings;
  }
}

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
        confidence: 0.92,
        metadata: { analysis_type: "import_resolution" },
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
        findings.push({
          rule_id: "L7",
          severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
          remediation: "Declare delegation explicitly. Validate upstream responses. Don't forward credentials blindly.",
          owasp_category: "MCP06-excessive-permissions",
          mitre_technique: "AML.T0054",
          confidence: 0.80,
          metadata: { analysis_type: "import_resolution", line },
        });
        break;
      }
    }

    return findings;
  }
}

// ─── L13: Credential File Theft ───────────────────────────────────────────

class CredentialFileTheftRule implements TypedRule {
  readonly id = "L13";
  readonly name = "Credential File Theft (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];

    // Phase 1: AST taint — credential file read → network exfil
    try {
      const astFlows = analyzeASTTaint(context.source_code);
      // Find file reads that might be credential files reaching network sinks
      const exfilFlows = astFlows.filter(f =>
        f.source.category === "file_read" && f.sink.category === "ssrf" && !f.sanitized
      );

      for (const flow of exfilFlows) {
        const isCredFile = /(?:npmrc|pypirc|docker.*config|ssh|aws|credentials|auth)/i.test(
          flow.source.expression + " " + flow.path.map(s => s.expression).join(" ")
        );
        if (isCredFile) {
          findings.push({
            rule_id: "L13",
            severity: "critical",
            evidence:
              `[AST taint] Credential file read → network exfil: ` +
              `"${flow.source.expression}" (L${flow.source.line}) → "${flow.sink.expression.slice(0, 50)}" (L${flow.sink.line}).`,
            remediation: "Never read credential files (.npmrc, .pypirc, .ssh/) and send their contents over the network.",
            owasp_category: "MCP07-insecure-config",
            mitre_technique: "AML.T0057",
            confidence: flow.confidence,
            metadata: { analysis_type: "ast_taint" },
          });
        }
      }
    } catch { /* fall through */ }

    // Phase 2: Direct patterns — reading known credential files
    if (findings.length === 0) {
      const credFileReads = [
        { regex: /(?:readFile|readFileSync|open|cat)\s*\([^)]*(?:\.npmrc|npmrc)/gi, desc: ".npmrc token file" },
        { regex: /(?:readFile|readFileSync|open|cat)\s*\([^)]*(?:\.pypirc|pip\.conf)/gi, desc: ".pypirc credential file" },
        { regex: /(?:readFile|readFileSync|open|cat)\s*\([^)]*(?:\.docker\/config\.json)/gi, desc: "Docker credential file" },
        { regex: /(?:readFile|readFileSync|open|cat)\s*\([^)]*(?:\.ssh\/id_)/gi, desc: "SSH private key" },
        { regex: /(?:readFile|readFileSync|open|cat)\s*\([^)]*(?:\.aws\/credentials)/gi, desc: "AWS credentials file" },
      ];

      for (const { regex, desc } of credFileReads) {
        regex.lastIndex = 0;
        const match = regex.exec(context.source_code);
        if (match) {
          const line = getLineNumber(context.source_code, match.index);
          findings.push({
            rule_id: "L13",
            severity: "critical",
            evidence: `Reading ${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
            remediation: `Never read ${desc} in application code. Use proper auth mechanisms.`,
            owasp_category: "MCP07-insecure-config",
            mitre_technique: "AML.T0057",
            confidence: 0.88,
            metadata: { analysis_type: "structural", line },
          });
          break;
        }
      }
    }

    return findings;
  }
}

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
          confidence: 0.85,
          metadata: { analysis_type: "structural", line },
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
          confidence: 0.90,
          metadata: { analysis_type: "structural", line },
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
            metadata: { analysis_type: "ast_taint" },
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
          findings.push({
            rule_id: "K8",
            severity: "critical",
            evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
            remediation: "Use scoped, per-service credentials. Never share API keys across trust boundaries.",
            owasp_category: "ASI03-identity-privilege-abuse",
            mitre_technique: "AML.T0054",
            confidence: 0.75,
            metadata: { analysis_type: "structural", line },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── Register ──────────────────────────────────────────────────────────────

registerTypedRule(new ActionsTagPoisoningRule());
registerTypedRule(new MaliciousBuildPluginRule());
registerTypedRule(new ConfigSymlinkRule());
registerTypedRule(new TransitiveMCPDelegationRule());
registerTypedRule(new CredentialFileTheftRule());
registerTypedRule(new AuditLogTamperingRule());
registerTypedRule(new AutoApproveBypassRule());
registerTypedRule(new CrossBoundaryCredentialRule());
