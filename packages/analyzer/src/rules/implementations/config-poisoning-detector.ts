/**
 * Config Poisoning Detector — Deep analysis for J1, L4, L11, Q4
 *
 * Detects code that writes to agent/IDE config files with malicious content.
 * Uses taint analysis to trace WHAT is written, not just WHERE.
 *
 * What this catches that YAML regex can't:
 * - J1: Content from untrusted source written to .claude/.cursor config
 * - L4: Shell execution hidden in MCP config command field
 * - L11: Env var injection (LD_PRELOAD, NODE_OPTIONS) via config env block
 * - Q4: IDE config write with auto-approve patterns
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { analyzeASTTaint } from "../analyzers/taint-ast.js";
import { analyzeTaint } from "../analyzers/taint.js";

// ─── Shared config path patterns ───────────────────────────────────────────

const AGENT_CONFIG_PATHS = [
  /\.claude\b/i, /\.cursor\b/i, /\.vscode\b/i, /\.gemini\b/i,
  /mcp\.json/i, /mcp_config/i, /claude_desktop_config/i,
  /\.mcp\.json/i, /settings\.json.*mcp/i,
];

const DANGEROUS_ENV_VARS = [
  /LD_PRELOAD/i, /DYLD_INSERT_LIBRARIES/i, /DYLD_LIBRARY_PATH/i,
  /NODE_OPTIONS/i, /PYTHONPATH/i, /PYTHONSTARTUP/i,
  /ANTHROPIC_API_URL/i, /OPENAI_API_BASE/i, /OPENAI_BASE_URL/i,
  /API_BASE_URL/i, /AZURE_OPENAI_ENDPOINT/i,
  /HTTP_PROXY/i, /HTTPS_PROXY/i, /ALL_PROXY/i,
];

const AUTO_APPROVE_PATTERNS = [
  /auto[_\s-]?approve/i, /enableAll/i, /enableAllProjectMcpServers/i,
  /enabledMcpjsonServers/i, /auto[_\s-]?start/i, /auto[_\s-]?connect/i,
];

const SHELL_EXEC_PATTERNS = [
  /["']command["']\s*:\s*["'](?:bash|sh|zsh|cmd|powershell)\s+-[ce]\s/,
  /shell\s*:\s*true/,
  /(?:spawn|exec|fork).*(?:shell\s*:\s*true)/,
];

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

function getLineNumber(source: string, index: number): number {
  return source.substring(0, index).split("\n").length;
}

// ─── J1: Cross-Agent Configuration Poisoning ──────────────────────────────

class CrossAgentConfigPoisoningRule implements TypedRule {
  readonly id = "J1";
  readonly name = "Cross-Agent Configuration Poisoning (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];

    // Phase 1: Taint analysis — trace data flow to config file writes
    try {
      const astFlows = analyzeASTTaint(context.source_code);
      const configWriteFlows = astFlows.filter(
        (f) => f.sink.category === "file_write" &&
          AGENT_CONFIG_PATHS.some((p) => p.test(f.sink.expression))
      );

      for (const flow of configWriteFlows) {
        if (!flow.sanitized) {
          findings.push({
            rule_id: "J1",
            severity: "critical",
            evidence:
              `[AST taint] Untrusted ${flow.source.category} data ` +
              `"${flow.source.expression}" (L${flow.source.line}) flows to agent config write ` +
              `"${flow.sink.expression.slice(0, 60)}" (L${flow.sink.line}). ` +
              `${flow.path.length} propagation step(s). ` +
              `Compromised upstream agent can inject malicious MCP servers into downstream config.`,
            remediation:
              "Never write to other agents' config files (.claude/, .cursor/, mcp.json) " +
              "with untrusted data. Validate and sanitize all content before config writes. " +
              "Use separate config files per trust boundary.",
            owasp_category: "MCP05-privilege-escalation",
            mitre_technique: "AML.T0060",
            confidence: flow.confidence,
            metadata: {
              analysis_type: "ast_taint",
              source_line: flow.source.line,
              sink_line: flow.sink.line,
            },
          });
        }
      }
    } catch {
      // AST parsing failed
    }

    // Phase 2: Pattern fallback — detect config file writes without full taint
    if (findings.length === 0) {
      const lines = context.source_code.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const writesConfig =
          /(?:writeFile|writeFileSync|fs\.write|open.*['"]w)/.test(line) &&
          AGENT_CONFIG_PATHS.some((p) => p.test(line));

        if (writesConfig) {
          findings.push({
            rule_id: "J1",
            severity: "high",
            evidence:
              `[Regex fallback] Config file write at line ${i + 1}: "${line.trim().slice(0, 80)}". ` +
              `Taint analysis could not confirm untrusted data flow — manual review needed.`,
            remediation:
              "Verify that the content written to agent config files does not come from " +
              "untrusted sources. Cross-agent config writes enable RCE (CVE-2025-53773).",
            owasp_category: "MCP05-privilege-escalation",
            mitre_technique: "AML.T0060",
            confidence: 0.60,
            metadata: { analysis_type: "regex_fallback", line: i + 1 },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── L4: MCP Config File Code Injection ───────────────────────────────────

class MCPConfigCodeInjectionRule implements TypedRule {
  readonly id = "L4";
  readonly name = "MCP Config File Code Injection";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Detect shell execution in MCP config command fields
    for (const pattern of SHELL_EXEC_PATTERNS) {
      const match = pattern.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        // Check if this is within an MCP config context
        const surroundingText = source.substring(
          Math.max(0, match.index - 200),
          Math.min(source.length, match.index + 200)
        );
        const isMCPConfig = /mcpServers|mcp\.json|mcp_config|claude_desktop/i.test(surroundingText);

        if (isMCPConfig) {
          findings.push({
            rule_id: "L4",
            severity: "critical",
            evidence:
              `Shell execution in MCP config at line ${line}: "${match[0].slice(0, 80)}". ` +
              `MCP config command field should use direct binary paths, not shell interpreters.`,
            remediation:
              "Replace shell commands (bash -c, sh -c) in MCP config with direct binary paths. " +
              "Never use shell: true. Validate command fields against an allowlist. " +
              "See CVE-2025-59536 (Claude Code config injection).",
            owasp_category: "MCP05-privilege-escalation",
            mitre_technique: "AML.T0060",
            confidence: 0.90,
            metadata: { analysis_type: "structural", line },
          });
        }
      }
    }

    // Detect env var exfiltration via MCP config
    const envExfilPattern = /["'](?:args|command)["'].*(?:process\.env|\$\{?(?:API_KEY|TOKEN|SECRET|DATABASE|PASSWORD))/gi;
    let match: RegExpExecArray | null;
    envExfilPattern.lastIndex = 0;
    while ((match = envExfilPattern.exec(source)) !== null) {
      const line = getLineNumber(source, match.index);
      findings.push({
        rule_id: "L4",
        severity: "critical",
        evidence:
          `Environment variable reference in MCP config args at line ${line}: "${match[0].slice(0, 80)}". ` +
          `Sensitive env vars in MCP config args can be exfiltrated to malicious server endpoints.`,
        remediation:
          "Never pass sensitive environment variables (API keys, tokens) as MCP server arguments. " +
          "Use dedicated credential stores or OAuth. See CVE-2026-21852.",
        owasp_category: "MCP07-insecure-config",
        mitre_technique: "AML.T0060",
        confidence: 0.85,
        metadata: { analysis_type: "pattern", line },
      });
      break;
    }

    return findings;
  }
}

// ─── L11: Environment Variable Injection via MCP Config ───────────────────

class EnvVarInjectionRule implements TypedRule {
  readonly id = "L11";
  readonly name = "Environment Variable Injection via MCP Config";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Detect dangerous env vars in MCP config env blocks
    for (const envPattern of DANGEROUS_ENV_VARS) {
      const searchPattern = new RegExp(
        `["']env["']\\s*:\\s*\\{[^}]*["']${envPattern.source}["']`,
        "gi"
      );
      const match = searchPattern.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const envName = envPattern.source.replace(/\\/g, "");

        findings.push({
          rule_id: "L11",
          severity: "critical",
          evidence:
            `Dangerous environment variable "${envName}" in MCP config env block at line ${line}. ` +
            `This can hijack library loading (LD_PRELOAD), inject Node.js code (NODE_OPTIONS), ` +
            `or redirect API calls to attacker-controlled endpoints (ANTHROPIC_API_URL).`,
          remediation:
            `Remove "${envName}" from MCP config env blocks. ` +
            "Only safe env vars (PORT, HOST, LOG_LEVEL, NODE_ENV) should be in config. " +
            "See CVE-2026-21852 (API key exfiltration via config env override).",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0060",
          confidence: 0.90,
          metadata: { analysis_type: "pattern", line, env_var: envName },
        });
      }
    }

    return findings;
  }
}

// ─── Q4: IDE MCP Configuration Injection ──────────────────────────────────

class IDEConfigInjectionRule implements TypedRule {
  readonly id = "Q4";
  readonly name = "IDE MCP Configuration Injection (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Phase 1: Taint — trace untrusted data to IDE config writes
    try {
      const astFlows = analyzeASTTaint(source);
      const ideWriteFlows = astFlows.filter(
        (f) => f.sink.category === "file_write" &&
          /\.cursor|\.vscode|mcp\.json|settings\.json/i.test(f.sink.expression)
      );

      for (const flow of ideWriteFlows) {
        if (!flow.sanitized) {
          findings.push({
            rule_id: "Q4",
            severity: "critical",
            evidence:
              `[AST taint] ${flow.source.category} data flows to IDE config write ` +
              `(L${flow.source.line} → L${flow.sink.line}). ` +
              `CVE-2025-54135 "CurXecute": malicious project writes to .cursor config.`,
            remediation:
              "Never write to IDE config files (.cursor/, .vscode/, mcp.json) from untrusted sources. " +
              "Validate all server registrations. See CVE-2025-54135, CVE-2025-59536.",
            owasp_category: "MCP10-supply-chain",
            mitre_technique: "AML.T0054",
            confidence: flow.confidence,
            metadata: { analysis_type: "ast_taint" },
          });
        }
      }
    } catch {
      // Fall through
    }

    // Phase 2: Detect auto-approve patterns in config writes
    for (const pattern of AUTO_APPROVE_PATTERNS) {
      const match = pattern.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        // Check surrounding context for config write
        const context200 = source.substring(
          Math.max(0, match.index - 200),
          Math.min(source.length, match.index + 200)
        );
        const isConfigContext = /(?:write|create|modify|update|save|fs\.)/.test(context200) &&
          /(?:\.cursor|\.vscode|mcp\.json|settings)/i.test(context200);

        if (isConfigContext) {
          findings.push({
            rule_id: "Q4",
            severity: "critical",
            evidence:
              `Auto-approve pattern "${match[0]}" at line ${line} in IDE config write context. ` +
              `Enables silent MCP server execution without user consent.`,
            remediation:
              "Never set auto-approve patterns (enableAllProjectMcpServers, auto_approve) " +
              "programmatically. These must be explicit user choices.",
            owasp_category: "MCP10-supply-chain",
            mitre_technique: "AML.T0054",
            confidence: 0.88,
            metadata: { analysis_type: "pattern", line },
          });
          break;
        }
      }
    }

    // Phase 3: Detect case-sensitivity bypass (CVE-2025-59944)
    const caseBypass = /(?:MCP|Mcp|mCp|mcP)\.(?:JSON|Json|jSon|jsoN)/g;
    const caseMatch = caseBypass.exec(source);
    if (caseMatch) {
      const line = getLineNumber(source, caseMatch.index);
      findings.push({
        rule_id: "Q4",
        severity: "high",
        evidence:
          `Case-variant MCP config reference "${caseMatch[0]}" at line ${line}. ` +
          `CVE-2025-59944: case-insensitive config lookup bypasses approval.`,
        remediation:
          "Use exact case for MCP config file references. " +
          "Validate case-sensitivity in config path resolution.",
        owasp_category: "MCP10-supply-chain",
        mitre_technique: "AML.T0054",
        confidence: 0.80,
        metadata: { analysis_type: "pattern", line },
      });
    }

    return findings;
  }
}

// ─── Register ──────────────────────────────────────────────────────────────

registerTypedRule(new CrossAgentConfigPoisoningRule());
registerTypedRule(new MCPConfigCodeInjectionRule());
registerTypedRule(new EnvVarInjectionRule());
registerTypedRule(new IDEConfigInjectionRule());
