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
import { EvidenceChainBuilder } from "../../evidence.js";
import { computeCodeSignals } from "../../confidence-signals.js";

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
          const builder = new EvidenceChainBuilder()
            .source({
              source_type: "agent-output",
              location: `line ${flow.source.line}:${flow.source.column}`,
              observed: flow.source.expression,
              rationale:
                "Untrusted data enters from an external or agent-controlled source. In cross-agent " +
                "architectures, output from one agent can become input to another agent's configuration " +
                "writer — creating a lateral movement path between trust boundaries.",
            });

          for (const step of flow.path) {
            builder.propagation({
              propagation_type: step.type === "assignment" || step.type === "destructure" ? "variable-assignment"
                : step.type === "template_embed" ? "template-literal"
                : step.type === "return_value" || step.type === "callback_arg" ? "function-call"
                : "direct-pass",
              location: `line ${step.line}`,
              observed: step.expression.slice(0, 80),
            });
          }

          builder
            .sink({
              sink_type: "config-modification",
              location: `line ${flow.sink.line}:${flow.sink.column}`,
              observed: flow.sink.expression.slice(0, 80),
              cve_precedent: "CVE-2025-53773",
            })
            .mitigation({
              mitigation_type: "input-validation",
              present: false,
              location: `between source (L${flow.source.line}) and sink (L${flow.sink.line})`,
              detail:
                "No sanitization or schema validation found between the untrusted data source and the " +
                "config file write. Agent config files (.claude/, .cursor/, mcp.json) control which MCP " +
                "servers are loaded and auto-approved — unsanitized writes grant arbitrary code execution.",
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "other-agents",
              exploitability: flow.path.length <= 1 ? "trivial" : "moderate",
              scenario:
                "A compromised upstream agent writes a malicious MCP server entry into a downstream agent's " +
                "config file. When the downstream agent restarts, it loads the attacker-controlled server, which " +
                "gains full code execution on the host. CVE-2025-53773 demonstrated this exact chain in GitHub Copilot.",
            })
            .factor("ast_confirmed", 0.15, "AST-based taint tracking confirmed data flow from source to config write")
            .factor(
              "config_target_identified",
              0.1,
              `Sink expression matches known agent config path pattern — confirmed write to agent/IDE configuration`
            )
            .reference({
              id: "CVE-2025-53773",
              title: "GitHub Copilot Cross-Agent RCE via MCP Config Injection",
              url: "https://nvd.nist.gov/vuln/detail/CVE-2025-53773",
              year: 2025,
              relevance:
                "Same attack pattern: untrusted data written to agent config file enables RCE on downstream agent. " +
                "CVE-2025-53773 demonstrated this in GitHub Copilot through malicious .mcp.json writes.",
            })
            .verification({
              step_type: "trace-flow",
              instruction:
                `Trace the data flow from source at line ${flow.source.line} through ${flow.path.length} ` +
                `propagation step(s) to the config file write at line ${flow.sink.line}. Verify that no ` +
                `sanitizer, schema validator, or allowlist filter exists between the source and the sink. ` +
                `Check whether the written content could include arbitrary MCP server definitions.`,
              target: `source_code:${flow.source.line}-${flow.sink.line}`,
              expected_observation:
                `Data flows from ${flow.source.expression} through ${flow.path.length} step(s) to a file ` +
                `write targeting an agent config path. No validation or sanitization in the path.`,
            })
            .verification({
              step_type: "check-config",
              instruction:
                "Identify which agent config files this code can write to (.claude/settings.json, " +
                ".cursor/mcp.json, claude_desktop_config.json, etc.). Check whether auto-approve or " +
                "auto-start settings could be set by the written content. Verify whether the target config " +
                "format allows embedding shell commands in the 'command' field of server entries.",
              target: "agent configuration file format and security boundaries",
              expected_observation:
                "Config file format allows arbitrary server entries with 'command' fields that execute " +
                "shell commands. No integrity verification or user confirmation before loading new servers.",
            });

          const chain = builder.build();

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
              evidence_chain: chain,
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
          const chain = new EvidenceChainBuilder()
            .source({
              source_type: "agent-output",
              location: `line ${i + 1}`,
              observed: line.trim().slice(0, 80),
              rationale:
                "Code writes to an agent configuration file path. The data source could not be confirmed " +
                "via taint analysis, but the write target is a known agent config path that controls MCP " +
                "server loading and execution.",
            })
            .sink({
              sink_type: "config-modification",
              location: `line ${i + 1}`,
              observed: line.trim().slice(0, 80),
              cve_precedent: "CVE-2025-53773",
            })
            .mitigation({
              mitigation_type: "input-validation",
              present: false,
              location: `line ${i + 1}`,
              detail:
                "Taint analysis could not trace the data source, so no sanitizer verification was possible. " +
                "Manual review is needed to confirm whether the written content comes from a trusted source.",
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "other-agents",
              exploitability: "moderate",
              scenario:
                "If the written content originates from an untrusted source, an attacker can inject a malicious " +
                "MCP server definition into the target agent's config. The next agent restart loads the attacker's " +
                "server, granting arbitrary code execution.",
            })
            .factor("regex_only", -0.15, "No taint analysis confirmation — regex pattern match only, manual review needed")
            .reference({
              id: "CVE-2025-53773",
              title: "GitHub Copilot Cross-Agent RCE via MCP Config Injection",
              year: 2025,
              relevance:
                "Config file write targeting agent paths matches the CVE-2025-53773 attack pattern " +
                "where malicious project files write to agent configurations.",
            })
            .verification({
              step_type: "inspect-source",
              instruction:
                `Examine source code at line ${i + 1} to determine what data is being written to the config file. ` +
                `Trace the data source manually — check whether it comes from user input, network responses, ` +
                `environment variables, or hardcoded values. If the source is untrusted, this is a confirmed finding.`,
              target: `source_code:${i + 1}`,
              expected_observation:
                `File write operation targeting an agent config path (.claude/, .cursor/, mcp.json). ` +
                `Data source should be verified manually.`,
            })
            .verification({
              step_type: "check-config",
              instruction:
                "Check whether the target config file format supports auto-approve or auto-start settings. " +
                "Verify whether writing arbitrary content to this file could cause the agent to load and " +
                "execute untrusted MCP servers without user confirmation.",
              target: "target agent configuration file schema",
              expected_observation:
                "Config format allows server entries with 'command' fields — an attacker-controlled " +
                "write to this file enables arbitrary command execution.",
            });

          const j1Signals = computeCodeSignals({
            sourceCode: context.source_code,
            matchLine: i + 1,
            matchText: line.trim(),
            lineText: line,
            context: context,
            owaspCategory: "MCP05-privilege-escalation",
          });
          for (const sig of j1Signals) {
            chain.factor(sig.factor, sig.adjustment, sig.rationale);
          }

          const j1Chain = chain.build();

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
            confidence: j1Chain.confidence,
            metadata: { analysis_type: "regex_fallback", line: i + 1, evidence_chain: j1Chain },
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
          const chain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `line ${line}`,
              observed: match[0].slice(0, 80),
              rationale:
                "MCP config command fields define what binary is executed when the server starts. " +
                "Using shell interpreters (bash -c, sh -c) instead of direct binary paths enables " +
                "shell metacharacter injection and arbitrary command chains via &&, ||, or ;.",
            })
            .sink({
              sink_type: "command-execution",
              location: `line ${line}`,
              observed: `Shell interpreter invocation in MCP config: ${match[0].slice(0, 60)}`,
              cve_precedent: "CVE-2025-59536",
            })
            .mitigation({
              mitigation_type: "input-validation",
              present: false,
              location: `MCP config command field at line ${line}`,
              detail:
                "No command allowlist or shell metacharacter filtering applied to the config command field. " +
                "Shell interpreters accept arbitrary command strings, bypassing any path-based restrictions.",
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "server-host",
              exploitability: "trivial",
              scenario:
                "A malicious project or compromised dependency writes an MCP config entry with 'bash -c' " +
                "as the command. The shell interprets the argument as an arbitrary command string, enabling " +
                "data exfiltration, reverse shells, or credential theft on the host machine. CVE-2025-59536 " +
                "demonstrated this exact vector in Claude Code config injection.",
            })
            .factor("shell_in_config", 0.15, "Shell interpreter explicitly invoked in config command field — high confidence")
            .factor("mcp_config_context", 0.1, "Pattern found within MCP configuration context (mcpServers/mcp.json)")
            .reference({
              id: "CVE-2025-59536",
              title: "Claude Code Config Injection via Shell Command in MCP Config",
              year: 2025,
              relevance:
                "CVE-2025-59536 demonstrated that shell commands in MCP config command fields enable " +
                "arbitrary code execution. The same pattern applies to all MCP clients that execute " +
                "config-defined server commands.",
            })
            .verification({
              step_type: "inspect-source",
              instruction:
                `Review the MCP config at line ${line} to confirm a shell interpreter (bash, sh, zsh, cmd, ` +
                `powershell) is used with -c or -e flags. Check whether the command string that follows the ` +
                `shell invocation contains dynamic content, environment variable expansion, or chained commands. ` +
                `Verify this is production code, not test fixtures.`,
              target: `source_code:${line}`,
              expected_observation:
                `Shell interpreter with execution flag found in MCP config command field. ` +
                `The command string may contain arbitrary shell syntax.`,
            })
            .verification({
              step_type: "check-config",
              instruction:
                "Examine how the MCP client loads and executes this config entry. Check whether the client " +
                "validates command fields against an allowlist of permitted binaries. Verify whether the client " +
                "uses execFile (safe — no shell) or exec/spawn with shell:true (unsafe — full shell interpretation). " +
                "If the client passes the command through a shell, any metacharacters are exploitable.",
              target: "MCP client server launch implementation",
              expected_observation:
                "Client executes config command through shell interpreter, enabling arbitrary command injection.",
            });

          const l4ShellSignals = computeCodeSignals({
            sourceCode: source,
            matchLine: line,
            matchText: match[0],
            lineText: source.split("\n")[line - 1] || "",
            context: context,
            owaspCategory: "MCP05-privilege-escalation",
          });
          for (const sig of l4ShellSignals) {
            chain.factor(sig.factor, sig.adjustment, sig.rationale);
          }

          const l4ShellChain = chain.build();

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
            confidence: l4ShellChain.confidence,
            metadata: { analysis_type: "structural", line, evidence_chain: l4ShellChain },
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
      const envChain = new EvidenceChainBuilder()
        .source({
          source_type: "environment",
          location: `line ${line}`,
          observed: match[0].slice(0, 80),
          rationale:
            "Sensitive environment variables (API keys, tokens, database credentials) are referenced " +
            "in MCP config args or command fields. These variables contain secrets that should never be " +
            "passed as arguments to external server processes.",
        })
        .propagation({
          propagation_type: "direct-pass",
          location: `MCP config args field at line ${line}`,
          observed: "Environment variable value is interpolated into server launch arguments, " +
            "which are visible to the server process and may be logged or transmitted",
        })
        .sink({
          sink_type: "credential-exposure",
          location: `line ${line}`,
          observed: `Sensitive env var in MCP config args: ${match[0].slice(0, 60)}`,
          cve_precedent: "CVE-2026-21852",
        })
        .mitigation({
          mitigation_type: "auth-check",
          present: false,
          location: `MCP config at line ${line}`,
          detail:
            "No credential management system (OAuth, secret store, encrypted config) is used. " +
            "Secrets are passed as plain-text arguments to the MCP server process, exposing them " +
            "to process inspection, /proc/cmdline, and server-side logging.",
        })
        .impact({
          impact_type: "credential-theft",
          scope: "connected-services",
          exploitability: "trivial",
          scenario:
            "API keys and tokens passed as MCP server arguments are visible to the server process. " +
            "A malicious or compromised MCP server can read its own arguments, exfiltrate the credentials " +
            "to an attacker-controlled endpoint, and gain access to the victim's cloud services, databases, " +
            "or AI provider accounts.",
        })
        .factor("env_var_in_args", 0.1, "Sensitive environment variable pattern detected in config args")
        .reference({
          id: "CVE-2026-21852",
          title: "API Key Exfiltration via MCP Config Env Override",
          year: 2026,
          relevance:
            "CVE-2026-21852 documented how sensitive environment variables passed in MCP config " +
            "were exfiltrated by malicious servers reading their own process arguments.",
        })
        .verification({
          step_type: "inspect-source",
          instruction:
            `Review the MCP config at line ${line} to identify which environment variables are referenced. ` +
            `Determine whether these contain secrets (API_KEY, TOKEN, SECRET, PASSWORD, DATABASE) or ` +
            `non-sensitive values (PORT, HOST, LOG_LEVEL). Check whether the values are passed as command-line ` +
            `arguments (visible in process list) or as environment variables (slightly less exposed).`,
          target: `source_code:${line}`,
          expected_observation:
            `Sensitive environment variable reference in MCP config args, exposing secrets to the server process.`,
        })
        .verification({
          step_type: "check-config",
          instruction:
            "Verify whether the MCP client uses a secure credential delivery mechanism (OAuth 2.0, " +
            "encrypted config, secret store integration) or passes secrets as plain-text arguments. " +
            "Check if the server process could read its own command-line arguments via /proc/self/cmdline " +
            "or process.argv to exfiltrate the credentials.",
          target: "MCP client credential delivery mechanism",
          expected_observation:
            "Credentials are passed as plain-text arguments — no secure credential delivery mechanism in use.",
        });

      const l4EnvSignals = computeCodeSignals({
        sourceCode: source,
        matchLine: line,
        matchText: match[0],
        lineText: source.split("\n")[line - 1] || "",
        context: context,
        owaspCategory: "MCP07-insecure-config",
      });
      for (const sig of l4EnvSignals) {
        envChain.factor(sig.factor, sig.adjustment, sig.rationale);
      }

      const l4EnvChain = envChain.build();

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
        confidence: l4EnvChain.confidence,
        metadata: { analysis_type: "pattern", line, evidence_chain: l4EnvChain },
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

        const isLibraryHijack = /LD_PRELOAD|DYLD_INSERT|DYLD_LIBRARY/i.test(envName);
        const isCodeInjection = /NODE_OPTIONS|PYTHONPATH|PYTHONSTARTUP/i.test(envName);
        const isAPIRedirect = /API_URL|API_BASE|OPENAI_BASE|AZURE.*ENDPOINT|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY/i.test(envName);

        const envChain = new EvidenceChainBuilder()
          .source({
            source_type: "environment",
            location: `line ${line}`,
            observed: `"${envName}" in MCP config env block`,
            rationale:
              "MCP config env blocks set environment variables for the server process at launch time. " +
              "Certain environment variables (LD_PRELOAD, NODE_OPTIONS, ANTHROPIC_API_URL) control " +
              "critical runtime behavior — library loading, code injection, or API endpoint routing — " +
              "and should never be configurable from untrusted sources.",
          })
          .sink({
            sink_type: isLibraryHijack ? "code-evaluation"
              : isAPIRedirect ? "network-send"
              : "config-modification",
            location: `MCP server process environment at line ${line}`,
            observed:
              isLibraryHijack
                ? `${envName} causes the dynamic linker to load attacker-controlled shared libraries before any other code`
                : isCodeInjection
                  ? `${envName} injects arbitrary code or module paths into the Node.js/Python runtime`
                  : isAPIRedirect
                    ? `${envName} redirects API calls to an attacker-controlled endpoint for credential interception`
                    : `${envName} modifies critical runtime behavior of the server process`,
            cve_precedent: "CVE-2026-21852",
          })
          .mitigation({
            mitigation_type: "input-validation",
            present: false,
            location: `MCP config env block at line ${line}`,
            detail:
              "No allowlist filtering on environment variables in the config env block. Dangerous variables " +
              "like LD_PRELOAD, NODE_OPTIONS, and API endpoint overrides should be blocked at the config " +
              "parsing layer — they grant equivalent-to-RCE capabilities to whoever controls the config.",
          })
          .impact({
            impact_type: isLibraryHijack || isCodeInjection ? "remote-code-execution" : "credential-theft",
            scope: "server-host",
            exploitability: "trivial",
            scenario:
              isLibraryHijack
                ? `Setting ${envName} in the MCP config causes the server process's dynamic linker to load ` +
                  `an attacker-controlled shared library (.so/.dylib) before the server's own code runs. ` +
                  `This grants arbitrary native code execution with the server's permissions — a complete host compromise.`
                : isCodeInjection
                  ? `Setting ${envName} in the MCP config injects arbitrary code or module paths into the ` +
                    `server's runtime. For NODE_OPTIONS, --require can preload malicious modules. For PYTHONPATH, ` +
                    `attacker-controlled modules shadow legitimate imports. Both achieve arbitrary code execution.`
                  : `Setting ${envName} in the MCP config redirects the server's API calls to an attacker-controlled ` +
                    `proxy endpoint. All API keys, tokens, and request data are intercepted. For AI service endpoints ` +
                    `(ANTHROPIC_API_URL, OPENAI_BASE_URL), this captures all model interactions including sensitive prompts.`,
          })
          .factor(
            isLibraryHijack ? "library_hijack_var" : isCodeInjection ? "code_injection_var" : "api_redirect_var",
            0.15,
            `${envName} is a known dangerous environment variable in the ${isLibraryHijack ? "library hijack" : isCodeInjection ? "code injection" : "API redirect"} category`
          )
          .reference({
            id: "CVE-2026-21852",
            title: "API Key Exfiltration via MCP Config Environment Override",
            year: 2026,
            relevance:
              "CVE-2026-21852 documented how MCP config env blocks were used to set dangerous environment " +
              "variables that redirected API calls and exfiltrated credentials. The same technique applies " +
              "to library hijack (LD_PRELOAD) and code injection (NODE_OPTIONS) variables.",
          })
          .verification({
            step_type: "inspect-source",
            instruction:
              `Locate the env block at line ${line} and confirm that "${envName}" is set. Determine whether ` +
              `the value is hardcoded or comes from an untrusted source (user input, network response, ` +
              `other config file). Even hardcoded dangerous env vars are a risk if the config file can be ` +
              `modified by untrusted code (see J1: cross-agent config poisoning).`,
            target: `source_code:${line}`,
            expected_observation:
              `Environment variable "${envName}" is set in the MCP config env block. ` +
              `This variable controls ${isLibraryHijack ? "shared library loading" : isCodeInjection ? "runtime code injection" : "API endpoint routing"}.`,
          })
          .verification({
            step_type: "check-config",
            instruction:
              "Check whether the MCP client validates environment variables before passing them to server " +
              "processes. Look for an allowlist of permitted env vars (PORT, HOST, LOG_LEVEL, NODE_ENV) or " +
              "a blocklist of dangerous ones (LD_PRELOAD, NODE_OPTIONS, *_PROXY). If neither exists, any " +
              "env var in the config is passed through to the server process without restriction.",
            target: "MCP client env variable filtering/validation logic",
            expected_observation:
              "No env variable filtering — all config-defined env vars are passed to the server process.",
          });

        const l11Signals = computeCodeSignals({
          sourceCode: source,
          matchLine: line,
          matchText: match[0],
          lineText: source.split("\n")[line - 1] || "",
          context: context,
          owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of l11Signals) {
          envChain.factor(sig.factor, sig.adjustment, sig.rationale);
        }

        const l11Chain = envChain.build();

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
          confidence: l11Chain.confidence,
          metadata: { analysis_type: "pattern", line, env_var: envName, evidence_chain: l11Chain },
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
          const builder = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `line ${flow.source.line}:${flow.source.column}`,
              observed: flow.source.expression,
              rationale:
                "Untrusted data enters from a project file, network response, or dependency output. " +
                "In the CurXecute attack pattern (CVE-2025-54135), a malicious project repo contains " +
                "code that writes to the IDE's MCP configuration during build or install.",
            });

          for (const step of flow.path) {
            builder.propagation({
              propagation_type: step.type === "assignment" || step.type === "destructure" ? "variable-assignment"
                : step.type === "template_embed" ? "template-literal"
                : "function-call",
              location: `line ${step.line}`,
              observed: step.expression.slice(0, 80),
            });
          }

          builder
            .sink({
              sink_type: "config-modification",
              location: `line ${flow.sink.line}:${flow.sink.column}`,
              observed: flow.sink.expression.slice(0, 80),
              cve_precedent: "CVE-2025-54135",
            })
            .mitigation({
              mitigation_type: "confirmation-gate",
              present: false,
              location: `between source (L${flow.source.line}) and sink (L${flow.sink.line})`,
              detail:
                "No user confirmation or integrity check before writing to IDE config. IDE configs control " +
                "which MCP servers are auto-loaded and auto-approved — an unchecked write silently adds " +
                "attacker-controlled servers that execute on next IDE launch.",
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "server-host",
              exploitability: flow.path.length <= 1 ? "trivial" : "moderate",
              scenario:
                "A malicious project contains code that writes a new MCP server entry to the IDE's configuration " +
                "(.cursor/mcp.json, .vscode/settings.json). When the developer opens the project, the write executes " +
                "silently. On next IDE restart, the attacker's MCP server loads with full access to the developer's " +
                "filesystem and credentials. CVE-2025-54135 (CurXecute) demonstrated this in Cursor IDE.",
            })
            .factor("ast_confirmed", 0.15, "AST taint analysis confirmed data flow to IDE config write")
            .reference({
              id: "CVE-2025-54135",
              title: "CurXecute: Cursor IDE Remote Code Execution via .cursor Config Injection",
              year: 2025,
              relevance:
                "CVE-2025-54135 demonstrated that malicious project repos can write to .cursor/mcp.json, " +
                "silently registering attacker-controlled MCP servers that execute on IDE restart.",
            })
            .verification({
              step_type: "trace-flow",
              instruction:
                `Trace the taint path from line ${flow.source.line} to line ${flow.sink.line}. Verify that ` +
                `the data source is untrusted (project file, dependency, network) and that no user confirmation ` +
                `or content validation exists in the path. Check if the written content can include 'command' ` +
                `fields with shell execution or 'auto-approve' settings.`,
              target: `source_code:${flow.source.line}-${flow.sink.line}`,
              expected_observation:
                "Untrusted data flows to IDE config write without user confirmation or content validation.",
            })
            .verification({
              step_type: "check-config",
              instruction:
                "Check whether the target IDE validates or sandboxes MCP server entries added to its config. " +
                "Verify if the IDE prompts the user before loading newly-added servers, or if they auto-start. " +
                "Check for enableAllProjectMcpServers or similar auto-approve settings that would bypass " +
                "any user confirmation for project-level MCP configs.",
              target: "IDE MCP server loading and approval logic",
              expected_observation:
                "IDE auto-loads MCP servers from config without user confirmation, enabling silent " +
                "code execution from injected server entries.",
            });

          const chain = builder.build();

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
            metadata: { analysis_type: "ast_taint", evidence_chain: chain },
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
          const autoApproveChain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `line ${line}`,
              observed: `Auto-approve pattern: "${match[0]}"`,
              rationale:
                "Code programmatically sets auto-approve or auto-start settings in IDE MCP configuration. " +
                "These settings should only be set by explicit user choice, never by project code or dependencies.",
            })
            .sink({
              sink_type: "privilege-grant",
              location: `line ${line}`,
              observed: `Auto-approve pattern "${match[0]}" in IDE config write context — bypasses user consent`,
              cve_precedent: "CVE-2025-59944",
            })
            .mitigation({
              mitigation_type: "confirmation-gate",
              present: false,
              location: `config write at line ${line}`,
              detail:
                "No user confirmation before setting auto-approve. Once set, all project-level MCP servers " +
                "execute without consent — a single config write disables the entire human-in-the-loop safety barrier.",
            })
            .impact({
              impact_type: "privilege-escalation",
              scope: "ai-client",
              exploitability: "trivial",
              scenario:
                "Code writes an auto-approve setting (enableAllProjectMcpServers, auto_start) to the IDE config. " +
                "Once enabled, any MCP server defined in the project's config executes automatically without user " +
                "approval. Combined with a malicious server entry, this achieves silent code execution — the user " +
                "never sees a confirmation dialog.",
            })
            .factor("auto_approve_in_config", 0.15, "Auto-approve pattern found within IDE config write context")
            .reference({
              id: "CVE-2025-59944",
              title: "Case-Insensitive Config Bypass for MCP Auto-Approval",
              year: 2025,
              relevance:
                "Auto-approve settings bypass all user consent for MCP server loading. CVE-2025-59944 " +
                "showed that case-sensitivity bypasses could enable auto-approval without explicit user consent.",
            })
            .verification({
              step_type: "inspect-source",
              instruction:
                `Examine line ${line} to confirm the auto-approve pattern is being written to an IDE config file. ` +
                `Determine whether this write is triggered by user action (safe) or by project code, build scripts, ` +
                `or dependencies (dangerous). Check the full write content for other dangerous settings like shell ` +
                `commands or credential references.`,
              target: `source_code:${line}`,
              expected_observation:
                `Auto-approve pattern "${match[0]}" is being set programmatically in IDE MCP config, not by user action.`,
            })
            .verification({
              step_type: "check-config",
              instruction:
                "Verify the impact of the auto-approve setting on MCP server loading. Check whether the IDE " +
                "skips user confirmation dialogs when this setting is enabled. Determine if project-level MCP " +
                "configs can define arbitrary server commands that would execute without user consent once " +
                "auto-approve is active.",
              target: "IDE auto-approve behavior and MCP server loading flow",
              expected_observation:
                "With auto-approve enabled, all project-level MCP servers load and execute without user " +
                "confirmation, including servers with shell commands in their 'command' field.",
            });

          const q4AutoSignals = computeCodeSignals({
            sourceCode: source,
            matchLine: line,
            matchText: match[0],
            lineText: source.split("\n")[line - 1] || "",
            context: context,
            owaspCategory: "MCP10-supply-chain",
          });
          for (const sig of q4AutoSignals) {
            autoApproveChain.factor(sig.factor, sig.adjustment, sig.rationale);
          }

          const q4AutoChain = autoApproveChain.build();

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
            confidence: q4AutoChain.confidence,
            metadata: { analysis_type: "pattern", line, evidence_chain: q4AutoChain },
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
      const caseChain = new EvidenceChainBuilder()
        .source({
          source_type: "external-content",
          location: `line ${line}`,
          observed: `Case-variant MCP config reference: "${caseMatch[0]}"`,
          rationale:
            "A non-standard case variant of the MCP config filename is used (e.g., MCP.JSON instead of mcp.json). " +
            "On case-insensitive filesystems (macOS, Windows), this resolves to the same file but may bypass " +
            "case-sensitive security checks that validate config file paths.",
        })
        .sink({
          sink_type: "config-modification",
          location: `line ${line}`,
          observed: `"${caseMatch[0]}" — case variant may bypass approval checks that only match lowercase`,
          cve_precedent: "CVE-2025-59944",
        })
        .mitigation({
          mitigation_type: "input-validation",
          present: false,
          location: `config path validation at line ${line}`,
          detail:
            "Config path validation uses case-sensitive string comparison. On case-insensitive filesystems, " +
            "a case variant like MCP.JSON bypasses the check but resolves to the same file as mcp.json.",
        })
        .impact({
          impact_type: "privilege-escalation",
          scope: "ai-client",
          exploitability: "moderate",
          scenario:
            "An attacker uses a case-variant filename (MCP.JSON, Mcp.json) to write to the MCP config file " +
            "while bypassing case-sensitive path validation. On macOS and Windows (case-insensitive filesystems), " +
            "the variant resolves to the same file. Security checks that only match the lowercase form are evaded, " +
            "allowing unauthorized server registration.",
        })
        .factor("case_variant_detected", 0.1, "Non-standard case variant of MCP config filename suggests intentional bypass")
        .reference({
          id: "CVE-2025-59944",
          title: "Case-Insensitive MCP Config Bypass for Server Approval",
          year: 2025,
          relevance:
            "CVE-2025-59944 demonstrated that case-insensitive config file lookup enabled bypass of " +
            "server approval mechanisms. Attackers used case variants to write to config files without " +
            "triggering case-sensitive security checks.",
        })
        .verification({
          step_type: "inspect-source",
          instruction:
            `Check whether the case-variant reference "${caseMatch[0]}" at line ${line} is used to write to ` +
            `or read from a config file. Determine whether the application's config path validation is ` +
            `case-sensitive (bypassable on macOS/Windows) or case-insensitive (correct). Test whether the ` +
            `case variant resolves to the same file as the standard lowercase form on the target platform.`,
          target: `source_code:${line}`,
          expected_observation:
            `Case-variant "${caseMatch[0]}" used in config path — may bypass case-sensitive validation on ` +
            `case-insensitive filesystems.`,
        })
        .verification({
          step_type: "check-config",
          instruction:
            "Test the target platform's filesystem case sensitivity. On macOS (APFS default) and Windows " +
            "(NTFS), verify that MCP.JSON and mcp.json resolve to the same file. Check whether the IDE's " +
            "config loading normalizes filenames to lowercase before validation, or whether case variants " +
            "can bypass the approval mechanism.",
          target: "filesystem case sensitivity and config path normalization",
          expected_observation:
            "On case-insensitive filesystems, the case variant resolves to the same config file, " +
            "bypassing case-sensitive validation.",
        });

      const q4CaseSignals = computeCodeSignals({
        sourceCode: source,
        matchLine: line,
        matchText: caseMatch[0],
        lineText: source.split("\n")[line - 1] || "",
        context: context,
        owaspCategory: "MCP10-supply-chain",
      });
      for (const sig of q4CaseSignals) {
        caseChain.factor(sig.factor, sig.adjustment, sig.rationale);
      }

      const q4CaseChain = caseChain.build();

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
        confidence: q4CaseChain.confidence,
        metadata: { analysis_type: "pattern", line, evidence_chain: q4CaseChain },
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
