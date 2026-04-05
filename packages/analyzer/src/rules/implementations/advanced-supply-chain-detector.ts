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
import { EvidenceChainBuilder } from "../../evidence.js";
import { computeCodeSignals } from "../../confidence-signals.js";

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
          const chain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `line ${i + 1}: uses: ${action}@${ref}`,
              observed: `${action}@${ref}`,
              rationale: "GitHub Actions mutable tags can be force-pushed by the upstream repository owner at any time. An attacker who compromises the upstream repo can replace the tag with malicious code that runs in every downstream CI pipeline.",
            })
            .sink({
              sink_type: "command-execution",
              location: `GitHub Actions runner executing ${action}@${ref}`,
              observed: `uses: ${action}@${ref} — mutable tag reference`,
              cve_precedent: "CWE-829",
            })
            .mitigation({
              mitigation_type: "input-validation",
              present: false,
              location: `line ${i + 1}`,
              detail: "No SHA pinning found for this Action reference. Mutable tags (main, master, latest, vN) can be silently replaced without any change to the workflow file.",
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "server-host",
              exploitability: "moderate",
              scenario: "An attacker compromises the upstream Action repository and force-pushes a new commit to the mutable tag. Every downstream workflow referencing this tag now executes attacker-controlled code with full CI runner access, including access to secrets.",
            })
            .factor("mutable_tag_reference", 0.1, "The reference uses a mutable tag pattern (main/master/latest/vN) rather than a SHA pin")
            .reference({
              id: "CVE-2025-30066",
              title: "tj-actions/changed-files tag poisoning",
              relevance: "Demonstrates real-world exploitation of mutable Action tags — attacker force-pushed a malicious commit to the v35 tag affecting thousands of repositories.",
            })
            .verification({
              step_type: "inspect-source",
              instruction: "Open the workflow file and locate the uses: directive at the indicated line. Confirm the Action reference uses a mutable tag (e.g., @main, @v1) rather than a full 40-character SHA hash.",
              target: `line ${i + 1}`,
              expected_observation: `uses: ${action}@${ref} with a mutable tag instead of a SHA pin`,
            })
            .verification({
              step_type: "check-dependency",
              instruction: "Check the upstream Action repository to verify whether the tag is mutable. Navigate to the Action repository on GitHub and check if the tag can be force-pushed or if the repository enforces tag protection rules.",
              target: `https://github.com/${action}`,
              expected_observation: "The tag is a mutable Git tag or branch name that can be updated without notification to downstream consumers",
            });

          const l1TagSignals = computeCodeSignals({
            sourceCode: context.source_code,
            matchLine: i + 1,
            matchText: `${action}@${ref}`,
            lineText: line,
            context,
            owaspCategory: "MCP10-supply-chain",
          });
          for (const sig of l1TagSignals) chain.factor(sig.factor, sig.adjustment, sig.rationale);
          const l1TagBuilt = chain.build();

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
            confidence: l1TagBuilt.confidence,
            metadata: { analysis_type: "structural", line: i + 1, action, ref, evidence_chain: l1TagBuilt },
          });
        }
      }

      // Pipe-to-shell: curl|bash in run step
      if (/(?:curl|wget)\s+.*\|\s*(?:bash|sh|sudo|python|node)/i.test(line)) {
        const l1PipeChain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `line ${i + 1}: ${line.slice(0, 80)}`,
            observed: line.slice(0, 100),
            rationale: "Remote script downloaded via curl/wget is untrusted external content that executes without integrity verification.",
          })
          .sink({
            sink_type: "command-execution",
            location: `line ${i + 1}`,
            observed: `Pipe-to-shell pattern: downloaded content piped directly to bash/sh/python/node`,
          })
          .impact({
            impact_type: "remote-code-execution",
            scope: "server-host",
            exploitability: "trivial",
            scenario: "An attacker who compromises the remote URL or performs a MITM attack can inject arbitrary code that executes with the CI runner's full privileges.",
          })
          .factor("pipe_to_shell", 0.15, "Direct pipe-to-shell is the highest-risk installation pattern — no checksum, no pinning")
          .verification({
            step_type: "inspect-source",
            instruction: "Locate the curl/wget | bash pattern at the indicated line. Confirm the downloaded script is piped directly to a shell interpreter without checksum verification.",
            target: `line ${i + 1}`,
            expected_observation: "curl or wget output piped to bash, sh, python, or node",
          });

        const l1PipeSignals = computeCodeSignals({
          sourceCode: context.source_code,
          matchLine: i + 1,
          matchText: line.slice(0, 80),
          lineText: line,
          context,
          owaspCategory: "MCP10-supply-chain",
        });
        for (const sig of l1PipeSignals) l1PipeChain.factor(sig.factor, sig.adjustment, sig.rationale);
        const l1PipeBuilt = l1PipeChain.build();

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
          confidence: l1PipeBuilt.confidence,
          metadata: { analysis_type: "structural", line: i + 1, evidence_chain: l1PipeBuilt },
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
          const l2TaintChain = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `line ${flow.source.line}: "${flow.source.expression}"`,
              observed: flow.source.expression,
              rationale: "Data originates in a build plugin context where plugins execute with full system access during compilation.",
            })
            .propagation({
              propagation_type: "function-call",
              location: `line ${flow.source.line} → line ${flow.sink.line}`,
              observed: `Taint flows from "${flow.source.expression}" to "${flow.sink.expression.slice(0, 50)}"`,
            })
            .sink({
              sink_type: flow.sink.category === "command_execution" ? "command-execution" : "network-send",
              location: `line ${flow.sink.line}`,
              observed: `${flow.sink.category}: "${flow.sink.expression.slice(0, 80)}"`,
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "server-host",
              exploitability: "moderate",
              scenario: "A malicious build plugin executes arbitrary commands or exfiltrates data during the build process, compromising the build output and potentially the CI environment.",
            })
            .factor("ast_taint_flow", 0.1, "Complete AST taint path from source to dangerous sink in build plugin context")
            .verification({
              step_type: "inspect-source",
              instruction: "Examine the build plugin code at the indicated lines. Confirm the taint flow from the source expression to the dangerous sink.",
              target: `lines ${flow.source.line}–${flow.sink.line}`,
              expected_observation: `Build plugin code with ${flow.sink.category} pattern`,
            })
            .build();

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
            metadata: { analysis_type: "ast_taint", evidence_chain: l2TaintChain },
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
          const l2StructChain = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `line ${line}: "${match[0].slice(0, 80)}"`,
              observed: match[0].slice(0, 100),
              rationale: "Build configuration file contains a plugin or hook with dangerous capabilities (network fetch, command execution, or environment exfiltration).",
            })
            .sink({
              sink_type: desc.includes("exec") ? "command-execution" : "network-send",
              location: `line ${line}`,
              observed: `${desc}: "${match[0].slice(0, 80)}"`,
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "server-host",
              exploitability: "moderate",
              scenario: "A build plugin with exec or network access can steal secrets, inject backdoors into build artifacts, or exfiltrate source code during the build process.",
            })
            .factor("structural_pattern", 0.05, "Structural pattern match in build configuration context")
            .verification({
              step_type: "inspect-source",
              instruction: "Open the build configuration file and examine the plugin/hook definition at the indicated line. Confirm it performs network requests or command execution.",
              target: `line ${line}`,
              expected_observation: desc,
            });

          const l2Signals = computeCodeSignals({
            sourceCode: context.source_code,
            matchLine: line,
            matchText: match[0].slice(0, 80),
            lineText: (context.source_code.split("\n")[line - 1] || ""),
            context,
            owaspCategory: "MCP10-supply-chain",
          });
          for (const sig of l2Signals) l2StructChain.factor(sig.factor, sig.adjustment, sig.rationale);
          const l2StructBuilt = l2StructChain.build();

          findings.push({
            rule_id: "L2",
            severity: "critical",
            evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
            remediation: "Build plugins should not make network requests or execute commands.",
            owasp_category: "MCP10-supply-chain",
            mitre_technique: "AML.T0017",
            confidence: l2StructBuilt.confidence,
            metadata: { analysis_type: "structural", line, evidence_chain: l2StructBuilt },
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
        const l6SymlinkChain = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${line}: "${match[0].slice(0, 80)}"`,
            observed: match[0].slice(0, 100),
            rationale: "Code creates a symlink targeting a sensitive system path, enabling escape from the intended directory scope.",
          })
          .sink({
            sink_type: "file-write",
            location: `line ${line}`,
            observed: `${desc}: symlink creation to sensitive path`,
            cve_precedent: "CVE-2025-53109",
          })
          .impact({
            impact_type: "privilege-escalation",
            scope: "server-host",
            exploitability: "moderate",
            scenario: "An attacker creates a symlink pointing to a sensitive system path (e.g., /etc/passwd, ~/.ssh). When the MCP server follows the symlink, it reads or writes outside its intended directory boundary, enabling data theft or config poisoning.",
          })
          .factor("sensitive_target_path", 0.1, "Symlink targets a known sensitive system directory")
          .reference({
            id: "CVE-2025-53109",
            title: "Anthropic filesystem MCP server symlink bypass",
            relevance: "Demonstrates real-world symlink-based directory traversal in an MCP server.",
          })
          .verification({
            step_type: "inspect-source",
            instruction: "Examine the symlink creation at the indicated line. Verify the target path is a sensitive system directory and that no realpath() or lstat() check precedes it.",
            target: `line ${line}`,
            expected_observation: `Symlink to sensitive path without protection: ${desc}`,
          });

        const l6SymSignals = computeCodeSignals({
          sourceCode: source,
          matchLine: line,
          matchText: match[0].slice(0, 80),
          lineText: (source.split("\n")[line - 1] || ""),
          context,
          owaspCategory: "MCP05-privilege-escalation",
        });
        for (const sig of l6SymSignals) l6SymlinkChain.factor(sig.factor, sig.adjustment, sig.rationale);
        const l6SymBuilt = l6SymlinkChain.build();

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
          confidence: l6SymBuilt.confidence,
          metadata: { analysis_type: "structural", line, evidence_chain: l6SymBuilt },
        });
      }
    }

    // Detect file access without symlink protection (TOCTOU)
    const toctouPattern = /(?:fs\.stat|statSync|os\.stat)[\s\S]{0,200}(?:fs\.readFile|readFileSync|open)(?!.*(?:O_NOFOLLOW|NOFOLLOW|lstat|realpath))/gi;
    const toctouMatch = toctouPattern.exec(source);
    if (toctouMatch) {
      const line = getLineNumber(source, toctouMatch.index);
      const l6ToctouChain = new EvidenceChainBuilder()
        .source({
          source_type: "file-content",
          location: `line ${line}: stat() followed by read()`,
          observed: toctouMatch[0].slice(0, 100),
          rationale: "A stat() call followed by a read() without O_NOFOLLOW creates a TOCTOU race window where an attacker can replace the file with a symlink.",
        })
        .propagation({
          propagation_type: "direct-pass",
          location: `line ${line}`,
          observed: "File path used in stat() is reused in subsequent read() without atomic open",
        })
        .sink({
          sink_type: "file-write",
          location: `line ${line}`,
          observed: "File read without O_NOFOLLOW or fstat() — vulnerable to symlink substitution between stat and open",
        })
        .impact({
          impact_type: "privilege-escalation",
          scope: "server-host",
          exploitability: "complex",
          scenario: "An attacker races between the stat() and read() calls, replacing the target file with a symlink to a sensitive file. The server then reads the symlinked file, bypassing directory boundary restrictions.",
        })
        .factor("toctou_race", 0.05, "TOCTOU race condition requires precise timing but is a proven attack vector")
        .verification({
          step_type: "inspect-source",
          instruction: "Locate the stat()/read() sequence and verify there is no O_NOFOLLOW flag or fstat() check on the opened file descriptor between the two operations.",
          target: `line ${line}`,
          expected_observation: "stat() followed by readFile/open without symlink protection",
        });

      const l6ToctouSignals = computeCodeSignals({
        sourceCode: source,
        matchLine: line,
        matchText: toctouMatch[0].slice(0, 80),
        lineText: (source.split("\n")[line - 1] || ""),
        context,
        owaspCategory: "MCP05-privilege-escalation",
      });
      for (const sig of l6ToctouSignals) l6ToctouChain.factor(sig.factor, sig.adjustment, sig.rationale);
      const l6ToctouBuilt = l6ToctouChain.build();

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
        confidence: l6ToctouBuilt.confidence,
        metadata: { analysis_type: "structural", line, evidence_chain: l6ToctouBuilt },
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
          const l13TaintChain = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `line ${flow.source.line}: "${flow.source.expression}"`,
              observed: flow.source.expression,
              rationale: "Credential file (.npmrc, .pypirc, .ssh/, .aws/credentials, .docker/config.json) is read by the application, exposing stored tokens and secrets.",
            })
            .propagation({
              propagation_type: "function-call",
              location: `line ${flow.source.line} → line ${flow.sink.line}`,
              observed: `Credential file content flows from "${flow.source.expression}" to network sink "${flow.sink.expression.slice(0, 50)}"`,
            })
            .sink({
              sink_type: "network-send",
              location: `line ${flow.sink.line}`,
              observed: `${flow.sink.category}: "${flow.sink.expression.slice(0, 80)}"`,
            })
            .impact({
              impact_type: "credential-theft",
              scope: "connected-services",
              exploitability: "moderate",
              scenario: "The MCP server reads a credential file (e.g., .npmrc with auth tokens) and exfiltrates its contents over the network to an attacker-controlled endpoint, enabling supply chain compromise of downstream registries.",
            })
            .factor("credential_file_exfil", 0.15, "AST taint confirms credential file read flows to network sink without sanitization")
            .verification({
              step_type: "trace-flow",
              instruction: "Trace the data flow from the credential file read to the network call. Confirm the file contents are sent over the network without redaction.",
              target: `lines ${flow.source.line}–${flow.sink.line}`,
              expected_observation: "Credential file content passed to HTTP request, fetch, or similar network API",
            })
            .build();

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
            metadata: { analysis_type: "ast_taint", evidence_chain: l13TaintChain },
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
          const l13StructChain = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `line ${line}: "${match[0].slice(0, 80)}"`,
              observed: match[0].slice(0, 100),
              rationale: `Application code reads a known credential file (${desc}), which typically contains authentication tokens, API keys, or private keys.`,
            })
            .sink({
              sink_type: "credential-exposure",
              location: `line ${line}`,
              observed: `Reading ${desc} into application memory`,
            })
            .impact({
              impact_type: "credential-theft",
              scope: "connected-services",
              exploitability: "moderate",
              scenario: `The MCP server reads ${desc} which contains authentication credentials. Even without an observed network exfiltration sink, loading credentials into memory creates a theft vector via logging, error messages, or tool responses.`,
            })
            .factor("credential_file_read", 0.1, "Direct read of a known credential file path")
            .verification({
              step_type: "trace-flow",
              instruction: `Search the source code for file read operations targeting ${desc}. Confirm the file path matches a known credential storage location.`,
              target: `line ${line}`,
              expected_observation: `readFile/readFileSync/open call with ${desc} path`,
            });

          const l13Signals = computeCodeSignals({
            sourceCode: context.source_code,
            matchLine: line,
            matchText: match[0].slice(0, 80),
            lineText: (context.source_code.split("\n")[line - 1] || ""),
            context,
            owaspCategory: "MCP07-insecure-config",
          });
          for (const sig of l13Signals) l13StructChain.factor(sig.factor, sig.adjustment, sig.rationale);
          const l13StructBuilt = l13StructChain.build();

          findings.push({
            rule_id: "L13",
            severity: "critical",
            evidence: `Reading ${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
            remediation: `Never read ${desc} in application code. Use proper auth mechanisms.`,
            owasp_category: "MCP07-insecure-config",
            mitre_technique: "AML.T0057",
            confidence: l13StructBuilt.confidence,
            metadata: { analysis_type: "structural", line, evidence_chain: l13StructBuilt },
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

registerTypedRule(new ActionsTagPoisoningRule());
registerTypedRule(new MaliciousBuildPluginRule());
registerTypedRule(new ConfigSymlinkRule());
registerTypedRule(new TransitiveMCPDelegationRule());
registerTypedRule(new CredentialFileTheftRule());
registerTypedRule(new AuditLogTamperingRule());
registerTypedRule(new AutoApproveBypassRule());
registerTypedRule(new CrossBoundaryCredentialRule());
