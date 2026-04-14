/**
 * C1 — Command Injection Examiner
 *
 * This is the first rule migrated from the v1 TypedRule pattern to the
 * Examiner discipline. The detection pipeline is unchanged — we keep all
 * three phases (AST taint, regex taint, regex fallback) verbatim — but the
 * rule now declares:
 *
 *   • a research-cited hypothesis (CVE-2025-6514 as primary source)
 *   • an edge-case manifest with ≥5 variants, ≥4 adversarial mutations,
 *     ≥4 negative controls, and a CVE replay
 *   • cross-rule interactions (A8 cross-reference, J2 specialization,
 *     K9 related, C16 sibling)
 *
 * The declarative metadata is what the Phase 7.5 CI validator enforces.
 * The analyze() body is what the red-team fixture corpus exercises. Two
 * servers that trip C1 produce two different evidence chains — because
 * they were examined differently, observed differently, and had different
 * mitigations ruled in or out.
 *
 * Detection phases preserved from the v1 implementation:
 *   Phase 1: AST taint (TypeScript compiler API) — highest confidence
 *   Phase 2: Regex taint fallback — patterns AST can't parse
 *   Phase 3: Pattern fallback — broad-net with lower severity
 *
 * Confidence model (derived from evidence chain, not hardcoded result values):
 *   Direct flow (req.body → exec): 0.95
 *   Single-hop propagation:         0.85
 *   Multi-hop propagation:          0.70
 *   Regex fallback:                 0.50 (flagged "high" not "critical")
 */

import { Examiner, type Hypothesis, type EdgeCaseManifest, registerExaminer } from "../../examiner.js";
import type { RuleResult, RuleRequirements, AnalysisTechnique } from "../../base.js";
import type { AnalysisContext } from "../../../engine.js";
import { analyzeASTTaint, type ASTTaintFlow } from "../../analyzers/taint-ast.js";
import { analyzeTaint, type TaintFlow } from "../../analyzers/taint.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";

const OWASP = "MCP03-command-injection";
const MITRE = "AML.T0054";
const REMEDIATION =
  "Replace exec()/execSync() with execFile() and pass arguments as an array, never as a string. " +
  "Validate all inputs against an allowlist before use in any shell context. " +
  "For subprocess.run, always pass a list and shell=False. " +
  "Use a validation library (Zod, Joi) to constrain input before it reaches any shell function.";

/** Regex fallback patterns for when source code doesn't have enough structure for taint analysis */
const FALLBACK_PATTERNS = [
  { regex: /exec(?:Sync)?\s*\(`[^`]*\$\{/g, desc: "template literal in exec()", pattern_strength: 0.8 },
  { regex: /exec(?:Sync)?\s*\(\s*(?!['"`])(\w+)/g, desc: "variable passed to exec()", pattern_strength: 0.6 },
  { regex: /spawn(?:Sync)?\s*\([^)]*shell\s*:\s*true/g, desc: "spawnSync with shell: true", pattern_strength: 0.75 },
  { regex: /vm\.run(?:InNewContext|InThisContext|InContext)\s*\(/g, desc: "vm.runInNewContext with potential user input", pattern_strength: 0.65 },
  { regex: /subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True/g, desc: "subprocess with shell=True", pattern_strength: 0.7 },
  { regex: /os\.system\s*\(\s*(?!['"`])(\w+)/g, desc: "variable passed to os.system()", pattern_strength: 0.65 },
  { regex: /shell\.exec\s*\(/g, desc: "shelljs exec()", pattern_strength: 0.6 },
];

/** Patterns that indicate a safe usage (not injection) */
const SAFE_PATTERNS = [
  /exec(?:File|FileSync)\s*\(/, // execFile is the safe alternative
  /\/\/\s*safe:/,
  /\/\/\s*nosec/,
  /__tests?__/,
  /\.(?:test|spec)\./,
];

class C1CommandInjectionExaminer extends Examiner {
  readonly id = "C1";
  readonly name = "Command Injection";
  readonly technique: AnalysisTechnique = "ast-taint";
  readonly requires: RuleRequirements = { source_code: true };

  // ── Phase 1: HYPOTHESIS (research-grounded) ──────────────────────────────
  readonly hypothesis: Hypothesis = {
    statement:
      "An MCP server tool handler that passes unsanitized user-controlled input into a " +
      "shell-invoking API (exec, spawn with shell:true, execSync, Python subprocess " +
      "shell=True, os.system, shelljs.exec, vm.runInContext, template-literal exec) " +
      "enables remote command execution on the server host. The rule is only satisfied " +
      "when a source-to-sink flow exists without a sufficient sanitizer in the path.",
    threat_reference: {
      primary: {
        kind: "CVE",
        id: "CVE-2025-6514",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
        note: "mcp-remote OS command injection, CVSS 9.6 — canonical public exploit of MCP-surface command injection",
      },
      supporting: [
        {
          kind: "CVE",
          id: "CVE-2025-68143",
          note: "mcp-server-git path validation bypass + unrestricted git_init + arg injection chain",
        },
        {
          kind: "framework",
          id: "OWASP-MCP03",
          url: "https://owasp.org/www-project-mcp-top-10/",
          note: "OWASP MCP Top 10 — Command Injection",
        },
        {
          kind: "mitre",
          id: "AML.T0054",
          note: "MITRE ATLAS — LLM Plugin Compromise",
        },
      ],
    },
    attack_class: "remote-code-execution",
    derived_from: "owasp-mcp-top-10",
  };

  // ── Phase 4: EDGE-CASE MANIFEST (what variants are handled) ──────────────
  // The validator asserts ≥5 variants, ≥3 adversarial mutations, ≥3 negative
  // controls, and that the CVE replay exists and fires at ≥0.9 confidence.
  readonly edge_cases: EdgeCaseManifest = {
    variants: [
      {
        id: "v1-exec-user-input",
        kind: "true-positive",
        description: "exec(userInput, cb) — direct variable pass to child_process.exec",
        fixture: "c-code:C1:exec() with user input — basic",
      },
      {
        id: "v2-execsync-concat",
        kind: "true-positive",
        description: "execSync('ls ' + req.body.path) — string concatenation with request body",
        fixture: "c-code:C1:execSync with string concatenation",
      },
      {
        id: "v3-template-literal",
        kind: "true-positive",
        description: "exec(`ls ${req.query.dir}`) — template literal embedding request query",
        fixture: "c-code:C1:Template literal in exec",
      },
      {
        id: "v4-python-subprocess-shell",
        kind: "true-positive",
        description: "subprocess.run(cmd, shell=True) — Python shell=True with variable",
        fixture: "c-code:C1:Python subprocess with shell=True",
      },
      {
        id: "v5-vm-runincontext",
        kind: "true-positive",
        description: "vm.runInNewContext(userCode, sandbox) — JS VM sandbox-escape vector",
        fixture: "c-code:C1:vm.runInNewContext with user input",
      },
      {
        id: "v6-spawnsync-shell-true",
        kind: "true-positive",
        description: "spawnSync('bash', ['-c', userInput], { shell: true }) — shell:true with argv",
        fixture: "c-code:C1:spawnSync with shell: true",
      },
    ],
    adversarial_mutations: [
      {
        id: "adv1-alias-rename-sink",
        description: "const runCmd = execSync; runCmd(userInput) — sink aliased through rename",
        bypass: "alias-rename",
        fixture: "c-code:C1:adversarial alias-rename execSync",
      },
      {
        id: "adv2-base64-wrapped",
        description: "eval(Buffer.from(userInput, 'base64').toString()) — indirect sink via base64 decode",
        bypass: "encoding-base64",
        fixture: "c-code:C1:adversarial base64-wrapped eval",
      },
      {
        id: "adv3-spread-args-join",
        description: "exec([cmdHead, userInput].join(' ')) — array flattening disguising concatenation",
        bypass: "spread-args",
        fixture: "c-code:C1:adversarial spread-args join",
      },
      {
        id: "adv4-unicode-homoglyph-param",
        description: "Parameter named 'соmmand' (Cyrillic о) bypasses taint-source name list",
        bypass: "unicode-homoglyph",
        fixture: "c-code:C1:adversarial unicode homoglyph parameter",
      },
    ],
    known_safe_patterns: [
      {
        id: "neg1-execfile-array",
        description: "execFile('/usr/bin/git', ['status', '--porcelain'], cb) — argv array, no shell",
        rationale: "execFile does not spawn a shell; argv is passed directly to execve(2)",
        fixture: "c-code:C1:Safe: execFile with array args",
      },
      {
        id: "neg2-spawn-array",
        description: "spawn('ls', ['-la', sanitizedPath]) — argv array, no shell",
        rationale: "spawn without shell:true does not shell-interpret arguments",
        fixture: "c-code:C1:Safe: spawn with array args — no shell",
      },
      {
        id: "neg3-comment-only",
        description: "// We do not use exec() here — comment mention, not a call",
        rationale: "Comment text is not executable code; taint engine must not flag mentions",
        fixture: "c-code:C1:Comment mentioning exec — not actual call",
      },
      {
        id: "neg4-sql-execute",
        description: "db.execute('SELECT ...', [userId]) — SQL execute is not OS command",
        rationale: "db.execute is parameterized SQL dispatch, not shell invocation",
        fixture: "c-code:C1:SQL execute — not OS command",
      },
    ],
    cve_replays: [
      {
        cve: "CVE-2025-6514",
        fixture: "cve-replays:CVE-2025-6514",
        expected_confidence_min: 0.9,
      },
    ],
    interacts_with: [
      {
        rule_id: "A8",
        relation: "cross-reference",
        note: "Description-capability mismatch raises C1 prior when a 'read-only' tool has shell-invoking code",
      },
      {
        rule_id: "J2",
        relation: "specialized-by",
        note: "J2 (Git Argument Injection) is C1 specialized to git --upload-pack / --exec / --receive-pack",
      },
      {
        rule_id: "K9",
        relation: "related",
        note: "K9 (Dangerous Post-Install Hooks) is C1 at install time — same sinks, different entry point",
      },
      {
        rule_id: "C16",
        relation: "sibling",
        note: "C16 (Dynamic Code Evaluation) covers eval()/new Function() — code-eval analogs of exec()",
      },
    ],
  };

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code) return [];

    // Skip test files entirely — signal-to-noise is not worth it
    const isTestFile = /(?:__tests?__|\.(?:test|spec)\.)/.test(context.source_code);
    if (isTestFile) return [];

    const results: RuleResult[] = [];

    // ── Phase 1: AST taint (highest confidence) ────────────────────────────
    let astFlowCount = 0;
    try {
      const astFlows = analyzeASTTaint(context.source_code);
      const astCommandFlows = astFlows.filter(
        (f) => f.sink.category === "command_execution" || f.sink.category === "vm_escape",
      );
      for (const flow of astCommandFlows) {
        astFlowCount++;
        results.push(this.astFlowToResult(flow));
      }
    } catch (_err) {
      // AST parsing failed (malformed code, unsupported syntax) — fall through to regex taint
    }

    // ── Phase 2: Regex taint (fallback for patterns AST misses) ─────────────
    if (astFlowCount === 0) {
      const taintFlows = analyzeTaint(context.source_code);
      const commandFlows = taintFlows.filter((f) => f.sink.category === "command_execution");
      for (const flow of commandFlows) {
        results.push(this.taintFlowToResult(flow));
      }
    }

    // ── Phase 3: Pattern fallback (broad net, lower severity) ──────────────
    // Only runs if neither taint phase found anything critical, to avoid duplicate findings.
    const hasCritical = results.some((r) => r.severity === "critical");
    if (astFlowCount === 0 && !hasCritical) {
      results.push(...this.patternFallbackResults(context.source_code));
    }

    return results;
  }

  // ── Evidence chain builders ─────────────────────────────────────────────

  private astFlowToResult(flow: ASTTaintFlow): RuleResult {
    const chain = this.buildASTEvidenceChain(flow);
    return {
      rule_id: this.id,
      severity: flow.sanitized ? "informational" : "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: flow.sanitized
        ? "Sanitizer detected. Verify it handles all edge cases (metacharacters, encoding, argv-vs-string)."
        : REMEDIATION,
      chain,
    };
  }

  private buildASTEvidenceChain(flow: ASTTaintFlow): EvidenceChain {
    const builder = new EvidenceChainBuilder().source({
      source_type: "user-parameter",
      location: `line ${flow.source.line}:${flow.source.column}`,
      observed: flow.source.expression,
      rationale: `Untrusted ${flow.source.category} source enters here`,
    });

    for (const step of flow.path) {
      builder.propagation({
        propagation_type:
          step.type === "assignment" || step.type === "destructure"
            ? "variable-assignment"
            : step.type === "template_embed"
              ? "template-literal"
              : step.type === "return_value" || step.type === "callback_arg" || step.type === "parameter_binding"
                ? "function-call"
                : "direct-pass",
        location: `line ${step.line}`,
        observed: step.expression.slice(0, 80),
      });
    }

    builder.sink({
      sink_type: flow.sink.category === "vm_escape" ? "code-evaluation" : "command-execution",
      location: `line ${flow.sink.line}:${flow.sink.column}`,
      observed: flow.sink.expression.slice(0, 80),
      cve_precedent: "CVE-2025-6514",
    });

    if (flow.sanitized && flow.sanitizer_name) {
      builder.mitigation({
        mitigation_type: "sanitizer-function",
        present: true,
        location: `in taint path`,
        detail: `Sanitizer "${flow.sanitizer_name}" found — verify it handles all edge cases`,
      });
    } else {
      builder.mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: `between source (L${flow.source.line}) and sink (L${flow.sink.line})`,
        detail: "No sanitizer or validation found in the data flow path",
      });
    }

    builder
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: flow.path.length <= 1 ? "trivial" : "moderate",
        scenario: `Attacker provides crafted input via ${flow.source.category} → flows through ${flow.path.length} step(s) → reaches ${flow.sink.category} sink → arbitrary command execution on server host`,
      })
      .factor("ast_confirmed", 0.15, "AST-based taint tracking confirmed data flow")
      .reference({
        id: "CVE-2025-6514",
        title: "mcp-remote OS command injection (CVSS 9.6)",
        relevance: "Same attack pattern: user input reaching exec() without sanitization in MCP server",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Verify untrusted input at line ${flow.source.line} reaches command execution at line ${flow.sink.line}`,
        target: `source_code:${flow.source.line}-${flow.sink.line}`,
        expected_observation: `Data flows from ${flow.source.expression} through ${flow.path.length} step(s) to ${flow.sink.expression.slice(0, 40)}`,
      })
      .verification({
        step_type: "trace-flow",
        instruction: `Trace the taint path: ${flow.path.map((s) => `L${s.line}`).join(" → ")} and verify no sanitizer exists`,
        target: flow.path.map((s) => `line ${s.line}`).join(", "),
        expected_observation: "No sanitization or input validation between source and sink",
      });

    return builder.build();
  }

  private taintFlowToResult(flow: TaintFlow): RuleResult {
    const chain = this.buildTaintEvidenceChain(flow);
    return {
      rule_id: this.id,
      severity: flow.sanitized ? "informational" : "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: flow.sanitized
        ? "Sanitizer detected. Verify it handles all edge cases."
        : REMEDIATION,
      chain,
    };
  }

  private buildTaintEvidenceChain(flow: TaintFlow): EvidenceChain {
    const builder = new EvidenceChainBuilder().source({
      source_type: "user-parameter",
      location: `line ${flow.source.line}`,
      observed: flow.source.expression,
      rationale: `Untrusted ${flow.source.category} source enters here`,
    });

    for (const step of flow.propagation_chain) {
      builder.propagation({
        propagation_type:
          step.type === "assignment" || step.type === "destructure"
            ? "variable-assignment"
            : step.type === "string_concat"
              ? "string-concatenation"
              : step.type === "function_return"
                ? "function-call"
                : "direct-pass",
        location: `line ${step.line}`,
        observed: `${step.to} (via ${step.type})`,
      });
    }

    builder.sink({
      sink_type: "command-execution",
      location: `line ${flow.sink.line}`,
      observed: flow.sink.expression.slice(0, 80),
      cve_precedent: "CVE-2025-68143",
    });

    if (flow.sanitized && flow.sanitizer) {
      builder.mitigation({
        mitigation_type: "sanitizer-function",
        present: true,
        location: `line ${flow.sanitizer.line}`,
        detail: `Sanitizer "${flow.sanitizer.expression}" found in path`,
      });
    } else {
      builder.mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: `between source (L${flow.source.line}) and sink (L${flow.sink.line})`,
        detail: "No sanitizer or validation found in the data flow path",
      });
    }

    builder
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: flow.propagation_chain.length <= 1 ? "trivial" : "moderate",
        scenario: `Attacker input via ${flow.source.category} → ${flow.propagation_chain.length} propagation step(s) → command execution sink → arbitrary command execution`,
      })
      .reference({
        id: "CVE-2025-68143",
        title: "Anthropic mcp-server-git argument injection chain",
        relevance: "Same pattern: input propagation to command execution in MCP server context",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Verify untrusted input at line ${flow.source.line} reaches command execution at line ${flow.sink.line}`,
        target: `source_code:${flow.source.line}-${flow.sink.line}`,
        expected_observation: `Data flows from ${flow.source.expression} through ${flow.propagation_chain.length} step(s) to ${flow.sink.expression.slice(0, 40)}`,
      });

    return builder.build();
  }

  private patternFallbackResults(source: string): RuleResult[] {
    const results: RuleResult[] = [];
    for (const { regex, desc } of FALLBACK_PATTERNS) {
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(source)) !== null) {
        const line = source.substring(0, match.index).split("\n").length;
        const lineText = source.split("\n")[line - 1] || "";
        if (SAFE_PATTERNS.some((p) => p.test(lineText))) continue;

        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `line ${line}`,
            observed: match[0].slice(0, 80),
            rationale: "Regex pattern detected potential user input in command context",
          })
          .sink({
            sink_type: "command-execution",
            location: `line ${line}`,
            observed: desc,
          })
          .impact({
            impact_type: "remote-code-execution",
            scope: "server-host",
            exploitability: "moderate",
            scenario: `Potential command injection via ${desc} — taint analysis could not confirm, manual review needed`,
          })
          .factor("regex_only", -0.15, "No taint analysis confirmation — regex pattern match only")
          .reference({
            id: "T-EXEC-001",
            title: "Command injection in MCP servers",
            relevance: "Pattern matches known command injection vectors in MCP server code",
          })
          .verification({
            step_type: "inspect-source",
            instruction: `Examine source code at line ${line} for command execution with user input`,
            target: `source_code:${line}`,
            expected_observation: `${desc} pattern with potential user-controlled input`,
          })
          .build();

        results.push({
          rule_id: this.id,
          severity: "high", // Lower than taint-confirmed critical
          owasp_category: OWASP,
          mitre_technique: MITRE,
          remediation: REMEDIATION,
          chain,
        });
        break; // One finding per fallback pattern
      }
    }
    return results;
  }
}

registerExaminer(new C1CommandInjectionExaminer());
