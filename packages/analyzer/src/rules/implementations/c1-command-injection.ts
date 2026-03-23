/**
 * C1 — Command Injection (Taint-Aware)
 *
 * REPLACES the YAML regex rule with taint analysis.
 *
 * Old behavior: Flags every `exec()` call in source code → massive false positives.
 * New behavior: Only flags when untrusted input can reach a command execution sink.
 *
 * Detection pipeline:
 * 1. Run taint analysis to find source→sink flows ending at command execution
 * 2. Check for sanitizers in the flow path
 * 3. Produce findings only for unsanitized flows
 * 4. Fall back to regex for languages/patterns taint analysis can't handle
 *
 * Confidence model:
 * - Direct flow (req.body → exec): 0.95
 * - Single-hop propagation: 0.85
 * - Multi-hop propagation: 0.70
 * - Regex fallback (no taint data): 0.50
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { analyzeASTTaint, type ASTTaintFlow } from "../analyzers/taint-ast.js";
import { analyzeTaint, type TaintFlow } from "../analyzers/taint.js";

const RULE_ID = "C1";
const RULE_NAME = "Command Injection (Taint-Aware)";
const OWASP = "MCP03-command-injection";
const MITRE = "AML.T0054";
const REMEDIATION =
  "Replace exec()/execSync() with execFile() and pass arguments as an array, never as a string. " +
  "Validate all inputs against an allowlist before use in any shell context. " +
  "For subprocess.run, always pass a list and shell=False. " +
  "Use a validation library (Zod, Joi) to constrain input before it reaches any shell function.";

/** Regex fallback patterns for when source code doesn't have enough structure for taint analysis */
const FALLBACK_PATTERNS = [
  // Template literal in exec — almost always injection
  { regex: /exec(?:Sync)?\s*\(`[^`]*\$\{/g, desc: "template literal in exec()", confidence: 0.8 },
  // exec with variable (not string literal)
  { regex: /exec(?:Sync)?\s*\(\s*(?!['"`])(\w+)/g, desc: "variable passed to exec()", confidence: 0.6 },
  // spawnSync with shell: true
  { regex: /spawn(?:Sync)?\s*\([^)]*shell\s*:\s*true/g, desc: "spawnSync with shell: true", confidence: 0.75 },
  // vm module (sandbox escape risk)
  { regex: /vm\.run(?:InNewContext|InThisContext|InContext)\s*\(/g, desc: "vm.runInNewContext with potential user input", confidence: 0.65 },
  // Python subprocess with shell=True and variable
  { regex: /subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True/g, desc: "subprocess with shell=True", confidence: 0.7 },
  // os.system with variable
  { regex: /os\.system\s*\(\s*(?!['"`])(\w+)/g, desc: "variable passed to os.system()", confidence: 0.65 },
  // shelljs
  { regex: /shell\.exec\s*\(/g, desc: "shelljs exec()", confidence: 0.6 },
];

/** Patterns that indicate a safe usage (not injection) */
const SAFE_PATTERNS = [
  /exec(?:File|FileSync)\s*\(/,  // execFile is the safe alternative
  /\/\/\s*safe:/,                 // Developer marked as safe
  /\/\/\s*nosec/,                 // nosec annotation
  /__tests?__/,                   // Test files
  /\.(?:test|spec)\./,            // Test files
];

class CommandInjectionRule implements TypedRule {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];

    // Check if entire file is a test file
    if (SAFE_PATTERNS.some((p) => p.test(context.source_code!))) {
      // Only skip if it's a test file pattern, not safe annotations
      const isTestFile = /(?:__tests?__|\.(?:test|spec)\.)/.test(context.source_code!);
      if (isTestFile) return [];
    }

    const findings: TypedFinding[] = [];

    // Phase 1: AST-based taint analysis (highest confidence)
    // Uses TypeScript compiler to parse source into a real AST,
    // then traces data flow through assignments, function calls, and returns.
    let astFlowCount = 0;
    try {
      const astFlows = analyzeASTTaint(context.source_code);
      const astCommandFlows = astFlows.filter(
        (f) => f.sink.category === "command_execution" || f.sink.category === "vm_escape"
      );

      for (const flow of astCommandFlows) {
        astFlowCount++;
        if (flow.sanitized) {
          findings.push({
            rule_id: RULE_ID,
            severity: "informational",
            evidence: this.formatASTEvidence(flow, true),
            remediation: "Sanitizer detected. Verify it handles all edge cases.",
            owasp_category: OWASP,
            mitre_technique: MITRE,
            confidence: flow.confidence * 0.3,
          });
        } else {
          findings.push({
            rule_id: RULE_ID,
            severity: "critical",
            evidence: this.formatASTEvidence(flow, false),
            remediation: REMEDIATION,
            owasp_category: OWASP,
            mitre_technique: MITRE,
            confidence: flow.confidence,
            metadata: {
              analysis_type: "ast_taint",
              source_category: flow.source.category,
              source_line: flow.source.line,
              sink_line: flow.sink.line,
              path_length: flow.path.length,
              path_steps: flow.path.map((s) => `${s.type}: ${s.expression}`),
            },
          });
        }
      }
    } catch (_err) {
      // AST parsing failed (malformed code, unsupported syntax)
      // Fall through to regex taint
    }

    // Phase 2: Regex-based taint analysis (fallback for patterns AST misses)
    // Only if AST found nothing — avoid duplicate findings
    if (astFlowCount === 0) {
      const taintFlows = analyzeTaint(context.source_code);
      const commandFlows = taintFlows.filter(
        (f) => f.sink.category === "command_execution"
      );

      for (const flow of commandFlows) {
        if (flow.sanitized) {
          findings.push({
            rule_id: RULE_ID,
            severity: "informational",
            evidence: this.formatTaintEvidence(flow, true),
            remediation: "Sanitizer detected. Verify it handles all edge cases.",
            owasp_category: OWASP,
            mitre_technique: MITRE,
            confidence: flow.confidence * 0.3,
          });
        } else {
          findings.push({
            rule_id: RULE_ID,
            severity: "critical",
            evidence: this.formatTaintEvidence(flow, false),
            remediation: REMEDIATION,
            owasp_category: OWASP,
            mitre_technique: MITRE,
            confidence: flow.confidence,
            metadata: {
              analysis_type: "taint",
              source_category: flow.source.category,
              source_line: flow.source.line,
              sink_line: flow.sink.line,
              propagation_length: flow.propagation_chain.length,
            },
          });
        }
      }
    }

    // Phase 3: Regex fallback for patterns neither AST nor regex taint catches
    // Only if no taint analysis found command flows
    if (astFlowCount === 0 && findings.filter((f) => f.severity === "critical").length === 0) {
      for (const { regex, desc, confidence } of FALLBACK_PATTERNS) {
        regex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = regex.exec(context.source_code)) !== null) {
          const line = context.source_code.substring(0, match.index).split("\n").length;

          // Check safe patterns at match location
          const lineText = context.source_code.split("\n")[line - 1] || "";
          if (SAFE_PATTERNS.some((p) => p.test(lineText))) continue;

          findings.push({
            rule_id: RULE_ID,
            severity: "high", // Lower than taint-confirmed critical
            evidence:
              `[Regex fallback] ${desc} at line ${line}: "${match[0].slice(0, 80)}". ` +
              `Taint analysis could not confirm data flow — manual review recommended.`,
            remediation: REMEDIATION,
            owasp_category: OWASP,
            mitre_technique: MITRE,
            confidence,
            metadata: {
              analysis_type: "regex_fallback",
              line,
              pattern: desc,
            },
          });
          break; // One finding per fallback pattern
        }
      }
    }

    return findings;
  }

  private formatASTEvidence(flow: ASTTaintFlow, sanitized: boolean): string {
    const pathStr =
      flow.path.length > 0
        ? ` → ${flow.path.map((s) => `${s.type}(${s.expression.slice(0, 50)}, L${s.line})`).join(" → ")}`
        : "";

    const sanitizerStr = sanitized && flow.sanitizer_name
      ? ` [SANITIZED by ${flow.sanitizer_name}]`
      : "";

    return (
      `[AST taint analysis] Untrusted ${flow.source.category} source ` +
      `"${flow.source.expression}" (L${flow.source.line}:${flow.source.column})` +
      `${pathStr} → reaches ${flow.sink.category} sink ` +
      `"${flow.sink.expression.slice(0, 60)}" (L${flow.sink.line}:${flow.sink.column})` +
      `${sanitizerStr}. ` +
      `AST-confirmed data flow with ${flow.path.length} intermediate step(s). ` +
      `Confidence: ${(flow.confidence * 100).toFixed(0)}%.`
    );
  }

  private formatTaintEvidence(flow: TaintFlow, sanitized: boolean): string {
    const chain = flow.propagation_chain;
    const chainStr =
      chain.length > 0
        ? ` → ${chain.map((p) => `${p.to} (line ${p.line}, ${p.type})`).join(" → ")}`
        : "";

    const sanitizerStr = sanitized && flow.sanitizer
      ? ` [SANITIZED by ${flow.sanitizer.expression} at line ${flow.sanitizer.line}]`
      : "";

    return (
      `[Taint analysis] Untrusted ${flow.source.category} source ` +
      `"${flow.source.expression}" (line ${flow.source.line})` +
      `${chainStr} → reaches command execution sink ` +
      `"${flow.sink.expression.slice(0, 60)}" (line ${flow.sink.line})` +
      `${sanitizerStr}. ` +
      `Confidence: ${(flow.confidence * 100).toFixed(0)}%.`
    );
  }
}

registerTypedRule(new CommandInjectionRule());
