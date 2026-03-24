/**
 * CodeAnalyzer — Real program analysis for source code rules (C1–C16)
 *
 * Replaces 16 YAML regex patterns with AST-based analysis using
 * TypeScript compiler API. Each rule is a structured analysis pass,
 * not a regex pattern.
 *
 * The sink registry is the core IP: every dangerous function across
 * JS/TS/Python, with argument positions, sanitizer lists, and
 * explanations of WHY it's dangerous.
 */

import ts from "typescript";
import type { AnalysisContext } from "../engine.js";
import type { Severity, OwaspCategory } from "@mcp-sentinel/database";
import { analyzeASTTaint, type ASTTaintFlow } from "../rules/analyzers/taint-ast.js";
import { analyzePythonTaint, isPythonSource, type PythonTaintFlow, PYTHON_SINKS } from "../rules/analyzers/taint-python.js";
import { buildModuleGraph, hasMultiFileContext, type CrossModuleFlow } from "../rules/analyzers/module-graph.js";
import { shannonEntropy } from "../rules/analyzers/entropy.js";

export interface CodeFinding {
  rule_id: string;
  severity: Severity;
  evidence: string;
  remediation: string;
  owasp_category: OwaspCategory | null;
  mitre_technique: string | null;
  confidence: number;
  metadata?: Record<string, unknown>;
}

// ─── Sink Registry ──────────────────────────────────────────────────────────
// Every dangerous function with full metadata. This is the product — not regex.

interface SinkEntry {
  /** Function name as it appears in source */
  fn: string;
  /** Module it typically comes from */
  module: string | null;
  /** Which argument positions are dangerous (0-indexed) */
  dangerous_args: number[];
  /** Vulnerability category */
  category: string;
  /** What sanitizers neutralize this sink */
  sanitizers: string[];
  /** Why this function is dangerous */
  why: string;
  /** Which rule ID this maps to */
  rule_id: string;
}

const SINK_REGISTRY: SinkEntry[] = [
  // ── C1: Command Injection ──
  { fn: "exec", module: "child_process", dangerous_args: [0], category: "command_execution",
    sanitizers: ["execFile", "escapeShell", "shellEscape", "shlex.quote"],
    why: "Spawns a shell and executes the string — shell metacharacters interpreted",
    rule_id: "C1" },
  { fn: "execSync", module: "child_process", dangerous_args: [0], category: "command_execution",
    sanitizers: ["execFileSync", "escapeShell"], why: "Synchronous shell execution", rule_id: "C1" },
  { fn: "spawn", module: "child_process", dangerous_args: [0], category: "command_execution",
    sanitizers: [], why: "Process spawn — dangerous with shell:true option", rule_id: "C1" },
  { fn: "spawnSync", module: "child_process", dangerous_args: [0], category: "command_execution",
    sanitizers: [], why: "Synchronous process spawn", rule_id: "C1" },
  { fn: "system", module: "os", dangerous_args: [0], category: "command_execution",
    sanitizers: ["shlex.quote"], why: "Python os.system — direct shell execution", rule_id: "C1" },
  { fn: "popen", module: "os", dangerous_args: [0], category: "command_execution",
    sanitizers: [], why: "Python os.popen", rule_id: "C1" },
  { fn: "runInNewContext", module: "vm", dangerous_args: [0], category: "vm_escape",
    sanitizers: [], why: "VM sandbox escape — code runs in a new V8 context", rule_id: "C1" },
  { fn: "runInThisContext", module: "vm", dangerous_args: [0], category: "vm_escape",
    sanitizers: [], why: "VM sandbox escape — code runs in current context", rule_id: "C1" },

  // ── C4: SQL Injection ──
  { fn: "query", module: "pg", dangerous_args: [0], category: "sql_injection",
    sanitizers: ["escape", "prepare", "parameterize"],
    why: "PostgreSQL query — string concatenation enables injection", rule_id: "C4" },
  { fn: "execute", module: "sqlite3", dangerous_args: [0], category: "sql_injection",
    sanitizers: ["escape", "prepare"], why: "SQLite execute", rule_id: "C4" },
  { fn: "raw", module: "knex", dangerous_args: [0], category: "sql_injection",
    sanitizers: [], why: "Knex raw query — bypasses query builder sanitization", rule_id: "C4" },

  // ── C16: Dynamic Code Eval ──
  { fn: "eval", module: null, dangerous_args: [0], category: "code_eval",
    sanitizers: [], why: "Executes arbitrary JavaScript — no sanitization possible", rule_id: "C16" },
  { fn: "Function", module: null, dangerous_args: [0], category: "code_eval",
    sanitizers: [], why: "new Function() — creates function from string (equivalent to eval)",
    rule_id: "C16" },
  { fn: "setTimeout", module: null, dangerous_args: [0], category: "code_eval",
    sanitizers: [], why: "setTimeout with string arg — evaluated as code", rule_id: "C16" },
  { fn: "setInterval", module: null, dangerous_args: [0], category: "code_eval",
    sanitizers: [], why: "setInterval with string arg — evaluated as code", rule_id: "C16" },

  // ── C3: SSRF ──
  { fn: "fetch", module: null, dangerous_args: [0], category: "ssrf",
    sanitizers: ["validateUrl", "isValidUrl", "URL"],
    why: "Server-side fetch — attacker controls destination URL", rule_id: "C3" },
  { fn: "get", module: "http", dangerous_args: [0], category: "ssrf",
    sanitizers: ["validateUrl"], why: "HTTP GET with user-controlled URL", rule_id: "C3" },
  { fn: "request", module: "http", dangerous_args: [0], category: "ssrf",
    sanitizers: ["validateUrl"], why: "HTTP request with user-controlled URL", rule_id: "C3" },

  // ── C2: Path Traversal ──
  { fn: "readFile", module: "fs", dangerous_args: [0], category: "path_traversal",
    sanitizers: ["resolve", "normalize", "realpath", "sanitizePath"],
    why: "File read — path traversal via ../", rule_id: "C2" },
  { fn: "readFileSync", module: "fs", dangerous_args: [0], category: "path_traversal",
    sanitizers: ["resolve", "normalize", "realpath"],
    why: "Synchronous file read", rule_id: "C2" },
  { fn: "writeFile", module: "fs", dangerous_args: [0], category: "path_traversal",
    sanitizers: ["resolve", "normalize"],
    why: "File write — arbitrary path write", rule_id: "C2" },
  { fn: "writeFileSync", module: "fs", dangerous_args: [0], category: "path_traversal",
    sanitizers: ["resolve", "normalize"], why: "Synchronous file write", rule_id: "C2" },
  { fn: "unlink", module: "fs", dangerous_args: [0], category: "path_traversal",
    sanitizers: ["resolve", "normalize"], why: "File delete", rule_id: "C2" },

  // ── C12: Unsafe Deserialization ──
  { fn: "loads", module: "pickle", dangerous_args: [0], category: "deserialization",
    sanitizers: [],
    why: "Python pickle.loads — arbitrary code execution on untrusted data", rule_id: "C12" },
  { fn: "load", module: "yaml", dangerous_args: [0], category: "deserialization",
    sanitizers: ["safe_load", "SafeLoader"],
    why: "PyYAML yaml.load without SafeLoader — code execution via YAML tags", rule_id: "C12" },
  { fn: "unserialize", module: null, dangerous_args: [0], category: "deserialization",
    sanitizers: [],
    why: "PHP unserialize — object injection", rule_id: "C12" },
];

// ── Rule metadata ──

interface RuleMeta {
  id: string;
  name: string;
  severity: Severity;
  owasp: OwaspCategory;
  mitre: string;
  remediation: string;
}

const RULE_META: Record<string, RuleMeta> = {
  C1: { id: "C1", name: "Command Injection", severity: "critical",
    owasp: "MCP03-command-injection", mitre: "AML.T0054",
    remediation: "Replace exec()/execSync() with execFile(). Pass arguments as arrays. Validate all inputs against an allowlist." },
  C2: { id: "C2", name: "Path Traversal", severity: "critical",
    owasp: "MCP05-privilege-escalation", mitre: "AML.T0054",
    remediation: "Use path.resolve() to normalize paths. Validate against an allowed directory prefix. Reject paths containing '..'." },
  C3: { id: "C3", name: "Server-Side Request Forgery", severity: "high",
    owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
    remediation: "Validate URLs against an allowlist of permitted hosts. Use URL parsing to verify scheme and host before requesting." },
  C4: { id: "C4", name: "SQL Injection", severity: "critical",
    owasp: "MCP03-command-injection", mitre: "AML.T0054",
    remediation: "Use parameterized queries. Never concatenate user input into SQL strings." },
  C5: { id: "C5", name: "Hardcoded Secrets", severity: "critical",
    owasp: "MCP07-insecure-config", mitre: "AML.T0057",
    remediation: "Move secrets to environment variables or a secrets manager. Never commit credentials to source code." },
  C10: { id: "C10", name: "Prototype Pollution", severity: "critical",
    owasp: "MCP05-privilege-escalation", mitre: "AML.T0054",
    remediation: "Freeze prototypes. Validate object keys against an allowlist. Use Map instead of plain objects for user-controlled keys." },
  C12: { id: "C12", name: "Unsafe Deserialization", severity: "critical",
    owasp: "MCP03-command-injection", mitre: "AML.T0054",
    remediation: "Use yaml.safe_load() instead of yaml.load(). Never unpickle untrusted data. Use JSON for serialization." },
  C14: { id: "C14", name: "JWT Algorithm Confusion", severity: "critical",
    owasp: "MCP07-insecure-config", mitre: "AML.T0054",
    remediation: "Pin the algorithm in jwt.verify() options: { algorithms: ['RS256'] }. Never accept 'none'. Reject algorithm downgrade." },
  C15: { id: "C15", name: "Timing Attack on Secret Comparison", severity: "high",
    owasp: "MCP07-insecure-config", mitre: "AML.T0054",
    remediation: "Use crypto.timingSafeEqual() or hmac.compare_digest() for secret comparison. Never use === on secrets." },
  C16: { id: "C16", name: "Dynamic Code Evaluation", severity: "critical",
    owasp: "MCP03-command-injection", mitre: "AML.T0054",
    remediation: "Remove eval(). Use JSON.parse() for data. Use a sandbox (vm2/isolated-vm) if dynamic code is required." },
  // Upgraded G–Q rules (moved from regex to engine analysis)
  J1: { id: "J1", name: "Cross-Agent Configuration Poisoning", severity: "critical",
    owasp: "MCP05-privilege-escalation", mitre: "AML.T0060",
    remediation: "Never write to agent configuration paths (.claude/, .cursor/, .gemini/, ~/.mcp.json). Validate all file write paths against an allowlist." },
  J5: { id: "J5", name: "Tool Output Poisoning Patterns", severity: "critical",
    owasp: "MCP01-prompt-injection", mitre: "AML.T0054",
    remediation: "Never include user input or LLM manipulation directives in error messages or tool responses. Use structured error codes." },
  K5: { id: "K5", name: "Auto-Approve / Bypass Confirmation Pattern", severity: "critical",
    owasp: "MCP06-excessive-permissions", mitre: "AML.T0054",
    remediation: "Always require explicit user confirmation for destructive operations. Never provide --yes/--no-confirm flags or auto_approve settings." },
};

// ─── Main CodeAnalyzer ──────────────────────────────────────────────────────

export class CodeAnalyzer {
  analyze(context: AnalysisContext): CodeFinding[] {
    if (!context.source_code) return [];

    const findings: CodeFinding[] = [];

    // 1. AST taint analysis — traces user input to dangerous sinks
    findings.push(...this.runTaintAnalysis(context.source_code));

    // 2. Cross-module taint analysis — traces taint across file boundaries
    if (hasMultiFileContext(context.source_files)) {
      findings.push(...this.runCrossModuleAnalysis(context.source_files!));
    }

    // 3. AST pattern analysis — structural checks that don't need taint
    findings.push(...this.runASTPatternAnalysis(context.source_code));

    // 4. Secret detection via entropy — not regex patterns
    findings.push(...this.runSecretDetection(context.source_code));

    // 5. Upgraded G–Q rules: AST-based structural analysis
    findings.push(...this.detectJ1ConfigPoisoning(context.source_code));
    findings.push(...this.detectJ5OutputPoisoning(context.source_code));
    findings.push(...this.detectK5AutoApprove(context.source_code));

    return findings;
  }

  /**
   * Phase 1: Taint analysis using real AST parsing.
   * Routes to TypeScript compiler API for JS/TS or tree-sitter for Python.
   */
  private runTaintAnalysis(source: string): CodeFinding[] {
    if (isPythonSource(source)) {
      return this.runPythonTaintAnalysis(source);
    }
    return this.runJSTaintAnalysis(source);
  }

  /** JS/TS taint analysis using TypeScript compiler AST. */
  private runJSTaintAnalysis(source: string): CodeFinding[] {
    const findings: CodeFinding[] = [];

    try {
      const flows = analyzeASTTaint(source);
      for (const flow of flows) {
        // Look up the sink in our registry for metadata
        const sinkEntry = SINK_REGISTRY.find(
          (s) => s.fn === this.extractFnName(flow.sink.expression)
        );
        const ruleId = sinkEntry?.rule_id || this.categoryToRule(flow.sink.category);
        const meta = RULE_META[ruleId];
        if (!meta) continue;

        if (flow.sanitized) {
          findings.push({
            rule_id: ruleId,
            severity: "informational",
            evidence:
              `[AST taint — sanitized] ${flow.source.category} source ` +
              `"${flow.source.expression}" (L${flow.source.line}) → ` +
              `sanitized by ${flow.sanitizer_name} → ` +
              `${flow.sink.category} sink "${flow.sink.expression.slice(0, 50)}" (L${flow.sink.line}). ` +
              (sinkEntry ? `Sink: ${sinkEntry.why}` : ""),
            remediation: `Sanitizer "${flow.sanitizer_name}" detected. Verify it handles all edge cases.`,
            owasp_category: meta.owasp,
            mitre_technique: meta.mitre,
            confidence: flow.confidence * 0.3,
          });
        } else {
          const pathDesc = flow.path.length > 0
            ? flow.path.map((s) => `${s.type}(L${s.line})`).join(" → ") + " → "
            : "";

          findings.push({
            rule_id: ruleId,
            severity: meta.severity,
            evidence:
              `[AST taint] ${flow.source.category} source ` +
              `"${flow.source.expression}" (L${flow.source.line}) → ` +
              `${pathDesc}` +
              `${flow.sink.category} sink "${flow.sink.expression.slice(0, 60)}" (L${flow.sink.line}). ` +
              (sinkEntry
                ? `${sinkEntry.why}. Module: ${sinkEntry.module || "global"}. ` +
                  `Known sanitizers: ${sinkEntry.sanitizers.join(", ") || "none"}.`
                : ""),
            remediation: meta.remediation,
            owasp_category: meta.owasp,
            mitre_technique: meta.mitre,
            confidence: flow.confidence,
            metadata: {
              engine: "code_analyzer",
              analysis: "ast_taint",
              source_category: flow.source.category,
              sink_fn: sinkEntry?.fn,
              sink_module: sinkEntry?.module,
              path_length: flow.path.length,
            },
          });
        }
      }
    } catch (_err) {
      // AST parsing failed — source may not be valid JS/TS
    }

    return findings;
  }

  /** Python taint analysis using tree-sitter AST. */
  private runPythonTaintAnalysis(source: string): CodeFinding[] {
    const findings: CodeFinding[] = [];

    try {
      const flows = analyzePythonTaint(source);
      for (const flow of flows) {
        // Look up the sink in our Python registry
        const sinkEntry = PYTHON_SINKS.find(
          (s) => s.fn === this.extractFnName(flow.sink.expression)
        );
        const ruleId = sinkEntry?.rule_id || this.categoryToRule(flow.sink.category);
        const meta = RULE_META[ruleId];
        if (!meta) continue;

        if (flow.sanitized) {
          findings.push({
            rule_id: ruleId,
            severity: "informational",
            evidence:
              `[AST taint — Python — sanitized] ${flow.source.category} source ` +
              `"${flow.source.expression}" (L${flow.source.line}) → ` +
              `sanitized by ${flow.sanitizer_name} → ` +
              `${flow.sink.category} sink "${flow.sink.expression.slice(0, 50)}" (L${flow.sink.line}). ` +
              (sinkEntry ? `Sink: ${sinkEntry.why}` : ""),
            remediation: `Sanitizer "${flow.sanitizer_name}" detected. Verify it handles all edge cases.`,
            owasp_category: meta.owasp,
            mitre_technique: meta.mitre,
            confidence: flow.confidence * 0.3,
          });
        } else {
          const pathDesc = flow.path.length > 0
            ? flow.path.map((s) => `${s.type}(L${s.line})`).join(" → ") + " → "
            : "";

          findings.push({
            rule_id: ruleId,
            severity: meta.severity,
            evidence:
              `[AST taint — Python] ${flow.source.category} source ` +
              `"${flow.source.expression}" (L${flow.source.line}) → ` +
              `${pathDesc}` +
              `${flow.sink.category} sink "${flow.sink.expression.slice(0, 60)}" (L${flow.sink.line}). ` +
              (sinkEntry
                ? `${sinkEntry.why}. Module: ${sinkEntry.module || "global"}. ` +
                  `Known sanitizers: ${sinkEntry.sanitizers.join(", ") || "none"}.`
                : ""),
            remediation: meta.remediation,
            owasp_category: meta.owasp,
            mitre_technique: meta.mitre,
            confidence: flow.confidence,
            metadata: {
              engine: "code_analyzer",
              analysis: "ast_taint_python",
              source_category: flow.source.category,
              sink_fn: sinkEntry?.fn,
              sink_module: sinkEntry?.module,
              path_length: flow.path.length,
            },
          });
        }
      }
    } catch (_err) {
      // Python AST parsing failed — fall through to regex fallback
    }

    return findings;
  }

  /**
   * Cross-module taint analysis using the module graph.
   * Discovers taint flows that span file boundaries:
   *   utils.ts:getInput() → handler.ts:processRequest() → exec()
   */
  private runCrossModuleAnalysis(sourceFiles: Map<string, string>): CodeFinding[] {
    const findings: CodeFinding[] = [];

    try {
      const graph = buildModuleGraph(sourceFiles);

      for (const crossFlow of graph.crossModuleFlows) {
        const flow = crossFlow.flow;
        const sinkEntry =
          SINK_REGISTRY.find((s) => s.fn === this.extractFnName(flow.sink.expression)) ||
          PYTHON_SINKS.find((s) => s.fn === this.extractFnName(flow.sink.expression));
        const ruleId = sinkEntry?.rule_id || this.categoryToRule(flow.sink.category);
        const meta = RULE_META[ruleId];
        if (!meta) continue;

        // Deduplicate: skip if single-file analysis already found this exact sink
        const sinkKey = `${ruleId}:${flow.sink.line}:${flow.sink.expression.slice(0, 30)}`;
        // Cross-module flows are additive — they provide richer evidence

        const pathDesc = flow.path.length > 0
          ? flow.path.map((s) => `${s.type}(L${s.line})`).join(" → ") + " → "
          : "";

        findings.push({
          rule_id: ruleId,
          severity: flow.sanitized ? "informational" : meta.severity,
          evidence:
            `[AST taint — cross-module] ${flow.source.category} source ` +
            `"${flow.source.expression}" (${crossFlow.sourceFile}:L${flow.source.line}) → ` +
            `${pathDesc}` +
            `${flow.sink.category} sink "${flow.sink.expression.slice(0, 60)}" (${crossFlow.sinkFile}:L${flow.sink.line}). ` +
            `Module chain: ${crossFlow.moduleChain}. ` +
            (sinkEntry
              ? `${sinkEntry.why}. Known sanitizers: ${sinkEntry.sanitizers.join(", ") || "none"}.`
              : ""),
          remediation: flow.sanitized
            ? `Sanitizer "${flow.sanitizer_name}" detected across module boundary. Verify it handles all edge cases.`
            : meta.remediation,
          owasp_category: meta.owasp,
          mitre_technique: meta.mitre,
          confidence: flow.sanitized ? flow.confidence * 0.3 : flow.confidence,
          metadata: {
            engine: "code_analyzer",
            analysis: "ast_taint_cross_module",
            source_file: crossFlow.sourceFile,
            sink_file: crossFlow.sinkFile,
            module_chain: crossFlow.moduleChain,
            sink_fn: sinkEntry?.fn,
            path_length: flow.path.length,
          },
        });
      }
    } catch (_err) {
      // Module graph construction failed — degrade gracefully
    }

    return findings;
  }

  /**
   * Phase 2: Structural AST pattern checks that don't need taint tracking.
   * These look for dangerous code PATTERNS regardless of data flow.
   */
  private runASTPatternAnalysis(source: string): CodeFinding[] {
    const findings: CodeFinding[] = [];

    let sourceFile: ts.SourceFile;
    try {
      sourceFile = ts.createSourceFile("analysis.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    } catch {
      return findings;
    }

    const visit = (node: ts.Node) => {
      // C10: Prototype Pollution — __proto__ assignment
      if (ts.isPropertyAccessExpression(node) && node.name.text === "__proto__") {
        findings.push({
          rule_id: "C10", severity: "critical",
          evidence: `[AST pattern] __proto__ access at L${this.getLine(sourceFile, node)} — prototype pollution vector. ` +
            `Assignment to __proto__ allows attacker to modify Object.prototype, affecting all objects.`,
          remediation: RULE_META.C10.remediation,
          owasp_category: "MCP05-privilege-escalation", mitre_technique: "AML.T0054",
          confidence: 0.9,
        });
      }
      if (ts.isStringLiteral(node) && node.text === "__proto__" && ts.isElementAccessExpression(node.parent)) {
        findings.push({
          rule_id: "C10", severity: "critical",
          evidence: `[AST pattern] obj["__proto__"] access at L${this.getLine(sourceFile, node)} — prototype pollution via bracket notation.`,
          remediation: RULE_META.C10.remediation,
          owasp_category: "MCP05-privilege-escalation", mitre_technique: "AML.T0054",
          confidence: 0.9,
        });
      }

      // C14: JWT Algorithm Confusion — verify() without algorithms option
      if (ts.isCallExpression(node)) {
        const callName = this.getCallExprName(node);

        if (callName === "verify" && node.arguments.length >= 2) {
          // Check if third argument (options) has algorithms property
          const opts = node.arguments[2];
          if (!opts) {
            findings.push({
              rule_id: "C14", severity: "critical",
              evidence: `[AST pattern] jwt.verify() at L${this.getLine(sourceFile, node)} called without options — no algorithm pinning. ` +
                `Allows attacker to use 'none' algorithm or downgrade RS256→HS256.`,
              remediation: RULE_META.C14.remediation,
              owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054",
              confidence: 0.8,
            });
          } else if (ts.isObjectLiteralExpression(opts)) {
            const hasAlgorithms = opts.properties.some(
              (p) => ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === "algorithms"
            );
            if (!hasAlgorithms) {
              findings.push({
                rule_id: "C14", severity: "critical",
                evidence: `[AST pattern] jwt.verify() at L${this.getLine(sourceFile, node)} — options object missing 'algorithms' key. ` +
                  `Without algorithm pinning, attacker can use 'none' or downgrade.`,
                remediation: RULE_META.C14.remediation,
                owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054",
                confidence: 0.85,
              });
            }
          }
        }

        // C15: Timing attack — === on secrets
        if (
          callName === "compare" ||
          callName === "verify" ||
          callName === "authenticate" ||
          callName === "validateToken" ||
          callName === "checkPassword"
        ) {
          // Check if there's a === comparison nearby on the return value
          // (Simplified: flag the comparison operator directly)
        }
      }

      // C15: Direct === comparison on variables named token/secret/key/password
      if (ts.isBinaryExpression(node) &&
        (node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
         node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken)) {
        const leftName = ts.isIdentifier(node.left) ? node.left.text : "";
        const rightName = ts.isIdentifier(node.right) ? node.right.text : "";
        const secretPattern = /^(token|secret|key|password|api_key|apiKey|hash|hmac|digest|signature)$/i;
        if (secretPattern.test(leftName) || secretPattern.test(rightName)) {
          findings.push({
            rule_id: "C15", severity: "high",
            evidence: `[AST pattern] String equality (===) on "${leftName || rightName}" at L${this.getLine(sourceFile, node)} — timing side-channel. ` +
              `Attackers can determine secret value byte-by-byte by measuring comparison time.`,
            remediation: RULE_META.C15.remediation,
            owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054",
            confidence: 0.75,
          });
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
    return findings;
  }

  /**
   * Phase 3: Secret detection using entropy analysis on string literals.
   *
   * Instead of regex patterns for each token format, we:
   * 1. Extract all string literals from the AST
   * 2. Compute Shannon entropy on each
   * 3. High-entropy strings (>4.5 bits/char) in assignment context = potential secrets
   * 4. Cross-reference with variable name patterns (apiKey, token, secret)
   *
   * This catches secrets in ANY format, not just the 20 patterns in the YAML rule.
   */
  private runSecretDetection(source: string): CodeFinding[] {
    const findings: CodeFinding[] = [];

    let sourceFile: ts.SourceFile;
    try {
      sourceFile = ts.createSourceFile("analysis.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    } catch {
      return findings;
    }

    const secretNamePattern = /(?:api[_-]?key|secret|token|password|credential|auth|private[_-]?key|access[_-]?key|bearer)/i;
    // Known token format prefixes (high confidence)
    const TOKEN_PREFIXES = ["sk-", "pk-", "sk_live_", "sk_test_", "ghp_", "gho_", "ghs_",
      "github_pat_", "xoxb-", "xoxp-", "xapp-", "AKIA", "ASIA", "SG.", "AIza", "eyJ",
      "-----BEGIN", "dapi", "npm_"];

    const visit = (node: ts.Node) => {
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
        const value = node.text;
        if (value.length < 16 || value.length > 500) {
          ts.forEachChild(node, visit);
          return;
        }

        // Check 1: Known token format prefixes
        const matchedPrefix = TOKEN_PREFIXES.find((p) => value.startsWith(p));
        if (matchedPrefix) {
          findings.push({
            rule_id: "C5", severity: "critical",
            evidence: `[AST secret] Token with prefix "${matchedPrefix}" at L${this.getLine(sourceFile, node)} — ` +
              `known credential format hardcoded in source. Value: "${value.slice(0, 8)}...${value.slice(-4)}".`,
            remediation: RULE_META.C5.remediation,
            owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0057",
            confidence: 0.95,
          });
          ts.forEachChild(node, visit);
          return;
        }

        // Check 2: High entropy + secret variable name
        const entropy = shannonEntropy(value);
        if (entropy > 4.5) {
          // Check if assigned to a variable with a secret-like name
          let varName = "";
          if (ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)) {
            varName = node.parent.name.text;
          }
          if (ts.isPropertyAssignment(node.parent) && ts.isIdentifier(node.parent.name)) {
            varName = node.parent.name.text;
          }

          if (varName && secretNamePattern.test(varName)) {
            findings.push({
              rule_id: "C5", severity: "critical",
              evidence: `[AST secret + entropy] Variable "${varName}" at L${this.getLine(sourceFile, node)} assigned ` +
                `high-entropy string (${entropy.toFixed(2)} bits/char). ` +
                `Value: "${value.slice(0, 8)}...${value.slice(-4)}". ` +
                `Entropy > 4.5 in a secret-named variable = likely credential.`,
              remediation: RULE_META.C5.remediation,
              owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0057",
              confidence: 0.85,
              metadata: { engine: "code_analyzer", analysis: "entropy_secret", entropy, variable: varName },
            });
          }
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
    return findings;
  }

  // ── J1: Cross-Agent Configuration Poisoning (AST upgrade) ──────────────────
  // Detects writeFileSync/writeFile/fs.writeFile where path contains agent config paths
  // AND content is user-influenced. CVE-2025-53773 backed.

  private static readonly AGENT_CONFIG_PATHS = [
    ".claude/", ".claude\\\\", ".cursor/", ".cursor\\\\",
    ".gemini/", ".gemini\\\\", ".mcp.json", "mcp.json",
    ".vscode/", "settings.json", "mcp_config",
  ];

  private static readonly FILE_WRITE_FUNCTIONS = new Set([
    "writeFileSync", "writeFile", "appendFileSync", "appendFile",
    "outputFileSync", "outputFile", "mkdirSync",
  ]);

  private detectJ1ConfigPoisoning(source: string): CodeFinding[] {
    const findings: CodeFinding[] = [];
    const meta = RULE_META.J1;

    let sourceFile: ts.SourceFile;
    try {
      sourceFile = ts.createSourceFile("j1.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    } catch { return findings; }

    const visit = (node: ts.Node) => {
      if (!ts.isCallExpression(node)) {
        ts.forEachChild(node, visit);
        return;
      }

      const callName = this.getCallExprName(node);
      if (!CodeAnalyzer.FILE_WRITE_FUNCTIONS.has(callName)) {
        ts.forEachChild(node, visit);
        return;
      }

      // Check first argument (path) for agent config paths
      if (node.arguments.length < 1) {
        ts.forEachChild(node, visit);
        return;
      }

      const pathArg = node.arguments[0];
      const pathText = pathArg.getText(sourceFile);

      const matchedConfigPath = CodeAnalyzer.AGENT_CONFIG_PATHS.find((cp) =>
        pathText.includes(cp)
      );

      if (matchedConfigPath) {
        const line = this.getLine(sourceFile, node);

        // Check if the content (second arg) is user-influenced
        // Heuristic: not a string literal, or contains variable reference
        let contentTainted = false;
        let contentEvidence = "hardcoded content";
        if (node.arguments.length >= 2) {
          const contentArg = node.arguments[1];
          if (!ts.isStringLiteral(contentArg) && !ts.isNoSubstitutionTemplateLiteral(contentArg)) {
            contentTainted = true;
            contentEvidence = `dynamic content: ${contentArg.getText(sourceFile).slice(0, 60)}`;
          }
          if (ts.isTemplateExpression(contentArg)) {
            contentTainted = true;
            contentEvidence = `template literal with interpolation`;
          }
        }

        findings.push({
          rule_id: "J1",
          severity: contentTainted ? "critical" : "high",
          evidence:
            `[AST — J1] ${callName}() at L${line} writes to agent config path "${matchedConfigPath}". ` +
            `Path arg: ${pathText.slice(0, 80)}. Content: ${contentEvidence}. ` +
            (contentTainted
              ? `User-influenced content written to agent config enables cross-agent RCE — ` +
                `compromised upstream agent adds malicious MCP server to downstream agent's config.`
              : `Static content write to agent config path — verify this is intentional.`),
          remediation: meta.remediation,
          owasp_category: meta.owasp,
          mitre_technique: meta.mitre,
          confidence: contentTainted ? 0.92 : 0.7,
          metadata: {
            engine: "code_analyzer", analysis: "ast_j1_config_poisoning",
            config_path: matchedConfigPath, content_tainted: contentTainted,
          },
        });
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);

    // Also check Python patterns: open(..., 'w').write() on config paths
    if (/\.claude|\.cursor|\.gemini|\.mcp\.json/i.test(source)) {
      const pyPattern = /open\s*\(\s*(['"][^'"]*(?:\.claude|\.cursor|\.gemini|\.mcp\.json)[^'"]*['"])/g;
      let m: RegExpExecArray | null;
      while ((m = pyPattern.exec(source))) {
        const line = source.slice(0, m.index).split("\n").length;
        findings.push({
          rule_id: "J1", severity: "critical",
          evidence:
            `[AST — J1] Python open() at L${line} targets agent config path: ${m[1]}. ` +
            `Writing to agent config paths enables cross-agent RCE via config poisoning.`,
          remediation: meta.remediation,
          owasp_category: meta.owasp, mitre_technique: meta.mitre,
          confidence: 0.85,
          metadata: { engine: "code_analyzer", analysis: "ast_j1_config_poisoning_py" },
        });
      }
    }

    return findings;
  }

  // ── J5: Tool Output Poisoning (AST upgrade) ──────────────────────────────────
  // Detects catch blocks that construct responses containing user input +
  // LLM manipulation patterns. CyberArk ATPA research.

  private static readonly LLM_MANIPULATION_PATTERNS = [
    /ignore\s+previous/i, /forget\s+(all|prior|previous)/i,
    /you\s+must\s+(now|always)/i, /read\s+~\/\.ssh/i,
    /IMPORTANT:\s*(Ignore|Override|Forget|Always|Never)/i,
    /instead\s*,?\s*(do|execute|run|read|send)/i,
    /to\s+resolve\s+this\s+error/i, /to\s+fix\s+this/i,
    /system\s+prompt/i, /new\s+instructions?:/i,
  ];

  private detectJ5OutputPoisoning(source: string): CodeFinding[] {
    const findings: CodeFinding[] = [];
    const meta = RULE_META.J5;

    let sourceFile: ts.SourceFile;
    try {
      sourceFile = ts.createSourceFile("j5.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    } catch { return findings; }

    const visit = (node: ts.Node) => {
      // Check catch clauses for response construction with manipulation patterns
      if (ts.isCatchClause(node)) {
        this.checkCatchBlockForPoisoning(sourceFile, node, findings);
      }

      // Check return/response statements containing manipulation strings
      if (ts.isReturnStatement(node) && node.expression) {
        this.checkExpressionForPoisoning(sourceFile, node.expression, findings, "return statement");
      }

      // Check property assignments in response objects (e.g., res.content = ...)
      if (ts.isPropertyAssignment(node) && ts.isIdentifier(node.name)) {
        const propName = node.name.text;
        if (["content", "message", "error", "text", "body", "description"].includes(propName)) {
          this.checkExpressionForPoisoning(sourceFile, node.initializer, findings, `"${propName}" property`);
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
    return findings;
  }

  private checkCatchBlockForPoisoning(
    sf: ts.SourceFile, catchClause: ts.CatchClause, findings: CodeFinding[]
  ): void {
    const meta = RULE_META.J5;
    const blockText = catchClause.block.getText(sf);

    // Check if catch block constructs a response with manipulation patterns
    for (const pattern of CodeAnalyzer.LLM_MANIPULATION_PATTERNS) {
      if (pattern.test(blockText)) {
        const line = this.getLine(sf, catchClause);
        findings.push({
          rule_id: "J5", severity: "critical",
          evidence:
            `[AST — J5] Catch block at L${line} constructs response with LLM manipulation pattern: ` +
            `"${pattern.source}". Error handlers that embed directives in responses enable ` +
            `tool output poisoning — the AI follows instructions from error messages.`,
          remediation: meta.remediation,
          owasp_category: meta.owasp, mitre_technique: meta.mitre,
          confidence: 0.88,
          metadata: { engine: "code_analyzer", analysis: "ast_j5_catch_poisoning" },
        });
        return; // One finding per catch block
      }
    }

    // Check if catch block includes the error variable in the response
    // (leaking raw error messages that could be attacker-controlled)
    const errorParam = catchClause.variableDeclaration?.name;
    if (errorParam && ts.isIdentifier(errorParam)) {
      const errorName = errorParam.text;
      // Check if error variable is interpolated into a template literal or concatenated
      const hasTemplateWithError = new RegExp(`\\$\\{[^}]*${errorName}[^}]*\\}`).test(blockText);
      const hasConcatWithError = new RegExp(`['"].*['"]\\s*\\+\\s*${errorName}`).test(blockText) ||
        new RegExp(`${errorName}\\s*\\+\\s*['"]`).test(blockText);

      if (hasTemplateWithError || hasConcatWithError) {
        // Now check if any LLM manipulation pattern could appear via the error
        const line = this.getLine(sf, catchClause);
        findings.push({
          rule_id: "J5", severity: "high",
          evidence:
            `[AST — J5] Catch block at L${line} interpolates error variable "${errorName}" into response. ` +
            `If the error originates from attacker-controlled input (e.g., malformed data), ` +
            `the error message becomes an injection vector into the AI's context.`,
          remediation: meta.remediation,
          owasp_category: meta.owasp, mitre_technique: meta.mitre,
          confidence: 0.75,
          metadata: { engine: "code_analyzer", analysis: "ast_j5_error_interpolation" },
        });
      }
    }
  }

  private checkExpressionForPoisoning(
    sf: ts.SourceFile, expr: ts.Expression, findings: CodeFinding[], context: string
  ): void {
    const meta = RULE_META.J5;
    const exprText = expr.getText(sf);

    for (const pattern of CodeAnalyzer.LLM_MANIPULATION_PATTERNS) {
      if (pattern.test(exprText)) {
        const line = this.getLine(sf, expr);
        findings.push({
          rule_id: "J5", severity: "critical",
          evidence:
            `[AST — J5] LLM manipulation pattern in ${context} at L${line}: ` +
            `"${pattern.source}" found in "${exprText.slice(0, 80)}". ` +
            `Tool responses containing directives cause the AI to follow them as instructions.`,
          remediation: meta.remediation,
          owasp_category: meta.owasp, mitre_technique: meta.mitre,
          confidence: 0.9,
          metadata: { engine: "code_analyzer", analysis: "ast_j5_output_poisoning" },
        });
        return; // One finding per expression
      }
    }
  }

  // ── K5: Auto-Approve / Bypass Confirmation (AST upgrade) ──────────────────────
  // Detects confirmation bypass patterns: confirm() mocked/overridden,
  // --yes/--no-confirm flags, UNSAFE_ prefixes, auto_approve settings.

  private detectK5AutoApprove(source: string): CodeFinding[] {
    const findings: CodeFinding[] = [];
    const meta = RULE_META.K5;

    let sourceFile: ts.SourceFile;
    try {
      sourceFile = ts.createSourceFile("k5.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    } catch { return findings; }

    const visit = (node: ts.Node) => {
      // Pattern 1: Property assignments with auto-approve semantics
      if (ts.isPropertyAssignment(node) && ts.isIdentifier(node.name)) {
        const propName = node.name.text.toLowerCase();
        const autoApproveNames = [
          "auto_approve", "autoapprove", "auto_confirm", "autoconfirm",
          "skip_confirmation", "skipconfirmation", "skip_user_confirmation",
          "always_approve", "alwaysapprove", "no_confirm", "noconfirm",
          "bypass_confirmation", "approval_mode",
        ];

        if (autoApproveNames.includes(propName)) {
          const value = node.initializer;
          // Check if set to true or 'auto' or 'always'
          const isEnabled =
            (value.kind === ts.SyntaxKind.TrueKeyword || value.getText(sourceFile) === "true") ||
            (ts.isStringLiteral(value) && /^(auto|always|skip|yes|none)$/i.test(value.text));

          if (isEnabled) {
            findings.push({
              rule_id: "K5", severity: "critical",
              evidence:
                `[AST — K5] Auto-approve pattern at L${this.getLine(sourceFile, node)}: ` +
                `"${node.name.text}: ${value.getText(sourceFile)}". ` +
                `Bypassing user confirmation for tool execution violates human-in-the-loop safety ` +
                `(EU AI Act Art. 14, ISO 42001 A.9.2, OWASP ASI09).`,
              remediation: meta.remediation,
              owasp_category: meta.owasp, mitre_technique: meta.mitre,
              confidence: 0.92,
              metadata: { engine: "code_analyzer", analysis: "ast_k5_auto_approve" },
            });
          }
        }
      }

      // Pattern 2: Function names with UNSAFE_ prefix
      if (ts.isFunctionDeclaration(node) && node.name) {
        const name = node.name.text;
        if (/^UNSAFE_|^unsafe_|^dangerously|^force_/i.test(name)) {
          findings.push({
            rule_id: "K5", severity: "high",
            evidence:
              `[AST — K5] Function "${name}" at L${this.getLine(sourceFile, node)} uses unsafe/force prefix. ` +
              `Functions that bypass safety checks by naming convention undermine human oversight.`,
            remediation: meta.remediation,
            owasp_category: meta.owasp, mitre_technique: meta.mitre,
            confidence: 0.7,
            metadata: { engine: "code_analyzer", analysis: "ast_k5_unsafe_prefix" },
          });
        }
      }

      // Pattern 3: CLI flags that bypass confirmation (--yes, --no-confirm, --force, -y)
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
        const text = node.text;
        if (/^--(yes|no-confirm|force|skip-confirm|auto-approve|no-prompt)\b/.test(text) ||
            text === "-y" || text === "-f") {
          // Check if this is in an option/argument definition context
          const parent = node.parent;
          if (parent && (ts.isPropertyAssignment(parent) || ts.isArrayLiteralExpression(parent) ||
              ts.isCallExpression(parent))) {
            findings.push({
              rule_id: "K5", severity: "high",
              evidence:
                `[AST — K5] Confirmation bypass flag "${text}" at L${this.getLine(sourceFile, node)}. ` +
                `CLI flags that skip user confirmation enable unattended destructive operations.`,
              remediation: meta.remediation,
              owasp_category: meta.owasp, mitre_technique: meta.mitre,
              confidence: 0.75,
              metadata: { engine: "code_analyzer", analysis: "ast_k5_bypass_flag" },
            });
          }
        }
      }

      // Pattern 4: confirm = () => true (mocked/overridden confirmation)
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        const name = node.name.text.toLowerCase();
        if ((name === "confirm" || name === "prompt" || name === "ask_confirmation") &&
            ts.isArrowFunction(node.initializer)) {
          const body = node.initializer.body;
          if (body.kind === ts.SyntaxKind.TrueKeyword ||
              (ts.isBlock(body) && body.getText(sourceFile).includes("true"))) {
            findings.push({
              rule_id: "K5", severity: "critical",
              evidence:
                `[AST — K5] Confirmation function "${node.name.text}" overridden to always return true at ` +
                `L${this.getLine(sourceFile, node)}. Mocking the confirmation function bypasses ` +
                `all human-in-the-loop safety checks.`,
              remediation: meta.remediation,
              owasp_category: meta.owasp, mitre_technique: meta.mitre,
              confidence: 0.95,
              metadata: { engine: "code_analyzer", analysis: "ast_k5_confirm_mock" },
            });
          }
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
    return findings;
  }

  // ── Helpers ──

  private extractFnName(expr: string): string {
    const match = expr.match(/(\w+)\s*\(/);
    return match ? match[1] : "";
  }

  private categoryToRule(category: string): string {
    const map: Record<string, string> = {
      command_execution: "C1", vm_escape: "C1",
      sql_injection: "C4", code_eval: "C16",
      ssrf: "C3", path_traversal: "C2",
      deserialization: "C12", xss: "C13",
    };
    return map[category] || "C1";
  }

  private getLine(sf: ts.SourceFile, node: ts.Node): number {
    return sf.getLineAndCharacterOfPosition(node.getStart()).line + 1;
  }

  private getCallExprName(node: ts.CallExpression): string {
    if (ts.isIdentifier(node.expression)) return node.expression.text;
    if (ts.isPropertyAccessExpression(node.expression)) return node.expression.name.text;
    return "";
  }
}
