/**
 * Tainted Execution Detector — Deep analysis for C4, C12, C13, C16, K9, J2
 *
 * Extends the taint-based approach proven in c1-command-injection.ts to 6 more rules.
 * Each rule filters AST taint flows by specific sink categories, then falls back
 * to targeted regex patterns for languages/constructs the AST engine can't parse.
 *
 * What this catches that YAML regex can't:
 * - C4:  db.query(userInput) flagged, db.query("SELECT 1") not flagged
 * - C12: pickle.loads(data) flagged only if data traces to untrusted source
 * - C13: render(userTemplate) flagged, render("index.html") not flagged
 * - C16: eval(expr) flagged only if expr is tainted, not hardcoded
 * - K9:  postinstall exec flagged only if payload comes from network
 * - J2:  git args flagged only if user input reaches --upload-pack / --exec
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import type { Severity, OwaspCategory } from "@mcp-sentinel/database";
import { analyzeASTTaint, type ASTTaintFlow } from "../analyzers/taint-ast.js";
import { analyzeTaint, type TaintFlow } from "../analyzers/taint.js";

// ─── Shared helpers ────────────────────────────────────────────────────────

const TEST_FILE_PATTERN = /(?:__tests?__|\.(?:test|spec)\.)/;

function isTestFile(source: string): boolean {
  return TEST_FILE_PATTERN.test(source);
}

function formatASTEvidence(ruleId: string, flow: ASTTaintFlow, sanitized: boolean): string {
  const pathStr =
    flow.path.length > 0
      ? ` → ${flow.path.map((s) => `${s.type}(${s.expression.slice(0, 50)}, L${s.line})`).join(" → ")}`
      : "";
  const sanitizerStr =
    sanitized && flow.sanitizer_name ? ` [SANITIZED by ${flow.sanitizer_name}]` : "";
  return (
    `[${ruleId} AST taint] ${flow.source.category} source ` +
    `"${flow.source.expression}" (L${flow.source.line})` +
    `${pathStr} → ${flow.sink.category} sink ` +
    `"${flow.sink.expression.slice(0, 60)}" (L${flow.sink.line})` +
    `${sanitizerStr}. ${flow.path.length} step(s). ` +
    `Confidence: ${(flow.confidence * 100).toFixed(0)}%.`
  );
}

function formatTaintEvidence(ruleId: string, flow: TaintFlow, sanitized: boolean): string {
  const chain = flow.propagation_chain;
  const chainStr =
    chain.length > 0
      ? ` → ${chain.map((p) => `${p.to} (L${p.line}, ${p.type})`).join(" → ")}`
      : "";
  const sanitizerStr =
    sanitized && flow.sanitizer ? ` [SANITIZED by ${flow.sanitizer.expression}]` : "";
  return (
    `[${ruleId} taint] ${flow.source.category} source ` +
    `"${flow.source.expression}" (L${flow.source.line})` +
    `${chainStr} → ${flow.sink.category} sink ` +
    `"${flow.sink.expression.slice(0, 60)}" (L${flow.sink.line})` +
    `${sanitizerStr}. Confidence: ${(flow.confidence * 100).toFixed(0)}%.`
  );
}

interface RuleDef {
  id: string;
  name: string;
  severity: Severity;
  /** AST sink categories to filter for */
  astSinkCategories: string[];
  /** Lightweight taint sink categories to filter for */
  taintSinkCategories: string[];
  owasp: OwaspCategory;
  mitre: string;
  remediation: string;
  /** Regex fallback patterns when taint analysis finds nothing */
  fallbackPatterns: Array<{ regex: RegExp; desc: string; confidence: number }>;
  /** Patterns that indicate safe usage — skip these lines */
  safePatterns: RegExp[];
}

// ─── Rule definitions ──────────────────────────────────────────────────────

const C4_SQL_INJECTION: RuleDef = {
  id: "C4",
  name: "SQL Injection (Taint-Aware)",
  severity: "critical",
  astSinkCategories: ["sql_injection"],
  taintSinkCategories: ["sql_query"],
  owasp: "MCP03-command-injection",
  mitre: "AML.T0054",
  remediation:
    "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings. " +
    "Use an ORM (Prisma, Drizzle, SQLAlchemy) or query builder (Knex) that parameterizes by default.",
  fallbackPatterns: [
    { regex: /(?:query|execute|raw)\s*\(\s*`[^`]*\$\{/g, desc: "template literal in SQL query", confidence: 0.80 },
    { regex: /(?:query|execute|raw)\s*\([^)]*\+\s*(?!['"`])\w+/g, desc: "string concatenation in SQL query", confidence: 0.70 },
    { regex: /cursor\.execute\s*\(\s*(?:f['"]|['"].*%s|['"].*\{)/g, desc: "Python f-string/format in SQL execute", confidence: 0.75 },
  ],
  safePatterns: [
    /\.prepare\s*\(/, // Prepared statements
    /\$\d+/,          // Parameterized placeholders ($1, $2)
    /\?\s*,/,         // ? placeholders
  ],
};

const C12_UNSAFE_DESERIALIZATION: RuleDef = {
  id: "C12",
  name: "Unsafe Deserialization (Taint-Aware)",
  severity: "critical",
  astSinkCategories: ["deserialization"],
  taintSinkCategories: ["deserialization"],
  owasp: "MCP03-command-injection",
  mitre: "AML.T0054",
  remediation:
    "Replace pickle.loads() with json.loads(). Replace yaml.load() with yaml.safe_load(). " +
    "Never deserialize untrusted data with pickle, marshal, or node-serialize. " +
    "Use SafeLoader for YAML: yaml.load(data, Loader=yaml.SafeLoader).",
  fallbackPatterns: [
    { regex: /pickle\.loads?\s*\(\s*(?!b['"])\w+/g, desc: "pickle.load with variable input", confidence: 0.85 },
    { regex: /yaml\.load\s*\([^)]*(?!SafeLoader|safe_load)/g, desc: "yaml.load without SafeLoader", confidence: 0.80 },
    { regex: /(?:unserialize|deserialize)\s*\(\s*(?!\s*['"`])\w+/g, desc: "deserialize with variable input", confidence: 0.75 },
    { regex: /marshal\.loads?\s*\(/g, desc: "marshal.loads (always unsafe)", confidence: 0.90 },
    { regex: /require\s*\(\s*['"]node-serialize['"]\s*\)/g, desc: "node-serialize (CVE-2017-5941)", confidence: 0.95 },
  ],
  safePatterns: [
    /safe_load/,
    /SafeLoader/,
    /json\.loads?/,
  ],
};

const C13_TEMPLATE_INJECTION: RuleDef = {
  id: "C13",
  name: "Server-Side Template Injection (Taint-Aware)",
  severity: "critical",
  astSinkCategories: ["template_injection"],
  taintSinkCategories: ["template_render"],
  owasp: "MCP03-command-injection",
  mitre: "AML.T0054",
  remediation:
    "Never pass user-controlled strings as the template itself. Use template files with safe variable interpolation. " +
    "For Jinja2: use sandbox mode. For Nunjucks: disable autoescaping only when explicitly needed. " +
    "Validate user input before passing to any template engine.",
  fallbackPatterns: [
    { regex: /(?:Jinja2|Environment)\s*\([^)]*\)\.from_string\s*\(\s*(?!['"`])\w+/g, desc: "Jinja2 from_string with variable", confidence: 0.85 },
    { regex: /nunjucks\.renderString\s*\(\s*(?!['"`])\w+/g, desc: "nunjucks.renderString with variable", confidence: 0.85 },
    { regex: /ejs\.render\s*\(\s*(?!['"`])\w+/g, desc: "ejs.render with variable template", confidence: 0.80 },
    { regex: /pug\.render\s*\(\s*(?!['"`])\w+/g, desc: "pug.render with variable template", confidence: 0.80 },
    { regex: /Handlebars\.compile\s*\(\s*(?!['"`])\w+/g, desc: "Handlebars.compile with variable", confidence: 0.75 },
    { regex: /Template\s*\(\s*(?!['"`])\w+\s*\)\.render/g, desc: "Mako Template with variable", confidence: 0.80 },
  ],
  safePatterns: [
    /render\s*\(\s*['"][^'"]+\.(?:html|ejs|pug|hbs|njk)['"]/,  // Template file path (safe)
    /res\.render\s*\(\s*['"]/,                                    // Express res.render with file (safe)
  ],
};

const C16_DYNAMIC_CODE_EVAL: RuleDef = {
  id: "C16",
  name: "Dynamic Code Evaluation (Taint-Aware)",
  severity: "critical",
  astSinkCategories: ["code_eval", "vm_escape"],
  taintSinkCategories: ["code_eval"],
  owasp: "MCP03-command-injection",
  mitre: "AML.T0054",
  remediation:
    "Remove eval() and new Function() calls. Use JSON.parse() for data, " +
    "a proper expression parser for math, or a sandboxed VM with restricted globals. " +
    "For Python: replace eval/exec with ast.literal_eval() for data parsing.",
  fallbackPatterns: [
    { regex: /\beval\s*\(\s*(?!['"`])\w+/g, desc: "eval() with variable input", confidence: 0.80 },
    { regex: /new\s+Function\s*\(\s*(?!['"`])\w+/g, desc: "new Function() with variable", confidence: 0.80 },
    { regex: /setTimeout\s*\(\s*(?!['"`(]|function)\w+/g, desc: "setTimeout with string (not function)", confidence: 0.70 },
    { regex: /importlib\.import_module\s*\(\s*(?!['"`])\w+/g, desc: "importlib with variable module name", confidence: 0.75 },
    { regex: /__import__\s*\(\s*(?!['"`])\w+/g, desc: "__import__ with variable", confidence: 0.75 },
  ],
  safePatterns: [
    /JSON\.parse/,
    /ast\.literal_eval/,
  ],
};

const K9_DANGEROUS_POSTINSTALL: RuleDef = {
  id: "K9",
  name: "Dangerous Post-Install Hooks (Taint-Aware)",
  severity: "critical",
  astSinkCategories: ["command_execution", "ssrf"],
  taintSinkCategories: ["command_execution", "url_request"],
  owasp: "MCP10-supply-chain",
  mitre: "AML.T0054",
  remediation:
    "Remove network calls and exec() from install hooks. Use postinstall only for " +
    "compilation (node-gyp, tsc). Never curl|bash in install scripts. " +
    "If a binary download is needed, use a dedicated prebuilt package.",
  fallbackPatterns: [
    { regex: /["'](?:postinstall|preinstall|install)["']\s*:\s*["'][^"']*(?:curl|wget|fetch)\s+[^"']*\|/g, desc: "pipe-to-shell in install hook", confidence: 0.95 },
    { regex: /["'](?:postinstall|preinstall)["']\s*:\s*["'][^"']*(?:eval|base64|atob|Buffer\.from)/g, desc: "encoded payload in install hook", confidence: 0.90 },
    { regex: /["'](?:postinstall|preinstall)["']\s*:\s*["'](?:bash|sh|zsh|cmd)\s/g, desc: "shell invocation in install hook", confidence: 0.85 },
    { regex: /cmdclass\s*=.*(?:install|build|develop).*(?:subprocess|os\.system|exec)/g, desc: "Python setup.py cmdclass with exec", confidence: 0.85 },
    { regex: /class\s+\w*(?:Install|PostInstall)\w*.*(?:subprocess|os\.system|urllib|requests\.get)/g, desc: "Python install class with network/exec", confidence: 0.80 },
  ],
  safePatterns: [
    /node-gyp|prebuild|esbuild|tsc|npx\s+tsc|compile|cmake/,
  ],
};

const J2_GIT_ARGUMENT_INJECTION: RuleDef = {
  id: "J2",
  name: "Git Argument Injection (Taint-Aware)",
  severity: "critical",
  astSinkCategories: ["command_execution"],
  taintSinkCategories: ["command_execution"],
  owasp: "MCP03-command-injection",
  mitre: "AML.T0054",
  remediation:
    "Never pass user input to git commands via exec(). Use a git library (simple-git, nodegit) " +
    "that doesn't invoke shell. Validate git refs against ^[a-zA-Z0-9._/-]+$. " +
    "Block arguments starting with '--' from user input.",
  fallbackPatterns: [
    { regex: /(?:exec|spawn)(?:Sync)?\s*\(\s*[`"']git\s+(?:clone|fetch|pull|push|init|remote)[^)]*(?:\$\{|\+\s*\w+)/g, desc: "git command with injected variable", confidence: 0.85 },
    { regex: /--(?:upload-pack|exec|receive-pack)\s*[=\s]+(?:\$\{|\w+)/g, desc: "git --upload-pack/--exec with variable", confidence: 0.90 },
    { regex: /git_init|git\.init/g, desc: "unrestricted git_init (CVE-2025-68143)", confidence: 0.70 },
    { regex: /(?:exec|spawn)(?:Sync)?\s*\(\s*[`"']git\s[^)]*\.\.\//g, desc: "git command with path traversal", confidence: 0.80 },
  ],
  safePatterns: [
    /execFile(?:Sync)?\s*\(\s*['"]git['"]/,  // execFile is safe (no shell injection)
    /simple-git/,                              // Library usage (safe)
  ],
};

// ─── Generic taint-based rule implementation ───────────────────────────────

class TaintBasedRule implements TypedRule {
  readonly id: string;
  readonly name: string;
  private def: RuleDef;

  constructor(def: RuleDef) {
    this.def = def;
    this.id = def.id;
    this.name = def.name;
  }

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];

    // Phase 1: AST taint analysis (highest confidence)
    let astFlowCount = 0;
    try {
      const astFlows = analyzeASTTaint(context.source_code);
      const relevantFlows = astFlows.filter((f) =>
        this.def.astSinkCategories.includes(f.sink.category)
      );

      for (const flow of relevantFlows) {
        astFlowCount++;
        if (flow.sanitized) {
          findings.push({
            rule_id: this.def.id,
            severity: "informational",
            evidence: formatASTEvidence(this.def.id, flow, true),
            remediation: "Sanitizer detected. Verify it handles all edge cases.",
            owasp_category: this.def.owasp,
            mitre_technique: this.def.mitre,
            confidence: flow.confidence * 0.3,
          });
        } else {
          findings.push({
            rule_id: this.def.id,
            severity: this.def.severity,
            evidence: formatASTEvidence(this.def.id, flow, false),
            remediation: this.def.remediation,
            owasp_category: this.def.owasp,
            mitre_technique: this.def.mitre,
            confidence: flow.confidence,
            metadata: {
              analysis_type: "ast_taint",
              source_category: flow.source.category,
              source_line: flow.source.line,
              sink_line: flow.sink.line,
              path_length: flow.path.length,
            },
          });
        }
      }
    } catch {
      // AST parsing failed — fall through to lightweight taint
    }

    // Phase 2: Lightweight taint analysis (fallback for Python and patterns AST misses)
    if (astFlowCount === 0) {
      const taintFlows = analyzeTaint(context.source_code);
      const relevantFlows = taintFlows.filter((f) =>
        this.def.taintSinkCategories.includes(f.sink.category)
      );

      for (const flow of relevantFlows) {
        if (flow.sanitized) {
          findings.push({
            rule_id: this.def.id,
            severity: "informational",
            evidence: formatTaintEvidence(this.def.id, flow, true),
            remediation: "Sanitizer detected. Verify it handles all edge cases.",
            owasp_category: this.def.owasp,
            mitre_technique: this.def.mitre,
            confidence: flow.confidence * 0.3,
          });
        } else {
          findings.push({
            rule_id: this.def.id,
            severity: this.def.severity,
            evidence: formatTaintEvidence(this.def.id, flow, false),
            remediation: this.def.remediation,
            owasp_category: this.def.owasp,
            mitre_technique: this.def.mitre,
            confidence: flow.confidence,
            metadata: {
              analysis_type: "taint",
              source_category: flow.source.category,
              source_line: flow.source.line,
              sink_line: flow.sink.line,
            },
          });
        }
      }
    }

    // Phase 3: Regex fallback for patterns neither taint engine catches
    const criticalFindings = findings.filter((f) => f.severity === this.def.severity);
    if (astFlowCount === 0 && criticalFindings.length === 0) {
      for (const { regex, desc, confidence } of this.def.fallbackPatterns) {
        regex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = regex.exec(context.source_code)) !== null) {
          const line = context.source_code.substring(0, match.index).split("\n").length;
          const lineText = context.source_code.split("\n")[line - 1] || "";

          // Skip safe patterns
          if (this.def.safePatterns.some((p) => p.test(lineText))) continue;

          findings.push({
            rule_id: this.def.id,
            severity: "high", // Lower than taint-confirmed findings
            evidence:
              `[${this.def.id} regex fallback] ${desc} at line ${line}: ` +
              `"${match[0].slice(0, 80)}". ` +
              `Taint analysis could not confirm data flow — manual review recommended.`,
            remediation: this.def.remediation,
            owasp_category: this.def.owasp,
            mitre_technique: this.def.mitre,
            confidence,
            metadata: { analysis_type: "regex_fallback", line, pattern: desc },
          });
          break; // One finding per fallback pattern
        }
      }
    }

    return findings;
  }
}

// ─── Register all rules ────────────────────────────────────────────────────

registerTypedRule(new TaintBasedRule(C4_SQL_INJECTION));
registerTypedRule(new TaintBasedRule(C12_UNSAFE_DESERIALIZATION));
registerTypedRule(new TaintBasedRule(C13_TEMPLATE_INJECTION));
registerTypedRule(new TaintBasedRule(C16_DYNAMIC_CODE_EVAL));
registerTypedRule(new TaintBasedRule(K9_DANGEROUS_POSTINSTALL));
registerTypedRule(new TaintBasedRule(J2_GIT_ARGUMENT_INJECTION));
