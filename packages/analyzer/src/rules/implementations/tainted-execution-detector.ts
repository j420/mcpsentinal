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
import { EvidenceChainBuilder } from "../../evidence.js";

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

/** Evidence chain parameters per rule — drives structured chain construction */
interface EvidenceConfig {
  source_type: "user-parameter" | "external-content";
  sink_type:
    | "sql-execution"
    | "deserialization"
    | "template-render"
    | "code-evaluation"
    | "command-execution";
  impact_type:
    | "remote-code-execution"
    | "data-exfiltration";
  cve_precedent: string;
  scope: "server-host" | "connected-services";
  /** Threat reference for the chain */
  threat_ref: { id: string; title: string; url?: string; relevance: string };
}

const EVIDENCE_CONFIGS: Record<string, EvidenceConfig> = {
  C4: {
    source_type: "user-parameter",
    sink_type: "sql-execution",
    impact_type: "data-exfiltration",
    cve_precedent: "CWE-89",
    scope: "connected-services",
    threat_ref: {
      id: "CWE-89",
      title: "SQL Injection via untrusted input in query construction",
      relevance: "User-controlled input concatenated into SQL queries enables data exfiltration, authentication bypass, and database manipulation",
    },
  },
  C12: {
    source_type: "user-parameter",
    sink_type: "deserialization",
    impact_type: "remote-code-execution",
    cve_precedent: "CWE-502",
    scope: "server-host",
    threat_ref: {
      id: "CWE-502",
      title: "Deserialization of Untrusted Data",
      url: "https://cwe.mitre.org/data/definitions/502.html",
      relevance: "Deserializing attacker-controlled data with pickle/yaml.load/node-serialize enables arbitrary code execution on the server host",
    },
  },
  C13: {
    source_type: "user-parameter",
    sink_type: "template-render",
    impact_type: "remote-code-execution",
    cve_precedent: "CWE-1336",
    scope: "server-host",
    threat_ref: {
      id: "CWE-1336",
      title: "Server-Side Template Injection (SSTI)",
      url: "https://cwe.mitre.org/data/definitions/1336.html",
      relevance: "User-controlled strings passed as templates to Jinja2/EJS/Pug/Nunjucks enable arbitrary code execution via template engine internals",
    },
  },
  C16: {
    source_type: "user-parameter",
    sink_type: "code-evaluation",
    impact_type: "remote-code-execution",
    cve_precedent: "CWE-95",
    scope: "server-host",
    threat_ref: {
      id: "CWE-95",
      title: "Eval Injection — Dynamic Code Evaluation with User Input",
      url: "https://cwe.mitre.org/data/definitions/95.html",
      relevance: "User input reaching eval()/new Function()/__import__() enables arbitrary code execution with full server privileges",
    },
  },
  K9: {
    source_type: "external-content",
    sink_type: "command-execution",
    impact_type: "remote-code-execution",
    cve_precedent: "CWE-829",
    scope: "server-host",
    threat_ref: {
      id: "CWE-829",
      title: "Inclusion of Functionality from Untrusted Control Sphere",
      url: "https://cwe.mitre.org/data/definitions/829.html",
      relevance: "Post-install hooks that fetch and execute remote code enable supply chain attacks — every npm install becomes an RCE vector",
    },
  },
  J2: {
    source_type: "user-parameter",
    sink_type: "command-execution",
    impact_type: "remote-code-execution",
    cve_precedent: "CVE-2025-68143",
    scope: "server-host",
    threat_ref: {
      id: "CVE-2025-68143",
      title: "Anthropic mcp-server-git argument injection chain (CVSS 9.8)",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2025-68143",
      relevance: "Three-CVE chain in official Anthropic git MCP server: path validation bypass + unrestricted git_init + argument injection enabling RCE via core.sshCommand",
    },
  },
};

// ─── Rule definitions ──────────────────────────────────────────────────────

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
  private evidenceConfig: EvidenceConfig;

  constructor(def: RuleDef) {
    this.def = def;
    this.id = def.id;
    this.name = def.name;
    this.evidenceConfig = EVIDENCE_CONFIGS[def.id];
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
          const sanitizedChain = this.buildASTEvidenceChain(flow);
          findings.push({
            rule_id: this.def.id,
            severity: "informational",
            evidence: formatASTEvidence(this.def.id, flow, true),
            remediation: "Sanitizer detected. Verify it handles all edge cases.",
            owasp_category: this.def.owasp,
            mitre_technique: this.def.mitre,
            confidence: flow.confidence * 0.3,
            metadata: { analysis_type: "ast_taint_sanitized", evidence_chain: sanitizedChain },
          });
        } else {
          const chain = this.buildASTEvidenceChain(flow);
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
              path_steps: flow.path.map((s) => `${s.type}: ${s.expression}`),
              evidence_chain: chain,
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
          const sanitizedChain = this.buildTaintEvidenceChain(flow);
          findings.push({
            rule_id: this.def.id,
            severity: "informational",
            evidence: formatTaintEvidence(this.def.id, flow, true),
            remediation: "Sanitizer detected. Verify it handles all edge cases.",
            owasp_category: this.def.owasp,
            mitre_technique: this.def.mitre,
            confidence: flow.confidence * 0.3,
            metadata: { analysis_type: "taint_sanitized", evidence_chain: sanitizedChain },
          });
        } else {
          const chain = this.buildTaintEvidenceChain(flow);
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
              propagation_length: flow.propagation_chain.length,
              evidence_chain: chain,
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

          const chain = this.buildRegexFallbackChain(line, desc, match[0]);
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
            metadata: { analysis_type: "regex_fallback", line, pattern: desc, evidence_chain: chain },
          });
          break; // One finding per fallback pattern
        }
      }
    }

    return findings;
  }

  /** Build structured evidence chain from AST taint flow */
  private buildASTEvidenceChain(flow: ASTTaintFlow) {
    const ec = this.evidenceConfig;
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: ec.source_type,
        location: `line ${flow.source.line}:${flow.source.column}`,
        observed: flow.source.expression,
        rationale: `Untrusted ${flow.source.category} source enters here — AI-filled tool parameters are attacker-controlled when the AI processes untrusted content`,
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
      sink_type: ec.sink_type,
      location: `line ${flow.sink.line}:${flow.sink.column}`,
      observed: flow.sink.expression.slice(0, 80),
      cve_precedent: ec.cve_precedent,
    });

    if (flow.sanitized && flow.sanitizer_name) {
      builder.mitigation({
        mitigation_type: "sanitizer-function",
        present: true,
        location: "in taint path",
        detail: `Sanitizer "${flow.sanitizer_name}" found — verify it handles all edge cases including encoding bypass`,
      });
    } else {
      builder.mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: `between source (L${flow.source.line}) and sink (L${flow.sink.line})`,
        detail: "No sanitizer or input validation found in the data flow path from source to sink",
      });
    }

    builder
      .impact({
        impact_type: ec.impact_type,
        scope: ec.scope,
        exploitability: flow.path.length <= 1 ? "trivial" : "moderate",
        scenario: this.buildImpactScenario(flow.source.category, flow.path.length, "ast"),
      })
      .factor("ast_confirmed", 0.15, "AST-based taint tracking confirmed complete source-to-sink data flow")
      .reference(ec.threat_ref)
      .verification({
        step_type: "inspect-source",
        instruction: `Verify untrusted input at line ${flow.source.line} reaches ${ec.sink_type} at line ${flow.sink.line}`,
        target: `source_code:${flow.source.line}-${flow.sink.line}`,
        expected_observation: `Data flows from ${flow.source.expression} through ${flow.path.length} step(s) to ${flow.sink.expression.slice(0, 40)}`,
      })
      .verification({
        step_type: "trace-flow",
        instruction: `Trace the taint path: ${flow.path.length > 0 ? flow.path.map((s) => `L${s.line}`).join(" → ") : "direct"} and verify no sanitizer exists between source and sink`,
        target: flow.path.length > 0 ? flow.path.map((s) => `line ${s.line}`).join(", ") : `line ${flow.source.line}-${flow.sink.line}`,
        expected_observation: "No sanitization, parameterization, or input validation between source and sink",
      });

    return builder.build();
  }

  /** Build structured evidence chain from lightweight (regex-based) taint flow */
  private buildTaintEvidenceChain(flow: TaintFlow) {
    const ec = this.evidenceConfig;
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: ec.source_type,
        location: `line ${flow.source.line}`,
        observed: flow.source.expression,
        rationale: `Untrusted ${flow.source.category} source enters here — MCP tool parameters are populated by the AI client from potentially attacker-influenced prompts`,
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
      sink_type: ec.sink_type,
      location: `line ${flow.sink.line}`,
      observed: flow.sink.expression.slice(0, 80),
      cve_precedent: ec.cve_precedent,
    });

    if (flow.sanitized && flow.sanitizer) {
      builder.mitigation({
        mitigation_type: "sanitizer-function",
        present: true,
        location: `line ${flow.sanitizer.line}`,
        detail: `Sanitizer "${flow.sanitizer.expression}" found in propagation path`,
      });
    } else {
      builder.mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: `between source (L${flow.source.line}) and sink (L${flow.sink.line})`,
        detail: "No sanitizer or input validation found in the data flow path from source to sink",
      });
    }

    builder
      .impact({
        impact_type: ec.impact_type,
        scope: ec.scope,
        exploitability: flow.propagation_chain.length <= 1 ? "trivial" : "moderate",
        scenario: this.buildImpactScenario(flow.source.category, flow.propagation_chain.length, "taint"),
      })
      .factor("taint_confirmed", 0.1, "Regex-based taint tracking confirmed source-to-sink propagation chain")
      .reference(ec.threat_ref)
      .verification({
        step_type: "inspect-source",
        instruction: `Verify untrusted input at line ${flow.source.line} reaches ${ec.sink_type} at line ${flow.sink.line}`,
        target: `source_code:${flow.source.line}-${flow.sink.line}`,
        expected_observation: `Data flows from ${flow.source.expression} through ${flow.propagation_chain.length} step(s) to ${flow.sink.expression.slice(0, 40)}`,
      })
      .verification({
        step_type: "trace-flow",
        instruction: `Follow the propagation chain and confirm no sanitizer or parameterization exists`,
        target: flow.propagation_chain.length > 0 ? flow.propagation_chain.map((s) => `line ${s.line}`).join(", ") : `line ${flow.source.line}-${flow.sink.line}`,
        expected_observation: "No input validation, sanitization, or parameterized query construction between source and sink",
      });

    return builder.build();
  }

  /** Build evidence chain for regex-only fallback findings */
  private buildRegexFallbackChain(line: number, desc: string, matchText: string) {
    const ec = this.evidenceConfig;
    return new EvidenceChainBuilder()
      .source({
        source_type: ec.source_type,
        location: `line ${line}`,
        observed: matchText.slice(0, 80),
        rationale: "Regex pattern detected potential untrusted input in a dangerous context — taint analysis could not parse the code structure",
      })
      .sink({
        sink_type: ec.sink_type,
        location: `line ${line}`,
        observed: desc,
        cve_precedent: ec.cve_precedent,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: `line ${line}`,
        detail: "Regex-only detection — unable to determine if sanitization exists. Manual code review required.",
      })
      .impact({
        impact_type: ec.impact_type,
        scope: ec.scope,
        exploitability: "moderate",
        scenario: `Potential ${desc} detected at line ${line}. If user-controlled input reaches this ${ec.sink_type} sink without validation, an attacker could achieve ${ec.impact_type}. Taint analysis could not confirm the data flow — manual review is needed to determine exploitability.`,
      })
      .factor("regex_only", -0.15, "No taint analysis confirmation — regex pattern match only, higher false positive risk")
      .reference(ec.threat_ref)
      .verification({
        step_type: "inspect-source",
        instruction: `Examine source code at line ${line} for ${ec.sink_type} with user-controlled input`,
        target: `source_code:${line}`,
        expected_observation: `${desc} pattern with potential user-controlled input reaching a dangerous sink`,
      })
      .verification({
        step_type: "trace-flow",
        instruction: `Manually trace data flow backward from line ${line} to identify the source of the input and any sanitization`,
        target: `source_code:1-${line}`,
        expected_observation: "Input originates from an MCP tool parameter or external source and flows to the sink without validation",
      })
      .build();
  }

  /** Build a rule-specific, multi-sentence impact scenario */
  private buildImpactScenario(sourceCategory: string, pathLength: number, analysisType: string): string {
    const ruleId = this.def.id;
    const ec = this.evidenceConfig;

    switch (ruleId) {
      case "C4":
        return (
          `An attacker crafts a prompt causing the AI to fill a tool parameter with a SQL injection payload such as "' OR 1=1 --". ` +
          `The tainted input propagates through ${pathLength} step(s) from the ${sourceCategory} source to the SQL query construction, ` +
          `enabling extraction of database contents, bypass of authentication checks, or modification of stored data. ` +
          `${analysisType === "ast" ? "AST" : "Taint"} analysis confirmed the complete source-to-sink flow.`
        );
      case "C12":
        return (
          `An attacker provides serialized payload data (e.g., crafted pickle stream or YAML with !!python/object tags) via the ${sourceCategory} source. ` +
          `The payload flows through ${pathLength} step(s) to reach the deserialization sink, where it triggers arbitrary code execution during object reconstruction. ` +
          `This is the same class of vulnerability as CVE-2017-5941 (node-serialize RCE) and affects any language with native object serialization.`
        );
      case "C13":
        return (
          `An attacker injects template syntax (e.g., "{{7*7}}" for Jinja2 or "<%= process.exit() %>" for EJS) via the ${sourceCategory} source. ` +
          `The input propagates through ${pathLength} step(s) to the template rendering engine, which interprets it as executable template code rather than data. ` +
          `Successful exploitation grants full code execution within the template engine sandbox, which often provides access to the underlying runtime.`
        );
      case "C16":
        return (
          `An attacker provides a code string (e.g., "require('child_process').execSync('id')") via the ${sourceCategory} source. ` +
          `The string flows through ${pathLength} step(s) to reach eval()/new Function(), which executes it with full server privileges. ` +
          `This enables arbitrary command execution, file system access, and lateral movement from the MCP server host.`
        );
      case "K9":
        return (
          `A malicious package uses post-install hooks to fetch and execute remote code during npm install or pip install. ` +
          `The payload downloads from an attacker-controlled URL and executes with the installing user's full privileges. ` +
          `Every developer or CI system that installs this package is silently compromised — this is the primary vector for npm/PyPI supply chain attacks.`
        );
      case "J2":
        return (
          `An attacker provides a git argument injection payload (e.g., "--upload-pack=malicious_command") via the ${sourceCategory} source. ` +
          `The input flows through ${pathLength} step(s) to a git CLI invocation, where the injected argument is interpreted as a git flag enabling arbitrary command execution. ` +
          `This matches CVE-2025-68143/68144/68145: a three-CVE chain in the official Anthropic mcp-server-git that achieved RCE via git_init + core.sshCommand injection.`
        );
      default:
        return (
          `Untrusted ${sourceCategory} input flows through ${pathLength} step(s) to reach a ${ec.sink_type} sink. ` +
          `Successful exploitation could result in ${ec.impact_type} on the ${ec.scope}.`
        );
    }
  }
}

// ─── Register all rules ────────────────────────────────────────────────────

// C4 migrated to packages/analyzer/src/rules/implementations/c4-sql-injection/
registerTypedRule(new TaintBasedRule(C12_UNSAFE_DESERIALIZATION));
registerTypedRule(new TaintBasedRule(C13_TEMPLATE_INJECTION));
registerTypedRule(new TaintBasedRule(C16_DYNAMIC_CODE_EVAL));
registerTypedRule(new TaintBasedRule(K9_DANGEROUS_POSTINSTALL));
registerTypedRule(new TaintBasedRule(J2_GIT_ARGUMENT_INJECTION));
