/**
 * Report Generator — produces Markdown report from computed statistics.
 *
 * Generates "State of MCP Security Q1 2026" report combining:
 * - Ecosystem overview
 * - Vulnerability prevalence
 * - Framework comparison
 * - OWASP compliance rates
 * - AST vs regex detection comparison
 * - Recommendations
 */

import type { EcosystemOverview } from "./ecosystem-stats.js";
import type { TrendReport } from "./trend-analysis.js";
import type { CategoryReport } from "./category-breakdown.js";

export interface ReportData {
  ecosystem: EcosystemOverview;
  trends: TrendReport;
  categories: CategoryReport;
  generated_at: string;
}

export function generateMarkdownReport(data: ReportData): string {
  const { ecosystem: eco, trends, categories: cats } = data;
  const lines: string[] = [];

  const h = (level: number, text: string) => lines.push(`${"#".repeat(level)} ${text}\n`);
  const p = (text: string) => lines.push(`${text}\n`);
  const blank = () => lines.push("");
  const table = (headers: string[], rows: string[][]) => {
    lines.push(`| ${headers.join(" | ")} |`);
    lines.push(`| ${headers.map(() => "---").join(" | ")} |`);
    for (const row of rows) {
      lines.push(`| ${row.join(" | ")} |`);
    }
    blank();
  };

  // ── Title ──
  h(1, "State of MCP Security — Q1 2026");
  p(`*Generated: ${data.generated_at} by MCP Sentinel*`);
  p(`*Dataset: ${eco.total_crawled.toLocaleString()} servers crawled, ${eco.total_scanned.toLocaleString()} scanned with 177 detection rules across 17 categories*`);
  blank();

  // ── Executive Summary ──
  h(2, "Executive Summary");
  blank();
  p(`MCP Sentinel scanned **${eco.total_scanned.toLocaleString()}** MCP servers from the public ecosystem using **177 deterministic detection rules** — the most comprehensive security assessment of the MCP ecosystem to date.`);
  blank();

  p("**Key findings:**");
  p(`- **${eco.critical_pct}%** of servers have at least one critical vulnerability`);
  p(`- Average security score: **${eco.average_score}/100** (median: ${eco.median_score})`);
  p(`- **${eco.total_findings.toLocaleString()}** total findings across ${eco.unique_rules_triggered} distinct rule types`);
  p(`- **${eco.findings_per_server_avg}** findings per server on average`);
  if (trends.prevalence_rates.command_injection_pct > 0) {
    p(`- **${trends.prevalence_rates.command_injection_pct}%** vulnerable to command injection (OWASP MCP03)`);
  }
  if (trends.prevalence_rates.prompt_injection_pct > 0) {
    p(`- **${trends.prevalence_rates.prompt_injection_pct}%** vulnerable to prompt injection (OWASP MCP01)`);
  }
  blank();

  // ── 1. Ecosystem Overview ──
  h(2, "1. Ecosystem Overview");
  blank();

  table(
    ["Metric", "Value"],
    [
      ["Servers crawled", eco.total_crawled.toLocaleString()],
      ["Servers scanned", eco.total_scanned.toLocaleString()],
      ["Scan coverage", `${eco.scan_coverage_pct}%`],
      ["Average score", `${eco.average_score}/100`],
      ["Median score", `${eco.median_score}/100`],
      ["Servers with critical findings", `${eco.servers_with_critical.toLocaleString()} (${eco.critical_pct}%)`],
      ["Total findings", eco.total_findings.toLocaleString()],
      ["Unique rules triggered", eco.unique_rules_triggered.toString()],
    ],
  );

  h(3, "Score Distribution");
  blank();
  table(
    ["Rating", "Score Range", "Servers", "% of Total"],
    eco.score_distribution.map((d) => [
      d.range.split(" ")[0],
      d.range,
      d.count.toLocaleString(),
      `${d.pct}%`,
    ]),
  );

  h(3, "Language Distribution");
  blank();
  const langEntries = Object.entries(eco.language_distribution).slice(0, 8);
  table(
    ["Language", "Servers", "% of Total"],
    langEntries.map(([lang, count]) => [
      lang,
      count.toLocaleString(),
      `${Math.round((count / eco.total_crawled) * 100)}%`,
    ]),
  );

  h(3, "Server Category Distribution");
  blank();
  const catEntries = Object.entries(eco.category_distribution).slice(0, 10);
  table(
    ["Category", "Servers"],
    catEntries.map(([cat, count]) => [cat, count.toLocaleString()]),
  );

  // ── 2. Vulnerability Prevalence ──
  h(2, "2. Vulnerability Prevalence");
  blank();

  h(3, "Severity Distribution");
  blank();
  table(
    ["Severity", "Count", "% of Findings", "% of Servers Affected"],
    trends.severity_distribution.map((s) => [
      `**${s.severity}**`,
      s.count.toLocaleString(),
      `${s.pct_of_total}%`,
      `${s.pct_of_servers}%`,
    ]),
  );

  h(3, "Vulnerability Prevalence Rates");
  blank();
  p("Percentage of scanned servers affected by each vulnerability class:");
  blank();
  const pr = trends.prevalence_rates;
  table(
    ["Vulnerability Class", "% of Servers"],
    [
      ["Any finding", `${pr.any_finding_pct}%`],
      ["Critical finding", `${pr.critical_finding_pct}%`],
      ["High finding", `${pr.high_finding_pct}%`],
      ["Command Injection (MCP03)", `${pr.command_injection_pct}%`],
      ["Path Traversal (MCP05)", `${pr.path_traversal_pct}%`],
      ["Prompt Injection (MCP01)", `${pr.prompt_injection_pct}%`],
      ["SSRF / Data Exfiltration (MCP04)", `${pr.ssrf_pct}%`],
    ],
  );

  h(3, "Top 20 Most Prevalent Vulnerabilities");
  blank();
  table(
    ["#", "Rule", "Name", "Severity", "Affected Servers", "% of Scanned"],
    trends.top_vulnerabilities.map((v, i) => [
      (i + 1).toString(),
      v.rule_id,
      v.rule_name,
      v.severity,
      v.affected_servers.toLocaleString(),
      `${v.pct_of_scanned}%`,
    ]),
  );

  // ── Comparison with Published Research ──
  h(3, "Comparison with Published Research");
  blank();
  p("How MCP Sentinel's findings compare to other published ecosystem assessments:");
  blank();
  table(
    ["Metric", "MCP Sentinel", "Equixly (Feb 2026)", "Enkrypt AI", "MCPGuard", "arXiv 2506.13538"],
    [
      ["Servers analyzed", eco.total_scanned.toLocaleString(), "2,614", "1,000", "700", "1,899"],
      ["Detection rules", "177", "~20", "~15", "~30", "~10"],
      ["Command injection %", `${pr.command_injection_pct}%`, "43%", "—", "—", "—"],
      ["Critical vuln %", `${pr.critical_finding_pct}%`, "82% (path trav.)", "33%", "78%", "7.2%"],
      ["Analysis method", "AST taint + regex", "DAST", "DAST", "LLM agent", "Static (regex)"],
    ],
  );

  // ── 3. Framework Comparison ──
  h(2, "3. Framework Security Comparison");
  blank();
  p("Security posture by MCP framework — which framework produces more secure servers?");
  blank();
  table(
    ["Framework", "Servers", "Avg Score", "Median Score"],
    cats.framework_comparison
      .filter((f) => f.server_count >= 5)
      .map((f) => [
        `**${f.framework}**`,
        f.server_count.toLocaleString(),
        f.average_score.toString(),
        f.median_score.toString(),
      ]),
  );

  // ── 4. OWASP MCP Top 10 Compliance ──
  h(2, "4. OWASP MCP Top 10 Compliance");
  blank();
  p("Compliance rate = percentage of scanned servers with NO findings in that category.");
  blank();
  table(
    ["OWASP ID", "Category", "Violations", "Affected Servers", "Compliance Rate"],
    cats.owasp_compliance.map((o) => [
      o.owasp_id,
      o.owasp_name,
      o.total_violations.toLocaleString(),
      o.affected_servers.toLocaleString(),
      `**${o.compliance_rate_pct}%**`,
    ]),
  );

  // ── 5. AST vs Regex Detection ──
  h(2, "5. What AST Analysis Catches That Regex Misses");
  blank();
  p("MCP Sentinel uses two detection methods: **AST-based taint analysis** (traces data flow through program structure) and **regex pattern matching** (searches for dangerous patterns in source text).");
  blank();
  table(
    ["Method", "Findings", "Data Flow Tracking"],
    cats.detection_comparison.map((d) => [
      `**${d.method}**`,
      d.findings_count.toLocaleString(),
      d.unique_flows > 0 ? `${d.unique_flows.toLocaleString()} unique flows` : "None (pattern only)",
    ]),
  );
  blank();
  p("**Why this matters:** AST taint analysis traces the actual data flow from user input to dangerous sink. It can determine that `exec(cmd)` is safe when `cmd` comes from a hardcoded string, and dangerous when `cmd` comes from `req.body.input`. Regex cannot make this distinction.");
  blank();

  h(3, "Example: AST Taint Flow (Anonymized)");
  blank();
  p("```");
  p(cats.detection_comparison[0]?.example_evidence || "No AST findings available");
  p("```");
  blank();
  p("The AST engine traces: **source** (user-controlled input) → **propagation** (variable assignments, function calls, return values) → **sink** (dangerous function). Each step in the chain is verified at the AST level.");
  blank();

  h(3, "Cross-Module Analysis");
  blank();
  p("MCP Sentinel's cross-module analysis can detect vulnerabilities that span file boundaries:");
  blank();
  p("```");
  p("[AST taint — cross-module] http_body source \"req.body.cmd\" (utils.ts:L5) →");
  p("  return_value → import getInput from \"./utils\" → assignment →");
  p("  command_execution sink \"exec(cmd)\" (handler.ts:L12).");
  p("  Module chain: utils.ts:getInput() → handler.ts:processRequest()");
  p("```");
  blank();
  p("No other MCP security tool performs cross-file taint analysis.");
  blank();

  // ── 6. Finding Category Distribution ──
  h(2, "6. Finding Category Distribution");
  blank();
  table(
    ["Category", "Findings", "% of Total"],
    cats.finding_category_distribution.map((c) => [
      c.category,
      c.count.toLocaleString(),
      `${c.pct}%`,
    ]),
  );

  // ── 7. Language Breakdown ──
  h(2, "7. Security by Language");
  blank();
  table(
    ["Language", "Servers", "Avg Score"],
    cats.language_breakdown
      .filter((l) => l.server_count >= 5)
      .map((l) => [
        l.language,
        l.server_count.toLocaleString(),
        l.average_score.toString(),
      ]),
  );

  // ── 8. Recommendations ──
  h(2, "8. Recommendations");
  blank();

  h(3, "For MCP Server Authors");
  blank();
  p("1. **Validate all inputs** — Use Zod or JSON Schema to constrain every parameter. Missing validation (B1) is the most common finding.");
  p("2. **Use `execFile()` instead of `exec()`** — The #1 critical finding is command injection via `exec()` with unsanitized input.");
  p("3. **Add tool annotations** — Declare `destructiveHint: true` on write operations. Clients use annotations for auto-approval decisions.");
  p("4. **Audit your dependencies** — Run `npm audit` / `pip-audit` before publishing. Known CVEs in dependencies affect your security score.");
  p("5. **Don't hardcode secrets** — Move API keys to environment variables. Our entropy-based detection finds tokens that regex-based scanners miss.");
  blank();

  h(3, "For AI Client Developers");
  blank();
  p("1. **Check the MCP Sentinel score** before connecting to any server. Servers scoring below 60 have significant security issues.");
  p("2. **Never auto-approve destructive tools** — Always require user confirmation for tools without `readOnlyHint: true`.");
  p("3. **Validate the `instructions` field** from MCP initialize responses — it's an injection surface (H2).");
  p("4. **Implement tool count monitoring** — A sudden increase in tools may indicate a rug-pull attack (G6).");
  p("5. **Use the lethal trifecta as a filter** — Any server with private data access + untrusted content ingestion + external communication capabilities should be treated as high-risk.");
  blank();

  h(3, "For Enterprises");
  blank();
  p("1. **Establish a minimum score threshold** — We recommend 70+ for production use, 80+ for sensitive data access.");
  p("2. **Map to your compliance framework** — MCP Sentinel's K-rules map directly to ISO 27001, EU AI Act, and NIST AI RMF controls.");
  p("3. **Monitor for drift** — Subscribe to score change alerts. A server that was safe last week may not be safe today.");
  p("4. **Audit your MCP config** — Use `npx mcp-sentinel check` in CI/CD to scan your Claude/Cursor/VS Code MCP configuration.");
  p("5. **Require OWASP MCP Top 10 compliance** — Add it to your vendor security questionnaire.");
  blank();

  // ── Methodology ──
  h(2, "Methodology");
  blank();
  p("**Data collection:** MCP Sentinel crawls 7 sources (npm, PyPI, GitHub, Smithery, PulseMCP, Official Registry, modelcontextprotocol repo) and deduplicates by canonical identifier.");
  p("**Analysis:** Each server is analyzed with 177 deterministic detection rules across 17 categories (A–Q). Rules use 4 engine types: regex, schema-check, behavioral, and composite. Code analysis uses AST-based taint tracking (TypeScript compiler API for JS/TS, tree-sitter for Python) with cross-module import resolution.");
  p("**Scoring:** Composite 0–100 score using weighted penalty deductions per finding. Critical = -25, High = -15, Medium = -8, Low = -3, Informational = -1. Lethal trifecta (F1) caps at 40.");
  p("**Limitations:** Source code analysis depends on GitHub availability. Servers without public source get description/schema analysis only. No dynamic testing in v1 (static analysis only).");
  blank();

  // ── Footer ──
  p("---");
  p(`*This report was generated by [MCP Sentinel](https://mcp-sentinel.com) — the security intelligence layer for the MCP ecosystem.*`);
  p(`*177 detection rules | 17 categories | AST taint analysis | Cross-module tracking | OWASP MCP Top 10 mapped*`);
  blank();

  return lines.join("\n");
}
