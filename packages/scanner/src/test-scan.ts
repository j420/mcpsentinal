#!/usr/bin/env node
/**
 * Standalone test scan — no database required.
 *
 * Runs the full analysis pipeline (fetch → audit → analyze → score) against
 * a real public MCP server and prints a detailed security report.
 *
 * Usage:
 *   tsx packages/scanner/src/test-scan.ts [github-url]
 *   tsx packages/scanner/src/test-scan.ts --local    # use built-in vulnerable fixture
 *
 * Examples:
 *   tsx packages/scanner/src/test-scan.ts --local
 *   tsx packages/scanner/src/test-scan.ts https://github.com/modelcontextprotocol/servers
 *   GITHUB_TOKEN=ghp_xxx tsx packages/scanner/src/test-scan.ts https://github.com/owner/repo
 */

import path from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { AnalysisEngine, loadRules, getRulesVersion } from "@mcp-sentinel/analyzer";
import { computeScore } from "@mcp-sentinel/scorer";
import { SourceFetcher } from "./fetcher.js";
import { DependencyAuditor } from "./auditor.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const RULES_DIR = path.resolve(__dirname, "../../../rules");
const FIXTURE_PATH = path.resolve(__dirname, "fixtures/vulnerable-server.ts");

const arg = process.argv[2];
const useLocal = arg === "--local";
const target = useLocal ? "local://fixture/vulnerable-server" : (arg ?? "https://github.com/modelcontextprotocol/servers");

// ── Run ───────────────────────────────────────────────────────────────────────
async function main() {
  const separator = "═".repeat(62);
  console.log(`\n${separator}`);
  console.log("  MCP SENTINEL — Standalone Security Scan");
  console.log(separator);
  console.log(`  Target  : ${target}`);
  console.log(`  Mode    : ${useLocal ? "LOCAL FIXTURE (no network)" : "GitHub fetch"}`);
  console.log(`  Rules   : ${RULES_DIR}`);
  console.log(separator + "\n");

  // ── Step 1: Load detection rules ──────────────────────────────────────────
  process.stdout.write("Loading detection rules... ");
  const rules = loadRules(RULES_DIR);
  const rulesVersion = getRulesVersion(rules);
  const ruleCategories: Record<string, string> = {};
  for (const rule of rules) ruleCategories[rule.id] = rule.category;
  console.log(`${rules.length} rules loaded (${rulesVersion})`);

  const engine = new AnalysisEngine(rules);

  // ── Step 2: Get source code ────────────────────────────────────────────────
  let sourceCode: string | null = null;
  let enrichedDeps: Awaited<ReturnType<DependencyAuditor["audit"]>> = [];
  let filesFetched: string[] = [];

  if (useLocal) {
    // Local fixture mode — instant, no network needed
    console.log("Using local vulnerable fixture (fixtures/vulnerable-server.ts)");
    sourceCode = readFileSync(FIXTURE_PATH, "utf-8");
    filesFetched = ["fixtures/vulnerable-server.ts"];
    console.log(`  Source: ${sourceCode.length.toLocaleString()} bytes loaded from fixture\n`);
  } else {
    // GitHub fetch mode
    process.stdout.write("Fetching source code from GitHub... ");
    const fetcher = new SourceFetcher();
    const t1 = Date.now();
    const fetched = await fetcher.fetchFromGitHub(target);
    const fetchMs = Date.now() - t1;

    if (fetched.error) {
      console.log(`\n  ⚠  Fetch error: ${fetched.error}`);
    } else {
      console.log(
        `${fetched.files_fetched.length} files, ${(fetched.source_code?.length ?? 0).toLocaleString()} bytes (${fetchMs}ms)`
      );
      if (fetched.files_fetched.length > 0) {
        console.log(`     Files: ${fetched.files_fetched.join(", ")}`);
      }
    }
    console.log(`  Dependencies found: ${fetched.raw_dependencies.length}`);

    sourceCode = fetched.source_code;
    filesFetched = fetched.files_fetched;

    // ── Step 3: CVE audit via OSV ────────────────────────────────────────────
    if (fetched.raw_dependencies.length > 0) {
      process.stdout.write(`Auditing ${fetched.raw_dependencies.length} dependencies via OSV... `);
      const auditor = new DependencyAuditor();
      const t2 = Date.now();
      enrichedDeps = await auditor.audit(fetched.raw_dependencies);
      const auditMs = Date.now() - t2;
      const vulnDeps = enrichedDeps.filter((d) => d.has_known_cve);
      console.log(`done (${auditMs}ms)`);
      if (vulnDeps.length > 0) {
        console.log(`  ⚠  ${vulnDeps.length} dependencies with known CVEs:`);
        for (const d of vulnDeps.slice(0, 5)) {
          console.log(`     • ${d.name}@${d.version ?? "?"} → ${d.cve_ids.slice(0, 3).join(", ")}`);
        }
        if (vulnDeps.length > 5) console.log(`     ... and ${vulnDeps.length - 5} more`);
      } else {
        console.log("  ✓ No known CVEs found in dependencies");
      }
    }
  }

  // ── Step 4: Assemble analysis context ────────────────────────────────────
  // Use a synthetic server record (no DB needed)
  const synthId = "00000000-0000-0000-0000-000000000001";
  const context = {
    server: {
      id: synthId,
      name: useLocal ? "vulnerable-fixture" : target.split("/").slice(-2).join("/"),
      description: useLocal ? "Intentionally vulnerable MCP server fixture for rule validation" : `Scanned from ${target}`,
      github_url: useLocal ? null : target,
    },
    tools: [],                  // No live connection in standalone mode
    source_code: sourceCode,
    dependencies: enrichedDeps.map((d) => ({
      name: d.name,
      version: d.version,
      has_known_cve: d.has_known_cve,
      cve_ids: d.cve_ids,
      last_updated: d.last_updated,
    })),
    connection_metadata: null,  // No live connection
    initialize_metadata: undefined,
  };

  // ── Step 5: Run analysis engine ────────────────────────────────────────────
  process.stdout.write("Running analysis engine... ");
  const t3 = Date.now();
  const findings = engine.analyze(context);
  const analysisMs = Date.now() - t3;
  console.log(`${findings.length} findings (${analysisMs}ms)\n`);

  // ── Step 6: Compute score ──────────────────────────────────────────────────
  const score = computeScore(findings, ruleCategories);

  // ── Report ────────────────────────────────────────────────────────────────
  printReport(target, score, findings, filesFetched, sourceCode, enrichedDeps);
}

function printReport(
  target: string,
  score: ReturnType<typeof computeScore>,
  findings: ReturnType<InstanceType<typeof AnalysisEngine>["analyze"]>,
  filesFetched: string[],
  sourceCode: string | null,
  deps: Awaited<ReturnType<DependencyAuditor["audit"]>>
) {
  const separator = "─".repeat(62);
  const badge = scoreBadge(score.total_score);

  console.log("═".repeat(62));
  console.log("  SECURITY SCAN REPORT");
  console.log("═".repeat(62));
  console.log(`  Server     : ${target}`);
  console.log(`  Score      : ${badge} ${score.total_score}/100`);
  console.log(`  Findings   : ${findings.length}`);
  console.log(`  Source     : ${filesFetched.length} files, ${(sourceCode?.length ?? 0).toLocaleString()} bytes`);
  console.log(`  Deps       : ${deps.length} total, ${deps.filter((d) => d.has_known_cve).length} with CVEs`);
  console.log(separator);

  // Sub-scores
  console.log("  Sub-scores:");
  console.log(`    Description  ${scoreBar(score.description_score)} ${score.description_score}`);
  console.log(`    Schema       ${scoreBar(score.config_score)}       ${score.config_score}`);
  console.log(`    Code         ${scoreBar(score.code_score)}         ${score.code_score}`);
  console.log(`    Dependencies ${scoreBar(score.deps_score)}  ${score.deps_score}`);
  console.log(`    Behavioral   ${scoreBar(score.behavior_score)}     ${score.behavior_score}`);
  console.log(separator);

  // OWASP coverage
  const owaspClean = Object.values(score.owasp_coverage).filter(Boolean).length;
  const owaspTotal = Object.keys(score.owasp_coverage).length;
  console.log(`  OWASP MCP Top 10 coverage: ${owaspClean}/${owaspTotal} categories clean`);
  const dirtyCategories = Object.entries(score.owasp_coverage)
    .filter(([, clean]) => !clean)
    .map(([cat]) => cat);
  if (dirtyCategories.length > 0) {
    console.log(`  Affected categories: ${dirtyCategories.join(", ")}`);
  }
  console.log(separator);

  // Findings grouped by severity
  if (findings.length === 0) {
    console.log("  ✓ No findings — server appears clean");
  } else {
    const bySeverity = groupBy(findings, (f) => f.severity);
    const order = ["critical", "high", "medium", "low", "informational"] as const;

    for (const sev of order) {
      const group = bySeverity.get(sev) ?? [];
      if (group.length === 0) continue;

      const icon = severityIcon(sev);
      console.log(`\n  ${icon} ${sev.toUpperCase()} (${group.length})`);

      for (const f of group) {
        console.log(`    [${f.rule_id}] ${f.evidence.substring(0, 100)}`);
        if (f.owasp_category) console.log(`           OWASP: ${f.owasp_category}`);
        console.log(`           Fix: ${f.remediation.substring(0, 90)}`);
      }
    }
  }

  console.log("\n" + "═".repeat(62));
  console.log(`  Rating: ${scoreRating(score.total_score)}`);
  console.log("═".repeat(62) + "\n");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreBadge(score: number): string {
  if (score >= 80) return "🟢";
  if (score >= 60) return "🟡";
  if (score >= 40) return "🟠";
  return "🔴";
}

function scoreBar(score: number): string {
  const filled = Math.round(score / 10);
  return "█".repeat(filled) + "░".repeat(10 - filled);
}

function scoreRating(score: number): string {
  if (score >= 80) return `GOOD (${score}) — Low risk`;
  if (score >= 60) return `MODERATE (${score}) — Review recommended`;
  if (score >= 40) return `POOR (${score}) — Remediation required`;
  return `CRITICAL (${score}) — Do not deploy`;
}

function severityIcon(sev: string): string {
  return { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", informational: "⚪" }[sev] ?? "•";
}

function groupBy<T>(arr: T[], key: (item: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of arr) {
    const k = key(item);
    const existing = map.get(k) ?? [];
    existing.push(item);
    map.set(k, existing);
  }
  return map;
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
