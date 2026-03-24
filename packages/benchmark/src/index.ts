#!/usr/bin/env node
/**
 * Benchmark Runner — evaluates MCP Sentinel and competitors on the curated corpus.
 *
 * Usage:
 *   pnpm benchmark                # Run benchmark, text output
 *   pnpm benchmark --report       # Generate Markdown report
 *   pnpm benchmark --json         # JSON output
 *   pnpm benchmark --competitors  # Include competitor tools
 *
 * No database required — runs entirely on the in-memory corpus.
 */

import { writeFileSync } from "fs";
import { resolve } from "path";
import pino from "pino";
import { BENCHMARK_CORPUS, getCorpusStats, type BenchmarkServer, type CorpusCategory } from "./corpus.js";
import { computeMetrics } from "./ground-truth.js";
import { COMPETITOR_ADAPTERS, type CompetitorResult } from "./competitors.js";
import { generateBenchmarkReport, type ToolBenchmarkResult, type BenchmarkReport } from "./report.js";

const logger = pino({ name: "benchmark" }, process.stderr);

// ── Sentinel Scanner ────────────────────────────────────────────────────────

interface SentinelFinding {
  rule_id: string;
  severity: string;
  evidence: string;
}

/** Lazily cached engine + rules — loaded once, reused for all 100 servers. */
let cachedEngine: { analyze: (ctx: unknown) => SentinelFinding[] } | null = null;

async function getOrCreateEngine(): Promise<{ analyze: (ctx: unknown) => SentinelFinding[] }> {
  if (cachedEngine) return cachedEngine;

  const { AnalysisEngine, loadRules } = await import("@mcp-sentinel/analyzer");

  const rulesDir = resolve(import.meta.dirname ?? ".", "../../../rules");
  let rules;
  try {
    rules = loadRules(rulesDir);
  } catch {
    try {
      rules = loadRules(resolve(process.cwd(), "rules"));
    } catch {
      logger.warn("Rules directory not found — running with empty ruleset");
      rules = [];
    }
  }

  logger.info({ rules_loaded: rules.length }, "Analyzer engine initialized");
  const engine = new AnalysisEngine(rules);

  cachedEngine = {
    analyze: (ctx) => {
      const findings = engine.analyze(ctx as Parameters<typeof engine.analyze>[0]);
      return findings.map((f) => ({
        rule_id: f.rule_id,
        severity: f.severity,
        evidence: f.evidence,
      }));
    },
  };

  return cachedEngine;
}

/**
 * Run MCP Sentinel analysis on a single benchmark server.
 * Uses the cached analyzer engine (no DB required).
 */
async function runSentinel(server: BenchmarkServer): Promise<SentinelFinding[]> {
  const engine = await getOrCreateEngine();
  return engine.analyze(server.context);
}

// ── Benchmark Execution ─────────────────────────────────────────────────────

interface ServerResult {
  server_id: string;
  category: CorpusCategory;
  sentinel_findings: string[];
  competitor_findings: Map<string, string[]>;
  expected_findings: string[];
  must_not_fire: string[];
  /** All findings detected that are NOT in expected_findings — used for full FP measurement */
  sentinel_unexpected: string[];
}

async function runBenchmark(includeCompetitors: boolean): Promise<{
  results: ServerResult[];
  competitorMeta: Map<string, CompetitorResult>;
  sentinel_elapsed_ms: number;
}> {
  const corpus = BENCHMARK_CORPUS;
  const stats = getCorpusStats();

  logger.info(stats, "Starting benchmark");

  // Warm up engine before timing
  await getOrCreateEngine();

  const results: ServerResult[] = [];
  const competitorMeta = new Map<string, CompetitorResult>();
  const sentinelStart = Date.now();

  for (let i = 0; i < corpus.length; i++) {
    const server = corpus[i];
    const progress = `[${i + 1}/${corpus.length}]`;

    // Run Sentinel
    let sentinelFindings: SentinelFinding[] = [];
    try {
      sentinelFindings = await runSentinel(server);
    } catch (err) {
      logger.error({ server: server.id, err }, `${progress} Sentinel scan failed`);
    }

    const sentinelRuleIds = [...new Set(sentinelFindings.map((f) => f.rule_id))];
    const expectedSet = new Set(server.expected_findings);
    const unexpectedFindings = sentinelRuleIds.filter((id) => !expectedSet.has(id));

    // Run competitors
    const compFindings = new Map<string, string[]>();
    if (includeCompetitors) {
      for (const [name, adapter] of Object.entries(COMPETITOR_ADAPTERS)) {
        try {
          const result = await adapter(
            server.context.source_code,
            server.context.tools.map((t) => ({ name: t.name, description: t.description })),
            server.name
          );
          compFindings.set(name, result.findings.map((f) => f.rule_id));
          if (!competitorMeta.has(name)) competitorMeta.set(name, result);
        } catch {
          compFindings.set(name, []);
        }
      }
    }

    results.push({
      server_id: server.id,
      category: server.category,
      sentinel_findings: sentinelRuleIds,
      competitor_findings: compFindings,
      expected_findings: server.expected_findings,
      must_not_fire: server.must_not_fire,
      sentinel_unexpected: unexpectedFindings,
    });

    if ((i + 1) % 25 === 0) {
      logger.info(`${progress} ${server.category} batch complete`);
    }
  }

  const sentinel_elapsed_ms = Date.now() - sentinelStart;
  return { results, competitorMeta, sentinel_elapsed_ms };
}

// ── Metrics Computation ─────────────────────────────────────────────────────

function computeToolMetrics(
  results: ServerResult[],
  findingsGetter: (r: ServerResult) => string[],
  toolName: string,
  elapsed_ms: number
): ToolBenchmarkResult {
  let tp = 0, fn = 0, tn = 0, fp = 0;
  let totalFindings = 0;

  const byCategory: Record<CorpusCategory, { tp: number; fn: number; tn: number; fp: number }> = {
    "cve-backed": { tp: 0, fn: 0, tn: 0, fp: 0 },
    "intentionally-vulnerable": { tp: 0, fn: 0, tn: 0, fp: 0 },
    "clean": { tp: 0, fn: 0, tn: 0, fp: 0 },
    "tricky": { tp: 0, fn: 0, tn: 0, fp: 0 },
  };

  for (const result of results) {
    const findings = findingsGetter(result);
    totalFindings += findings.length;

    // True positives: expected finding present AND detected
    for (const expected of result.expected_findings) {
      if (findings.includes(expected)) {
        tp++;
        byCategory[result.category].tp++;
      } else {
        fn++;
        byCategory[result.category].fn++;
      }
    }

    // False positives: TWO sources
    // 1. Explicit must_not_fire rules that incorrectly triggered
    for (const blocked of result.must_not_fire) {
      if (findings.includes(blocked)) {
        fp++;
        byCategory[result.category].fp++;
      } else {
        tn++;
        byCategory[result.category].tn++;
      }
    }

    // 2. On clean/tricky servers, ANY finding not in expected_findings is a false positive
    if (result.category === "clean" || result.category === "tricky") {
      const expectedSet = new Set(result.expected_findings);
      const mustNotSet = new Set(result.must_not_fire);
      for (const f of findings) {
        if (!expectedSet.has(f) && !mustNotSet.has(f)) {
          fp++;
          byCategory[result.category].fp++;
        }
      }
    }
  }

  const catMetrics = {} as Record<CorpusCategory, BenchmarkMetrics>;
  for (const [cat, counts] of Object.entries(byCategory)) {
    catMetrics[cat as CorpusCategory] = computeMetrics(counts.tp, counts.fn, counts.tn, counts.fp);
  }

  return {
    tool_name: toolName,
    overall_metrics: computeMetrics(tp, fn, tn, fp),
    by_category: catMetrics,
    unique_findings: 0, // computed after all tools run
    unique_finding_ids: [],
    total_findings: totalFindings,
    elapsed_ms,
  };
}

/**
 * Compute findings only Sentinel detected.
 *
 * Comparison uses VULNERABILITY EQUIVALENCE, not raw rule IDs.
 * Competitor tools use different rule ID schemes, so we map both
 * Sentinel and competitor findings to a common vulnerability class
 * before comparison.
 */
function computeUniqueFindings(
  sentinelResult: ToolBenchmarkResult,
  results: ServerResult[],
  competitorNames: string[]
): void {
  const uniqueIds: string[] = [];

  for (const r of results) {
    for (const finding of r.sentinel_findings) {
      if (!r.expected_findings.includes(finding)) continue; // only count verified TPs

      const vulnClass = mapToVulnClass(finding);
      const foundByCompetitor = competitorNames.some((comp) => {
        const compFindings = r.competitor_findings.get(comp) || [];
        return compFindings.some((cf) => mapToVulnClass(cf) === vulnClass);
      });

      if (!foundByCompetitor) {
        uniqueIds.push(`${r.server_id}:${finding}`);
      }
    }
  }

  sentinelResult.unique_findings = uniqueIds.length;
  sentinelResult.unique_finding_ids = uniqueIds;
}

/**
 * Map tool-specific rule IDs to a common vulnerability class.
 * This enables cross-tool comparison despite different taxonomies.
 */
function mapToVulnClass(ruleId: string): string {
  const VULN_MAP: Record<string, string> = {
    // Sentinel rule IDs → class
    "C1": "command-injection", "C9": "command-injection", "C13": "command-injection",
    "C2": "path-traversal",
    "C3": "ssrf",
    "C4": "sql-injection",
    "C5": "hardcoded-secrets",
    "C10": "prototype-pollution",
    "C11": "redos",
    "C12": "unsafe-deserialization",
    "C14": "jwt-confusion",
    "C15": "timing-attack",
    "C16": "code-eval",
    "H1": "oauth-insecure",
    "J1": "cross-agent-config-poison",
    "J2": "git-arg-injection",
    "J4": "info-disclosure",
    "J5": "tool-output-poisoning",
    "J7": "openapi-injection",
    "K5": "auto-approve-bypass",
    "I15": "session-security",
    "G1": "indirect-injection-gateway",
    "F1": "lethal-trifecta",
    "I7": "sampling-abuse",
    // Baseline scanner rule IDs → class
    "CMD-INJ": "command-injection",
    "CODE-EVAL": "code-eval",
    "SQL-INJ": "sql-injection",
    "SECRET": "hardcoded-secrets",
    "DESER": "unsafe-deserialization",
    "OAUTH": "oauth-insecure",
    "PATH-TRAV": "path-traversal",
  };
  return VULN_MAP[ruleId] ?? ruleId;
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const reportMode = args.includes("--report");
  const jsonMode = args.includes("--json");
  const includeCompetitors = args.includes("--competitors");

  const { results, competitorMeta, sentinel_elapsed_ms } = await runBenchmark(includeCompetitors);

  // Compute Sentinel metrics
  const sentinelResult = computeToolMetrics(
    results, (r) => r.sentinel_findings, "MCP Sentinel", sentinel_elapsed_ms
  );

  // Compute competitor metrics — only include tools that produced findings
  const competitorResults: ToolBenchmarkResult[] = [];
  if (includeCompetitors) {
    // Filter to only tools that returned available: true with actual findings
    const availableCompetitors: string[] = [];
    for (const compName of Object.keys(COMPETITOR_ADAPTERS)) {
      const meta = competitorMeta.get(compName);
      if (meta?.available) {
        availableCompetitors.push(compName);
        const compResult = computeToolMetrics(
          results, (r) => r.competitor_findings.get(compName) || [], compName, 0
        );
        competitorResults.push(compResult);
      } else {
        logger.info({ tool: compName, error: meta?.error }, "Competitor unavailable, excluded from metrics");
      }
    }
    computeUniqueFindings(sentinelResult, results, availableCompetitors);
  } else {
    // Always compare against baseline
    const baselineStart = Date.now();
    const baselineResults: ServerResult[] = [];
    for (const server of BENCHMARK_CORPUS) {
      const adapter = COMPETITOR_ADAPTERS["baseline-regex"];
      const result = await adapter(
        server.context.source_code,
        server.context.tools.map((t) => ({ name: t.name, description: t.description })),
        server.name
      );
      const original = results.find((r) => r.server_id === server.id);
      baselineResults.push({
        server_id: server.id,
        category: server.category,
        sentinel_findings: original?.sentinel_findings || [],
        competitor_findings: new Map([["baseline-regex", result.findings.map((f) => f.rule_id)]]),
        expected_findings: server.expected_findings,
        must_not_fire: server.must_not_fire,
        sentinel_unexpected: original?.sentinel_unexpected || [],
      });
    }
    const baselineElapsed = Date.now() - baselineStart;

    const baselineResult = computeToolMetrics(
      baselineResults, (r) => r.competitor_findings.get("baseline-regex") || [],
      "baseline-regex-scanner", baselineElapsed
    );
    competitorResults.push(baselineResult);

    computeUniqueFindings(sentinelResult, baselineResults, ["baseline-regex"]);
  }

  // Target metrics
  const PRECISION_TARGET = 85;
  const RECALL_TARGET = 70;
  const UNIQUE_TARGET = 30;
  const FP_TARGET = 15;

  const report: BenchmarkReport = {
    generated_at: new Date().toISOString().slice(0, 10),
    corpus_size: BENCHMARK_CORPUS.length,
    tools_compared: ["MCP Sentinel", ...competitorResults.map((c) => c.tool_name)],
    sentinel_result: sentinelResult,
    competitor_results: competitorResults,
    target_metrics: {
      precision_target: PRECISION_TARGET,
      recall_target: RECALL_TARGET,
      unique_detection_target: UNIQUE_TARGET,
      false_positive_target: FP_TARGET,
      precision_met: sentinelResult.overall_metrics.precision >= PRECISION_TARGET,
      recall_met: sentinelResult.overall_metrics.recall >= RECALL_TARGET,
      unique_met: sentinelResult.unique_findings >= UNIQUE_TARGET,
      fp_met: sentinelResult.overall_metrics.false_positive_rate <= FP_TARGET,
    },
  };

  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
  } else if (reportMode) {
    const markdown = generateBenchmarkReport(report);
    const outPath = resolve(process.cwd(), "packages/benchmark/results/benchmark-q1-2026.md");
    writeFileSync(outPath, markdown);
    console.error(`Report written to ${outPath}`);
    console.log(markdown);
  } else {
    // Summary output
    console.log("MCP Security Tool Benchmark Results");
    console.log("=".repeat(50));
    console.log(`Corpus: ${BENCHMARK_CORPUS.length} servers`);
    console.log();
    console.log("MCP Sentinel:");
    console.log(`  Precision: ${sentinelResult.overall_metrics.precision}% (target: >${PRECISION_TARGET}%)`);
    console.log(`  Recall:    ${sentinelResult.overall_metrics.recall}% (target: >${RECALL_TARGET}%)`);
    console.log(`  F1:        ${sentinelResult.overall_metrics.f1_score}%`);
    console.log(`  FP Rate:   ${sentinelResult.overall_metrics.false_positive_rate}% (target: <${FP_TARGET}%)`);
    console.log(`  Unique:    ${sentinelResult.unique_findings} findings`);
    console.log(`  Total:     ${sentinelResult.total_findings} findings`);
    console.log(`  Time:      ${(sentinel_elapsed_ms / 1000).toFixed(1)}s`);
    console.log();

    // Show unexpected findings for debugging
    const unexpectedTotal = results.reduce((sum, r) => sum + r.sentinel_unexpected.length, 0);
    if (unexpectedTotal > 0) {
      console.log(`  Unexpected findings: ${unexpectedTotal} (on clean/tricky servers counted as FP)`);
      const topUnexpected = new Map<string, number>();
      for (const r of results) {
        if (r.category === "clean" || r.category === "tricky") {
          for (const u of r.sentinel_unexpected) {
            topUnexpected.set(u, (topUnexpected.get(u) || 0) + 1);
          }
        }
      }
      const sorted = [...topUnexpected.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
      for (const [rule, count] of sorted) {
        console.log(`    ${rule}: ${count} unexpected fires`);
      }
      console.log();
    }

    for (const comp of competitorResults) {
      console.log(`${comp.tool_name}:`);
      console.log(`  Precision: ${comp.overall_metrics.precision}%`);
      console.log(`  Recall:    ${comp.overall_metrics.recall}%`);
      console.log(`  F1:        ${comp.overall_metrics.f1_score}%`);
      console.log(`  Total:     ${comp.total_findings} findings`);
      console.log();
    }

    // Pass/fail summary
    console.log("Target Metrics:");
    console.log(`  Precision >${PRECISION_TARGET}%: ${report.target_metrics.precision_met ? "PASS" : "FAIL"}`);
    console.log(`  Recall >${RECALL_TARGET}%: ${report.target_metrics.recall_met ? "PASS" : "FAIL"}`);
    console.log(`  Unique >${UNIQUE_TARGET}: ${report.target_metrics.unique_met ? "PASS" : "FAIL"}`);
    console.log(`  FP Rate <${FP_TARGET}%: ${report.target_metrics.fp_met ? "PASS" : "FAIL"}`);
  }

  // Exit 1 if any target metric is not met (for CI gating)
  const allTargetsMet = report.target_metrics.precision_met
    && report.target_metrics.recall_met
    && report.target_metrics.unique_met
    && report.target_metrics.fp_met;
  return allTargetsMet ? 0 : 1;
}

main().then((exitCode) => {
  process.exitCode = exitCode;
}).catch((err) => {
  logger.error({ err }, "Benchmark failed");
  process.exit(1);
});
