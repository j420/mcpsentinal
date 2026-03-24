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
import { buildGroundTruth, computeMetrics, type BenchmarkMetrics } from "./ground-truth.js";
import { COMPETITOR_ADAPTERS, type CompetitorResult } from "./competitors.js";
import { generateBenchmarkReport, type ToolBenchmarkResult, type BenchmarkReport } from "./report.js";

const logger = pino({ name: "benchmark" }, process.stderr);

// ── Sentinel Scanner ────────────────────────────────────────────────────────

interface SentinelFinding {
  rule_id: string;
  severity: string;
  evidence: string;
}

/**
 * Run MCP Sentinel analysis on a single benchmark server.
 * Uses the analyzer engine directly (no DB required).
 */
async function runSentinel(server: BenchmarkServer): Promise<SentinelFinding[]> {
  // Dynamic import to avoid circular dependency issues
  const { AnalysisEngine } = await import("@mcp-sentinel/analyzer");
  const { loadRules } = await import("@mcp-sentinel/analyzer/rule-loader");

  const rulesDir = resolve(import.meta.dirname ?? ".", "../../../rules");
  let rules;
  try {
    rules = loadRules(rulesDir);
  } catch {
    // Fallback: try from project root
    try {
      rules = loadRules(resolve(process.cwd(), "rules"));
    } catch {
      logger.warn("Rules directory not found — running with empty ruleset");
      rules = [];
    }
  }

  const engine = new AnalysisEngine(rules);
  const findings = engine.analyze(server.context);

  return findings.map((f) => ({
    rule_id: f.rule_id,
    severity: f.severity,
    evidence: f.evidence,
  }));
}

// ── Benchmark Execution ─────────────────────────────────────────────────────

interface ServerResult {
  server_id: string;
  category: CorpusCategory;
  sentinel_findings: string[];
  competitor_findings: Map<string, string[]>;
  expected_findings: string[];
  must_not_fire: string[];
}

async function runBenchmark(includeCompetitors: boolean): Promise<{
  results: ServerResult[];
  competitorMeta: Map<string, CompetitorResult>;
}> {
  const corpus = BENCHMARK_CORPUS;
  const stats = getCorpusStats();

  logger.info(stats, "Starting benchmark");

  const results: ServerResult[] = [];
  const competitorMeta = new Map<string, CompetitorResult>();

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
    });

    if ((i + 1) % 25 === 0) {
      logger.info(`${progress} ${server.category} batch complete`);
    }
  }

  return { results, competitorMeta };
}

// ── Metrics Computation ─────────────────────────────────────────────────────

function computeToolMetrics(
  results: ServerResult[],
  findingsGetter: (r: ServerResult) => string[],
  toolName: string
): ToolBenchmarkResult {
  let tp = 0, fn = 0, tn = 0, fp = 0;
  let totalFindings = 0;
  const allDetected = new Set<string>();
  const start = Date.now();

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
        allDetected.add(`${result.server_id}:${expected}`);
      } else {
        fn++;
        byCategory[result.category].fn++;
      }
    }

    // False positives: must-not-fire rule incorrectly triggered
    for (const blocked of result.must_not_fire) {
      if (findings.includes(blocked)) {
        fp++;
        byCategory[result.category].fp++;
      } else {
        tn++;
        byCategory[result.category].tn++;
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
    elapsed_ms: Date.now() - start,
  };
}

function computeUniqueFindings(
  sentinelResult: ToolBenchmarkResult,
  results: ServerResult[],
  competitorNames: string[]
): void {
  const uniqueIds: string[] = [];

  for (const r of results) {
    for (const finding of r.sentinel_findings) {
      // Check if any competitor also found this
      const foundByCompetitor = competitorNames.some((comp) => {
        const compFindings = r.competitor_findings.get(comp) || [];
        return compFindings.includes(finding);
      });

      if (!foundByCompetitor && r.expected_findings.includes(finding)) {
        uniqueIds.push(`${r.server_id}:${finding}`);
      }
    }
  }

  sentinelResult.unique_findings = uniqueIds.length;
  sentinelResult.unique_finding_ids = uniqueIds;
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const reportMode = args.includes("--report");
  const jsonMode = args.includes("--json");
  const includeCompetitors = args.includes("--competitors");

  const { results, competitorMeta } = await runBenchmark(includeCompetitors);

  // Compute Sentinel metrics
  const sentinelResult = computeToolMetrics(
    results, (r) => r.sentinel_findings, "MCP Sentinel"
  );

  // Compute competitor metrics
  const competitorResults: ToolBenchmarkResult[] = [];
  if (includeCompetitors) {
    for (const compName of Object.keys(COMPETITOR_ADAPTERS)) {
      const compResult = computeToolMetrics(
        results, (r) => r.competitor_findings.get(compName) || [], compName
      );
      competitorResults.push(compResult);
    }
  }

  // Always compare against baseline
  if (!includeCompetitors) {
    // Run baseline inline
    const baselineResults: ServerResult[] = [];
    for (const server of BENCHMARK_CORPUS) {
      const adapter = COMPETITOR_ADAPTERS["baseline-regex"];
      const result = await adapter(
        server.context.source_code,
        server.context.tools.map((t) => ({ name: t.name, description: t.description })),
        server.name
      );
      baselineResults.push({
        server_id: server.id,
        category: server.category,
        sentinel_findings: results.find((r) => r.server_id === server.id)?.sentinel_findings || [],
        competitor_findings: new Map([["baseline-regex", result.findings.map((f) => f.rule_id)]]),
        expected_findings: server.expected_findings,
        must_not_fire: server.must_not_fire,
      });
    }

    const baselineResult = computeToolMetrics(
      baselineResults, (r) => r.competitor_findings.get("baseline-regex") || [], "baseline-regex-scanner"
    );
    competitorResults.push(baselineResult);

    // Compute unique findings vs baseline
    computeUniqueFindings(sentinelResult, baselineResults, ["baseline-regex"]);
  } else {
    computeUniqueFindings(sentinelResult, results, Object.keys(COMPETITOR_ADAPTERS));
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
    console.log();

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
    console.log(`  Precision >${PRECISION_TARGET}%: ${report.target_metrics.precision_met ? "PASS ✓" : "FAIL ✗"}`);
    console.log(`  Recall >${RECALL_TARGET}%: ${report.target_metrics.recall_met ? "PASS ✓" : "FAIL ✗"}`);
    console.log(`  Unique >${UNIQUE_TARGET}: ${report.target_metrics.unique_met ? "PASS ✓" : "FAIL ✗"}`);
    console.log(`  FP Rate <${FP_TARGET}%: ${report.target_metrics.fp_met ? "PASS ✓" : "FAIL ✗"}`);
  }
}

main().catch((err) => {
  logger.error({ err }, "Benchmark failed");
  process.exit(1);
});
