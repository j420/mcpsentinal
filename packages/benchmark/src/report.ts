/**
 * Benchmark Report Generator — produces comparison report.
 *
 * Generates a Markdown report comparing MCP Sentinel against competitors:
 * - Precision, recall, F1 for each tool
 * - Unique detection rate (findings only we catch)
 * - False positive rate comparison
 * - Per-category breakdown
 * - Per-corpus-category results (CVE, intentional, clean, tricky)
 */

import type { BenchmarkMetrics } from "./ground-truth.js";
import type { CorpusCategory } from "./corpus.js";

export interface ToolBenchmarkResult {
  tool_name: string;
  overall_metrics: BenchmarkMetrics;
  by_category: Record<CorpusCategory, BenchmarkMetrics>;
  unique_findings: number;
  unique_finding_ids: string[];
  total_findings: number;
  elapsed_ms: number;
}

export interface BenchmarkReport {
  generated_at: string;
  corpus_size: number;
  tools_compared: string[];
  sentinel_result: ToolBenchmarkResult;
  competitor_results: ToolBenchmarkResult[];
  target_metrics: {
    precision_target: number;
    recall_target: number;
    unique_detection_target: number;
    false_positive_target: number;
    precision_met: boolean;
    recall_met: boolean;
    unique_met: boolean;
    fp_met: boolean;
  };
}

export function generateBenchmarkReport(report: BenchmarkReport): string {
  const lines: string[] = [];
  const h = (level: number, text: string) => lines.push(`${"#".repeat(level)} ${text}\n`);
  const p = (text: string) => lines.push(`${text}\n`);
  const blank = () => lines.push("");
  const table = (headers: string[], rows: string[][]) => {
    lines.push(`| ${headers.join(" | ")} |`);
    lines.push(`| ${headers.map(() => "---").join(" | ")} |`);
    for (const row of rows) lines.push(`| ${row.join(" | ")} |`);
    blank();
  };

  h(1, "MCP Security Tool Benchmark — Q1 2026");
  p(`*Generated: ${report.generated_at} | Corpus: ${report.corpus_size} servers | Tools: ${report.tools_compared.length}*`);
  blank();

  // Executive Summary
  h(2, "Executive Summary");
  blank();
  const s = report.sentinel_result;
  p(`MCP Sentinel achieves **${s.overall_metrics.precision}% precision** and **${s.overall_metrics.recall}% recall** across a curated corpus of ${report.corpus_size} MCP servers with known ground truth.`);
  blank();
  const targets = report.target_metrics;
  table(
    ["Target", "Threshold", "Actual", "Status"],
    [
      ["Precision", `>${targets.precision_target}%`, `${s.overall_metrics.precision}%`, targets.precision_met ? "**PASS**" : "FAIL"],
      ["Recall", `>${targets.recall_target}%`, `${s.overall_metrics.recall}%`, targets.recall_met ? "**PASS**" : "FAIL"],
      ["Unique detections", `>${targets.unique_detection_target}%`, `${s.unique_findings} unique`, targets.unique_met ? "**PASS**" : "FAIL"],
      ["False positive rate", `<${targets.false_positive_target}%`, `${s.overall_metrics.false_positive_rate}%`, targets.fp_met ? "**PASS**" : "FAIL"],
    ],
  );

  // Tool Comparison
  h(2, "Tool Comparison");
  blank();
  const allTools = [report.sentinel_result, ...report.competitor_results];
  table(
    ["Tool", "Precision", "Recall", "F1", "FP Rate", "Unique Finds", "Total Findings", "Time"],
    allTools.map((t) => [
      `**${t.tool_name}**`,
      `${t.overall_metrics.precision}%`,
      `${t.overall_metrics.recall}%`,
      `${t.overall_metrics.f1_score}%`,
      `${t.overall_metrics.false_positive_rate}%`,
      t.unique_findings.toString(),
      t.total_findings.toString(),
      `${(t.elapsed_ms / 1000).toFixed(1)}s`,
    ]),
  );

  // Per-Corpus-Category
  h(2, "Results by Corpus Category");
  blank();
  const categories: CorpusCategory[] = ["cve-backed", "intentionally-vulnerable", "clean", "tricky"];
  for (const cat of categories) {
    h(3, cat.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()));
    blank();
    table(
      ["Tool", "Precision", "Recall", "FP Rate"],
      allTools
        .filter((t) => t.by_category[cat])
        .map((t) => [
          t.tool_name,
          `${t.by_category[cat].precision}%`,
          `${t.by_category[cat].recall}%`,
          `${t.by_category[cat].false_positive_rate}%`,
        ]),
    );
  }

  // Unique Detections
  h(2, "What Only MCP Sentinel Detects");
  blank();
  if (s.unique_finding_ids.length > 0) {
    p(`MCP Sentinel detected **${s.unique_findings} vulnerabilities** that no competitor tool found:`);
    blank();
    for (const id of s.unique_finding_ids.slice(0, 15)) {
      p(`- \`${id}\``);
    }
    if (s.unique_finding_ids.length > 15) {
      p(`- ... and ${s.unique_finding_ids.length - 15} more`);
    }
  } else {
    p("No unique detections in this benchmark run.");
  }
  blank();

  // Methodology
  h(2, "Methodology");
  blank();
  p("**Corpus:** 100 curated MCP servers — 25 with known CVEs (ground truth from NVD), 25 intentionally vulnerable (red-team fixtures), 25 verified clean, 25 tricky (sanitized code that looks dangerous).");
  p("**Metrics:** Standard SAST metrics — precision (TP/(TP+FP)), recall (TP/(TP+FN)), F1 (harmonic mean), false positive rate (FP/(FP+TN)).");
  p("**Fairness:** All tools scan the same corpus. Competitor tool output is normalized to a common finding format. Ground truth is manually verified.");
  p("**Limitations:** Some competitor tools were unavailable and replaced with a simulated regex baseline. Real competitor results may differ.");
  blank();

  p("---");
  p("*Generated by [MCP Sentinel Benchmark](https://mcp-sentinel.com/benchmark)*");

  return lines.join("\n");
}
