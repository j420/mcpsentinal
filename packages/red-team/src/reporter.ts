import type { AccuracyReport, RuleAccuracy } from "./types.js";

// ── Text reporter ─────────────────────────────────────────────────────────────

export function formatTextReport(report: AccuracyReport): string {
  const lines: string[] = [];
  const { pct, bar } = fmt;

  lines.push("╔══════════════════════════════════════════════════════════════╗");
  lines.push("║         MCP Sentinel — Rule Accuracy Audit Report            ║");
  lines.push("╚══════════════════════════════════════════════════════════════╝");
  lines.push("");
  lines.push(`Generated:     ${report.generated_at}`);
  lines.push(`Rules version: ${report.rules_version}`);
  lines.push(`Rules tested:  ${report.total_rules_tested}`);
  lines.push(`Fixtures:      ${report.total_fixtures} total | ${report.total_passed} passed | ${report.total_failed} failed`);
  lines.push("");

  const overallSymbol = report.passes_layer5_threshold ? "✅" : "❌";
  lines.push(`${overallSymbol} Layer 5 threshold (≥80% precision): ${report.passes_layer5_threshold ? "PASSED" : "FAILED"}`);
  lines.push(`   Overall precision (TN rate): ${pct(report.overall_precision)}`);
  lines.push(`   Overall recall    (TP rate): ${pct(report.overall_recall)}`);
  lines.push("");

  // Category summary
  lines.push("── By Category ─────────────────────────────────────────────────");
  for (const [cat, acc] of Object.entries(report.by_category).sort()) {
    const symbol = acc.passes_threshold ? "✅" : "❌";
    lines.push(
      `  ${symbol} ${cat}  precision=${pct(acc.avg_precision)}  recall=${pct(acc.avg_recall)}  (${acc.rules_count} rule${acc.rules_count !== 1 ? "s" : ""})`
    );
  }
  lines.push("");

  // Per-rule detail
  lines.push("── By Rule ─────────────────────────────────────────────────────");
  for (const r of report.by_rule.sort((a, b) => a.rule_id.localeCompare(b.rule_id))) {
    const combined = r.true_positive_recall * r.true_negative_precision;
    const symbol = combined >= 0.64 ? "✅" : "⚠️ ";
    lines.push(
      `  ${symbol} ${r.rule_id.padEnd(5)} ${r.rule_name.padEnd(45)} ` +
        `prec=${pct(r.true_negative_precision)}  rec=${pct(r.true_positive_recall)}  ` +
        `${bar(combined)}  ${r.passed}/${r.total}`
    );
    if (r.failed_fixtures.length > 0) {
      for (const f of r.failed_fixtures) {
        const expected = f.expect_finding ? "firing" : "silent";
        const got = f.got_finding ? "fired" : "silent";
        lines.push(`         ✗ [${f.kind}] ${f.fixture_description} — expected ${expected}, got ${got}`);
      }
    }
  }
  lines.push("");

  // Worst performers
  if (report.worst_performers.length > 0) {
    lines.push("── Worst Performers (bottom 10 by precision × recall) ───────────");
    for (const r of report.worst_performers) {
      lines.push(`  ⚠️  ${r.rule_id}: ${r.rule_name}`);
      lines.push(
        `     precision=${pct(r.true_negative_precision)} recall=${pct(r.true_positive_recall)} failed=${r.failed}`
      );
    }
  }

  return lines.join("\n");
}

// ── JSON reporter ─────────────────────────────────────────────────────────────

export function formatJsonReport(report: AccuracyReport): string {
  return JSON.stringify(report, null, 2);
}

// ── HTML reporter ─────────────────────────────────────────────────────────────

export function formatHtmlReport(report: AccuracyReport): string {
  const scoreColor = (v: number) =>
    v >= 0.9 ? "#34D399" : v >= 0.8 ? "#FCD34D" : v >= 0.6 ? "#FB923C" : "#F87171";

  const rows = report.by_rule
    .sort((a, b) => a.rule_id.localeCompare(b.rule_id))
    .map((r) => {
      const combined = r.true_positive_recall * r.true_negative_precision;
      return `
      <tr style="border-bottom:1px solid #20263A">
        <td style="padding:8px 12px;font-family:monospace;color:#4A9EFF">${r.rule_id}</td>
        <td style="padding:8px 12px;color:#EDF1FF">${r.rule_name}</td>
        <td style="padding:8px 12px;text-align:center;color:${scoreColor(r.true_negative_precision)}">${fmt.pct(r.true_negative_precision)}</td>
        <td style="padding:8px 12px;text-align:center;color:${scoreColor(r.true_positive_recall)}">${fmt.pct(r.true_positive_recall)}</td>
        <td style="padding:8px 12px;text-align:center;color:${scoreColor(combined)}">${fmt.pct(combined)}</td>
        <td style="padding:8px 12px;text-align:center;color:#8B97B3">${r.passed}/${r.total}</td>
      </tr>`;
    })
    .join("");

  const catRows = Object.entries(report.by_category)
    .sort()
    .map(([, acc]) => {
      const symbol = acc.passes_threshold ? "✅" : "❌";
      return `
      <tr style="border-bottom:1px solid #20263A">
        <td style="padding:8px 12px;color:#EDF1FF">${symbol} ${acc.category}</td>
        <td style="padding:8px 12px;text-align:center;color:${scoreColor(acc.avg_precision)}">${fmt.pct(acc.avg_precision)}</td>
        <td style="padding:8px 12px;text-align:center;color:${scoreColor(acc.avg_recall)}">${fmt.pct(acc.avg_recall)}</td>
        <td style="padding:8px 12px;text-align:center;color:#8B97B3">${acc.rules_count}</td>
      </tr>`;
    })
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>MCP Sentinel — Rule Accuracy Report</title>
  <style>
    body { background:#090B0F; color:#EDF1FF; font-family:'Inter',sans-serif; margin:0; padding:32px; }
    h1 { font-size:28px; font-weight:800; letter-spacing:-0.03em; margin-bottom:4px; }
    .sub { color:#8B97B3; font-size:14px; margin-bottom:32px; }
    .kpi-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:32px; }
    .kpi { background:#10131A; border:1px solid rgba(255,255,255,0.06); border-radius:10px; padding:20px; }
    .kpi-value { font-size:32px; font-weight:700; letter-spacing:-0.04em; }
    .kpi-label { font-size:11px; text-transform:uppercase; letter-spacing:0.07em; color:#505A72; margin-top:4px; }
    .section { margin-bottom:40px; }
    h2 { font-size:16px; font-weight:700; margin-bottom:16px; color:#8B97B3; text-transform:uppercase; letter-spacing:0.06em; }
    table { width:100%; border-collapse:collapse; background:#10131A; border-radius:10px; overflow:hidden; }
    th { padding:10px 12px; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:0.07em; color:#505A72; background:#181C26; }
    .pass { color:#34D399; font-weight:700; }
    .fail { color:#F87171; font-weight:700; }
  </style>
</head>
<body>
  <h1>MCP Sentinel — Rule Accuracy Report</h1>
  <div class="sub">Generated ${report.generated_at} · Rules version ${report.rules_version}</div>

  <div class="kpi-grid">
    <div class="kpi">
      <div class="kpi-value" style="color:${scoreColor(report.overall_precision)}">${fmt.pct(report.overall_precision)}</div>
      <div class="kpi-label">Overall Precision</div>
    </div>
    <div class="kpi">
      <div class="kpi-value" style="color:${scoreColor(report.overall_recall)}">${fmt.pct(report.overall_recall)}</div>
      <div class="kpi-label">Overall Recall</div>
    </div>
    <div class="kpi">
      <div class="kpi-value">${report.total_rules_tested}</div>
      <div class="kpi-label">Rules Tested</div>
    </div>
    <div class="kpi">
      <div class="kpi-value" style="color:${report.passes_layer5_threshold ? "#34D399" : "#F87171"}">${report.passes_layer5_threshold ? "PASS" : "FAIL"}</div>
      <div class="kpi-label">Layer 5 Threshold</div>
    </div>
  </div>

  <div class="section">
    <h2>By Category</h2>
    <table>
      <thead><tr>
        <th>Category</th><th>Avg Precision</th><th>Avg Recall</th><th>Rules</th>
      </tr></thead>
      <tbody>${catRows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>By Rule</h2>
    <table>
      <thead><tr>
        <th>ID</th><th>Name</th><th>Precision</th><th>Recall</th><th>Combined</th><th>Fixtures</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>
</body>
</html>`;
}

// ── Formatting helpers ────────────────────────────────────────────────────────

const fmt = {
  pct: (v: number) => `${(v * 100).toFixed(0)}%`,
  bar: (v: number) => {
    const filled = Math.round(v * 10);
    return "[" + "█".repeat(filled) + "░".repeat(10 - filled) + "]";
  },
};

export function printSummary(report: AccuracyReport): void {
  const { pct } = fmt;
  const symbol = report.passes_layer5_threshold ? "✅" : "❌";
  console.log(
    `${symbol} precision=${pct(report.overall_precision)} recall=${pct(report.overall_recall)} ` +
      `fixtures=${report.total_passed}/${report.total_fixtures} ` +
      `rules=${report.total_rules_tested}`
  );
  if (report.total_failed > 0) {
    console.log(`   ${report.total_failed} fixture(s) failed:`);
    for (const r of report.by_rule) {
      for (const f of r.failed_fixtures) {
        console.log(`   ✗ ${r.rule_id}: ${f.fixture_description}`);
      }
    }
  }
}
