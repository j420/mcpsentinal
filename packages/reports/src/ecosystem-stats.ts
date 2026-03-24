/**
 * Ecosystem Statistics — aggregate metrics from scan data.
 *
 * Computes top-level ecosystem health metrics:
 * - Total servers crawled / scanned
 * - Language and framework distribution
 * - Score distributions and averages
 * - Finding prevalence rates
 */

import type pg from "pg";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Row = Record<string, any>;

export interface EcosystemOverview {
  total_crawled: number;
  total_scanned: number;
  scan_coverage_pct: number;
  average_score: number;
  median_score: number;
  servers_with_critical: number;
  critical_pct: number;
  language_distribution: Record<string, number>;
  framework_distribution: Record<string, number>;
  category_distribution: Record<string, number>;
  score_distribution: Array<{ range: string; count: number; pct: number }>;
  score_rating_distribution: { good: number; moderate: number; poor: number; critical: number };
  total_findings: number;
  unique_rules_triggered: number;
  findings_per_server_avg: number;
}

export async function computeEcosystemOverview(pool: pg.Pool): Promise<EcosystemOverview> {
  const [
    totalRes, scannedRes, avgScoreRes, medianRes,
    criticalRes, langRes, frameworkRes, categoryRes,
    distRes, totalFindingsRes, uniqueRulesRes, findingsPerServerRes,
  ] = await Promise.all([
    pool.query("SELECT COUNT(*) as cnt FROM servers"),
    pool.query("SELECT COUNT(*) as cnt FROM servers WHERE latest_score IS NOT NULL"),
    pool.query("SELECT AVG(latest_score) as avg FROM servers WHERE latest_score IS NOT NULL"),
    pool.query(`
      SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY latest_score) as median
      FROM servers WHERE latest_score IS NOT NULL
    `),
    pool.query(`
      SELECT COUNT(DISTINCT s.id) as cnt
      FROM servers s
      JOIN scans sc ON sc.server_id = s.id AND sc.status = 'completed'
      JOIN findings f ON f.scan_id = sc.id AND f.severity = 'critical'
    `),
    pool.query(`
      SELECT COALESCE(language, 'unknown') as lang, COUNT(*) as cnt
      FROM servers GROUP BY lang ORDER BY cnt DESC
    `),
    pool.query(`
      SELECT
        CASE
          WHEN npm_package IS NOT NULL AND npm_package LIKE '%modelcontextprotocol%' THEN '@modelcontextprotocol/sdk'
          WHEN pypi_package IS NOT NULL AND (pypi_package LIKE '%fastmcp%' OR description ILIKE '%fastmcp%') THEN 'FastMCP'
          WHEN pypi_package IS NOT NULL AND (pypi_package LIKE '%mcp%' OR description ILIKE '%mcp python%') THEN 'mcp-python'
          WHEN npm_package IS NOT NULL THEN 'custom-node'
          WHEN pypi_package IS NOT NULL THEN 'custom-python'
          ELSE 'unknown'
        END AS framework,
        COUNT(*) as cnt
      FROM servers GROUP BY framework ORDER BY cnt DESC
    `),
    pool.query(`
      SELECT COALESCE(category, 'other') as cat, COUNT(*) as cnt
      FROM servers GROUP BY cat ORDER BY cnt DESC
    `),
    pool.query(`
      SELECT
        CASE
          WHEN latest_score >= 80 THEN 'Good (80-100)'
          WHEN latest_score >= 60 THEN 'Moderate (60-79)'
          WHEN latest_score >= 40 THEN 'Poor (40-59)'
          ELSE 'Critical (0-39)'
        END AS range,
        COUNT(*) AS count
      FROM servers WHERE latest_score IS NOT NULL
      GROUP BY range ORDER BY range DESC
    `),
    pool.query(`
      SELECT COUNT(*) as cnt FROM findings f
      JOIN scans s ON f.scan_id = s.id WHERE s.status = 'completed'
    `),
    pool.query(`
      SELECT COUNT(DISTINCT rule_id) as cnt FROM findings f
      JOIN scans s ON f.scan_id = s.id WHERE s.status = 'completed'
    `),
    pool.query(`
      SELECT AVG(finding_count) as avg FROM (
        SELECT s.server_id, COUNT(*) as finding_count
        FROM findings f JOIN scans s ON f.scan_id = s.id
        WHERE s.status = 'completed'
        GROUP BY s.server_id
      ) sub
    `),
  ]);

  const totalCrawled = parseInt(totalRes.rows[0].cnt, 10);
  const totalScanned = parseInt(scannedRes.rows[0].cnt, 10);
  const avgScore = parseFloat(avgScoreRes.rows[0].avg) || 0;
  const medianScore = parseFloat(medianRes.rows[0].median) || 0;
  const criticalCount = parseInt(criticalRes.rows[0].cnt, 10);
  const totalFindings = parseInt(totalFindingsRes.rows[0].cnt, 10);

  const scoreDistribution = distRes.rows.map((r: Row) => ({
    range: r.range as string,
    count: parseInt(r.count, 10),
    pct: totalScanned > 0 ? Math.round((parseInt(r.count, 10) / totalScanned) * 100) : 0,
  }));

  const ratingDist = { good: 0, moderate: 0, poor: 0, critical: 0 };
  for (const d of scoreDistribution) {
    if (d.range.includes("80-100")) ratingDist.good = d.count;
    else if (d.range.includes("60-79")) ratingDist.moderate = d.count;
    else if (d.range.includes("40-59")) ratingDist.poor = d.count;
    else ratingDist.critical = d.count;
  }

  return {
    total_crawled: totalCrawled,
    total_scanned: totalScanned,
    scan_coverage_pct: totalCrawled > 0 ? Math.round((totalScanned / totalCrawled) * 100) : 0,
    average_score: Math.round(avgScore * 10) / 10,
    median_score: Math.round(medianScore * 10) / 10,
    servers_with_critical: criticalCount,
    critical_pct: totalScanned > 0 ? Math.round((criticalCount / totalScanned) * 100) : 0,
    language_distribution: Object.fromEntries(
      langRes.rows.map((r: Row) => [r.lang, parseInt(r.cnt, 10)])
    ),
    framework_distribution: Object.fromEntries(
      frameworkRes.rows.map((r: Row) => [r.framework, parseInt(r.cnt, 10)])
    ),
    category_distribution: Object.fromEntries(
      categoryRes.rows.map((r: Row) => [r.cat, parseInt(r.cnt, 10)])
    ),
    score_distribution: scoreDistribution,
    score_rating_distribution: ratingDist,
    total_findings: totalFindings,
    unique_rules_triggered: parseInt(uniqueRulesRes.rows[0].cnt, 10),
    findings_per_server_avg: Math.round((parseFloat(findingsPerServerRes.rows[0]?.avg) || 0) * 10) / 10,
  };
}
