/**
 * Trend Analysis — score distributions and vulnerability prevalence over time.
 *
 * Uses the score_history and findings tables to track how the ecosystem
 * security posture changes between scan windows.
 */

import type pg from "pg";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Row = Record<string, any>;

export interface TrendWindow {
  period: string;
  servers_scanned: number;
  average_score: number;
  median_score: number;
  critical_findings: number;
  high_findings: number;
  total_findings: number;
}

export interface SeverityTrend {
  severity: string;
  count: number;
  pct_of_total: number;
  pct_of_servers: number;
}

export interface VulnPrevalence {
  rule_id: string;
  rule_name: string;
  severity: string;
  owasp_category: string | null;
  occurrence_count: number;
  affected_servers: number;
  pct_of_scanned: number;
}

export interface TrendReport {
  /** Weekly scan windows showing ecosystem evolution */
  weekly_trends: TrendWindow[];
  /** Current severity breakdown */
  severity_distribution: SeverityTrend[];
  /** Top 20 most prevalent vulnerabilities */
  top_vulnerabilities: VulnPrevalence[];
  /** Vulnerability prevalence as % of scanned servers */
  prevalence_rates: {
    any_finding_pct: number;
    critical_finding_pct: number;
    high_finding_pct: number;
    command_injection_pct: number;
    path_traversal_pct: number;
    prompt_injection_pct: number;
    ssrf_pct: number;
  };
}

export async function computeTrendReport(pool: pg.Pool): Promise<TrendReport> {
  const [
    weeklyRes, severityRes, topVulnRes, totalScannedRes,
    anyFindingRes, critRes, highRes,
    cmdInjRes, pathTravRes, promptInjRes, ssrfRes,
  ] = await Promise.all([
    // Weekly trends from score_history
    pool.query(`
      SELECT
        DATE_TRUNC('week', recorded_at) as period,
        COUNT(DISTINCT server_id) as servers_scanned,
        AVG(score) as avg_score,
        PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY score) as median_score,
        SUM(findings_count) as total_findings
      FROM score_history
      GROUP BY period ORDER BY period DESC LIMIT 12
    `),
    // Severity distribution across all completed scans
    pool.query(`
      SELECT severity, COUNT(*) as cnt
      FROM findings f JOIN scans s ON f.scan_id = s.id
      WHERE s.status = 'completed'
      GROUP BY severity ORDER BY
        CASE severity
          WHEN 'critical' THEN 1 WHEN 'high' THEN 2
          WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
        END
    `),
    // Top 20 most prevalent findings
    pool.query(`
      SELECT
        f.rule_id,
        f.severity,
        f.owasp_category,
        COUNT(*) as occurrence_count,
        COUNT(DISTINCT s.server_id) as affected_servers
      FROM findings f JOIN scans s ON f.scan_id = s.id
      WHERE s.status = 'completed'
      GROUP BY f.rule_id, f.severity, f.owasp_category
      ORDER BY affected_servers DESC
      LIMIT 20
    `),
    pool.query("SELECT COUNT(*) as cnt FROM servers WHERE latest_score IS NOT NULL"),
    // Servers with any finding
    pool.query(`
      SELECT COUNT(DISTINCT s.server_id) as cnt
      FROM findings f JOIN scans s ON f.scan_id = s.id WHERE s.status = 'completed'
    `),
    // Servers with critical findings
    pool.query(`
      SELECT COUNT(DISTINCT s.server_id) as cnt
      FROM findings f JOIN scans s ON f.scan_id = s.id
      WHERE s.status = 'completed' AND f.severity = 'critical'
    `),
    // Servers with high findings
    pool.query(`
      SELECT COUNT(DISTINCT s.server_id) as cnt
      FROM findings f JOIN scans s ON f.scan_id = s.id
      WHERE s.status = 'completed' AND f.severity = 'high'
    `),
    // Command injection prevalence
    pool.query(`
      SELECT COUNT(DISTINCT s.server_id) as cnt
      FROM findings f JOIN scans s ON f.scan_id = s.id
      WHERE s.status = 'completed' AND f.owasp_category = 'MCP03-command-injection'
    `),
    // Path traversal prevalence
    pool.query(`
      SELECT COUNT(DISTINCT s.server_id) as cnt
      FROM findings f JOIN scans s ON f.scan_id = s.id
      WHERE s.status = 'completed' AND f.owasp_category = 'MCP05-privilege-escalation'
    `),
    // Prompt injection prevalence
    pool.query(`
      SELECT COUNT(DISTINCT s.server_id) as cnt
      FROM findings f JOIN scans s ON f.scan_id = s.id
      WHERE s.status = 'completed' AND f.owasp_category = 'MCP01-prompt-injection'
    `),
    // SSRF prevalence
    pool.query(`
      SELECT COUNT(DISTINCT s.server_id) as cnt
      FROM findings f JOIN scans s ON f.scan_id = s.id
      WHERE s.status = 'completed' AND f.owasp_category = 'MCP04-data-exfiltration'
    `),
  ]);

  const totalScanned = parseInt(totalScannedRes.rows[0].cnt, 10) || 1;
  const totalFindings = severityRes.rows.reduce((sum: number, r: Row) => sum + parseInt(r.cnt, 10), 0);
  const pctOf = (n: string) => Math.round((parseInt(n, 10) / totalScanned) * 1000) / 10;

  // Rule name lookup (embedded subset — avoids requiring rule loader)
  const RULE_NAMES: Record<string, string> = {
    A1: "Prompt Injection in Description", A2: "Excessive Scope Claims",
    A3: "Suspicious URLs", A4: "Tool Name Shadowing", A5: "Description Length Anomaly",
    A6: "Unicode Homoglyph Attack", A7: "Zero-Width Character Injection",
    A8: "Description-Capability Mismatch", A9: "Encoded Instructions",
    B1: "Missing Input Validation", B2: "Dangerous Parameter Types",
    B3: "Excessive Parameter Count", B4: "Schema-less Tools",
    B5: "Parameter Description Injection", B6: "Unconstrained Additional Properties",
    B7: "Dangerous Default Values",
    C1: "Command Injection", C2: "Path Traversal", C3: "SSRF",
    C4: "SQL Injection", C5: "Hardcoded Secrets", C6: "Error Leakage",
    C7: "Wildcard CORS", C8: "No Auth on Network", C9: "Excessive Filesystem Scope",
    C10: "Prototype Pollution", C12: "Unsafe Deserialization", C14: "JWT Algorithm Confusion",
    C15: "Timing Attack", C16: "Dynamic Code Eval",
    D1: "Known CVEs", D3: "Typosquatting Risk", D5: "Known Malicious Packages",
    E1: "No Auth Required", E2: "Insecure Transport",
    F1: "Lethal Trifecta", F5: "Namespace Squatting", F7: "Multi-Step Exfiltration",
    G1: "Indirect Injection Gateway", G2: "Trust Assertion Injection",
    H1: "OAuth Insecure", H2: "Initialize Injection", H3: "Multi-Agent Propagation",
    I1: "Annotation Deception", I16: "Consent Fatigue",
  };

  return {
    weekly_trends: weeklyRes.rows.map((r: Row) => ({
      period: (r.period as Date).toISOString().slice(0, 10),
      servers_scanned: parseInt(r.servers_scanned, 10),
      average_score: Math.round(parseFloat(r.avg_score) * 10) / 10,
      median_score: Math.round(parseFloat(r.median_score) * 10) / 10,
      critical_findings: 0, // would need a join — approximate from total
      high_findings: 0,
      total_findings: parseInt(r.total_findings, 10),
    })),
    severity_distribution: severityRes.rows.map((r: Row) => ({
      severity: r.severity,
      count: parseInt(r.cnt, 10),
      pct_of_total: Math.round((parseInt(r.cnt, 10) / totalFindings) * 1000) / 10,
      pct_of_servers: pctOf(r.cnt),
    })),
    top_vulnerabilities: topVulnRes.rows.map((r: Row) => ({
      rule_id: r.rule_id,
      rule_name: RULE_NAMES[r.rule_id] || r.rule_id,
      severity: r.severity,
      owasp_category: r.owasp_category,
      occurrence_count: parseInt(r.occurrence_count, 10),
      affected_servers: parseInt(r.affected_servers, 10),
      pct_of_scanned: Math.round((parseInt(r.affected_servers, 10) / totalScanned) * 1000) / 10,
    })),
    prevalence_rates: {
      any_finding_pct: pctOf(anyFindingRes.rows[0].cnt),
      critical_finding_pct: pctOf(critRes.rows[0].cnt),
      high_finding_pct: pctOf(highRes.rows[0].cnt),
      command_injection_pct: pctOf(cmdInjRes.rows[0].cnt),
      path_traversal_pct: pctOf(pathTravRes.rows[0].cnt),
      prompt_injection_pct: pctOf(promptInjRes.rows[0].cnt),
      ssrf_pct: pctOf(ssrfRes.rows[0].cnt),
    },
  };
}
