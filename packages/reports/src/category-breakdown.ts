/**
 * Category Breakdown — findings by category, severity, language, and framework.
 *
 * Produces the data for:
 * - Framework comparison (FastMCP vs SDK vs custom)
 * - OWASP MCP Top 10 compliance rates
 * - AST vs regex detection comparison
 * - Language-specific vulnerability patterns
 */

import type pg from "pg";

export interface FrameworkComparison {
  framework: string;
  server_count: number;
  average_score: number;
  median_score: number;
  critical_finding_rate: number;
  top_findings: Array<{ rule_id: string; count: number }>;
}

export interface OwaspCompliance {
  owasp_id: string;
  owasp_name: string;
  total_violations: number;
  affected_servers: number;
  compliance_rate_pct: number;
}

export interface DetectionMethodComparison {
  method: string;
  findings_count: number;
  unique_flows: number;
  example_evidence: string;
}

export interface LanguageBreakdown {
  language: string;
  server_count: number;
  average_score: number;
  top_vulnerability: string;
  critical_rate_pct: number;
}

export interface CategoryReport {
  framework_comparison: FrameworkComparison[];
  owasp_compliance: OwaspCompliance[];
  detection_comparison: DetectionMethodComparison[];
  language_breakdown: LanguageBreakdown[];
  finding_category_distribution: Array<{ category: string; count: number; pct: number }>;
}

const OWASP_NAMES: Record<string, string> = {
  "MCP01-prompt-injection": "Prompt Injection",
  "MCP02-tool-poisoning": "Tool Poisoning",
  "MCP03-command-injection": "Command Injection",
  "MCP04-data-exfiltration": "Data Exfiltration",
  "MCP05-privilege-escalation": "Privilege Escalation",
  "MCP06-excessive-permissions": "Excessive Permissions",
  "MCP07-insecure-config": "Insecure Configuration",
  "MCP08-dependency-vuln": "Dependency Vulnerabilities",
  "MCP09-logging-monitoring": "Logging & Monitoring",
  "MCP10-supply-chain": "Supply Chain",
};

export async function computeCategoryReport(pool: pg.Pool): Promise<CategoryReport> {
  const [frameworkRes, owaspRes, astRes, regexRes, langRes, catRes, totalScannedRes] =
    await Promise.all([
      // Framework comparison
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
          COUNT(*) as server_count,
          AVG(latest_score) as avg_score,
          PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY latest_score) as median_score
        FROM servers WHERE latest_score IS NOT NULL
        GROUP BY framework ORDER BY server_count DESC
      `),
      // OWASP compliance
      pool.query(`
        SELECT
          f.owasp_category,
          COUNT(*) as total_violations,
          COUNT(DISTINCT s.server_id) as affected_servers
        FROM findings f JOIN scans s ON f.scan_id = s.id
        WHERE s.status = 'completed' AND f.owasp_category IS NOT NULL
        GROUP BY f.owasp_category ORDER BY affected_servers DESC
      `),
      // AST taint findings
      pool.query(`
        SELECT COUNT(*) as cnt FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.status = 'completed' AND f.evidence LIKE '%[AST taint%'
      `),
      // Regex-only findings
      pool.query(`
        SELECT COUNT(*) as cnt FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.status = 'completed' AND f.evidence NOT LIKE '%[AST%'
      `),
      // Language breakdown
      pool.query(`
        SELECT
          COALESCE(sv.language, 'unknown') as language,
          COUNT(*) as server_count,
          AVG(sv.latest_score) as avg_score
        FROM servers sv WHERE sv.latest_score IS NOT NULL
        GROUP BY language ORDER BY server_count DESC
      `),
      // Finding category distribution (by rule prefix)
      pool.query(`
        SELECT
          CASE
            WHEN rule_id LIKE 'A%' THEN 'Description Analysis'
            WHEN rule_id LIKE 'B%' THEN 'Schema Analysis'
            WHEN rule_id LIKE 'C%' THEN 'Code Analysis'
            WHEN rule_id LIKE 'D%' THEN 'Dependency Analysis'
            WHEN rule_id LIKE 'E%' THEN 'Behavioral Analysis'
            WHEN rule_id LIKE 'F%' THEN 'Ecosystem Context'
            WHEN rule_id LIKE 'G%' THEN 'Adversarial AI'
            WHEN rule_id LIKE 'H%' THEN '2026 Attack Surface'
            WHEN rule_id LIKE 'I%' THEN 'Protocol Surface'
            WHEN rule_id LIKE 'J%' THEN 'Threat Intelligence'
            WHEN rule_id LIKE 'K%' THEN 'Compliance'
            ELSE 'Advanced (L-Q)'
          END AS category,
          COUNT(*) as cnt
        FROM findings f JOIN scans s ON f.scan_id = s.id
        WHERE s.status = 'completed'
        GROUP BY category ORDER BY cnt DESC
      `),
      pool.query("SELECT COUNT(*) as cnt FROM servers WHERE latest_score IS NOT NULL"),
    ]);

  const totalScanned = parseInt(totalScannedRes.rows[0].cnt, 10) || 1;
  const totalFindings = catRes.rows.reduce((s, r) => s + parseInt(r.cnt, 10), 0) || 1;

  // Framework comparison with critical rate
  const frameworkComparison: FrameworkComparison[] = frameworkRes.rows.map((r) => ({
    framework: r.framework,
    server_count: parseInt(r.server_count, 10),
    average_score: Math.round(parseFloat(r.avg_score) * 10) / 10,
    median_score: Math.round(parseFloat(r.median_score) * 10) / 10,
    critical_finding_rate: 0, // filled below if needed
    top_findings: [],
  }));

  // OWASP compliance
  const owaspCompliance: OwaspCompliance[] = Object.entries(OWASP_NAMES).map(([id, name]) => {
    const row = owaspRes.rows.find((r) => r.owasp_category === id);
    const affected = row ? parseInt(row.affected_servers, 10) : 0;
    return {
      owasp_id: id,
      owasp_name: name,
      total_violations: row ? parseInt(row.total_violations, 10) : 0,
      affected_servers: affected,
      compliance_rate_pct: Math.round(((totalScanned - affected) / totalScanned) * 1000) / 10,
    };
  });

  // AST vs regex comparison
  const astCount = parseInt(astRes.rows[0].cnt, 10);
  const regexCount = parseInt(regexRes.rows[0].cnt, 10);

  // Sample AST evidence (anonymized)
  const astExample = await pool.query(`
    SELECT evidence FROM findings f
    JOIN scans s ON f.scan_id = s.id
    WHERE s.status = 'completed' AND f.evidence LIKE '%[AST taint%' AND f.severity = 'critical'
    LIMIT 1
  `);

  const detectionComparison: DetectionMethodComparison[] = [
    {
      method: "AST Taint Analysis",
      findings_count: astCount,
      unique_flows: astCount, // each AST finding is a unique flow
      example_evidence: astExample.rows[0]?.evidence
        ? anonymizeEvidence(astExample.rows[0].evidence)
        : "No AST taint findings yet",
    },
    {
      method: "Regex Pattern Matching",
      findings_count: regexCount,
      unique_flows: 0, // regex doesn't produce flows
      example_evidence: "Pattern-matched detection (no data flow tracking)",
    },
  ];

  // Language breakdown
  const languageBreakdown: LanguageBreakdown[] = langRes.rows.map((r) => ({
    language: r.language,
    server_count: parseInt(r.server_count, 10),
    average_score: Math.round(parseFloat(r.avg_score) * 10) / 10,
    top_vulnerability: "", // would need a sub-query per language
    critical_rate_pct: 0,
  }));

  return {
    framework_comparison: frameworkComparison,
    owasp_compliance: owaspCompliance,
    detection_comparison: detectionComparison,
    language_breakdown: languageBreakdown,
    finding_category_distribution: catRes.rows.map((r) => ({
      category: r.category,
      count: parseInt(r.cnt, 10),
      pct: Math.round((parseInt(r.cnt, 10) / totalFindings) * 1000) / 10,
    })),
  };
}

/** Remove server-specific identifiers from evidence strings */
function anonymizeEvidence(evidence: string): string {
  return evidence
    .replace(/["']https?:\/\/[^"'\s]+["']/g, '"[URL]"')
    .replace(/["'][A-Za-z0-9_-]{20,}["']/g, '"[TOKEN]"')
    .replace(/\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g, "[UUID]")
    .replace(/\b(?:sk|pk|ghp|gho|xoxb|AKIA)[A-Za-z0-9_-]+/g, "[REDACTED]");
}
