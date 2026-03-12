#!/usr/bin/env node

import { readFileSync, existsSync } from "fs";
import { join, resolve } from "path";
import { AnalysisEngine, loadRules, getRulesVersion } from "@mcp-sentinel/analyzer";
import { computeScore } from "@mcp-sentinel/scorer";
import type { AnalysisContext } from "@mcp-sentinel/analyzer";

const RULES_DIR = resolve(import.meta.dirname || __dirname, "../../../rules");

interface MCPConfig {
  mcpServers?: Record<
    string,
    {
      command?: string;
      args?: string[];
      url?: string;
      env?: Record<string, string>;
    }
  >;
}

interface ScanResult {
  server_name: string;
  score: number;
  findings_count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  top_findings: string[];
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || "check";
  const jsonOutput = args.includes("--json");

  if (command === "check") {
    await runCheck(jsonOutput);
  } else if (command === "help" || command === "--help") {
    printHelp();
  } else {
    console.error(`Unknown command: ${command}`);
    printHelp();
    process.exit(1);
  }
}

async function runCheck(jsonOutput: boolean) {
  // Find MCP config files
  const config = findMCPConfig();
  if (!config) {
    console.error(
      "No MCP configuration found. Looked for:\n" +
        "  - claude_desktop_config.json\n" +
        "  - mcp.json\n" +
        "  - .mcp.json\n\n" +
        "Run this command in a directory with MCP configuration."
    );
    process.exit(1);
  }

  const servers = config.mcpServers || {};
  const serverNames = Object.keys(servers);

  if (serverNames.length === 0) {
    console.error("No MCP servers found in configuration.");
    process.exit(1);
  }

  // Load detection rules
  const rules = loadRules(RULES_DIR);
  const rulesVersion = getRulesVersion(rules);
  const engine = new AnalysisEngine(rules);

  const ruleCategories: Record<string, string> = {};
  for (const rule of rules) {
    ruleCategories[rule.id] = rule.category;
  }

  if (!jsonOutput) {
    console.log(`\n🔍 MCP Sentinel — Security Scanner`);
    console.log(`   Rules: ${rules.length} (v${rulesVersion})`);
    console.log(`   Servers: ${serverNames.length} configured\n`);
    console.log("─".repeat(70));
  }

  const results: ScanResult[] = [];
  let worstScore = 100;

  for (const [name, serverConfig] of Object.entries(servers)) {
    const context: AnalysisContext = {
      server: {
        id: name,
        name,
        description: null,
        github_url: null,
      },
      tools: [],
      source_code: null,
      dependencies: [],
      connection_metadata: serverConfig.url
        ? {
            auth_required: false,
            transport: serverConfig.url.startsWith("https") ? "https" : "http",
            response_time_ms: 0,
          }
        : null,
    };

    const findings = engine.analyze(context);
    const score = computeScore(findings, ruleCategories);

    const result: ScanResult = {
      server_name: name,
      score: score.total_score,
      findings_count: findings.length,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      top_findings: findings.slice(0, 3).map((f) => `[${f.severity.toUpperCase()}] ${f.rule_id}: ${f.evidence.substring(0, 100)}`),
    };
    results.push(result);
    worstScore = Math.min(worstScore, score.total_score);

    if (!jsonOutput) {
      const scoreColor = getScoreIndicator(score.total_score);
      console.log(
        `\n  ${scoreColor} ${name.padEnd(40)} Score: ${score.total_score}/100`
      );
      console.log(
        `     Findings: ${findings.length} (${result.critical}C ${result.high}H ${result.medium}M ${result.low}L)`
      );
      for (const finding of result.top_findings) {
        console.log(`     → ${finding}`);
      }
    }
  }

  if (jsonOutput) {
    console.log(
      JSON.stringify(
        {
          version: rulesVersion,
          scanned: results.length,
          worst_score: worstScore,
          results,
        },
        null,
        2
      )
    );
  } else {
    console.log("\n" + "─".repeat(70));
    console.log(
      `\n  Summary: ${results.length} servers scanned, worst score: ${worstScore}/100\n`
    );
  }

  // CI mode: exit with non-zero if any server scores below 60
  if (args.includes("--ci") && worstScore < 60) {
    process.exit(1);
  }
}

function findMCPConfig(): MCPConfig | null {
  const configPaths = [
    "claude_desktop_config.json",
    "mcp.json",
    ".mcp.json",
    join(
      process.env.HOME || process.env.USERPROFILE || "~",
      ".config",
      "claude",
      "claude_desktop_config.json"
    ),
  ];

  for (const configPath of configPaths) {
    const fullPath = resolve(configPath);
    if (existsSync(fullPath)) {
      try {
        const content = readFileSync(fullPath, "utf-8");
        return JSON.parse(content) as MCPConfig;
      } catch {
        continue;
      }
    }
  }

  return null;
}

function getScoreIndicator(score: number): string {
  if (score >= 80) return "✅";
  if (score >= 60) return "⚠️";
  if (score >= 40) return "🟠";
  return "🔴";
}

const args = process.argv.slice(2);

function printHelp() {
  console.log(`
MCP Sentinel — MCP Server Security Scanner

Usage:
  npx mcp-sentinel check         Scan MCP servers in your config
  npx mcp-sentinel check --json  Output results as JSON
  npx mcp-sentinel check --ci    Exit with code 1 if score < 60

Options:
  --json    Machine-readable JSON output
  --ci      CI mode: non-zero exit on low scores
  --help    Show this help message
`);
}

main().catch((err) => {
  console.error("Scan failed:", err.message);
  process.exit(1);
});
