#!/usr/bin/env node

import { readFileSync, existsSync, statSync } from "fs";
import { join, resolve, isAbsolute } from "path";
import { fileURLToPath } from "url";
import { AnalysisEngine, loadRules, getRulesVersion } from "@mcp-sentinel/analyzer";
import { computeScore } from "@mcp-sentinel/scorer";
import type { AnalysisContext } from "@mcp-sentinel/analyzer";
import { z } from "zod";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const RULES_DIR = resolve(__dirname, "../../../rules");

// ─── Exit Codes — stable public contract ─────────────────────────────────────
// Consumers (CI pipelines, GitHub Actions) rely on these codes. Never renumber.
const EXIT = {
  CLEAN: 0,         // All servers above threshold — no action needed
  FINDINGS: 1,      // One or more servers below threshold — CI should fail
  INPUT_ERROR: 2,   // Bad config file / invalid arguments — operator error
  INTERNAL_ERROR: 3 // Unexpected scanner runtime error — file a bug
} as const;

// ─── Security Limits ─────────────────────────────────────────────────────────
// Prevents OOM from crafted large config files
const MAX_CONFIG_BYTES = 1024 * 1024; // 1 MB
// Prevents runaway scans on over-specified configs
const MAX_SERVERS = 500;
const WARN_SERVERS = 100;

// ─── MCP Config Schema — Zod validation ──────────────────────────────────────
// Validates the structure of the config file before any processing.
// env values are NEVER included in output — they may contain secrets.
const MCPServerEntrySchema = z.object({
  command: z.string().optional(),
  args: z.array(z.string()).optional(),
  url: z.string().optional(),
  // env is accepted but values are stripped before analysis context is built
  env: z.record(z.string(), z.string()).optional(),
}).passthrough(); // allow unknown fields — forward-compatible

const MCPConfigSchema = z.object({
  mcpServers: z.record(z.string(), MCPServerEntrySchema).optional(),
}).passthrough();

type MCPConfig = z.infer<typeof MCPConfigSchema>;
type MCPServerEntry = z.infer<typeof MCPServerEntrySchema>;
type Severity = "critical" | "high" | "medium" | "low" | "informational";

// ─── CLI Arguments ────────────────────────────────────────────────────────────
interface CLIArgs {
  command: string;
  jsonOutput: boolean;
  ciMode: boolean;
  minScore: number;
  failOn: Severity | null;
  configPath: string | null;
  showVersion: boolean;
  showHelp: boolean;
}

// ─── Scan Result ─────────────────────────────────────────────────────────────
// JSON output shape — treat as stable public API contract.
// Breaking changes (rename/remove fields) require a major version bump.
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

// ─── Security Utilities ───────────────────────────────────────────────────────

/**
 * Strip ANSI escape sequences and terminal control characters before printing
 * any string that originated from user data (server names, finding evidence).
 * Without this, a crafted server name like `\x1b[2J` could clear the terminal
 * or inject spurious output.
 */
function sanitizeForTerminal(input: string, maxLen = 200): string {
  return input
    // ANSI CSI sequences (colours, cursor movement, etc.)
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "")
    // OSC sequences (hyperlinks, titles)
    .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, "")
    // Any remaining bare ESC byte (not already consumed by CSI/OSC patterns above)
    // NOTE: do NOT use /\x1b[^[]/g — that pattern also consumes the char after ESC,
    // turning e.g. "a\x1bb" into "a" instead of "ab".
    .replace(/\x1b/g, "")
    // Unicode bidirectional/direction override characters (terminal direction attacks)
    // Covers: zero-width spaces, LRM/RLM, LRE/RLE/PDF/LRO/RLO (U+202A–U+202E),
    // and directional isolates LRI/RLI/FSI/PDI (U+2066–U+2069)
    .replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, "")
    // C0 control chars except tab (\x09) and LF (\x0a)
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "")
    .substring(0, maxLen);
}

/**
 * Validate that a user-supplied config path is safe to read:
 * - Must resolve to an absolute path
 * - Must end in .json
 * - Must not contain null bytes (null-byte injection)
 * - Must exist and be a regular file (not a directory or special device)
 * - Must be within size limit
 *
 * Note: we intentionally do NOT restrict to CWD/home paths because CI
 * environments legitimately place configs in arbitrary workspace directories.
 */
function validateConfigPath(
  rawPath: string
): { safe: true; resolved: string } | { safe: false; reason: string } {
  // Null byte check must come first — it can confuse path operations
  if (rawPath.includes("\x00")) {
    return { safe: false, reason: "Path contains null bytes" };
  }

  const resolved = resolve(rawPath);

  if (!isAbsolute(resolved)) {
    return { safe: false, reason: "Path did not resolve to an absolute path" };
  }

  if (!resolved.endsWith(".json")) {
    return { safe: false, reason: "Config file must have a .json extension" };
  }

  if (!existsSync(resolved)) {
    return { safe: false, reason: `File not found: ${resolved}` };
  }

  let stat;
  try {
    stat = statSync(resolved);
  } catch (err) {
    return {
      safe: false,
      reason: `Cannot stat file: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (!stat.isFile()) {
    return { safe: false, reason: "Path must point to a regular file, not a directory or device" };
  }

  if (stat.size > MAX_CONFIG_BYTES) {
    return {
      safe: false,
      reason: `Config file too large (${stat.size.toLocaleString()} bytes; max ${MAX_CONFIG_BYTES.toLocaleString()} bytes)`,
    };
  }

  return { safe: true, resolved };
}

// ─── Argument Parser ──────────────────────────────────────────────────────────

function parseArgs(argv: string[]): CLIArgs {
  const args = argv.slice(2);

  // The first arg is the command only if it doesn't start with --
  const firstArg = args[0];
  const command =
    !firstArg || firstArg.startsWith("--") || firstArg.startsWith("-")
      ? "check"
      : firstArg;

  const jsonOutput = args.includes("--json");
  const ciMode = args.includes("--ci");
  const showVersion = args.includes("--version") || args.includes("-v");
  const showHelp = args.includes("--help") || args.includes("-h");

  // --min-score <n>  (integer 0–100, default 60)
  let minScore = 60;
  const minScoreIdx = args.findIndex((a) => a === "--min-score");
  if (minScoreIdx !== -1) {
    const raw = args[minScoreIdx + 1];
    if (raw !== undefined) {
      const parsed = parseInt(raw, 10);
      if (!Number.isNaN(parsed) && parsed >= 0 && parsed <= 100) {
        minScore = parsed;
      } else {
        console.error(`Error: --min-score must be an integer between 0 and 100, got: ${sanitizeForTerminal(raw, 30)}`);
        process.exit(EXIT.INPUT_ERROR);
      }
    }
  }

  // --fail-on <severity>  (fail if ANY finding at this severity or higher)
  const VALID_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];
  let failOn: Severity | null = null;
  const failOnIdx = args.findIndex((a) => a === "--fail-on");
  if (failOnIdx !== -1) {
    const raw = args[failOnIdx + 1];
    if (raw && VALID_SEVERITIES.includes(raw as Severity)) {
      failOn = raw as Severity;
    } else {
      console.error(
        `Error: --fail-on must be one of: ${VALID_SEVERITIES.join(", ")}` +
          (raw ? `, got: ${sanitizeForTerminal(raw, 30)}` : " (missing value)")
      );
      process.exit(EXIT.INPUT_ERROR);
    }
  }

  // --config <path>
  let configPath: string | null = null;
  const configIdx = args.findIndex((a) => a === "--config");
  if (configIdx !== -1) {
    const raw = args[configIdx + 1];
    if (!raw || raw.startsWith("--")) {
      console.error("Error: --config requires a file path argument");
      process.exit(EXIT.INPUT_ERROR);
    }
    configPath = raw;
  }

  return { command, jsonOutput, ciMode, minScore, failOn, configPath, showVersion, showHelp };
}

// ─── Config Loading ───────────────────────────────────────────────────────────

type ConfigLoadResult =
  | { ok: true; config: MCPConfig; filePath: string }
  | { ok: false; error: string };

function loadMCPConfig(explicitPath: string | null): ConfigLoadResult {
  if (explicitPath !== null) {
    // User-supplied path — validate before use
    const validation = validateConfigPath(explicitPath);
    if (!validation.safe) {
      return { ok: false, error: `Invalid --config path: ${validation.reason}` };
    }
    return parseConfigFile(validation.resolved);
  }

  // Auto-discovery: search well-known locations in priority order
  const homeDir = process.env["HOME"] ?? process.env["USERPROFILE"] ?? "";
  const candidates = [
    resolve("claude_desktop_config.json"),
    resolve("mcp.json"),
    resolve(".mcp.json"),
    join(homeDir, ".config", "claude", "claude_desktop_config.json"),
  ];

  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue;

    let stat;
    try {
      stat = statSync(candidate);
    } catch {
      continue;
    }

    if (!stat.isFile()) continue;

    if (stat.size > MAX_CONFIG_BYTES) {
      return {
        ok: false,
        error: `Config file too large: ${candidate} (${stat.size.toLocaleString()} bytes; max ${MAX_CONFIG_BYTES.toLocaleString()})`,
      };
    }

    return parseConfigFile(candidate);
  }

  return {
    ok: false,
    error:
      "No MCP configuration found. Looked for:\n" +
      "  - claude_desktop_config.json\n" +
      "  - mcp.json\n" +
      "  - .mcp.json\n" +
      `  - ${join(homeDir, ".config", "claude", "claude_desktop_config.json")}\n\n` +
      "Run this command in a directory with MCP configuration, or use --config <path>.",
  };
}

function parseConfigFile(filePath: string): ConfigLoadResult {
  let content: string;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch (err) {
    return {
      ok: false,
      error: `Cannot read config file: ${filePath}\n  ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  let raw: unknown;
  try {
    raw = JSON.parse(content);
  } catch {
    return { ok: false, error: `Invalid JSON in config file: ${filePath}` };
  }

  const result = MCPConfigSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    return { ok: false, error: `Config schema validation failed in ${filePath}:\n${issues}` };
  }

  return { ok: true, config: result.data, filePath };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const cliArgs = parseArgs(process.argv);

  if (cliArgs.showVersion) {
    console.log("0.1.0");
    process.exit(EXIT.CLEAN);
  }

  if (cliArgs.showHelp) {
    printHelp();
    process.exit(EXIT.CLEAN);
  }

  if (cliArgs.command === "check") {
    await runCheck(cliArgs);
  } else if (
    cliArgs.command === "help" ||
    cliArgs.command === "--help" ||
    cliArgs.command === "-h"
  ) {
    printHelp();
    process.exit(EXIT.CLEAN);
  } else {
    console.error(`Unknown command: ${sanitizeForTerminal(cliArgs.command, 40)}`);
    printHelp();
    process.exit(EXIT.INPUT_ERROR);
  }
}

async function runCheck(cliArgs: CLIArgs): Promise<never> {
  // ── 1. Load and validate config ────────────────────────────────────────────
  const configResult = loadMCPConfig(cliArgs.configPath);
  if (!configResult.ok) {
    console.error(`Error: ${configResult.error}`);
    process.exit(EXIT.INPUT_ERROR);
  }

  const { config, filePath: configFilePath } = configResult;
  const servers = config.mcpServers ?? {};
  const serverNames = Object.keys(servers);

  if (serverNames.length === 0) {
    // A valid config with no servers is not an error, but nothing to do
    if (!cliArgs.jsonOutput) {
      console.log("No MCP servers found in configuration.");
    } else {
      console.log(JSON.stringify({ version: "unknown", scanned: 0, worst_score: 100, results: [] }, null, 2));
    }
    process.exit(EXIT.CLEAN);
  }

  if (serverNames.length > MAX_SERVERS) {
    console.error(
      `Error: Config contains ${serverNames.length} servers; maximum is ${MAX_SERVERS}.\n` +
        "Reduce the config size or split into multiple config files."
    );
    process.exit(EXIT.INPUT_ERROR);
  }

  // ── 2. Load detection rules ────────────────────────────────────────────────
  let rules: ReturnType<typeof loadRules>;
  try {
    rules = loadRules(RULES_DIR);
  } catch (err) {
    console.error(
      `Error: Failed to load detection rules from ${RULES_DIR}\n` +
        `  ${err instanceof Error ? err.message : String(err)}`
    );
    process.exit(EXIT.INTERNAL_ERROR);
  }

  if (rules.length === 0) {
    console.error("Error: No detection rules loaded. Check the rules directory.");
    process.exit(EXIT.INTERNAL_ERROR);
  }

  const rulesVersion = getRulesVersion(rules);
  const engine = new AnalysisEngine(rules);

  const ruleCategories: Record<string, string> = {};
  for (const rule of rules) {
    ruleCategories[rule.id] = rule.category;
  }

  // ── 3. Print header ────────────────────────────────────────────────────────
  if (!cliArgs.jsonOutput) {
    console.log(`\nMCP Sentinel — Security Scanner`);
    console.log(`   Config:  ${configFilePath}`);
    console.log(`   Rules:   ${rules.length} (v${rulesVersion})`);
    console.log(`   Servers: ${serverNames.length} configured`);
    if (serverNames.length >= WARN_SERVERS) {
      console.log(
        `   Warning: Large config detected (${serverNames.length} servers). Scan may take time.`
      );
    }
    console.log("\n" + "─".repeat(70));
  }

  // ── 4. Scan each server ────────────────────────────────────────────────────
  const results: ScanResult[] = [];
  let worstScore = 100;

  for (const [name, serverConfig] of Object.entries(servers)) {
    const safeServerName = sanitizeForTerminal(name);

    // Security boundary: env values are NEVER included in analysis context.
    // env may contain API keys, tokens, passwords. They must never be logged,
    // transmitted, or embedded in findings evidence.
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
      server_name: safeServerName,
      score: score.total_score,
      findings_count: findings.length,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      // Sanitize evidence before including in output — findings may match
      // content that itself contains control characters
      top_findings: findings
        .slice(0, 3)
        .map(
          (f) =>
            `[${f.severity.toUpperCase()}] ${f.rule_id}: ${sanitizeForTerminal(f.evidence, 100)}`
        ),
    };

    results.push(result);
    worstScore = Math.min(worstScore, score.total_score);

    if (!cliArgs.jsonOutput) {
      const indicator = getScoreIndicator(score.total_score);
      console.log(`\n  ${indicator} ${safeServerName.padEnd(40)} Score: ${score.total_score}/100`);
      console.log(
        `     Findings: ${findings.length} (${result.critical}C ${result.high}H ${result.medium}M ${result.low}L)`
      );
      for (const finding of result.top_findings) {
        console.log(`     -> ${finding}`);
      }
    }
  }

  // ── 5. Cross-config analysis (I13 — distributed lethal trifecta) ──────────
  // A single server may look safe, but combining read + untrusted content +
  // exfiltration across multiple servers is the I13 pattern.
  if (serverNames.length > 1) {
    const crossContext: AnalysisContext = {
      server: {
        id: "cross-config",
        name: "Cross-Config Analysis",
        description: `Aggregated analysis across ${serverNames.length} servers`,
        github_url: null,
      },
      tools: [],
      source_code: null,
      dependencies: [],
      connection_metadata: null,
    };

    const crossFindings = engine.analyze(crossContext).filter((f) => f.rule_id === "I13");

    if (crossFindings.length > 0) {
      const crossScore = computeScore(crossFindings, ruleCategories);
      worstScore = Math.min(worstScore, crossScore.total_score);

      const crossResult: ScanResult = {
        server_name: "[cross-config]",
        score: crossScore.total_score,
        findings_count: crossFindings.length,
        critical: crossFindings.filter((f) => f.severity === "critical").length,
        high: crossFindings.filter((f) => f.severity === "high").length,
        medium: crossFindings.filter((f) => f.severity === "medium").length,
        low: crossFindings.filter((f) => f.severity === "low").length,
        top_findings: crossFindings
          .slice(0, 3)
          .map(
            (f) =>
              `[${f.severity.toUpperCase()}] ${f.rule_id}: ${sanitizeForTerminal(f.evidence, 100)}`
          ),
      };

      results.push(crossResult);

      if (!cliArgs.jsonOutput) {
        const indicator = getScoreIndicator(crossScore.total_score);
        console.log(
          `\n  ${indicator} ${"[cross-config]".padEnd(40)} Score: ${crossScore.total_score}/100`
        );
        console.log(
          `     Findings: ${crossFindings.length} (${crossResult.critical}C ${crossResult.high}H ${crossResult.medium}M ${crossResult.low}L)`
        );
        for (const finding of crossResult.top_findings) {
          console.log(`     -> ${finding}`);
        }
      }
    }
  }

  // ── 6. Output ──────────────────────────────────────────────────────────────
  if (cliArgs.jsonOutput) {
    // Stable public JSON contract — never add or rename fields without a major bump
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
    console.log(`\n  Summary: ${results.length} servers scanned, worst score: ${worstScore}/100\n`);
  }

  // ── 7. CI failure evaluation ───────────────────────────────────────────────
  const SEVERITY_ORDER: Severity[] = [
    "informational",
    "low",
    "medium",
    "high",
    "critical",
  ];

  let shouldFail = false;

  // --ci / --min-score threshold
  if (cliArgs.ciMode && worstScore < cliArgs.minScore) {
    shouldFail = true;
    if (!cliArgs.jsonOutput) {
      console.error(
        `CI failure: worst score ${worstScore} is below threshold ${cliArgs.minScore}`
      );
    }
  }

  // --fail-on severity threshold
  if (cliArgs.failOn !== null) {
    const threshold = SEVERITY_ORDER.indexOf(cliArgs.failOn);
    const hasViolation = results.some((r) => {
      // Check if any result has findings at or above the threshold severity
      if (threshold <= SEVERITY_ORDER.indexOf("critical") && r.critical > 0) return true;
      if (threshold <= SEVERITY_ORDER.indexOf("high") && r.high > 0) return true;
      if (threshold <= SEVERITY_ORDER.indexOf("medium") && r.medium > 0) return true;
      if (threshold <= SEVERITY_ORDER.indexOf("low") && r.low > 0) return true;
      return false;
    });
    if (hasViolation) {
      shouldFail = true;
      if (!cliArgs.jsonOutput) {
        console.error(
          `CI failure: found findings at or above severity "${cliArgs.failOn}"`
        );
      }
    }
  }

  process.exit(shouldFail ? EXIT.FINDINGS : EXIT.CLEAN);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getScoreIndicator(score: number): string {
  if (score >= 80) return "[GOOD]";
  if (score >= 60) return "[WARN]";
  if (score >= 40) return "[POOR]";
  return "[CRIT]";
}

function printHelp(): void {
  console.log(`
MCP Sentinel — MCP Server Security Scanner

Usage:
  npx mcp-sentinel check                   Scan MCP servers in your config
  npx mcp-sentinel check --json            Machine-readable JSON output
  npx mcp-sentinel check --ci              CI mode: exit 1 if worst score < 60
  npx mcp-sentinel check --min-score 80    Custom CI score threshold (0-100)
  npx mcp-sentinel check --fail-on high    Exit 1 if any high or critical finding
  npx mcp-sentinel check --config <path>   Specify config file explicitly
  npx mcp-sentinel --version               Print version

Options:
  --json              Machine-readable JSON output (stable contract)
  --ci                Enable CI mode (non-zero exit on score below threshold)
  --min-score <n>     CI failure threshold, integer 0-100 (default: 60)
  --fail-on <sev>     Fail on findings at or above severity: critical|high|medium|low
  --config <path>     Path to MCP JSON config file (must be a .json file)
  --version / -v      Print version and exit
  --help / -h         Show this help message

Exit Codes:
  0  All servers pass threshold — safe to proceed
  1  One or more servers fail threshold — CI should block the change
  2  Config file error or invalid arguments — fix the input
  3  Internal scanner error — please report this as a bug

Config File Discovery (when --config is not specified):
  1. ./claude_desktop_config.json
  2. ./mcp.json
  3. ./.mcp.json
  4. ~/.config/claude/claude_desktop_config.json

JSON Output (stable public contract — v0.1.0):
  {
    "version": "<rules-version>",
    "scanned": <count>,
    "worst_score": <0-100>,
    "results": [
      {
        "server_name": "<name>",
        "score": <0-100>,
        "findings_count": <n>,
        "critical": <n>,
        "high": <n>,
        "medium": <n>,
        "low": <n>,
        "top_findings": ["[SEVERITY] RULE_ID: evidence..."]
      }
    ]
  }
`);
}

// ─── Exports for unit testing ─────────────────────────────────────────────────
// Pure functions and types are exported so tests can validate security logic
// directly without spawning subprocesses. The main() entry point is NOT
// exported — use subprocess tests to validate full CLI behaviour and exit codes.
export { sanitizeForTerminal, validateConfigPath, parseArgs, parseConfigFile, EXIT };
export type { CLIArgs };

// ─── Entry Point ──────────────────────────────────────────────────────────────
// Guard: only execute main() when this file is run directly as a script.
// When the module is imported by test runners (vitest) or other modules,
// process.argv[1] won't match this file's path, so main() is skipped.
// Both `node dist/cli.js` and `tsx src/cli.ts` set argv[1] to the script path.
const _entryFilePath = fileURLToPath(import.meta.url);
const _isEntryPoint = resolve(process.argv[1] ?? "") === _entryFilePath;

if (_isEntryPoint) {
  main().catch((err: unknown) => {
    // Unexpected error — don't expose full stack trace by default
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Unexpected error: ${message}`);
    console.error("Please report this at https://github.com/j420n/mcpsentinal/issues");
    process.exit(EXIT.INTERNAL_ERROR);
  });
}
