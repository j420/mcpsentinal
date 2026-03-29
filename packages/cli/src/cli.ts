#!/usr/bin/env node

import { readFileSync, existsSync, statSync } from "fs";
import { join, resolve, isAbsolute } from "path";
import { fileURLToPath } from "url";
import { MCPConnector } from "@mcp-sentinel/connector";
import { AnalysisEngine, loadRules, getRulesVersion } from "@mcp-sentinel/analyzer";
import { computeScore } from "@mcp-sentinel/scorer";
import { RiskMatrixAnalyzer } from "@mcp-sentinel/risk-matrix";
import { DynamicTester } from "@mcp-sentinel/dynamic-tester";
import type { DynamicReport } from "@mcp-sentinel/dynamic-tester";
import type { AnalysisContext, ProfiledAnalysisResult } from "@mcp-sentinel/analyzer";
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
  /** Enable gated dynamic tool invocation testing (requires server consent) */
  dynamic: boolean;
  /** Explicit server IDs pre-approved for dynamic testing (comma-separated) */
  dynamicAllowlist: string[];
  /** Path to write the dynamic test audit log */
  dynamicAuditLog: string | null;
  /** List all discovered MCP configs across all tools */
  discover: boolean;
  /** Scan ALL discovered configs (not just the first one found) */
  scanAll: boolean;
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

interface CrossServerResult {
  aggregate_risk: "none" | "low" | "medium" | "high" | "critical";
  patterns_detected: string[];
  attack_edges: number;
  score_caps: Record<string, number>;
  summary: string;
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

  // --dynamic: enable gated dynamic testing (requires explicit consent from server)
  const dynamic = args.includes("--dynamic");

  // --dynamic-allowlist <id1,id2,...>: pre-approve server IDs for dynamic testing
  let dynamicAllowlist: string[] = [];
  const allowlistIdx = args.findIndex((a) => a === "--dynamic-allowlist");
  if (allowlistIdx !== -1) {
    const raw = args[allowlistIdx + 1];
    if (!raw || raw.startsWith("--")) {
      console.error("Error: --dynamic-allowlist requires a comma-separated list of server IDs");
      process.exit(EXIT.INPUT_ERROR);
    }
    dynamicAllowlist = raw.split(",").map((s) => s.trim()).filter(Boolean);
  }

  // --dynamic-audit-log <path>: write dynamic test audit log to this file
  let dynamicAuditLog: string | null = null;
  const auditLogIdx = args.findIndex((a) => a === "--dynamic-audit-log");
  if (auditLogIdx !== -1) {
    const raw = args[auditLogIdx + 1];
    if (!raw || raw.startsWith("--")) {
      console.error("Error: --dynamic-audit-log requires a file path argument");
      process.exit(EXIT.INPUT_ERROR);
    }
    dynamicAuditLog = raw;
  }

  // --discover: list all found MCP configs across all tools
  const discover = args.includes("--discover");

  // --scan-all: scan ALL discovered configs (cross-config analysis)
  const scanAll = args.includes("--scan-all");

  return {
    command, jsonOutput, ciMode, minScore, failOn, configPath,
    showVersion, showHelp, dynamic, dynamicAllowlist, dynamicAuditLog,
    discover, scanAll,
  };
}

// ─── Config Source Types ──────────────────────────────────────────────────────

type ConfigSource =
  | "claude-desktop"
  | "claude-code"
  | "cursor"
  | "vscode-copilot"
  | "windsurf"
  | "gemini-cli"
  | "kiro"
  | "openclaw"
  | "project-mcp"   // mcp.json or .mcp.json in CWD
  | "explicit";     // --config flag

interface DiscoveredConfig {
  source: ConfigSource;
  filePath: string;
  config: MCPConfig;
  serverCount: number;
}

// Human-readable labels for each config source
const CONFIG_SOURCE_LABELS: Record<ConfigSource, string> = {
  "claude-desktop": "Claude Desktop",
  "claude-code": "Claude Code",
  "cursor": "Cursor",
  "vscode-copilot": "VS Code (Copilot)",
  "windsurf": "Windsurf (Codeium)",
  "gemini-cli": "Gemini CLI",
  "kiro": "Kiro (AWS)",
  "openclaw": "OpenClaw / ClawHub",
  "project-mcp": "Project MCP Config",
  "explicit": "Explicit (--config)",
};

// ─── Config Discovery ────────────────────────────────────────────────────────

interface ConfigCandidate {
  source: ConfigSource;
  path: string;
}

/**
 * Returns the platform-specific home directory.
 */
function getHomeDir(): string {
  return process.env["HOME"] ?? process.env["USERPROFILE"] ?? "";
}

/**
 * Returns the platform-specific app data directory.
 * macOS: ~/Library/Application Support
 * Linux: ~/.config
 * Windows: %APPDATA%
 */
function getAppDataDir(): string {
  const platform = process.platform;
  const home = getHomeDir();
  if (platform === "win32") {
    return process.env["APPDATA"] ?? join(home, "AppData", "Roaming");
  }
  if (platform === "darwin") {
    return join(home, "Library", "Application Support");
  }
  // linux and others
  return join(home, ".config");
}

/**
 * Generates all config candidate paths for the current platform.
 * Returns them in priority order: project-local first, then per-tool globals.
 */
function getConfigCandidates(): ConfigCandidate[] {
  const home = getHomeDir();
  const appData = getAppDataDir();
  const platform = process.platform;
  const cwd = process.cwd();

  const candidates: ConfigCandidate[] = [];

  // ── Project-local configs (highest priority) ──────────────────────────────

  // Generic project MCP configs
  candidates.push({ source: "project-mcp", path: join(cwd, "claude_desktop_config.json") });
  candidates.push({ source: "project-mcp", path: join(cwd, "mcp.json") });
  candidates.push({ source: "project-mcp", path: join(cwd, ".mcp.json") });

  // Cursor project
  candidates.push({ source: "cursor", path: join(cwd, ".cursor", "mcp.json") });

  // VS Code project
  candidates.push({ source: "vscode-copilot", path: join(cwd, ".vscode", "mcp.json") });

  // Windsurf project
  candidates.push({ source: "windsurf", path: join(cwd, ".windsurf", "mcp.json") });

  // Kiro project
  candidates.push({ source: "kiro", path: join(cwd, ".kiro", "mcp.json") });

  // ── Claude Desktop (per-platform) ────────────────────────────────────────
  if (platform === "darwin") {
    candidates.push({ source: "claude-desktop", path: join(appData, "Claude", "claude_desktop_config.json") });
  } else if (platform === "win32") {
    candidates.push({ source: "claude-desktop", path: join(appData, "Claude", "claude_desktop_config.json") });
  } else {
    // Linux
    candidates.push({ source: "claude-desktop", path: join(appData, "claude", "claude_desktop_config.json") });
  }

  // ── Claude Code ──────────────────────────────────────────────────────────
  candidates.push({ source: "claude-code", path: join(home, ".claude.json") });

  // ── Cursor (per-platform) ────────────────────────────────────────────────
  if (platform === "darwin") {
    candidates.push({ source: "cursor", path: join(appData, "Cursor", "User", "globalStorage", "cursor.mcp", "mcp.json") });
  } else if (platform === "win32") {
    candidates.push({ source: "cursor", path: join(appData, "Cursor", "User", "globalStorage", "cursor.mcp", "mcp.json") });
  } else {
    candidates.push({ source: "cursor", path: join(appData, "Cursor", "User", "globalStorage", "cursor.mcp", "mcp.json") });
  }

  // ── VS Code Copilot (per-platform) ───────────────────────────────────────
  if (platform === "darwin") {
    candidates.push({ source: "vscode-copilot", path: join(appData, "Code", "User", "globalStorage", "github.copilot", "mcp.json") });
  } else if (platform === "win32") {
    candidates.push({ source: "vscode-copilot", path: join(appData, "Code", "User", "globalStorage", "github.copilot", "mcp.json") });
  } else {
    candidates.push({ source: "vscode-copilot", path: join(appData, "Code", "User", "globalStorage", "github.copilot", "mcp.json") });
  }

  // ── Windsurf (per-platform) ──────────────────────────────────────────────
  if (platform === "darwin") {
    candidates.push({ source: "windsurf", path: join(appData, "Windsurf", "User", "globalStorage", "codeium.windsurf", "mcp.json") });
  } else if (platform === "win32") {
    candidates.push({ source: "windsurf", path: join(appData, "Windsurf", "User", "globalStorage", "codeium.windsurf", "mcp.json") });
  } else {
    candidates.push({ source: "windsurf", path: join(appData, "Windsurf", "User", "globalStorage", "codeium.windsurf", "mcp.json") });
  }

  // ── Gemini CLI ───────────────────────────────────────────────────────────
  candidates.push({ source: "gemini-cli", path: join(home, ".gemini", "settings.json") });

  // ── OpenClaw / ClawHub ───────────────────────────────────────────────────
  candidates.push({ source: "openclaw", path: join(home, ".openclaw", "config.json") });

  return candidates;
}

/**
 * Attempts to parse a config file, normalizing different config shapes
 * (mcpServers, servers, nested structures) into our standard MCPConfig shape.
 */
function normalizeConfig(raw: unknown): MCPConfig | null {
  if (typeof raw !== "object" || raw === null) return null;

  const obj = raw as Record<string, unknown>;

  // Standard shape: { mcpServers: { ... } }
  if (obj["mcpServers"] && typeof obj["mcpServers"] === "object") {
    const result = MCPConfigSchema.safeParse(raw);
    return result.success ? result.data : null;
  }

  // Alternate shape: { servers: { ... } } — used by some tools
  if (obj["servers"] && typeof obj["servers"] === "object") {
    const rewritten = { ...obj, mcpServers: obj["servers"] };
    const result = MCPConfigSchema.safeParse(rewritten);
    return result.success ? result.data : null;
  }

  // Gemini CLI / Claude Code: mcpServers may be nested inside the config
  // e.g. ~/.claude.json has { mcpServers: { ... } } alongside other keys
  // e.g. ~/.gemini/settings.json has { mcpServers: { ... } } inside
  // These are already handled by the mcpServers check above.

  // Last resort: try parsing as-is (passthrough schema allows extra keys)
  const result = MCPConfigSchema.safeParse(raw);
  return result.success ? result.data : null;
}

/**
 * Discovers ALL MCP config files across all supported AI coding tools.
 * Returns every valid config found, with source attribution.
 * Used by --discover and --scan-all flags.
 */
function discoverAllConfigs(): DiscoveredConfig[] {
  const candidates = getConfigCandidates();
  const discovered: DiscoveredConfig[] = [];
  const seenPaths = new Set<string>();

  for (const candidate of candidates) {
    // Deduplicate by resolved path (e.g. symlinks, same file via different routes)
    const resolvedPath = resolve(candidate.path);
    if (seenPaths.has(resolvedPath)) continue;
    seenPaths.add(resolvedPath);

    if (!existsSync(resolvedPath)) continue;

    let stat;
    try {
      stat = statSync(resolvedPath);
    } catch {
      continue;
    }

    if (!stat.isFile()) continue;
    if (stat.size > MAX_CONFIG_BYTES) continue;

    let content: string;
    try {
      content = readFileSync(resolvedPath, "utf-8");
    } catch {
      continue;
    }

    let raw: unknown;
    try {
      raw = JSON.parse(content);
    } catch {
      continue;
    }

    const config = normalizeConfig(raw);
    if (!config) continue;

    const serverCount = Object.keys(config.mcpServers ?? {}).length;

    // Only include configs that actually have servers defined
    if (serverCount === 0) continue;

    discovered.push({
      source: candidate.source,
      filePath: resolvedPath,
      config,
      serverCount,
    });
  }

  return discovered;
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

  // Auto-discovery: search all known config locations in priority order
  const candidates = getConfigCandidates();

  for (const candidate of candidates) {
    const resolvedPath = resolve(candidate.path);
    if (!existsSync(resolvedPath)) continue;

    let stat;
    try {
      stat = statSync(resolvedPath);
    } catch {
      continue;
    }

    if (!stat.isFile()) continue;

    if (stat.size > MAX_CONFIG_BYTES) {
      return {
        ok: false,
        error: `Config file too large: ${resolvedPath} (${stat.size.toLocaleString()} bytes; max ${MAX_CONFIG_BYTES.toLocaleString()})`,
      };
    }

    // Try to parse and normalize the config
    let content: string;
    try {
      content = readFileSync(resolvedPath, "utf-8");
    } catch (err) {
      continue;
    }

    let raw: unknown;
    try {
      raw = JSON.parse(content);
    } catch {
      continue;
    }

    const config = normalizeConfig(raw);
    if (!config) continue;

    // Only accept configs that have at least one server
    const serverCount = Object.keys(config.mcpServers ?? {}).length;
    if (serverCount === 0) continue;

    return { ok: true, config, filePath: resolvedPath };
  }

  const homeDir = getHomeDir();
  return {
    ok: false,
    error:
      "No MCP configuration found. Searched locations for:\n" +
      "  Claude Desktop, Claude Code, Cursor, VS Code (Copilot),\n" +
      "  Windsurf, Gemini CLI, Kiro, OpenClaw\n\n" +
      "Checked project configs:\n" +
      "  - ./claude_desktop_config.json, ./mcp.json, ./.mcp.json\n" +
      "  - .cursor/mcp.json, .vscode/mcp.json, .windsurf/mcp.json, .kiro/mcp.json\n\n" +
      "Checked global configs:\n" +
      `  - ${join(homeDir, ".claude.json")} (Claude Code)\n` +
      `  - ${join(homeDir, ".gemini", "settings.json")} (Gemini CLI)\n` +
      `  - ${getAppDataDir()}/<tool>/... (Claude Desktop, Cursor, VS Code, Windsurf)\n\n` +
      "Run this command in a directory with MCP configuration, or use --config <path>.\n" +
      "Use --discover to list all found MCP configs across all tools.",
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

// ─── Inspect Command ──────────────────────────────────────────────────────────

async function runInspect(args: string[]): Promise<never> {
  // Find the URL argument — first arg that looks like a URL, or after --url flag
  let endpoint: string | null = null;

  const urlFlagIdx = args.findIndex((a) => a === "--url");
  if (urlFlagIdx !== -1) {
    endpoint = args[urlFlagIdx + 1] ?? null;
  } else {
    // First positional arg after "inspect"
    const inspectIdx = args.indexOf("inspect");
    const candidate = args[inspectIdx + 1];
    if (candidate && !candidate.startsWith("--")) {
      endpoint = candidate;
    }
  }

  if (!endpoint) {
    console.error("Error: inspect requires a server URL.\n  Usage: npx mcp-sentinel inspect <url>");
    process.exit(EXIT.INPUT_ERROR);
  }

  // Basic URL validation
  try {
    new URL(endpoint);
  } catch {
    console.error(`Error: Invalid URL: ${sanitizeForTerminal(endpoint, 100)}`);
    process.exit(EXIT.INPUT_ERROR);
  }

  const jsonOutput = args.includes("--json");
  const connector = new MCPConnector({ timeout: 30_000 });

  if (!jsonOutput) {
    console.log(`\nMCP Sentinel — Server Inspector`);
    console.log(`   Endpoint: ${sanitizeForTerminal(endpoint, 100)}`);
    console.log("\nConnecting...");
  }

  const result = await connector.enumerate("inspect", endpoint);

  if (!result.connection_success) {
    console.error(`\nConnection failed: ${sanitizeForTerminal(result.connection_error ?? "unknown error", 200)}`);
    process.exit(EXIT.INTERNAL_ERROR);
  }

  if (jsonOutput) {
    console.log(JSON.stringify({
      endpoint,
      server_version: result.server_version,
      tools: result.tools.map((t) => ({
        name: t.name,
        description: t.description,
      })),
    }, null, 2));
    process.exit(EXIT.CLEAN);
  }

  // Human-readable output
  console.log(`\n   Server version : ${result.server_version ?? "(not reported)"}`);
  console.log(`   Tools found    : ${result.tools.length}`);
  console.log("\n" + "─".repeat(70));

  if (result.tools.length === 0) {
    console.log("\n  No tools found.");
  } else {
    for (const tool of result.tools) {
      console.log(`\n  ${sanitizeForTerminal(tool.name, 60)}`);
      if (tool.description) {
        // Wrap description at 66 chars with 4-space indent
        const desc = sanitizeForTerminal(tool.description, 500);
        const words = desc.split(" ");
        let line = "    ";
        for (const word of words) {
          if (line.length + word.length > 70) {
            console.log(line);
            line = "    " + word + " ";
          } else {
            line += word + " ";
          }
        }
        if (line.trim()) console.log(line);
      } else {
        console.log("    (no description)");
      }
    }
  }

  console.log("\n" + "─".repeat(70));
  process.exit(EXIT.CLEAN);
}

// ─── Scan Command — live URL → enumerate → analyze → score ───────────────────
// This is the missing link: inspect enumerates tools but runs no rules;
// check runs rules but has no live connection. scan <url> does both.

async function runScan(args: string[]): Promise<never> {
  // ── Parse args ────────────────────────────────────────────────────────────
  let endpoint: string | null = null;
  let filterRule: string | null = null;
  const jsonOutput = args.includes("--json");

  const scanIdx = args.indexOf("scan");
  if (scanIdx !== -1) {
    const candidate = args[scanIdx + 1];
    if (candidate && !candidate.startsWith("--")) {
      endpoint = candidate;
    }
  }
  const urlFlagIdx = args.findIndex((a) => a === "--url");
  if (urlFlagIdx !== -1) endpoint = args[urlFlagIdx + 1] ?? null;

  const ruleFlagIdx = args.findIndex((a) => a === "--rule");
  if (ruleFlagIdx !== -1) filterRule = args[ruleFlagIdx + 1] ?? null;

  if (!endpoint) {
    console.error(
      "Error: scan requires a server URL.\n" +
      "  Usage: npx mcp-sentinel scan <url> [--rule <id>] [--json]"
    );
    process.exit(EXIT.INPUT_ERROR);
  }

  try { new URL(endpoint); } catch {
    console.error(`Error: Invalid URL: ${sanitizeForTerminal(endpoint, 100)}`);
    process.exit(EXIT.INPUT_ERROR);
  }

  // ── Load rules ────────────────────────────────────────────────────────────
  let rules;
  try {
    rules = loadRules(RULES_DIR);
  } catch (err) {
    console.error(`Error loading rules: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(EXIT.INTERNAL_ERROR);
  }
  const rulesVersion = getRulesVersion(rules);
  const engine = new AnalysisEngine(rules);
  const ruleCategories: Record<string, string> = {};
  for (const rule of rules) {
    ruleCategories[rule.id] = rule.category;
  }

  if (!jsonOutput) {
    console.log(`\nMCP Sentinel — Live Security Scan`);
    console.log(`   Endpoint  : ${sanitizeForTerminal(endpoint, 120)}`);
    console.log(`   Rules     : ${rules.length} rules loaded (v${rulesVersion})`);
    if (filterRule) {
      console.log(`   Filter    : rule ${sanitizeForTerminal(filterRule, 20)} only`);
    }
    console.log("\nStep 1/3  Connecting and enumerating tools...");
  }

  // ── Step 1: Enumerate tools from live server ──────────────────────────────
  const connector = new MCPConnector({ timeout: 30_000 });
  const enumResult = await connector.enumerate("cli-scan", endpoint);

  if (!enumResult.connection_success) {
    const errMsg = sanitizeForTerminal(enumResult.connection_error ?? "unknown error", 200);
    if (jsonOutput) {
      console.log(JSON.stringify({
        endpoint,
        connection_success: false,
        error: errMsg,
        findings: [],
        score: null,
      }, null, 2));
    } else {
      console.error(`\nConnection failed: ${errMsg}`);
    }
    process.exit(EXIT.INTERNAL_ERROR);
  }

  if (!jsonOutput) {
    console.log(`          ✓ Connected — ${enumResult.tools.length} tool(s) found`);
    if (enumResult.server_version) {
      console.log(`            Server version: ${sanitizeForTerminal(enumResult.server_version, 60)}`);
    }
    if (enumResult.server_instructions) {
      console.log(`            Instructions field: present (${enumResult.server_instructions.length} chars)`);
    }
    console.log("\nStep 2/3  Running analysis rules...");
  }

  // ── Step 2: Build analysis context from enumeration result ────────────────
  const context: AnalysisContext = {
    server: {
      id: "cli-scan",
      name: sanitizeForTerminal(new URL(endpoint).hostname, 100),
      description: null,
      github_url: null,
    },
    tools: enumResult.tools.map((t) => ({
      name: t.name,
      description: t.description ?? null,
      input_schema: t.input_schema as Record<string, unknown> | null ?? null,
      annotations: (t as { annotations?: Record<string, unknown> }).annotations ?? null,
    })),
    source_code: null,       // not fetched in CLI scan — run pnpm scan for full pipeline
    dependencies: [],        // not audited in CLI scan
    connection_metadata: {
      auth_required: false,
      transport: endpoint.startsWith("https") ? "streamable-http" : "sse",
      response_time_ms: enumResult.response_time_ms ?? 0,
    },
    initialize_metadata: {
      server_version: enumResult.server_version ?? null,
      server_instructions: enumResult.server_instructions ?? null,
    },
    resources: (enumResult.resources ?? []).map((r) => ({
      uri: r.uri,
      name: r.name,
      description: r.description ?? null,
      mimeType: r.mimeType ?? null,
    })),
    prompts: (enumResult.prompts ?? []).map((p) => ({
      name: p.name,
      description: p.description ?? null,
      arguments: (p.arguments ?? []).map((a) => ({
        name: a.name,
        description: a.description ?? null,
        required: a.required ?? false,
      })),
    })),
    roots: enumResult.roots ?? [],
    declared_capabilities: enumResult.declared_capabilities ?? null,
  };

  // ── Step 3: Profile-aware analysis + score ────────────────────────────────
  const profileResult = engine.analyzeWithProfile(context);
  let findings = profileResult.scored_findings;

  // Optionally filter to a single rule for focused testing
  if (filterRule) {
    const ruleUpper = filterRule.toUpperCase();
    findings = findings.filter((f) => f.rule_id === ruleUpper);
  }

  const scoreResult = computeScore(findings, ruleCategories);

  if (!jsonOutput) {
    const rawCount = profileResult.all_annotated.length;
    const filteredOut = rawCount - profileResult.scored_findings.length;
    console.log(`          ✓ Analysis complete — ${findings.length} finding(s) (${filteredOut} filtered as irrelevant)\n`);
    if (profileResult.profile.attack_surfaces.length > 0) {
      console.log(`          Attack surfaces: ${profileResult.profile.attack_surfaces.join(", ")}`);
    }
  }

  // ── Output ────────────────────────────────────────────────────────────────
  const SEV_ORDER = ["critical", "high", "medium", "low", "informational"] as const;

  if (jsonOutput) {
    console.log(JSON.stringify({
      endpoint,
      rules_version: rulesVersion,
      server_version: enumResult.server_version ?? null,
      tools_enumerated: enumResult.tools.length,
      score: scoreResult.total_score,
      sub_scores: {
        code: scoreResult.code_score,
        deps: scoreResult.deps_score,
        config: scoreResult.config_score,
        description: scoreResult.description_score,
        behavior: scoreResult.behavior_score,
      },
      profile: {
        attack_surfaces: profileResult.profile.attack_surfaces,
        capabilities: profileResult.profile.capabilities
          .filter((c) => c.confidence >= 0.5)
          .map((c) => ({ capability: c.capability, confidence: Math.round(c.confidence * 100) / 100 })),
        threats_checked: profileResult.threats.map((t) => t.id),
        total_raw_findings: profileResult.all_annotated.length,
        filtered_as_irrelevant: profileResult.all_annotated.length - profileResult.scored_findings.length,
      },
      findings_count: findings.length,
      findings: findings.map((f) => ({
        rule_id: f.rule_id,
        severity: f.severity,
        owasp: f.owasp_category,
        mitre: f.mitre_technique,
        evidence: f.evidence,
        remediation: f.remediation,
      })),
    }, null, 2));
    process.exit(findings.length > 0 ? EXIT.FINDINGS : EXIT.CLEAN);
  }

  // Human-readable output
  const divider = "─".repeat(72);

  // Score banner
  const scoreLabel =
    scoreResult.total_score >= 80 ? "GOOD" :
    scoreResult.total_score >= 60 ? "MODERATE" :
    scoreResult.total_score >= 40 ? "POOR" : "CRITICAL";
  console.log(`Step 3/3  Score: ${scoreResult.total_score}/100  [${scoreLabel}]`);
  console.log(`          Findings: ${findings.length} total`);
  for (const sev of SEV_ORDER) {
    const count = findings.filter((f) => f.severity === sev).length;
    if (count > 0) console.log(`            ${sev.padEnd(14)}: ${count}`);
  }
  console.log();

  // Tools summary
  console.log(divider);
  console.log(`TOOLS ENUMERATED (${enumResult.tools.length})`);
  console.log(divider);
  for (const tool of enumResult.tools.slice(0, 20)) {
    const toolName = sanitizeForTerminal(tool.name, 40);
    const hasFindings = findings.some(
      (f) => f.evidence.includes(`tool:${tool.name}`) || f.evidence.includes(tool.name)
    );
    console.log(`  ${hasFindings ? "⚠" : "✓"}  ${toolName}`);
  }
  if (enumResult.tools.length > 20) {
    console.log(`  ... and ${enumResult.tools.length - 20} more`);
  }
  console.log();

  // Findings
  if (findings.length === 0) {
    console.log(divider);
    console.log("FINDINGS");
    console.log(divider);
    console.log("  ✓  No findings detected across applicable rules.\n");
  } else {
    for (const sev of SEV_ORDER) {
      const sevFindings = findings.filter((f) => f.severity === sev);
      if (sevFindings.length === 0) continue;

      console.log(divider);
      console.log(`${sev.toUpperCase()} (${sevFindings.length})`);
      console.log(divider);

      for (const f of sevFindings) {
        console.log(`\n  [${f.rule_id}] ${sanitizeForTerminal(
          (f.rule_id + " — " + f.evidence).slice(0, 200), 200
        )}`);
        if (f.owasp_category) {
          console.log(`         OWASP: ${f.owasp_category}`);
        }
        if (f.mitre_technique) {
          console.log(`         MITRE: ${f.mitre_technique}`);
        }
        console.log(`         Fix  : ${sanitizeForTerminal(f.remediation, 160)}`);
      }
      console.log();
    }
  }

  console.log(divider);
  console.log(
    `NOTE: This scan covers rules that apply to live tool enumeration.\n` +
    `      Source code (C1–C16), dependency (D1–D7), and full compliance\n` +
    `      rules require the full pipeline: pnpm scan --server=<id>`
  );
  console.log(divider);

  process.exit(findings.length > 0 ? EXIT.FINDINGS : EXIT.CLEAN);
}

// ─── Discover Command ────────────────────────────────────────────────────────

function runDiscover(jsonOutput: boolean): never {
  const discovered = discoverAllConfigs();

  if (jsonOutput) {
    const output = {
      discovered: discovered.map((d) => ({
        source: d.source,
        source_label: CONFIG_SOURCE_LABELS[d.source],
        file_path: d.filePath,
        server_count: d.serverCount,
        server_names: Object.keys(d.config.mcpServers ?? {}),
      })),
      total_configs: discovered.length,
      total_servers: discovered.reduce((sum, d) => sum + d.serverCount, 0),
    };
    console.log(JSON.stringify(output, null, 2));
    process.exit(EXIT.CLEAN);
  }

  // Human-readable output
  console.log(`\nMCP Sentinel — Config Discovery\n`);

  if (discovered.length === 0) {
    console.log("  No MCP configurations found on this system.\n");
    console.log("  Searched locations for:");
    console.log("    Claude Desktop, Claude Code, Cursor, VS Code (Copilot),");
    console.log("    Windsurf, Gemini CLI, Kiro, OpenClaw\n");
    console.log("  Use --config <path> to specify a config file explicitly.");
    process.exit(EXIT.CLEAN);
  }

  const divider = "─".repeat(72);
  let totalServers = 0;

  for (const d of discovered) {
    const label = CONFIG_SOURCE_LABELS[d.source];
    totalServers += d.serverCount;
    console.log(divider);
    console.log(`  ${label}`);
    console.log(`  File: ${d.filePath}`);
    console.log(`  Servers: ${d.serverCount}`);
    const serverNames = Object.keys(d.config.mcpServers ?? {});
    for (const name of serverNames) {
      console.log(`    - ${sanitizeForTerminal(name, 60)}`);
    }
  }

  console.log(divider);
  console.log(`\n  Total: ${discovered.length} config(s), ${totalServers} server(s)\n`);
  console.log("  Use --scan-all to scan all discovered configs.");
  console.log("  Use --config <path> to scan a specific config file.\n");

  process.exit(EXIT.CLEAN);
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

  // --discover flag or "discover" command: list all found configs
  if (cliArgs.discover || cliArgs.command === "discover") {
    runDiscover(cliArgs.jsonOutput);
  }

  if (cliArgs.command === "check") {
    await runCheck(cliArgs);
  } else if (cliArgs.command === "inspect") {
    await runInspect(process.argv.slice(2));
  } else if (cliArgs.command === "scan") {
    await runScan(process.argv.slice(2));
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
  let servers: Record<string, MCPServerEntry> = {};
  let configFilePath: string;
  let discoveredConfigs: DiscoveredConfig[] | null = null;

  if (cliArgs.scanAll) {
    // --scan-all: discover and merge ALL configs across all tools
    discoveredConfigs = discoverAllConfigs();
    if (discoveredConfigs.length === 0) {
      console.error("Error: --scan-all found no MCP configurations. Use --discover to see search locations.");
      process.exit(EXIT.INPUT_ERROR);
    }

    configFilePath = `${discoveredConfigs.length} config(s) via --scan-all`;

    // Merge all servers from all configs, prefixing server names with source
    // to avoid collisions (e.g. two tools both have a "filesystem" server)
    for (const dc of discoveredConfigs) {
      const dcServers = dc.config.mcpServers ?? {};
      for (const [name, entry] of Object.entries(dcServers)) {
        // Prefix with source label if scanning multiple configs to avoid name collisions
        const prefixedName = discoveredConfigs.length > 1
          ? `[${CONFIG_SOURCE_LABELS[dc.source]}] ${name}`
          : name;
        servers[prefixedName] = entry;
      }
    }
  } else {
    const configResult = loadMCPConfig(cliArgs.configPath);
    if (!configResult.ok) {
      console.error(`Error: ${configResult.error}`);
      process.exit(EXIT.INPUT_ERROR);
    }
    configFilePath = configResult.filePath;
    servers = configResult.config.mcpServers ?? {};
  }

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

    const profileResult = engine.analyzeWithProfile(context);
    const findings = profileResult.scored_findings;
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

  // ── 5. Cross-server risk matrix (Layer 5 — P01–P12 patterns) ─────────────
  // Analyzes capability combinations across all servers in the config.
  // Detects attack paths that no individual server scan can find:
  // credential harvesting chains, injection propagation, multi-hop exfiltration, etc.
  let crossServerResult: CrossServerResult | null = null;

  if (serverNames.length > 1) {
    const riskMatrixAnalyzer = new RiskMatrixAnalyzer();

    // Build server input from scanned results — tools not available in CLI mode,
    // so the analyzer classifies based on server name patterns and config metadata.
    // The per-server scores from the current run are passed in as latest_score
    // so P11 (low-score server in high-trust config) fires correctly.
    const serverInputs = serverNames.map((name, i) => ({
      server_id: name,
      server_name: name,
      server_slug: name.toLowerCase().replace(/[^a-z0-9]+/g, "-"),
      latest_score: results[i]?.score ?? null,
      category: null,
      tools: [],  // CLI mode: tools not available without live enumeration
    }));

    const riskReport = riskMatrixAnalyzer.analyze(serverInputs);

    if (riskReport.edges.length > 0) {
      crossServerResult = {
        aggregate_risk: riskReport.aggregate_risk,
        patterns_detected: riskReport.patterns_detected,
        attack_edges: riskReport.edges.length,
        score_caps: riskReport.score_caps,
        summary: riskReport.summary,
      };

      // Apply score caps from critical cross-server patterns to worstScore
      const capValues = Object.values(riskReport.score_caps);
      if (capValues.length > 0) {
        const lowestCap = Math.min(...capValues);
        worstScore = Math.min(worstScore, lowestCap);
      }

      if (!cliArgs.jsonOutput) {
        const riskIndicator =
          riskReport.aggregate_risk === "critical" ? "[CRIT]" :
          riskReport.aggregate_risk === "high" ? "[WARN]" :
          riskReport.aggregate_risk === "medium" ? "[WARN]" : "[INFO]";
        console.log(`\n  ${riskIndicator} [cross-server risk matrix]`);
        console.log(`     ${sanitizeForTerminal(riskReport.summary, 200)}`);
        if (riskReport.patterns_detected.length > 0) {
          console.log(`     Patterns: ${riskReport.patterns_detected.join(", ")}`);
        }
        if (Object.keys(riskReport.score_caps).length > 0) {
          const cappedServers = Object.entries(riskReport.score_caps)
            .map(([id, cap]) => `${sanitizeForTerminal(id, 40)} → capped at ${cap}`)
            .join(", ");
          console.log(`     Score caps applied: ${cappedServers}`);
        }
      }
    }
  }

  // ── 6. Dynamic testing (--dynamic flag — gated by server consent) ─────────
  // Only runs when:
  //   (a) --dynamic is passed explicitly
  //   (b) Server entry has a `url` field (HTTP/SSE transport — required for SDK connect)
  //   (c) Server grants consent via allowlist, tool_declaration, or .well-known
  //
  // ADR-007: We NEVER call tools without consent. The DynamicTester enforces
  // this internally, but we also check for the url field here to avoid
  // attempting dynamic tests against stdio servers that have no HTTP endpoint.
  const dynamicResults: Record<string, DynamicReport> = {};

  if (cliArgs.dynamic) {
    if (!cliArgs.jsonOutput) {
      console.log("\n" + "─".repeat(70));
      console.log("  Dynamic Testing (consent-gated)\n");
    }

    const tester = new DynamicTester({
      allowlist: cliArgs.dynamicAllowlist,
      ...(cliArgs.dynamicAuditLog ? { audit_log_path: cliArgs.dynamicAuditLog } : {}),
    });

    for (const [name, serverConfig] of Object.entries(servers)) {
      const endpoint = serverConfig.url;
      if (!endpoint) {
        if (!cliArgs.jsonOutput) {
          console.log(`  [SKIP] ${sanitizeForTerminal(name, 40)} — no url (stdio server, skipping dynamic test)`);
        }
        continue;
      }

      if (!cliArgs.jsonOutput) {
        console.log(`  [TEST] ${sanitizeForTerminal(name, 40)} @ ${sanitizeForTerminal(endpoint, 60)}`);
      }

      try {
        // In CLI mode we have no live tool enumeration, so pass an empty tools
        // list. DynamicTester will check consent and report consent_denied if
        // the server hasn't opted in — this is the correct behaviour.
        const report = await tester.test(
          { id: name, name },
          endpoint,
          [],
          // callTool stub — not invoked until consent granted AND tools available
          async (_toolName: string, _input: Record<string, unknown>) => {
            throw new Error("No tools available for dynamic testing in CLI static-analysis mode");
          }
        );

        dynamicResults[name] = report;

        if (!cliArgs.jsonOutput) {
          if (!report.consent.consented) {
            console.log(`       Consent: DENIED — server has not opted in`);
          } else {
            console.log(`       Consent: ${report.consent.method ?? "granted"}`);
            console.log(`       Tools tested: ${report.tools_tested}, skipped: ${report.tools_skipped}`);
            console.log(`       Output injection risk: ${report.risk_summary.output_injection_risk}`);
            console.log(`       Injection vulnerability: ${report.risk_summary.injection_vulnerability}`);
            if (report.output_findings_count > 0) {
              console.log(`       Output findings: ${report.output_findings_count}`);
            }
          }
        }
      } catch (dynErr) {
        const msg = dynErr instanceof Error ? dynErr.message : String(dynErr);
        if (!cliArgs.jsonOutput) {
          console.log(`       Error: ${sanitizeForTerminal(msg, 120)}`);
        }
      }
    }
  }

  // ── 7. Output ──────────────────────────────────────────────────────────────
  if (cliArgs.jsonOutput) {
    // Stable public JSON contract — never add or rename fields without a major bump
    const output: Record<string, unknown> = {
      version: rulesVersion,
      scanned: results.length,
      worst_score: worstScore,
      results,
    };
    if (crossServerResult) {
      output["cross_server"] = crossServerResult;
    }
    if (Object.keys(dynamicResults).length > 0) {
      // Include consent status and risk summary — omit full probes array (too large)
      output["dynamic"] = Object.fromEntries(
        Object.entries(dynamicResults).map(([name, r]) => [
          name,
          {
            consented: r.consent.consented,
            consent_method: r.consent.method,
            tools_tested: r.tools_tested,
            tools_skipped: r.tools_skipped,
            output_findings_count: r.output_findings_count,
            injection_vulnerable_count: r.injection_vulnerable_count,
            output_injection_risk: r.risk_summary.output_injection_risk,
            injection_vulnerability: r.risk_summary.injection_vulnerability,
            schema_compliance: r.risk_summary.schema_compliance,
            timing_anomalies: r.risk_summary.timing_anomalies,
          },
        ])
      );
    }
    console.log(JSON.stringify(output, null, 2));
  } else {
    console.log("\n" + "─".repeat(70));
    console.log(`\n  Summary: ${results.length} servers scanned, worst score: ${worstScore}/100\n`);
  }

  // ── 8. CI failure evaluation ───────────────────────────────────────────────
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
  npx mcp-sentinel inspect <url>                List tools exposed by an MCP server
  npx mcp-sentinel inspect <url> --json         JSON output of tool names + descriptions
  npx mcp-sentinel scan <url>                   Connect to a live MCP server and run security rules
  npx mcp-sentinel scan <url> --rule A1         Run only the specified rule (e.g. A1 = Prompt Injection)
  npx mcp-sentinel scan <url> --json            Machine-readable JSON scan output
  npx mcp-sentinel check                        Scan MCP servers in your config
  npx mcp-sentinel check --json                 Machine-readable JSON output
  npx mcp-sentinel check --ci                   CI mode: exit 1 if worst score < 60
  npx mcp-sentinel check --min-score 80         Custom CI score threshold (0-100)
  npx mcp-sentinel check --fail-on high         Exit 1 if any high or critical finding
  npx mcp-sentinel check --config <path>        Specify config file explicitly
  npx mcp-sentinel check --scan-all             Scan ALL discovered configs across all tools
  npx mcp-sentinel check --dynamic              Enable dynamic tool invocation (consent-gated)
  npx mcp-sentinel check --dynamic-allowlist <ids>  Pre-approve server IDs (comma-separated)
  npx mcp-sentinel discover                     List all found MCP configs across all tools
  npx mcp-sentinel discover --json              JSON output of discovered configs
  npx mcp-sentinel --version                    Print version

Options:
  --json                       Machine-readable JSON output (stable contract)
  --ci                         Enable CI mode (non-zero exit on score below threshold)
  --min-score <n>              CI failure threshold, integer 0-100 (default: 60)
  --fail-on <sev>              Fail on findings at or above severity: critical|high|medium|low
  --config <path>              Path to MCP JSON config file (must be a .json file)
  --discover                   List all MCP configs found across all supported tools
  --scan-all                   Scan ALL discovered configs (enables cross-config analysis)
  --dynamic                    Enable consent-gated dynamic tool invocation testing.
                               Only servers that opt in via allowlist, tool_declaration,
                               or .well-known/mcp-sentinel.json are tested. Requires
                               servers to have a 'url' field (HTTP/SSE transport).
  --dynamic-allowlist <ids>    Comma-separated list of server names to pre-approve
                               for dynamic testing (equivalent to an explicit allowlist).
  --dynamic-audit-log <path>   Path to write the dynamic test audit log (JSONL format).
                               Defaults to ./dynamic-test-audit.jsonl.
  --version / -v               Print version and exit
  --help / -h                  Show this help message

Exit Codes:
  0  All servers pass threshold — safe to proceed
  1  One or more servers fail threshold — CI should block the change
  2  Config file error or invalid arguments — fix the input
  3  Internal scanner error — please report this as a bug

Config File Auto-Discovery:
  The CLI searches for MCP configs from all major AI coding tools:

  Project-local (checked first):
    ./claude_desktop_config.json, ./mcp.json, ./.mcp.json
    .cursor/mcp.json, .vscode/mcp.json, .windsurf/mcp.json, .kiro/mcp.json

  Claude Desktop:
    macOS:   ~/Library/Application Support/Claude/claude_desktop_config.json
    Linux:   ~/.config/claude/claude_desktop_config.json
    Windows: %APPDATA%/Claude/claude_desktop_config.json

  Claude Code:
    ~/.claude.json

  Cursor:
    macOS:   ~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json
    Linux:   ~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json
    Windows: %APPDATA%/Cursor/User/globalStorage/cursor.mcp/mcp.json

  VS Code (Copilot):
    macOS:   ~/Library/Application Support/Code/User/globalStorage/github.copilot/mcp.json
    Linux:   ~/.config/Code/User/globalStorage/github.copilot/mcp.json
    Windows: %APPDATA%/Code/User/globalStorage/github.copilot/mcp.json

  Windsurf (Codeium):
    macOS:   ~/Library/Application Support/Windsurf/User/globalStorage/codeium.windsurf/mcp.json
    Linux:   ~/.config/Windsurf/User/globalStorage/codeium.windsurf/mcp.json
    Windows: %APPDATA%/Windsurf/User/globalStorage/codeium.windsurf/mcp.json

  Gemini CLI:  ~/.gemini/settings.json
  Kiro (AWS):  .kiro/mcp.json (project-local)
  OpenClaw:    ~/.openclaw/config.json

  Use --discover to see which configs are found on your system.

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
export { sanitizeForTerminal, validateConfigPath, parseArgs, parseConfigFile, discoverAllConfigs, normalizeConfig, getConfigCandidates, EXIT };
export type { CLIArgs, ConfigSource, DiscoveredConfig };

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
