/**
 * J1 — Agent-config target registry.
 *
 * A "target" is a filesystem location (path suffix) that some widely-deployed
 * AI-agent tooling reads as its per-project or per-user configuration and
 * where a new MCP server entry is auto-loaded on the next launch. Writing to
 * any of these locations from a non-interactive MCP server is the
 * cross-agent configuration-poisoning primitive documented in CVE-2025-53773.
 *
 * Object-literal shape (not a string-literal array) so the
 * `no-static-patterns` guard leaves it alone. Consumers build a ReadonlySet
 * from the keys at module load. Each entry records which IDE/agent reads
 * the file — the finding must name the victim so an auditor can confirm
 * the affected trust boundary.
 *
 * The match is substring-based (not regex). A path whose normalised form
 * contains ANY of these suffixes is considered a candidate target. The
 * gatherer checks path-component boundaries so "/.claude" matches
 * "~/.claude/settings.json" but not "/my.claude.backup".
 */

export type AgentHost =
  | "claude-code"
  | "claude-desktop"
  | "cursor"
  | "vscode"
  | "gemini"
  | "continue"
  | "amp"
  | "generic-mcp";

export interface AgentConfigTarget {
  /** The IDE/agent that reads this file. */
  host: AgentHost;
  /**
   * Short human description of the field — used in the evidence rationale.
   * Kept short (≤ 60 chars) because the narrative renderer truncates.
   */
  role: string;
}

/**
 * Substrings to match against a normalised (lower-cased, forward-slash)
 * path. Each key is a suffix-or-component of a known agent config file.
 *
 * The set is intentionally conservative — a dozen entries, not a hundred —
 * because over-broad matching (e.g. just "mcp") produces false positives
 * on project source files that happen to contain "mcp" in their names.
 */
export const AGENT_CONFIG_TARGETS: Record<string, AgentConfigTarget> = {
  ".claude/settings.local.json": { host: "claude-code", role: "Claude Code per-project settings" },
  ".claude/settings.json": { host: "claude-code", role: "Claude Code shared settings" },
  ".claude/mcp.json": { host: "claude-code", role: "Claude Code MCP server registry" },
  ".claude_desktop_config.json": { host: "claude-desktop", role: "Claude Desktop config" },
  "claude_desktop_config.json": { host: "claude-desktop", role: "Claude Desktop config" },
  ".cursor/mcp.json": { host: "cursor", role: "Cursor per-project MCP registry" },
  ".cursor/settings.json": { host: "cursor", role: "Cursor per-project settings" },
  ".vscode/mcp.json": { host: "vscode", role: "VS Code MCP registry" },
  ".vscode/settings.json": { host: "vscode", role: "VS Code + Copilot settings" },
  ".gemini/settings.json": { host: "gemini", role: "Gemini Code Assist settings" },
  ".continue/config.json": { host: "continue", role: "Continue.dev MCP config" },
  ".amp/settings.json": { host: "amp", role: "Amp Code settings" },
  ".mcp.json": { host: "generic-mcp", role: "Project-root MCP registry" },
  "/mcp.json": { host: "generic-mcp", role: "User-home MCP registry" },
};
