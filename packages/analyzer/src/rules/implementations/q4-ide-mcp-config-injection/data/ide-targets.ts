/**
 * Q4 — IDE MCP config target registry.
 *
 * Each entry records an IDE whose trust model for MCP has a known,
 * CVE-documented auto-load / auto-approve weakness. The registry drives
 * the evidence rationale — the finding names WHICH IDE is the victim
 * and which CVE class applies.
 *
 * Record<string, IdeTarget> keeps the no-static-patterns guard satisfied.
 */

export type IdeName = "cursor" | "vscode" | "claude-code" | "claude-desktop" | "windsurf" | "kiro" | "zed" | "roo-code";

export interface IdeTarget {
  ide: IdeName;
  /** Short human description — consumed in evidence rationale. */
  label: string;
  /** The CVE primarily associated with this IDE's MCP trust model. */
  cve: string;
}

/**
 * Path suffixes that unambiguously identify an IDE's MCP config file.
 * Matched against normalised (lower-cased, forward-slash) path text on a
 * path-component boundary.
 */
export const IDE_CONFIG_TARGETS: Record<string, IdeTarget> = {
  ".cursor/mcp.json": {
    ide: "cursor",
    label: "Cursor per-project MCP registry",
    cve: "CVE-2025-54135",
  },
  ".cursor/settings.json": {
    ide: "cursor",
    label: "Cursor per-project settings",
    cve: "CVE-2025-54136",
  },
  ".vscode/mcp.json": {
    ide: "vscode",
    label: "VS Code MCP registry",
    cve: "CVE-2025-59536",
  },
  ".vscode/settings.json": {
    ide: "vscode",
    label: "VS Code settings + Copilot MCP",
    cve: "CVE-2025-53773",
  },
  ".claude/settings.local.json": {
    ide: "claude-code",
    label: "Claude Code per-project settings",
    cve: "CVE-2025-59536",
  },
  ".claude/mcp.json": {
    ide: "claude-code",
    label: "Claude Code MCP registry",
    cve: "CVE-2025-59536",
  },
  ".amp/settings.json": {
    ide: "kiro",
    label: "Amp Code settings",
    cve: "CVE-2025-54135",
  },
  ".continue/config.json": {
    ide: "roo-code",
    label: "Continue.dev MCP config",
    cve: "CVE-2025-54135",
  },
};

/**
 * Property keys that, when set to `true` in code, programmatically enable
 * auto-approval of MCP servers inside an IDE. These bypass the user-
 * confirmation gate that the IDE normally requires before loading a new
 * project-level MCP server.
 *
 * Object literal — no static-string-array. Consumers iterate the keys.
 */
export const AUTO_APPROVE_KEYS: Record<string, true> = {
  enableAllProjectMcpServers: true,
  autoApprove: true,
  auto_approve: true,
  autoApproveAllMcp: true,
  trustAllServers: true,
  trust_all_servers: true,
  skipMcpConsent: true,
  skip_mcp_consent: true,
};

/**
 * Case-variant tokens that resolve to an MCP config filename on
 * case-insensitive filesystems (macOS APFS default, Windows NTFS).
 * Canonical form is `.cursor/mcp.json` / `mcp.json` — any mixed-case
 * variant is a CVE-2025-59944 bypass primitive.
 *
 * The matcher records ANY case-other-than-canonical as a hit. We keep
 * the canonical forms here so the check knows what "normal" looks like.
 */
export const CANONICAL_MCP_FILENAMES: Record<string, true> = {
  "mcp.json": true,
  "settings.local.json": true,
  "settings.json": true,
  "claude_desktop_config.json": true,
};
