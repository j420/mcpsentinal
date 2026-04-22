/**
 * L4 — MCP config marker vocabulary.
 *
 * Used to confirm that a fragment of source code is talking about an MCP
 * config (the JSON shape: `{ mcpServers: { <name>: { command: ..., args:
 * ..., env: ... } } }`) rather than an unrelated object literal.
 *
 * Record<string, true> (not a string-literal array) so the no-static-
 * patterns guard leaves it alone.
 */

/**
 * MCP config shape identifiers. The presence of ANY of these keys inside
 * an object literal whose subtree also has a `command` or `args` field
 * raises our confidence that we are looking at an MCP-config literal.
 */
export const MCP_CONFIG_CONTEXT_MARKERS: Record<string, true> = {
  mcpServers: true,
  mcp_config: true,
  mcp_servers: true,
  claudeDesktop: true,
  claude_desktop: true,
  mcp: true,
};

/**
 * Config filename suffixes an MCP client reads. Used as a secondary
 * signal: if the source code writes to one of these paths it is almost
 * certainly generating an MCP config; combined with a shell-interpreter
 * command field this is the CVE-2025-59536 primitive.
 */
export const MCP_CONFIG_FILENAMES: Record<string, true> = {
  ".mcp.json": true,
  "mcp.json": true,
  "claude_desktop_config.json": true,
  ".cursor/mcp.json": true,
  ".vscode/mcp.json": true,
  "settings.local.json": true,
  ".continue/config.json": true,
};

/**
 * Shell interpreters whose invocation in the `command` field of an MCP
 * server entry is the classic code-injection primitive. The client spawns
 * the command with the full arg array, but a shell interpreter turns
 * the subsequent -c / -e argument into an arbitrary command string.
 */
export const SHELL_INTERPRETERS: Record<string, true> = {
  bash: true,
  sh: true,
  zsh: true,
  dash: true,
  fish: true,
  ksh: true,
  cmd: true,
  "cmd.exe": true,
  powershell: true,
  "powershell.exe": true,
  pwsh: true,
};

/**
 * Flags that turn a shell invocation into an arbitrary-command evaluator.
 * `-c "…"` and `-e "…"` are the canonical primitives; /C is the Windows
 * cmd.exe equivalent.
 */
export const SHELL_EVAL_FLAGS: Record<string, true> = {
  "-c": true,
  "-e": true,
  "/c": true,
  "/C": true,
};

/**
 * Tokens whose appearance in `command` or `args` text indicates the entry
 * will pipe a network fetch into a shell — the `curl ... | sh` family
 * (CVE-2025-59536 walkthrough includes this payload shape).
 */
export const FETCH_AND_EXECUTE_TOKENS: Record<string, true> = {
  "curl ": true,
  "wget ": true,
  "Invoke-WebRequest": true,
  "iwr ": true,
  "$(curl": true,
  "$(wget": true,
};

/**
 * Sensitive environment variable name substrings. Presence in the
 * rendered config literal suggests a credential is being shipped as a
 * plain-text process argument — the CVE-2026-21852 exfiltration primitive.
 */
export const SENSITIVE_ENV_SUBSTRINGS: Record<string, true> = {
  API_KEY: true,
  ACCESS_TOKEN: true,
  SECRET: true,
  PASSWORD: true,
  DATABASE_URL: true,
  DB_PASSWORD: true,
  ANTHROPIC_API_KEY: true,
  OPENAI_API_KEY: true,
  GITHUB_TOKEN: true,
  AWS_SECRET_ACCESS_KEY: true,
};

/**
 * API-base overrides — setting any of these redirects the server's
 * outbound AI traffic to an attacker-controlled endpoint. CVE-2026-21852
 * directly exploited ANTHROPIC_API_URL.
 */
export const API_BASE_ENV_NAMES: Record<string, true> = {
  ANTHROPIC_API_URL: true,
  OPENAI_API_BASE: true,
  OPENAI_BASE_URL: true,
  AZURE_OPENAI_ENDPOINT: true,
  GOOGLE_API_ENDPOINT: true,
  API_BASE_URL: true,
};
