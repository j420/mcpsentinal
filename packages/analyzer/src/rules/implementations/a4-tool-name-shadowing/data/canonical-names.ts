/**
 * A4 — canonical tool-name catalogue. Derived from official Anthropic,
 * MCP reference, and community MCP server documentation. Each entry
 * carries a semantic category used in the evidence narrative.
 */

export type ToolCategory =
  | "filesystem"
  | "execution"
  | "network"
  | "database"
  | "messaging"
  | "git"
  | "memory"
  | "resource";

export interface CanonicalName {
  category: ToolCategory;
  origin: string;
}

export const CANONICAL_TOOLS: Readonly<Record<string, CanonicalName>> = {
  "read_file": { category: "filesystem", origin: "Anthropic filesystem server" },
  "write_file": { category: "filesystem", origin: "Anthropic filesystem server" },
  "list_files": { category: "filesystem", origin: "Anthropic filesystem server" },
  "delete_file": { category: "filesystem", origin: "Anthropic filesystem server" },
  "search_files": { category: "filesystem", origin: "Anthropic filesystem server" },
  "read_directory": { category: "filesystem", origin: "MCP filesystem reference" },
  "create_directory": { category: "filesystem", origin: "MCP filesystem reference" },
  "move_file": { category: "filesystem", origin: "Anthropic filesystem server" },
  "copy_file": { category: "filesystem", origin: "Anthropic filesystem server" },
  "execute_command": { category: "execution", origin: "MCP shell server" },
  "run_script": { category: "execution", origin: "MCP shell server" },
  "run_code": { category: "execution", origin: "MCP code-exec reference" },
  "exec": { category: "execution", origin: "Generic shell tool" },
  "shell": { category: "execution", origin: "MCP shell server" },
  "bash": { category: "execution", origin: "MCP shell server" },
  "terminal": { category: "execution", origin: "MCP shell server" },
  "repl": { category: "execution", origin: "MCP Python REPL server" },
  "fetch_url": { category: "network", origin: "MCP fetch server" },
  "http_request": { category: "network", origin: "MCP HTTP reference" },
  "web_search": { category: "network", origin: "MCP Brave search server" },
  "browse": { category: "network", origin: "MCP browser server" },
  "query_database": { category: "database", origin: "MCP SQL server" },
  "sql_query": { category: "database", origin: "MCP SQL server" },
  "read_database": { category: "database", origin: "MCP SQL server" },
  "send_email": { category: "messaging", origin: "MCP email server" },
  "send_message": { category: "messaging", origin: "MCP Slack / Discord server" },
  "notify": { category: "messaging", origin: "MCP notification server" },
  "git_clone": { category: "git", origin: "MCP git server" },
  "git_commit": { category: "git", origin: "MCP git server" },
  "git_push": { category: "git", origin: "MCP git server" },
  "git_pull": { category: "git", origin: "MCP git server" },
  "memory_store": { category: "memory", origin: "MCP memory server" },
  "memory_retrieve": { category: "memory", origin: "MCP memory server" },
  "memory_search": { category: "memory", origin: "MCP memory server" },
  "read_resource": { category: "resource", origin: "MCP spec core" },
  "write_resource": { category: "resource", origin: "MCP spec core" },
  "subscribe": { category: "resource", origin: "MCP spec core" },
  "list_tools": { category: "resource", origin: "MCP spec core" },
  "get_tool": { category: "resource", origin: "MCP spec core" },
  "call_tool": { category: "resource", origin: "MCP spec core" },
};

/** Canonical names as a fast-check Set for exact-match path. */
export const CANONICAL_SET: ReadonlySet<string> = new Set(Object.keys(CANONICAL_TOOLS));
