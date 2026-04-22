/**
 * Q13 — MCP bridge package vocabulary.
 */

/**
 * Known bridge-package names that should ALWAYS be pinned.
 * Keys are lowercase canonical names.
 */
export const BRIDGE_PACKAGE_NAMES: Readonly<Record<string, string>> = {
  "mcp-remote": "npm:mcp-remote",
  "mcp-proxy": "npm:mcp-proxy",
  "mcp-gateway": "npm:mcp-gateway",
  "fastmcp": "pypi:fastmcp",
  "@modelcontextprotocol/sdk": "npm:@modelcontextprotocol/sdk",
};

/**
 * Command prefixes that, when they appear at the start of a
 * command-line literal, indicate a fetch-and-execute of the
 * following package.
 */
export const FETCH_EXEC_COMMANDS: Readonly<Record<string, true>> = {
  npx: true,
  uvx: true,
  pipx: true,
};

/**
 * Loose version-range markers that, in a JSON package.json, mean
 * "latest" — i.e. NOT pinned.
 */
export const LOOSE_VERSION_MARKERS: Readonly<Record<string, true>> = {
  "*": true,
  "latest": true,
  "^": true,  // treated as a prefix signal
  "~": true,
};
