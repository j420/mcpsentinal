/**
 * L8 version-rollback vocabulary.
 *
 * Typed records replacing the 4 regex literals (two version patterns, one
 * MCP-critical prefix pattern, one override-prop pattern) in the legacy
 * detector.
 */

export interface PackageManagerSpec {
  readonly kind: "npm" | "pip" | "pnpm" | "yarn" | "brew";
  readonly install_verb: string;
  readonly pin_separator: string; // '@' for npm, '==' for pip, '@' for pnpm/yarn
}

export const PACKAGE_INSTALL_COMMANDS: Readonly<Record<string, PackageManagerSpec>> = {
  npm: { kind: "npm", install_verb: "install", pin_separator: "@" },
  pip: { kind: "pip", install_verb: "install", pin_separator: "==" },
  pnpm: { kind: "pnpm", install_verb: "add", pin_separator: "@" },
  yarn: { kind: "yarn", install_verb: "add", pin_separator: "@" },
  brew: { kind: "brew", install_verb: "install", pin_separator: "@" },
};

/** package.json / pnpm-workspace override sections the rule inspects. */
export const OVERRIDE_SECTIONS: readonly string[] = [
  "overrides",
  "resolutions",
];

/** MCP-critical prefixes — case-insensitive prefix match on package names.
 *  Rolling back any of these is strictly more dangerous than other rollbacks. */
export const MCP_CRITICAL_PREFIXES: readonly string[] = [
  "mcp",
  "modelcontextprotocol",
  "fastmcp",
  "anthropic",
  "openai",
];
