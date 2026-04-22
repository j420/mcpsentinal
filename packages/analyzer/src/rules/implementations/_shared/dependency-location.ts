/**
 * Shared helpers for D/E rules that cite dependency locations.
 *
 * Lives in _shared because D1, D2, D4, D5, D6, D7 all need the same
 * ecosystem inference + RFC 6901 manifest pointer construction.
 * Extracted from d3-typosquatting conventions so every D-rule's
 * evidence chain cites the manifest the same way.
 *
 * No regex. Ecosystem inference is a hand-rolled prefix check.
 */

export type Ecosystem = "npm" | "pypi" | "go" | "rubygems" | "cargo";

/**
 * Infer the ecosystem from a bare package name.
 *
 * We prefer npm by default because that is the dominant MCP language
 * target; any call site with better information (auditor tags,
 * manifest path) should pass ecosystem in directly rather than call
 * this helper.
 */
export function inferEcosystem(name: string): Ecosystem {
  // Scoped packages `@x/y` are definitively npm.
  if (name.length > 0 && name.charCodeAt(0) === 0x40 /* @ */) return "npm";
  // Heuristic Python indicators — underscores are uncommon in npm and
  // very common in Python. A definitive check requires the manifest
  // filename, which the rule call site may override.
  if (hasUnderscore(name) && !hasDash(name)) return "pypi";
  return "npm";
}

function hasUnderscore(name: string): boolean {
  for (let i = 0; i < name.length; i++) {
    if (name.charCodeAt(i) === 0x5f /* _ */) return true;
  }
  return false;
}

function hasDash(name: string): boolean {
  for (let i = 0; i < name.length; i++) {
    if (name.charCodeAt(i) === 0x2d /* - */) return true;
  }
  return false;
}

/**
 * Build the RFC 6901 JSON pointer for a dependency entry in the
 * corresponding manifest format.
 */
export function jsonPointerForDep(ecosystem: Ecosystem, name: string): string {
  const escaped = escapeJsonPointerSegment(name);
  switch (ecosystem) {
    case "npm":
      return `/dependencies/${escaped}`;
    case "pypi":
      return `/project/dependencies/${escaped}`;
    case "go":
      return `/require/${escaped}`;
    case "rubygems":
      return `/dependencies/${escaped}`;
    case "cargo":
      return `/dependencies/${escaped}`;
  }
}

/** RFC 6901 segment escaping: '~' → '~0', '/' → '~1'. */
export function escapeJsonPointerSegment(segment: string): string {
  const chars: string[] = [];
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (ch === "~") chars.push("~0");
    else if (ch === "/") chars.push("~1");
    else chars.push(ch);
  }
  return chars.join("");
}

/**
 * Manifest file for a given ecosystem. Default npm manifest is
 * package.json; PyPI defaults to pyproject.toml.
 */
export function manifestFileFor(ecosystem: Ecosystem): string {
  switch (ecosystem) {
    case "npm":
      return "package.json";
    case "pypi":
      return "pyproject.toml";
    case "go":
      return "go.mod";
    case "rubygems":
      return "Gemfile";
    case "cargo":
      return "Cargo.toml";
  }
}
