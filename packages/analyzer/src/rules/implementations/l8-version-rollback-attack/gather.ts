/**
 * L8 evidence gathering — structural JSON parsing + AST install-command walker.
 * Zero regex literals.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  PACKAGE_INSTALL_COMMANDS,
  OVERRIDE_SECTIONS,
  MCP_CRITICAL_PREFIXES,
} from "./data/rollback-vocabulary.js";

export interface RollbackSite {
  readonly kind: "json-override" | "install-command";
  readonly location: Location;
  readonly package_name: string;
  readonly version_spec: string;
  readonly is_mcp_critical: boolean;
  readonly section_or_line: string;
}

/** Lexically determine if a version spec pins to a "dangerous old" version.
 *  Handles "0.x", "1.0.x", "<=N", "<N", ">=0" (no upper bound is risky). */
export function looksOld(version: string): boolean {
  const v = version.trim();
  if (v.length === 0) return false;

  // Constraint comparators ("<=X", "<X")
  if (v.startsWith("<=") || (v.startsWith("<") && !v.startsWith("<="))) {
    return true;
  }

  // Strip leading non-digit markers ("^", "~", "=", "v")
  let start = 0;
  while (start < v.length) {
    const ch = v.charCodeAt(start);
    const isDigit = ch >= 0x30 && ch <= 0x39;
    if (isDigit) break;
    start++;
  }
  const core = v.slice(start);

  // Parse up to three numeric components separated by "."
  const parts = splitDot(core);
  if (parts.length === 0) return false;
  const major = toInt(parts[0]);
  const minor = parts.length > 1 ? toInt(parts[1]) : 0;
  if (major === null) return false;

  // Major 0 (pre-1.0) and minor < 99 → always dangerous
  if (major === 0) return true;
  // Major 1 with minor 0 → also dangerous for security-critical packages
  if (major === 1 && minor === 0) return true;
  return false;
}

function splitDot(s: string): string[] {
  const parts: string[] = [];
  let cur = "";
  for (const ch of s) {
    if (ch === ".") {
      parts.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.length > 0) parts.push(cur);
  return parts;
}

function toInt(s: string): number | null {
  let out = 0;
  let any = false;
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    if (c < 0x30 || c > 0x39) break;
    out = out * 10 + (c - 0x30);
    any = true;
  }
  return any ? out : null;
}

export function isMcpCritical(pkgName: string): boolean {
  const lower = pkgName.toLowerCase();
  for (const prefix of MCP_CRITICAL_PREFIXES) {
    if (lower.startsWith(prefix)) return true;
    if (lower.startsWith("@" + prefix)) return true;
  }
  return false;
}

/** Walk a parsed JSON object looking for override sections with old versions. */
export function gatherJsonOverrides(
  parsed: unknown,
  file: string,
): RollbackSite[] {
  const sites: RollbackSite[] = [];
  if (!parsed || typeof parsed !== "object") return sites;

  const obj = parsed as Record<string, unknown>;
  for (const section of OVERRIDE_SECTIONS) {
    const s = obj[section];
    if (s && typeof s === "object") {
      collectFromObject(s as Record<string, unknown>, section, file, sites);
    }
  }

  // pnpm.overrides
  const pnpm = obj["pnpm"];
  if (pnpm && typeof pnpm === "object") {
    const p = (pnpm as Record<string, unknown>)["overrides"];
    if (p && typeof p === "object") {
      collectFromObject(p as Record<string, unknown>, "pnpm.overrides", file, sites);
    }
  }

  return sites;
}

function collectFromObject(
  obj: Record<string, unknown>,
  section: string,
  file: string,
  out: RollbackSite[],
): void {
  for (const [pkg, value] of Object.entries(obj)) {
    const version = String(value);
    if (looksOld(version)) {
      out.push({
        kind: "json-override",
        location: { kind: "config", file, json_pointer: `/${section}/${pkg}` },
        package_name: pkg,
        version_spec: version,
        is_mcp_critical: isMcpCritical(pkg),
        section_or_line: section,
      });
    }
  }
}

/** Scan source-code string literals for `npm|pip|pnpm|yarn|brew install pkg@ver`. */
export function gatherInstallCommands(source: string, file: string): RollbackSite[] {
  const sites: RollbackSite[] = [];

  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  } catch {
    return sites;
  }

  const visit = (node: ts.Node): void => {
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node)
    ) {
      const text = node.text;
      const hit = parseInstallString(text);
      if (hit !== null) {
        const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
        sites.push({
          kind: "install-command",
          location: { kind: "source", file, line },
          package_name: hit.pkg,
          version_spec: hit.version,
          is_mcp_critical: isMcpCritical(hit.pkg),
          section_or_line: `line ${line}`,
        });
      }
    }
    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sf, visit);
  return sites;
}

/** Parse a string like "npm install foo@0.1.0" — zero regex. */
export function parseInstallString(text: string): { pkg: string; version: string } | null {
  // Quick reject: must contain an install verb
  const lower = text.toLowerCase();
  let mgrKind: string | null = null;
  let verb = "";
  for (const [name, spec] of Object.entries(PACKAGE_INSTALL_COMMANDS)) {
    const phrase = name + " " + spec.install_verb;
    if (lower.includes(phrase)) {
      mgrKind = name;
      verb = phrase;
      break;
    }
  }
  if (mgrKind === null) return null;

  const spec = PACKAGE_INSTALL_COMMANDS[mgrKind]!;

  // Find the token after the install verb
  const idx = lower.indexOf(verb);
  const afterVerb = text.slice(idx + verb.length).trimStart();
  // Next token = package spec up to whitespace
  let j = 0;
  while (j < afterVerb.length) {
    const ch = afterVerb.charCodeAt(j);
    if (ch === 0x20 || ch === 0x09 || ch === 0x0a || ch === 0x0d) break;
    j++;
  }
  const pkgSpec = afterVerb.slice(0, j);
  if (pkgSpec.length === 0) return null;

  // Split on separator (@ for npm/pnpm/yarn/brew; == for pip)
  const sep = spec.pin_separator;
  // For npm-style, skip the leading "@" of a scoped package when finding sep
  let searchFrom = 0;
  if (pkgSpec.startsWith("@")) searchFrom = 1;
  const sepIdx = pkgSpec.indexOf(sep, searchFrom);
  if (sepIdx < 0) return null;

  const pkg = pkgSpec.slice(0, sepIdx);
  const version = pkgSpec.slice(sepIdx + sep.length);
  if (!pkg || !version) return null;

  if (!looksOld(version)) return null;

  return { pkg, version };
}

export function gatherL8(context: AnalysisContext): RollbackSite[] {
  const out: RollbackSite[] = [];
  const sourceFiles = context.source_files ?? (context.source_code ? new Map([["scan.ts", context.source_code]]) : new Map());

  for (const [file, text] of sourceFiles) {
    // Try JSON parse (package.json)
    try {
      const parsed = JSON.parse(text);
      out.push(...gatherJsonOverrides(parsed, file));
    } catch {
      // not JSON — fall through
    }
    // Always scan install commands in string literals
    out.push(...gatherInstallCommands(text, file));
  }

  return out;
}
