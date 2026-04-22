/**
 * L10 evidence gathering — structural JSON walk + AST property-assignment walk.
 * Zero regex literals.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  PROTECTED_VENDORS,
  AUTHOR_FIELD_NAMES,
  AUTHOR_FIELD_EXTRA,
} from "./data/vendor-vocabulary.js";

const AUTHOR_FIELDS_SET: ReadonlySet<string> = new Set([
  ...AUTHOR_FIELD_NAMES,
  ...AUTHOR_FIELD_EXTRA,
]);
const VENDOR_NAMES_LC: ReadonlySet<string> = new Set(
  Object.keys(PROTECTED_VENDORS).map((v) => v.toLowerCase()),
);

export interface SpoofSite {
  readonly location: Location;
  readonly vendor: string;
  readonly field: string;
  readonly observed: string;
  readonly package_name: string | null;
}

/** Word-tokenise string value and return first protected vendor found. */
function findVendorInString(s: string): string | null {
  const lower = s.toLowerCase();
  let start = 0;
  for (let i = 0; i <= lower.length; i++) {
    const c = i === lower.length ? 0x20 : lower.charCodeAt(i);
    const isWord =
      (c >= 0x30 && c <= 0x39) ||
      (c >= 0x41 && c <= 0x5a) ||
      (c >= 0x61 && c <= 0x7a) ||
      c === 0x5f;
    if (!isWord) {
      if (i > start) {
        const tok = lower.slice(start, i);
        if (VENDOR_NAMES_LC.has(tok)) return tok;
      }
      start = i + 1;
    }
  }
  return null;
}

/** True if the package name already attests to a vendor (scoped @vendor/…). */
function packageAttestsVendor(pkgName: string | null, vendor: string): boolean {
  if (!pkgName) return false;
  const lower = pkgName.toLowerCase();
  if (lower.startsWith("@" + vendor + "/")) return true;
  if (lower === vendor) return true;
  return false;
}

function extractAuthorValue(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v === "string") return v;
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    if (typeof obj.name === "string") return obj.name;
  }
  return null;
}

export function gatherFromJson(
  parsed: unknown,
  file: string,
): SpoofSite[] {
  if (!parsed || typeof parsed !== "object") return [];
  const obj = parsed as Record<string, unknown>;
  const pkgName = typeof obj.name === "string" ? obj.name : null;
  const sites: SpoofSite[] = [];

  for (const [key, value] of Object.entries(obj)) {
    if (!AUTHOR_FIELDS_SET.has(key.toLowerCase())) continue;
    const strVal = extractAuthorValue(value);
    if (!strVal) continue;
    const vendor = findVendorInString(strVal);
    if (!vendor) continue;
    if (packageAttestsVendor(pkgName, vendor)) continue;
    sites.push({
      location: { kind: "config", file, json_pointer: `/${key}` },
      vendor,
      field: key,
      observed: strVal,
      package_name: pkgName,
    });
  }
  return sites;
}

export function gatherFromAst(source: string, file: string): SpoofSite[] {
  const sites: SpoofSite[] = [];
  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  } catch {
    return sites;
  }

  const visit = (node: ts.Node): void => {
    if (ts.isPropertyAssignment(node)) {
      const name = getPropNameText(node.name);
      if (name !== null && AUTHOR_FIELDS_SET.has(name.toLowerCase())) {
        if (ts.isStringLiteral(node.initializer)) {
          const value = node.initializer.text;
          const vendor = findVendorInString(value);
          if (vendor !== null) {
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            sites.push({
              location: { kind: "source", file, line },
              vendor,
              field: name,
              observed: value,
              package_name: null,
            });
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sf, visit);
  return sites;
}

function getPropNameText(n: ts.PropertyName): string | null {
  if (ts.isIdentifier(n)) return n.text;
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text;
  return null;
}

export function gatherL10(context: AnalysisContext): SpoofSite[] {
  const out: SpoofSite[] = [];
  const files = context.source_files ?? (context.source_code ? new Map([["scan.ts", context.source_code]]) : new Map());
  for (const [file, text] of files) {
    if (!text) continue;
    try {
      const parsed = JSON.parse(text);
      out.push(...gatherFromJson(parsed, file));
      continue;
    } catch {
      // not JSON — fall through
    }
    out.push(...gatherFromAst(text, file));
  }
  // Deduplicate per (location, vendor)
  const seen = new Set<string>();
  return out.filter((s) => {
    const key = `${renderLoc(s.location)}|${s.vendor}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function renderLoc(loc: Location): string {
  if (loc.kind === "config") return `${loc.file}${loc.json_pointer}`;
  if (loc.kind === "source") return `${loc.file}:${loc.line}`;
  return JSON.stringify(loc);
}
