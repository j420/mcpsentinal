/**
 * Q6 gather step — vendor-impersonation hits across source code
 * and tool descriptions.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  VENDOR_TOKENS,
  IDENTITY_PROPERTY_NAMES,
  VENDOR_PHRASES,
  type VendorPhraseSpec,
} from "./data/vocabulary.js";

const VENDOR_SET: ReadonlySet<string> = new Set(Object.keys(VENDOR_TOKENS));
const IDENTITY_PROP_SET: ReadonlySet<string> = new Set(Object.keys(IDENTITY_PROPERTY_NAMES));

export type ImpersonationSurface = "source-object-literal" | "tool-description";

export interface ImpersonationSite {
  surface: ImpersonationSurface;
  /** Vendor token that matched (lowercased). */
  vendor: string;
  /** Source-kind Location (for source sites) or tool Location (for tool sites). */
  location: Location;
  /** Human-readable label. */
  label: string;
  /** The raw observed fragment, length-capped. */
  observed: string;
  /** Weight used in aggregation (source sites = fixed, tool sites = from spec). */
  weight: number;
}

export interface Q6Gathered {
  sites: ImpersonationSite[];
  /** True when neither source code nor tool metadata were available. */
  noContextAvailable: boolean;
}

export function gatherQ6(context: AnalysisContext): Q6Gathered {
  const sites: ImpersonationSite[] = [];
  const haveSource = Boolean(context.source_code);
  const haveTools = context.tools && context.tools.length > 0;
  if (!haveSource && !haveTools) return { sites: [], noContextAvailable: true };

  if (context.source_code) scanSource(context.source_code, sites);
  if (haveTools) scanTools(context, sites);

  return { sites, noContextAvailable: false };
}

function scanSource(text: string, out: ImpersonationSite[]): void {
  const sf = ts.createSourceFile("<concatenated-source>", text, ts.ScriptTarget.Latest, true);

  ts.forEachChild(sf, function visit(node) {
    // Detect object-literal property assignments where the property
    // name is an identity field and the value is a string literal
    // containing a vendor token.
    if (ts.isPropertyAssignment(node)) {
      const propName = propertyName(node.name);
      if (propName && IDENTITY_PROP_SET.has(propName.toLowerCase())) {
        const valueText = stringLiteralValue(node.initializer);
        if (valueText) {
          const vendor = matchVendor(valueText);
          if (vendor) {
            out.push({
              surface: "source-object-literal",
              vendor,
              location: sourceLocation(sf, node),
              label: `self-declared ${VENDOR_TOKENS[vendor]} identity in ${propName}`,
              observed: valueText.slice(0, 160),
              weight: 0.85,
            });
          }
        } else {
          // nested object — recurse on its properties
          if (ts.isObjectLiteralExpression(node.initializer)) {
            for (const p of node.initializer.properties) {
              if (ts.isPropertyAssignment(p)) {
                const innerName = propertyName(p.name);
                if (innerName && innerName.toLowerCase() === "name") {
                  const v = stringLiteralValue(p.initializer);
                  if (v) {
                    const vendor = matchVendor(v);
                    if (vendor) {
                      out.push({
                        surface: "source-object-literal",
                        vendor,
                        location: sourceLocation(sf, p),
                        label: `self-declared ${VENDOR_TOKENS[vendor]} identity in ${propName}.name`,
                        observed: v.slice(0, 160),
                        weight: 0.85,
                      });
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  });
}

function scanTools(context: AnalysisContext, out: ImpersonationSite[]): void {
  for (const tool of context.tools ?? []) {
    const text = tool.description ?? "";
    if (text.length === 0) continue;
    const tokens = tokenise(text);
    if (tokens.length === 0) continue;

    for (const [specKey, spec] of Object.entries(VENDOR_PHRASES)) {
      void specKey;
      const hits = findPhrase(tokens, spec);
      for (const hit of hits) {
        const vendor = findVendorIn(spec.tokens);
        if (!vendor) continue;
        out.push({
          surface: "tool-description",
          vendor,
          location: { kind: "tool", tool_name: tool.name },
          label: spec.label,
          observed: text.slice(hit.startOffset, hit.endOffset + 1).slice(0, 160),
          weight: spec.weight,
        });
      }
    }
  }
}

function findVendorIn(tokens: readonly string[]): string | null {
  for (const t of tokens) {
    const low = t.toLowerCase();
    if (VENDOR_SET.has(low)) return low;
  }
  return null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function propertyName(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return null;
}

function stringLiteralValue(expr: ts.Expression): string | null {
  if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) return expr.text;
  return null;
}

function matchVendor(value: string): string | null {
  const low = value.toLowerCase();
  for (const v of VENDOR_SET) {
    if (low.includes(v)) return v;
  }
  return null;
}

function sourceLocation(sf: ts.SourceFile, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file: sf.fileName, line: line + 1, col: character + 1 };
}

// ─── Tokeniser + phrase matcher (shared with G2 pattern) ──────────────────

interface Tok {
  text: string;
  offset: number;
}

function isWord(cp: number): boolean {
  return (
    (cp >= 0x30 && cp <= 0x39) ||
    (cp >= 0x41 && cp <= 0x5a) ||
    (cp >= 0x61 && cp <= 0x7a) ||
    cp === 0x5f
  );
}

function tokenise(text: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < text.length) {
    const cp = text.charCodeAt(i);
    if (isWord(cp)) {
      const start = i;
      let buf = "";
      while (i < text.length && isWord(text.charCodeAt(i))) {
        const c = text.charCodeAt(i);
        buf += c >= 0x41 && c <= 0x5a ? String.fromCharCode(c + 32) : String.fromCharCode(c);
        i++;
      }
      out.push({ text: buf, offset: start });
    } else {
      i++;
    }
  }
  return out;
}

function findPhrase(
  tokens: Tok[],
  spec: VendorPhraseSpec,
): Array<{ startOffset: number; endOffset: number }> {
  const out: Array<{ startOffset: number; endOffset: number }> = [];
  const k = spec.tokens.length;
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].text !== spec.tokens[0].toLowerCase()) continue;
    let cursor = i;
    let ok = true;
    for (let t = 1; t < k; t++) {
      let j = cursor + 1;
      const limit = Math.min(tokens.length, j + 3);
      let found = -1;
      while (j < limit) {
        if (tokens[j].text === spec.tokens[t].toLowerCase()) {
          found = j;
          break;
        }
        j++;
      }
      if (found < 0) {
        ok = false;
        break;
      }
      cursor = found;
    }
    if (ok) {
      const startOffset = tokens[i].offset;
      const end = tokens[cursor];
      const endOffset = end.offset + end.text.length - 1;
      out.push({ startOffset, endOffset });
    }
  }
  return out;
}
