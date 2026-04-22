/**
 * N5 gather — line-level scan for capability-declaration ↔ handler-
 * registration mismatches. Uses the shared MCP method catalogue.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  CAPABILITY_KEY_TO_METHODS,
  getSpecMethod,
} from "../_shared/mcp-method-catalogue.js";
import {
  HANDLER_REGISTRATION_FRAGMENTS,
  CAPABILITY_DECLARATION_FRAGMENTS,
  DOWNGRADE_VALUES,
} from "./data/n5-config.js";

export interface DeclarationSite {
  location: Location;
  line: number;
  line_text: string;
  /** The capability key (e.g. "tools", "sampling"). */
  capability_key: string;
  downgrade_label: string;
}

export interface HandlerSite {
  location: Location;
  line: number;
  line_text: string;
  registration_label: string;
  /** The method literal that was found on the line (e.g. "tools/call"). */
  method: string;
  /** The capability key this method belongs to. */
  capability_key: string;
}

export interface Mismatch {
  capability_key: string;
  declaration: DeclarationSite;
  handler: HandlerSite;
}

export interface N5Gathered {
  mismatches: Mismatch[];
}

function findDowngradedKey(lineLc: string): { key: string; label: string } | null {
  for (const capKey of Object.keys(CAPABILITY_KEY_TO_METHODS)) {
    const keyIdx = lineLc.indexOf(capKey);
    if (keyIdx === -1) continue;
    // The downgrade value must appear AFTER the key on the same line.
    const tail = lineLc.slice(keyIdx);
    for (const [v, label] of Object.entries(DOWNGRADE_VALUES)) {
      if (tail.indexOf(v) !== -1) {
        return { key: capKey, label };
      }
    }
  }
  return null;
}

function findMethodLiteral(
  lineLc: string,
): { method: string; capability_key: string } | null {
  // Scan for a spec-method literal in the line. `lineLc` is lower-cased,
  // so compare against the lower-case form of each canonical method key.
  for (const [capKey, methods] of Object.entries(CAPABILITY_KEY_TO_METHODS)) {
    for (const m of methods) {
      if (lineLc.indexOf(m.toLowerCase()) !== -1) {
        if (getSpecMethod(m)) return { method: m, capability_key: capKey };
      }
    }
  }
  return null;
}

export function gatherN5(context: AnalysisContext): N5Gathered {
  const source = context.source_code;
  if (!source) return { mismatches: [] };
  const lcSrc = source.toLowerCase();
  if (lcSrc.indexOf("__tests__") !== -1 || lcSrc.indexOf(".test.") !== -1)
    return { mismatches: [] };

  const lines = source.split("\n");
  const declKeys = Object.keys(CAPABILITY_DECLARATION_FRAGMENTS);
  const handlerKeys = Object.keys(HANDLER_REGISTRATION_FRAGMENTS);

  const declarations: DeclarationSite[] = [];
  const handlers: HandlerSite[] = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const lc = raw.toLowerCase();

    const hasDeclFrag = declKeys.some((k) => lc.indexOf(k) !== -1);
    if (hasDeclFrag) {
      // Look in this line AND up to 6 lines ahead for key:false shapes.
      // This handles multi-line `capabilities: { tools: false, ... }`.
      const windowEnd = Math.min(lines.length - 1, i + 6);
      for (let j = i; j <= windowEnd; j++) {
        const dec = findDowngradedKey(lines[j].toLowerCase());
        if (dec) {
          declarations.push({
            location: { kind: "source", file: "<aggregated>", line: j + 1 },
            line: j + 1,
            line_text: lines[j].trim().slice(0, 160),
            capability_key: dec.key,
            downgrade_label: dec.label,
          });
        }
      }
    }

    const hasHandlerFrag = handlerKeys.some((k) => lc.indexOf(k) !== -1);
    if (hasHandlerFrag) {
      const m = findMethodLiteral(lc);
      if (m) {
        handlers.push({
          location: { kind: "source", file: "<aggregated>", line: i + 1 },
          line: i + 1,
          line_text: raw.trim().slice(0, 160),
          registration_label:
            HANDLER_REGISTRATION_FRAGMENTS[
              handlerKeys.find((k) => lc.indexOf(k) !== -1) as string
            ],
          method: m.method,
          capability_key: m.capability_key,
        });
      }
    }
  }

  // Pair each declaration with any handler for the same capability key.
  const mismatches: Mismatch[] = [];
  const seen = new Set<string>();
  for (const d of declarations) {
    for (const h of handlers) {
      if (d.capability_key !== h.capability_key) continue;
      const key = `${d.line}:${h.line}:${d.capability_key}`;
      if (seen.has(key)) continue;
      seen.add(key);
      mismatches.push({
        capability_key: d.capability_key,
        declaration: d,
        handler: h,
      });
    }
  }
  return { mismatches };
}
