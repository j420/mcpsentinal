/** Q10 evidence gathering — linguistic, AST-free. Zero regex. */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  MEMORY_SIGNALS,
  MITIGATION_ANCHORS,
  MITIGATION_QUALIFIERS,
  type MemorySignal,
  type MemorySignalClass,
} from "./data/memory-vocabulary.js";

export interface Token {
  readonly value: string;
  readonly start: number;
  readonly end: number;
}

export interface MatchedSignal {
  readonly id: string;
  readonly cls: MemorySignalClass;
  readonly matched_text: string;
  readonly weight: number;
  readonly desc: string;
}

export interface MemorySite {
  readonly tool_name: string;
  readonly description: string;
  readonly location: Location;
  readonly matched_signals: readonly MatchedSignal[];
  readonly has_mitigation: boolean;
}

function isWordChar(c: number): boolean {
  return (
    (c >= 0x30 && c <= 0x39) ||
    (c >= 0x41 && c <= 0x5a) ||
    (c >= 0x61 && c <= 0x7a) ||
    c === 0x5f
  );
}

function isWordCharOrHyphen(c: number): boolean {
  return isWordChar(c) || c === 0x2d;
}

export function tokenise(text: string): Token[] {
  const tokens: Token[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (isWordChar(text.charCodeAt(i))) {
      const start = i;
      while (i < n && isWordCharOrHyphen(text.charCodeAt(i))) i++;
      tokens.push({ value: text.slice(start, i).toLowerCase(), start, end: i });
    } else {
      i++;
    }
  }
  return tokens;
}

function tokenIn(token: string, list: readonly string[]): boolean {
  for (const e of list) {
    if (token === e) return true;
    // Plural-safe: allow trailing "s" or "es" on the list entry to match
    if (token === e + "s") return true;
    if (token === e + "es") return true;
  }
  return false;
}

export function matchSignals(tokens: readonly Token[]): MatchedSignal[] {
  const matches: MatchedSignal[] = [];
  const seen = new Set<string>();

  for (const entry of Object.entries(MEMORY_SIGNALS) as Array<[string, MemorySignal]>) {
    const id = entry[0];
    const signal = entry[1];
    if (seen.has(id)) continue;

    for (let i = 0; i < tokens.length; i++) {
      const anchor = tokens[i];
      if (!tokenIn(anchor.value, signal.anchor_tokens)) continue;

      if (signal.qualifier_tokens.length === 0) {
        seen.add(id);
        matches.push({
          id,
          cls: signal.cls,
          matched_text: anchor.value,
          weight: signal.weight,
          desc: signal.desc,
        });
        break;
      }

      const endIdx = Math.min(tokens.length - 1, i + signal.proximity);
      let matched = false;
      for (let j = i + 1; j <= endIdx; j++) {
        if (tokenIn(tokens[j].value, signal.qualifier_tokens)) {
          matched = true;
          seen.add(id);
          matches.push({
            id,
            cls: signal.cls,
            matched_text: `${anchor.value} ... ${tokens[j].value}`,
            weight: signal.weight,
            desc: signal.desc,
          });
          break;
        }
      }
      if (matched) break;
    }
  }

  return matches;
}

export function detectMitigation(tokens: readonly Token[]): boolean {
  // Direct anchor match: "read-only", "immutable", "append-only", "facts"
  for (const tok of tokens) {
    if (tokenIn(tok.value, MITIGATION_ANCHORS)) return true;
  }
  // "facts only" / "no instructions" — anchor + qualifier within 3
  for (let i = 0; i < tokens.length - 1; i++) {
    const tok = tokens[i];
    if (tok.value === "no") {
      const next = tokens[i + 1];
      if (next.value === "instructions" || next.value === "instruction") return true;
    }
    if (tok.value === "facts" || tok.value === "fact") {
      // "facts only" or "only facts"
      for (let j = Math.max(0, i - 1); j <= Math.min(tokens.length - 1, i + 2); j++) {
        if (tokens[j].value === "only") return true;
      }
    }
  }
  // Sanity: "sanitize/validate/filter before store"
  for (let i = 0; i < tokens.length - 2; i++) {
    const tok = tokens[i];
    if (tok.value === "sanitize" || tok.value === "validate" || tok.value === "filter") {
      for (let j = i + 1; j <= Math.min(tokens.length - 1, i + 4); j++) {
        if (tokenIn(tokens[j].value, MITIGATION_QUALIFIERS)) return true;
        if (tokens[j].value === "before" || tokens[j].value === "memory" || tokens[j].value === "store") {
          return true;
        }
      }
    }
  }
  return false;
}

export function gatherQ10(context: AnalysisContext): MemorySite[] {
  if (!context.tools || context.tools.length === 0) return [];
  const sites: MemorySite[] = [];

  for (const tool of context.tools) {
    const desc = tool.description ?? "";
    if (desc.length < 15) continue;

    const tokens = tokenise(desc);
    const matches = matchSignals(tokens);
    if (matches.length === 0) continue;

    const mitigation = detectMitigation(tokens);
    sites.push({
      tool_name: tool.name,
      description: desc,
      location: { kind: "tool", tool_name: tool.name },
      matched_signals: matches,
      has_mitigation: mitigation,
    });
  }
  return sites;
}
