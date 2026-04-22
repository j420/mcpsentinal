/**
 * A1 gather step — tokenised phrase matching over tool descriptions.
 *
 * Deterministic, character-level tokenisation (no regex). For each tool
 * the gatherer emits zero or more PhraseMatchSite records, one per
 * phrase hit, plus any LLM-special-token substring hits and JSON role
 * delimiter hits. The rule orchestrator aggregates these via noisy-OR
 * in `index.ts`.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  INJECTION_PHRASES,
  LLM_SPECIAL_TOKENS,
  ROLE_MARKERS,
  type PhraseSpec,
} from "./data/injection-phrases.js";

/** A hit emitted by the gatherer. */
export interface PhraseMatchSite {
  tool_name: string;
  /** Where in the description text the match begins (char offset). */
  offset: number;
  /** Length of the matched span in source characters. */
  length: number;
  /** The matched substring, length-capped at 160 chars. */
  observed: string;
  /** Independent probability weight for noisy-OR aggregation. */
  weight: number;
  /** Human-readable label (for evidence narrative). */
  label: string;
  /** "phrase" | "special-token" | "role-marker" — scan kind. */
  kind: "phrase" | "special-token" | "role-marker";
}

export interface A1Gathered {
  /** Map: tool name → every hit inside that tool's description. */
  byTool: Map<string, PhraseMatchSite[]>;
  /** All hits in order; convenient for aggregate reporting. */
  all: PhraseMatchSite[];
}

/**
 * Character-level tokeniser. Splits on non-alphanumeric characters,
 * preserving offsets. Returns an array of `Token { text, offset }`.
 */
interface Token {
  text: string;
  offset: number;
}

function tokenise(text: string): Token[] {
  const out: Token[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const cp = text.charCodeAt(i);
    if (isWordChar(cp)) {
      const start = i;
      let buf = "";
      while (i < n && isWordChar(text.charCodeAt(i))) {
        buf += lowerAscii(text.charCodeAt(i));
        i++;
      }
      out.push({ text: buf, offset: start });
    } else {
      i++;
    }
  }
  return out;
}

function isWordChar(cp: number): boolean {
  // a-z, A-Z, 0-9, underscore
  return (
    (cp >= 0x30 && cp <= 0x39) ||
    (cp >= 0x41 && cp <= 0x5a) ||
    (cp >= 0x61 && cp <= 0x7a) ||
    cp === 0x5f
  );
}

function lowerAscii(cp: number): string {
  if (cp >= 0x41 && cp <= 0x5a) return String.fromCharCode(cp + 32);
  return String.fromCharCode(cp);
}

/**
 * Find all occurrences of a `PhraseSpec` in the token stream. A match
 * occurs when the spec tokens appear in order with at most `max_gap`
 * intervening tokens between adjacent spec tokens.
 *
 * Emits one hit per starting match (greedy); overlaps allowed so the
 * noisy-OR aggregator can see every independent signal.
 */
function findPhrase(tokens: Token[], spec: PhraseSpec, textLen: number): Array<{ offset: number; length: number }> {
  const hits: Array<{ offset: number; length: number }> = [];
  const n = tokens.length;
  const k = spec.tokens.length;
  if (k === 0) return hits;

  for (let i = 0; i < n; i++) {
    if (tokens[i].text !== spec.tokens[0]) continue;
    let matchedIdx = i;
    let ok = true;
    for (let t = 1; t < k; t++) {
      let j = matchedIdx + 1;
      const limit = Math.min(n, j + spec.max_gap + 1);
      let found = -1;
      while (j < limit) {
        if (tokens[j].text === spec.tokens[t]) {
          found = j;
          break;
        }
        j++;
      }
      if (found < 0) {
        ok = false;
        break;
      }
      matchedIdx = found;
    }
    if (ok) {
      const start = tokens[i].offset;
      const endTok = tokens[matchedIdx];
      const end = endTok.offset + endTok.text.length;
      hits.push({ offset: start, length: Math.min(textLen - start, end - start) });
    }
  }
  return hits;
}

/**
 * Scan a description for every LLM special token via exact substring
 * search (case-sensitive because the tokens are codepoint shibboleths).
 */
function scanSpecialTokens(desc: string, toolName: string, out: PhraseMatchSite[]): void {
  for (const token of Object.keys(LLM_SPECIAL_TOKENS)) {
    let from = 0;
    while (true) {
      const idx = desc.indexOf(token, from);
      if (idx < 0) break;
      const meta = LLM_SPECIAL_TOKENS[token];
      out.push({
        tool_name: toolName,
        offset: idx,
        length: token.length,
        observed: token,
        weight: meta.weight,
        label: meta.label,
        kind: "special-token",
      });
      from = idx + token.length;
    }
  }
}

/**
 * Scan for JSON role-marker delimiter strings (case-sensitive —
 * the JSON role keys are canonical).
 */
function scanRoleMarkers(desc: string, toolName: string, out: PhraseMatchSite[]): void {
  for (const marker of Object.keys(ROLE_MARKERS)) {
    const idx = desc.indexOf(marker);
    if (idx < 0) continue;
    const meta = ROLE_MARKERS[marker];
    out.push({
      tool_name: toolName,
      offset: idx,
      length: marker.length,
      observed: marker,
      weight: meta.weight,
      label: meta.label,
      kind: "role-marker",
    });
  }
}

/**
 * Top-level gather. Iterates every tool in the context and emits all
 * phrase / special-token / role-marker hits.
 */
export function gatherA1(context: AnalysisContext): A1Gathered {
  const byTool = new Map<string, PhraseMatchSite[]>();
  const all: PhraseMatchSite[] = [];
  for (const tool of context.tools ?? []) {
    const desc = tool.description ?? "";
    if (desc.length < 10) continue;
    const hits: PhraseMatchSite[] = [];

    const tokens = tokenise(desc);
    for (const spec of INJECTION_PHRASES) {
      const matches = findPhrase(tokens, spec, desc.length);
      for (const m of matches) {
        const observed = desc.slice(m.offset, m.offset + m.length).slice(0, 160);
        hits.push({
          tool_name: tool.name,
          offset: m.offset,
          length: m.length,
          observed,
          weight: spec.weight,
          label: spec.label,
          kind: "phrase",
        });
      }
    }
    scanSpecialTokens(desc, tool.name, hits);
    scanRoleMarkers(desc, tool.name, hits);

    if (hits.length > 0) {
      byTool.set(tool.name, hits);
      all.push(...hits);
    }
  }
  return { byTool, all };
}

/** Build a structured `tool`-kind Location for a finding. */
export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
