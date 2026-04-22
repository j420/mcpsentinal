/**
 * G5 gather step — tokenised prior-approval phrase matching.
 *
 * Deterministic, character-level tokenisation (NO regex, NO RegExp). For
 * each tool the gatherer emits zero or more PhraseMatchSite records,
 * one per phrase hit. The rule orchestrator aggregates these via
 * noisy-OR in `index.ts`.
 *
 * Suppression rule: a hit is only emitted when a permission-noun
 * (access / permission / scope / …) appears within ±8 tokens of the
 * matched phrase. Benign cross-references ("use alongside read_file")
 * don't have a permission noun adjacent and are therefore filtered out
 * at the gather step.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  PRIOR_APPROVAL_PHRASES,
  PERMISSION_NOUNS,
  type PhraseSpec,
  type PriorApprovalCategory,
} from "./data/prior-approval-phrases.js";

/** How far from the matched phrase we look for a permission noun. */
const PERMISSION_NOUN_WINDOW = 8;

/** Evidence hit emitted by the gatherer. */
export interface PhraseMatchSite {
  tool_name: string;
  /** Char offset where the matched phrase begins. */
  offset: number;
  /** Length of the matched span in source characters. */
  length: number;
  /** The matched substring, length-capped at 160 chars. */
  observed: string;
  /** Independent probability weight for noisy-OR aggregation. */
  weight: number;
  /** Human-readable label for evidence narrative. */
  label: string;
  /** Lethal edge-case category this spec belongs to. */
  category: PriorApprovalCategory;
  /** Lowercased permission noun observed inside the adjacency window. */
  nearby_permission_noun: string | null;
}

export interface G5Gathered {
  /** Map: tool name → every hit inside that tool's description. */
  byTool: Map<string, PhraseMatchSite[]>;
  /** All hits across all tools, in traversal order. */
  all: PhraseMatchSite[];
}

// ─── Character-level tokeniser (shared pattern with A1) ──────────────────────

interface Token {
  text: string;
  offset: number;
}

function isWordChar(cp: number): boolean {
  return (
    (cp >= 0x30 && cp <= 0x39) || // 0-9
    (cp >= 0x41 && cp <= 0x5a) || // A-Z
    (cp >= 0x61 && cp <= 0x7a) || // a-z
    cp === 0x5f // _
  );
}

function lowerAscii(cp: number): string {
  if (cp >= 0x41 && cp <= 0x5a) return String.fromCharCode(cp + 32);
  return String.fromCharCode(cp);
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

// ─── Phrase-match scanner ────────────────────────────────────────────────────

/**
 * Return every start-to-end token span where `spec.tokens` occur in order
 * with at most `spec.max_gap` intervening tokens between adjacent required
 * tokens. One span emitted per starting token match (overlaps are allowed
 * so the noisy-OR aggregator sees every independent signal).
 */
function findPhrase(
  tokens: Token[],
  spec: PhraseSpec,
): Array<{ start_tok: number; end_tok: number }> {
  const hits: Array<{ start_tok: number; end_tok: number }> = [];
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
    if (ok) hits.push({ start_tok: i, end_tok: matchedIdx });
  }
  return hits;
}

/**
 * Look for a permission noun in the token window surrounding a hit.
 * Returns the first match (lowercased) or null.
 */
function findPermissionNounInWindow(
  tokens: Token[],
  start_tok: number,
  end_tok: number,
): string | null {
  const lo = Math.max(0, start_tok - PERMISSION_NOUN_WINDOW);
  const hi = Math.min(tokens.length - 1, end_tok + PERMISSION_NOUN_WINDOW);
  for (let i = lo; i <= hi; i++) {
    const tok = tokens[i].text;
    if (PERMISSION_NOUNS[tok]) return tok;
  }
  return null;
}

// ─── Public entry point ──────────────────────────────────────────────────────

export function gatherG5(context: AnalysisContext): G5Gathered {
  const byTool = new Map<string, PhraseMatchSite[]>();
  const all: PhraseMatchSite[] = [];

  for (const tool of context.tools ?? []) {
    const desc = tool.description ?? "";
    if (desc.length < 10) continue;

    const tokens = tokenise(desc);
    if (tokens.length === 0) continue;

    const hits: PhraseMatchSite[] = [];

    for (const spec of PRIOR_APPROVAL_PHRASES) {
      const spans = findPhrase(tokens, spec);
      for (const span of spans) {
        const nearbyNoun = findPermissionNounInWindow(
          tokens,
          span.start_tok,
          span.end_tok,
        );
        // Suppression: every G5 category requires a permission noun in
        // the window. "Use alongside read_file" has no permission noun.
        if (!nearbyNoun) continue;

        const startChar = tokens[span.start_tok].offset;
        const endTok = tokens[span.end_tok];
        const endChar = endTok.offset + endTok.text.length;
        const observed = desc.slice(startChar, endChar).slice(0, 160);

        hits.push({
          tool_name: tool.name,
          offset: startChar,
          length: endChar - startChar,
          observed,
          weight: spec.weight,
          label: spec.label,
          category: spec.category,
          nearby_permission_noun: nearbyNoun,
        });
      }
    }

    if (hits.length > 0) {
      byTool.set(tool.name, hits);
      all.push(...hits);
    }
  }

  return { byTool, all };
}

/** Structured `tool`-kind Location for a finding. */
export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
