/**
 * G3 gather step — tokenised protocol-mimic phrase matching +
 * structural JSON-RPC envelope detection on tool descriptions.
 *
 * Two parallel walks:
 *
 *   1. `G3_PROTOCOL_MIMICS` — prose phrases like "returns JSON-RPC
 *      messages", using a WORD tokeniser (same as A1/B5/G2).
 *
 *   2. `G3_JSONRPC_SHAPES` — literal envelope fragments like
 *      `{"jsonrpc":"2.0"`, using a JSON-AWARE tokeniser that
 *      preserves punctuation (`{`, `}`, `:`, quoted strings) as
 *      individual tokens. This detects the envelope as an ordered
 *      token subsequence without any regex.
 *
 * Every emitted `MimicSite` carries a structured `tool` Location.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  G3_PROTOCOL_MIMICS,
  G3_JSONRPC_SHAPES,
  type PhraseSpec,
} from "../_shared/ai-manipulation-phrases.js";
import { FENCE_DEMOTION } from "./data/g3-scoring.js";

export type MimicKind = "prose_mimic" | "jsonrpc_shape";

export interface MimicSite {
  tool_name: string;
  phrase_id: string;
  kind: MimicKind;
  offset: number;
  length: number;
  observed: string;
  weight: number;
  effective_weight: number;
  fence_triggered: boolean;
  label: string;
  spec_kind: PhraseSpec["kind"];
}

export interface G3Gathered {
  byTool: Map<string, MimicSite[]>;
  all: MimicSite[];
}

// ─── Word tokeniser (for prose phrases) ─────────────────────────────────────

interface WordToken {
  text: string;
  offset: number;
}

function tokeniseWords(text: string): WordToken[] {
  const out: WordToken[] = [];
  let i = 0;
  while (i < text.length) {
    const cp = text.charCodeAt(i);
    if (isWord(cp)) {
      const start = i;
      let buf = "";
      while (i < text.length && isWord(text.charCodeAt(i))) {
        buf += lower(text.charCodeAt(i));
        i++;
      }
      out.push({ text: buf, offset: start });
    } else {
      i++;
    }
  }
  return out;
}

function isWord(cp: number): boolean {
  return (
    (cp >= 0x30 && cp <= 0x39) ||
    (cp >= 0x41 && cp <= 0x5a) ||
    (cp >= 0x61 && cp <= 0x7a) ||
    cp === 0x5f
  );
}

function lower(cp: number): string {
  if (cp >= 0x41 && cp <= 0x5a) return String.fromCharCode(cp + 32);
  return String.fromCharCode(cp);
}

// ─── JSON-aware tokeniser (for envelope detection) ──────────────────────────

interface JsonToken {
  text: string;
  offset: number;
}

/**
 * Tokeniser for structural JSON-like text. Emits:
 *   - single-char structural tokens: { } [ ] : , "
 *   - quoted strings as `"contents"` with surrounding quotes preserved
 *   - bare bareword runs (letters/digits) lowercased
 *
 * Whitespace is skipped. The emitted token stream lets us detect a
 * sequence like `{ "jsonrpc" : "2 0"` as an ordered subsequence of
 * individual tokens (≤5) without a regex.
 */
function tokeniseJson(text: string): JsonToken[] {
  const out: JsonToken[] = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text.charAt(i);
    const code = text.charCodeAt(i);
    // Skip ASCII whitespace.
    if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) {
      i++;
      continue;
    }
    // Structural tokens.
    if (c === "{" || c === "}" || c === "[" || c === "]" || c === ":" || c === ",") {
      out.push({ text: c, offset: i });
      i++;
      continue;
    }
    // Double-quoted string: consume until the closing quote.
    if (c === '"') {
      const start = i;
      i++;
      let buf = '"';
      while (i < n) {
        const cc = text.charAt(i);
        buf += cc.toLowerCase();
        i++;
        if (cc === '"') break;
      }
      out.push({ text: buf, offset: start });
      continue;
    }
    // Bareword: letters / digits / _ / - / . — everything else ends the run.
    if (
      (code >= 0x30 && code <= 0x39) ||
      (code >= 0x41 && code <= 0x5a) ||
      (code >= 0x61 && code <= 0x7a) ||
      code === 0x5f ||
      code === 0x2e ||
      code === 0x2d
    ) {
      const start = i;
      let buf = "";
      while (i < n) {
        const cc = text.charCodeAt(i);
        if (
          (cc >= 0x30 && cc <= 0x39) ||
          (cc >= 0x41 && cc <= 0x5a) ||
          (cc >= 0x61 && cc <= 0x7a) ||
          cc === 0x5f ||
          cc === 0x2e ||
          cc === 0x2d
        ) {
          buf += lower(cc);
          i++;
        } else {
          break;
        }
      }
      out.push({ text: buf, offset: start });
      continue;
    }
    i++;
  }
  return out;
}

// ─── Ordered phrase matcher (shared) ────────────────────────────────────────

/**
 * Find every ordered subsequence match of `spec.phrase_tokens` in
 * `tokens`, with at most `spec.max_gap` intervening tokens between
 * adjacent matched tokens. Token comparison is case-insensitive on
 * the spec side (specs are stored lowercase — matching the
 * tokenisers' output).
 */
function findOrdered(
  tokens: ReadonlyArray<{ text: string; offset: number }>,
  spec: PhraseSpec,
  textLen: number,
): Array<{ offset: number; length: number }> {
  const hits: Array<{ offset: number; length: number }> = [];
  const k = spec.phrase_tokens.length;
  if (k === 0) return hits;
  const first = spec.phrase_tokens[0].toLowerCase();
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].text !== first) continue;
    let matchedIdx = i;
    let ok = true;
    for (let t = 1; t < k; t++) {
      const target = spec.phrase_tokens[t].toLowerCase();
      let j = matchedIdx + 1;
      const limit = Math.min(tokens.length, j + spec.max_gap + 1);
      let found = -1;
      while (j < limit) {
        if (tokens[j].text === target) {
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
 * Fence-token detection uses the WORD tokeniser (all fence tokens
 * are barewords like "documentation", "educational", "explains").
 */
function fenceTriggered(
  wordTokens: ReadonlyArray<WordToken>,
  fence: ReadonlyArray<string>,
): boolean {
  if (fence.length === 0) return false;
  const seen = new Set<string>();
  for (const t of wordTokens) seen.add(t.text);
  for (const f of fence) {
    if (seen.has(f)) return true;
  }
  return false;
}

// ─── Top-level gather ───────────────────────────────────────────────────────

function scanTool(tool_name: string, desc: string): MimicSite[] {
  if (desc.length < 6) return [];
  const words = tokeniseWords(desc);
  const json = tokeniseJson(desc);
  const sites: MimicSite[] = [];

  const mimicCatalogue = G3_PROTOCOL_MIMICS as Readonly<Record<string, PhraseSpec>>;
  for (const phrase_id of Object.keys(mimicCatalogue)) {
    const spec = mimicCatalogue[phrase_id];
    const hits = findOrdered(words, spec, desc.length);
    if (hits.length === 0) continue;
    const fence = fenceTriggered(words, spec.false_positive_fence);
    for (const h of hits) {
      const observed = desc.slice(h.offset, h.offset + h.length).slice(0, 160);
      const effective_weight = fence ? spec.weight * FENCE_DEMOTION : spec.weight;
      sites.push({
        tool_name,
        phrase_id,
        kind: "prose_mimic",
        offset: h.offset,
        length: h.length,
        observed,
        weight: spec.weight,
        effective_weight,
        fence_triggered: fence,
        label: spec.label,
        spec_kind: spec.kind,
      });
    }
  }

  const shapeCatalogue = G3_JSONRPC_SHAPES as Readonly<Record<string, PhraseSpec>>;
  for (const phrase_id of Object.keys(shapeCatalogue)) {
    const spec = shapeCatalogue[phrase_id];
    const hits = findOrdered(json, spec, desc.length);
    if (hits.length === 0) continue;
    const fence = fenceTriggered(words, spec.false_positive_fence);
    for (const h of hits) {
      const observed = desc.slice(h.offset, h.offset + h.length).slice(0, 160);
      const effective_weight = fence ? spec.weight * FENCE_DEMOTION : spec.weight;
      sites.push({
        tool_name,
        phrase_id,
        kind: "jsonrpc_shape",
        offset: h.offset,
        length: h.length,
        observed,
        weight: spec.weight,
        effective_weight,
        fence_triggered: fence,
        label: spec.label,
        spec_kind: spec.kind,
      });
    }
  }

  return sites;
}

export function gatherG3(context: AnalysisContext): G3Gathered {
  const byTool = new Map<string, MimicSite[]>();
  const all: MimicSite[] = [];
  for (const tool of context.tools ?? []) {
    const desc = tool.description ?? "";
    const sites = scanTool(tool.name, desc);
    if (sites.length > 0) {
      byTool.set(tool.name, sites);
      all.push(...sites);
    }
  }
  return { byTool, all };
}

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
