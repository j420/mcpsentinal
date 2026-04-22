/**
 * G2 gather step — tokenised authority-phrase matching over tool
 * descriptions AND server initialize.instructions.
 *
 * Deterministic, character-level tokenisation (mirrors A1). For each
 * tool description and, if present, the initialize.instructions
 * field, the gatherer walks the G2_AUTHORITY_CLAIMS catalogue and
 * emits one `AuthoritySite` per match. A per-entry
 * `false_positive_fence` demotes the weight when legitimacy tokens
 * co-occur.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  G2_AUTHORITY_CLAIMS,
  type PhraseSpec,
} from "../_shared/ai-manipulation-phrases.js";
import { FENCE_DEMOTION } from "./data/g2-scoring.js";

/** Where the authority phrase was found. */
export type AuthoritySurface = "tool_description" | "initialize_instructions";

export interface AuthoritySite {
  surface: AuthoritySurface;
  /** Present when surface is "tool_description". */
  tool_name: string | null;
  /** Phrase id (catalogue key). */
  phrase_id: string;
  offset: number;
  length: number;
  observed: string;
  weight: number;
  effective_weight: number;
  fence_triggered: boolean;
  label: string;
  kind: PhraseSpec["kind"];
}

export interface G2Gathered {
  /** Key = `tool::<name>` or `initialize::instructions`. */
  byScope: Map<string, AuthoritySite[]>;
  all: AuthoritySite[];
}

interface Token {
  text: string;
  offset: number;
}

function tokenise(text: string): Token[] {
  const out: Token[] = [];
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

/** Find all matches of a `PhraseSpec`'s ordered token sequence in the tokens. */
function findPhrase(
  tokens: Token[],
  spec: PhraseSpec,
  textLen: number,
): Array<{ offset: number; length: number }> {
  const hits: Array<{ offset: number; length: number }> = [];
  const k = spec.phrase_tokens.length;
  if (k === 0) return hits;
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].text !== spec.phrase_tokens[0]) continue;
    let matchedIdx = i;
    let ok = true;
    for (let t = 1; t < k; t++) {
      let j = matchedIdx + 1;
      const limit = Math.min(tokens.length, j + spec.max_gap + 1);
      let found = -1;
      while (j < limit) {
        if (tokens[j].text === spec.phrase_tokens[t]) {
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

/** True if any fence token appears in the tokenised description. */
function fenceTriggered(tokens: Token[], fence: ReadonlyArray<string>): boolean {
  if (fence.length === 0) return false;
  const seen = new Set<string>();
  for (const t of tokens) seen.add(t.text);
  for (const f of fence) {
    if (seen.has(f)) return true;
  }
  return false;
}

/**
 * Scan a single text block for every catalogue entry; emit hits.
 */
function scanBlock(
  text: string,
  surface: AuthoritySurface,
  tool_name: string | null,
): AuthoritySite[] {
  if (text.length < 6) return [];
  const tokens = tokenise(text);
  const sites: AuthoritySite[] = [];
  const catalogue = G2_AUTHORITY_CLAIMS as Readonly<Record<string, PhraseSpec>>;
  for (const phrase_id of Object.keys(catalogue)) {
    const spec = catalogue[phrase_id];
    const hits = findPhrase(tokens, spec, text.length);
    if (hits.length === 0) continue;
    const fence = fenceTriggered(tokens, spec.false_positive_fence);
    for (const h of hits) {
      const observed = text.slice(h.offset, h.offset + h.length).slice(0, 160);
      const effective_weight = fence ? spec.weight * FENCE_DEMOTION : spec.weight;
      sites.push({
        surface,
        tool_name,
        phrase_id,
        offset: h.offset,
        length: h.length,
        observed,
        weight: spec.weight,
        effective_weight,
        fence_triggered: fence,
        label: spec.label,
        kind: spec.kind,
      });
    }
  }
  return sites;
}

/**
 * Top-level gather. Walks every tool description and the
 * initialize.instructions field if populated.
 */
export function gatherG2(context: AnalysisContext): G2Gathered {
  const byScope = new Map<string, AuthoritySite[]>();
  const all: AuthoritySite[] = [];

  for (const tool of context.tools ?? []) {
    const desc = tool.description ?? "";
    const hits = scanBlock(desc, "tool_description", tool.name);
    if (hits.length > 0) {
      byScope.set(`tool::${tool.name}`, hits);
      all.push(...hits);
    }
  }

  const instructions = context.initialize_metadata?.server_instructions ?? null;
  if (instructions) {
    const hits = scanBlock(instructions, "initialize_instructions", null);
    if (hits.length > 0) {
      byScope.set("initialize::instructions", hits);
      all.push(...hits);
    }
  }

  return { byScope, all };
}

/** Build a structured Location for a site. */
export function siteLocation(site: AuthoritySite): Location {
  if (site.surface === "initialize_instructions") {
    return { kind: "initialize", field: "instructions" };
  }
  // Fallback: tool scope. `tool_name` is non-null for tool_description.
  return { kind: "tool", tool_name: site.tool_name ?? "<unknown>" };
}
