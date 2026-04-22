/**
 * M4 evidence gathering — deterministic linguistic analysis.
 *
 * No regex literals. No string arrays > 5. The tokeniser walks the
 * description character-by-character, splitting on non-word boundaries.
 *
 * The gather step produces a flat list of `SquatSite` objects — one per
 * tool whose description carries at least one signal. `index.ts` consumes
 * this list and builds the evidence chain.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  SQUATTING_SIGNALS,
  NEGATION_TOKENS,
  NEGATION_PREFIXES,
  type SquatSignal,
  type SquatSignalClass,
} from "./data/squatting-vocabulary.js";

export interface Token {
  readonly value: string;
  readonly start: number;
  readonly end: number;
}

export interface MatchedSignal {
  readonly id: string;
  readonly cls: SquatSignalClass;
  readonly anchor_index: number;
  readonly qualifier_index: number;
  readonly matched_text: string;
  readonly weight: number;
  readonly desc: string;
}

export interface SquatSite {
  readonly tool_name: string;
  readonly description: string;
  readonly location: Location;
  readonly matched_signals: readonly MatchedSignal[];
  readonly has_negation: boolean;
  readonly bare_vendor_token: string | null;
}

// ─── Vendor catalogue (derived from vendor-attribution signals) ──────────────

const VENDOR_TOKENS: ReadonlySet<string> = new Set(
  Object.values(SQUATTING_SIGNALS)
    .filter((s) => s.cls === "vendor-attribution")
    .flatMap((s) => s.qualifier_tokens),
);

const NEGATION_TOKEN_SET: ReadonlySet<string> = new Set(NEGATION_TOKENS);

// ─── Tokeniser ───────────────────────────────────────────────────────────────

export function tokenise(text: string): Token[] {
  const tokens: Token[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const code = text.charCodeAt(i);
    if (isWordChar(code)) {
      const start = i;
      while (i < n && isWordCharOrHyphen(text.charCodeAt(i))) i++;
      const end = i;
      tokens.push({
        value: text.slice(start, end).toLowerCase(),
        start,
        end,
      });
    } else {
      i++;
    }
  }
  return tokens;
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

// ─── Signal matching ─────────────────────────────────────────────────────────

function tokenMatchesAnchor(token: string, anchors: readonly string[]): boolean {
  if (anchors.length === 0) return false;
  for (const a of anchors) {
    if (token === a) return true;
  }
  return false;
}

function tokenMatchesQualifier(
  token: string,
  qualifiers: readonly string[],
): boolean {
  if (qualifiers.length === 0) return false;
  for (const q of qualifiers) {
    if (token === q) return true;
  }
  return false;
}

export function matchSignals(tokens: readonly Token[]): MatchedSignal[] {
  const matches: MatchedSignal[] = [];

  for (const entry of Object.entries(SQUATTING_SIGNALS) as Array<
    [string, SquatSignal]
  >) {
    const id = entry[0];
    const signal = entry[1];

    for (let i = 0; i < tokens.length; i++) {
      const anchor = tokens[i];
      if (!tokenMatchesAnchor(anchor.value, signal.anchor_tokens)) continue;

      if (signal.qualifier_tokens.length === 0) {
        matches.push({
          id,
          cls: signal.cls,
          anchor_index: i,
          qualifier_index: -1,
          matched_text: anchor.value,
          weight: signal.weight,
          desc: signal.desc,
        });
        continue;
      }

      const endIdx = Math.min(tokens.length - 1, i + signal.proximity);
      for (let j = i + 1; j <= endIdx; j++) {
        if (tokenMatchesQualifier(tokens[j].value, signal.qualifier_tokens)) {
          matches.push({
            id,
            cls: signal.cls,
            anchor_index: i,
            qualifier_index: j,
            matched_text: `${anchor.value} ... ${tokens[j].value}`,
            weight: signal.weight,
            desc: signal.desc,
          });
          break;
        }
      }
    }
  }

  return matches;
}

export function detectNegation(
  tokens: readonly Token[],
  matches: readonly MatchedSignal[],
): boolean {
  for (const m of matches) {
    const start = Math.max(0, m.anchor_index - 3);
    for (let k = start; k < m.anchor_index; k++) {
      if (NEGATION_TOKEN_SET.has(tokens[k].value)) return true;
    }
  }
  for (const signal of Object.values(SQUATTING_SIGNALS)) {
    for (const a of signal.anchor_tokens) {
      for (const prefix of NEGATION_PREFIXES) {
        const expected = prefix + a;
        for (const tok of tokens) {
          if (tok.value === expected) return true;
        }
      }
    }
  }
  return false;
}

export function detectBareVendor(
  tokens: readonly Token[],
  matches: readonly MatchedSignal[],
): string | null {
  if (tokens.length === 0) return null;
  if (matches.some((m) => m.cls === "vendor-attribution")) return null;

  const first = tokens[0].value;
  if (VENDOR_TOKENS.has(first)) return first;

  if (tokens.length >= 2 && (first === "the" || first === "a" || first === "an")) {
    if (VENDOR_TOKENS.has(tokens[1].value)) return tokens[1].value;
  }
  return null;
}

export function gatherM4(context: AnalysisContext): SquatSite[] {
  if (!context.tools || context.tools.length === 0) return [];
  const sites: SquatSite[] = [];

  for (const tool of context.tools) {
    const desc = tool.description ?? "";
    if (desc.length < 10) continue;

    const tokens = tokenise(desc);
    if (tokens.length === 0) continue;

    const matches = matchSignals(tokens);
    const bareVendor = detectBareVendor(tokens, matches);
    if (matches.length === 0 && bareVendor === null) continue;

    const negation = detectNegation(tokens, matches);

    sites.push({
      tool_name: tool.name,
      description: desc,
      location: { kind: "tool", tool_name: tool.name },
      matched_signals: matches,
      has_negation: negation,
      bare_vendor_token: bareVendor,
    });
  }

  return sites;
}
