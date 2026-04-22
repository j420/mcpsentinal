/**
 * I3 gather — tokenised injection-phrase matcher over resource
 * metadata (name + description + URI). Uses the shared
 * INJECTION_PHRASES catalogue.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  INJECTION_PHRASES,
  type InjectionPhraseSpec,
} from "../_shared/protocol-shape-catalogue.js";
import { I3_MAX_GAP_TOKENS, I3_MIN_AGGREGATE_WEIGHT } from "./data/config.js";

export interface I3PhraseHit {
  key: string;
  spec: InjectionPhraseSpec;
  matched_field: "name" | "description" | "uri" | "combined";
}

export interface I3Fact {
  resource_uri: string;
  resource_name: string;
  resource_description: string | null;
  hits: I3PhraseHit[];
  aggregate_weight: number;
  combined_text_preview: string;
}

export interface I3GatherResult {
  facts: I3Fact[];
}

export function gatherI3(context: AnalysisContext): I3GatherResult {
  const facts: I3Fact[] = [];
  const resources = context.resources;
  if (!resources || resources.length === 0) return { facts };

  for (const resource of resources) {
    const name = resource.name ?? "";
    const desc = resource.description ?? "";
    const uri = resource.uri ?? "";
    const combined = `${name} ${desc} ${uri}`;

    const nameTokens = tokenise(name);
    const descTokens = tokenise(desc);
    const uriTokens = tokenise(uri);
    const combinedTokens = tokenise(combined);

    const hits: I3PhraseHit[] = [];
    for (const [key, spec] of Object.entries(INJECTION_PHRASES)) {
      if (matchPhrase(nameTokens, spec)) {
        hits.push({ key, spec, matched_field: "name" });
        continue;
      }
      if (matchPhrase(descTokens, spec)) {
        hits.push({ key, spec, matched_field: "description" });
        continue;
      }
      if (matchPhrase(uriTokens, spec)) {
        hits.push({ key, spec, matched_field: "uri" });
        continue;
      }
      if (matchPhrase(combinedTokens, spec)) {
        hits.push({ key, spec, matched_field: "combined" });
      }
    }

    if (hits.length === 0) continue;
    const aggregate = noisyOr(hits.map((h) => h.spec.weight));
    if (aggregate < I3_MIN_AGGREGATE_WEIGHT) continue;

    facts.push({
      resource_uri: uri,
      resource_name: name,
      resource_description: desc || null,
      hits,
      aggregate_weight: aggregate,
      combined_text_preview: combined.slice(0, 160),
    });
  }
  return { facts };
}

function tokenise(text: string): string[] {
  // Lowercase, replace non-word with spaces, preserve delimiter tokens like
  // <|system|> as-is (they contain angle brackets and pipes).
  // We emit delimiter tokens as single tokens when present.
  const out: string[] = [];
  const lowered = text.toLowerCase();
  let i = 0;
  while (i < lowered.length) {
    const c = lowered[i];
    // Try to capture a delimiter-style token starting with "<|"
    if (c === "<" && lowered[i + 1] === "|") {
      const end = lowered.indexOf("|>", i + 2);
      if (end > i + 2) {
        out.push(lowered.substring(i, end + 2));
        i = end + 2;
        continue;
      }
    }
    // Word character: accumulate
    if (isWord(c)) {
      let j = i;
      while (j < lowered.length && isWord(lowered[j])) j++;
      out.push(lowered.substring(i, j));
      i = j;
      continue;
    }
    i++;
  }
  return out;
}

function isWord(c: string): boolean {
  return (
    (c >= "a" && c <= "z") ||
    (c >= "0" && c <= "9") ||
    c === "_"
  );
}

function matchPhrase(tokens: string[], spec: InjectionPhraseSpec): boolean {
  const targets = spec.tokens;
  if (targets.length === 0) return false;
  let cursor = 0;
  for (const token of tokens) {
    if (token === targets[cursor]) {
      cursor++;
      if (cursor === targets.length) return true;
    } else if (cursor > 0) {
      // Allow gap of up to I3_MAX_GAP_TOKENS between matched positions.
      // Track gap implicitly: if we've matched 1+ and current token isn't
      // target, we allow some mismatches before resetting. We approximate
      // "gap" by not resetting until we see the starting target again.
      if (token === targets[0]) {
        cursor = 1;
      }
    }
  }
  return cursor === targets.length;
}

function noisyOr(weights: number[]): number {
  let p = 1;
  for (const w of weights) p *= 1 - w;
  return 1 - p;
}

// Silence linter for unused constant: consumed in future gap-aware impl.
void I3_MAX_GAP_TOKENS;
