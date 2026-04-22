/**
 * I6 gather — phrase matching over prompt metadata (name + description +
 * argument descriptions).
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  INJECTION_PHRASES,
  type InjectionPhraseSpec,
} from "../_shared/protocol-shape-catalogue.js";
import { I6_MIN_AGGREGATE_WEIGHT } from "./data/config.js";

export interface I6Hit {
  key: string;
  spec: InjectionPhraseSpec;
  matched_field: "name" | "description" | "argument";
}

export interface I6Fact {
  prompt_name: string;
  hits: I6Hit[];
  aggregate_weight: number;
  combined_preview: string;
}

export interface I6GatherResult {
  facts: I6Fact[];
}

export function gatherI6(context: AnalysisContext): I6GatherResult {
  const facts: I6Fact[] = [];
  const prompts = context.prompts;
  if (!prompts || prompts.length === 0) return { facts };

  for (const prompt of prompts) {
    const name = prompt.name ?? "";
    const desc = prompt.description ?? "";
    const argDescs = (prompt.arguments ?? [])
      .map((a) => `${a.name} ${a.description ?? ""}`)
      .join(" ");
    const combined = `${name} ${desc} ${argDescs}`;

    const nameTokens = tokenise(name);
    const descTokens = tokenise(desc);
    const argTokens = tokenise(argDescs);

    const hits: I6Hit[] = [];
    for (const [key, spec] of Object.entries(INJECTION_PHRASES)) {
      if (matchPhrase(nameTokens, spec)) {
        hits.push({ key, spec, matched_field: "name" });
        continue;
      }
      if (matchPhrase(descTokens, spec)) {
        hits.push({ key, spec, matched_field: "description" });
        continue;
      }
      if (matchPhrase(argTokens, spec)) {
        hits.push({ key, spec, matched_field: "argument" });
      }
    }
    if (hits.length === 0) continue;

    const aggregate = noisyOr(hits.map((h) => h.spec.weight));
    if (aggregate < I6_MIN_AGGREGATE_WEIGHT) continue;

    facts.push({
      prompt_name: name,
      hits,
      aggregate_weight: aggregate,
      combined_preview: combined.slice(0, 160),
    });
  }
  return { facts };
}

function tokenise(text: string): string[] {
  const out: string[] = [];
  const lowered = text.toLowerCase();
  let i = 0;
  while (i < lowered.length) {
    const c = lowered[i];
    if (c === "<" && lowered[i + 1] === "|") {
      const end = lowered.indexOf("|>", i + 2);
      if (end > i + 2) {
        out.push(lowered.substring(i, end + 2));
        i = end + 2;
        continue;
      }
    }
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
    } else if (cursor > 0 && token === targets[0]) {
      cursor = 1;
    }
  }
  return cursor === targets.length;
}

function noisyOr(weights: number[]): number {
  let p = 1;
  for (const w of weights) p *= 1 - w;
  return 1 - p;
}
