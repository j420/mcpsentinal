import type { AnalysisContext } from "../../../engine.js";
import {
  INJECTION_PHRASES,
  type InjectionPhraseSpec,
} from "../_shared/protocol-shape-catalogue.js";
import { J3_MIN_AGGREGATE_WEIGHT } from "./data/config.js";

export interface J3Hit {
  key: string;
  spec: InjectionPhraseSpec;
}

export interface J3Fact {
  tool_name: string;
  hits: J3Hit[];
  aggregate_weight: number;
  schema_preview: string;
  non_description_fields_scanned: string[];
}

export interface J3GatherResult {
  facts: J3Fact[];
}

export function gatherJ3(context: AnalysisContext): J3GatherResult {
  const facts: J3Fact[] = [];
  if (!context.tools) return { facts };

  for (const tool of context.tools) {
    const schema = tool.input_schema as Record<string, unknown> | null | undefined;
    if (!schema || typeof schema !== "object") continue;

    const nonDescFields = collectNonDescriptionStrings(schema);
    if (nonDescFields.length === 0) continue;

    const corpus = nonDescFields.join(" ").toLowerCase();
    const tokens = tokenise(corpus);

    const hits: J3Hit[] = [];
    for (const [key, spec] of Object.entries(INJECTION_PHRASES)) {
      if (matchPhrase(tokens, spec)) {
        hits.push({ key, spec });
      }
    }
    if (hits.length === 0) continue;

    const aggregate = noisyOr(hits.map((h) => h.spec.weight));
    if (aggregate < J3_MIN_AGGREGATE_WEIGHT) continue;

    facts.push({
      tool_name: tool.name,
      hits,
      aggregate_weight: aggregate,
      schema_preview: JSON.stringify(schema).slice(0, 180),
      non_description_fields_scanned: nonDescFields.map((s) => s.slice(0, 60)),
    });
  }
  return { facts };
}

/**
 * Collect string-valued schema fields that are NOT descriptions —
 * enum values, title, const, default, examples.
 */
function collectNonDescriptionStrings(
  schema: Record<string, unknown>,
): string[] {
  const out: string[] = [];
  walk(schema, (obj) => {
    for (const key of Object.keys(obj)) {
      if (key === "description") continue;
      const val = (obj as Record<string, unknown>)[key];
      if (key === "title" && typeof val === "string") out.push(val);
      else if (key === "const" && typeof val === "string") out.push(val);
      else if (key === "default" && typeof val === "string") out.push(val);
      else if (key === "enum" && Array.isArray(val)) {
        for (const v of val) if (typeof v === "string") out.push(v);
      } else if (key === "examples" && Array.isArray(val)) {
        for (const v of val) if (typeof v === "string") out.push(v);
      }
    }
  });
  return out;
}

function walk(
  obj: unknown,
  cb: (o: Record<string, unknown>) => void,
): void {
  if (!obj || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    for (const entry of obj) walk(entry, cb);
    return;
  }
  cb(obj as Record<string, unknown>);
  for (const val of Object.values(obj as Record<string, unknown>)) {
    if (val && typeof val === "object") walk(val, cb);
  }
}

function tokenise(text: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === "<" && text[i + 1] === "|") {
      const end = text.indexOf("|>", i + 2);
      if (end > i + 2) {
        out.push(text.substring(i, end + 2));
        i = end + 2;
        continue;
      }
    }
    if (isWord(c)) {
      let j = i;
      while (j < text.length && isWord(text[j])) j++;
      out.push(text.substring(i, j));
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
