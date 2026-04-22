/**
 * B5 gather step — applies the A1 phrase catalogue to parameter
 * descriptions inside every tool's input_schema.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  INJECTION_PHRASES,
  LLM_SPECIAL_TOKENS,
  type PhraseSpec,
} from "../a1-prompt-injection-description/data/injection-phrases.js";

export interface B5Site {
  tool_name: string;
  parameter_name: string;
  offset: number;
  length: number;
  observed: string;
  weight: number;
  label: string;
  kind: "phrase" | "special-token";
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

function findPhrase(tokens: Token[], spec: PhraseSpec): { offset: number; length: number } | null {
  const k = spec.tokens.length;
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].text !== spec.tokens[0]) continue;
    let idx = i;
    let ok = true;
    for (let t = 1; t < k; t++) {
      let j = idx + 1;
      const limit = Math.min(tokens.length, j + spec.max_gap + 1);
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
      idx = found;
    }
    if (ok) {
      const start = tokens[i].offset;
      const endTok = tokens[idx];
      return { offset: start, length: endTok.offset + endTok.text.length - start };
    }
  }
  return null;
}

export function gatherB5(context: AnalysisContext): B5Site[] {
  const out: B5Site[] = [];
  for (const tool of context.tools ?? []) {
    const schema = tool.input_schema;
    if (!schema) continue;
    const props = (schema.properties ?? null) as Record<string, Record<string, unknown>> | null;
    if (!props) continue;

    for (const [paramName, paramDef] of Object.entries(props)) {
      const desc = (paramDef.description ?? "") as string;
      if (desc.length < 10) continue;
      const tokens = tokenise(desc);

      for (const spec of INJECTION_PHRASES) {
        const hit = findPhrase(tokens, spec);
        if (!hit) continue;
        out.push({
          tool_name: tool.name,
          parameter_name: paramName,
          offset: hit.offset,
          length: hit.length,
          observed: desc.slice(hit.offset, hit.offset + hit.length).slice(0, 160),
          weight: spec.weight,
          label: spec.label,
          kind: "phrase",
        });
      }

      for (const token of Object.keys(LLM_SPECIAL_TOKENS)) {
        const idx = desc.indexOf(token);
        if (idx < 0) continue;
        const meta = LLM_SPECIAL_TOKENS[token];
        out.push({
          tool_name: tool.name,
          parameter_name: paramName,
          offset: idx,
          length: token.length,
          observed: token,
          weight: meta.weight,
          label: meta.label,
          kind: "special-token",
        });
      }
    }
  }
  return out;
}

export function paramLocation(tool_name: string, parameter_name: string): Location {
  return {
    kind: "parameter",
    tool_name,
    parameter_path: `input_schema.properties.${parameter_name}.description`,
  };
}
