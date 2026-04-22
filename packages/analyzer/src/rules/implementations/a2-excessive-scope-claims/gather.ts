/**
 * A2 gather step — tokenised modifier+noun co-occurrence detection.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { CLAIM_SPECS, type ClaimSpec } from "./data/scope-claims.js";

export interface ClaimSite {
  tool_name: string;
  offset: number;
  length: number;
  observed: string;
  weight: number;
  label: string;
  /** Whether schema has structured constraints that contradict the claim. */
  schema_has_constraints: boolean;
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
    (cp >= 0x61 && cp <= 0x7a)
  );
}

function lower(cp: number): string {
  if (cp >= 0x41 && cp <= 0x5a) return String.fromCharCode(cp + 32);
  return String.fromCharCode(cp);
}

function hasTightConstraints(schema: Record<string, unknown> | null | undefined): boolean {
  if (!schema) return false;
  const props = (schema.properties ?? null) as Record<string, Record<string, unknown>> | null;
  if (!props) return false;
  for (const prop of Object.values(props)) {
    if (prop.enum || prop.maxLength || prop.pattern) return true;
  }
  return false;
}

function findClaim(tokens: Token[], spec: ClaimSpec, textLen: number): { offset: number; length: number } | null {
  for (let i = 0; i < tokens.length; i++) {
    if (!spec.modifier_tokens.includes(tokens[i].text)) continue;
    const limit = Math.min(tokens.length, i + spec.max_gap + 2);
    for (let j = i + 1; j < limit; j++) {
      if (spec.noun_tokens.includes(tokens[j].text)) {
        const start = tokens[i].offset;
        const end = tokens[j].offset + tokens[j].text.length;
        return { offset: start, length: Math.min(textLen - start, end - start) };
      }
    }
  }
  return null;
}

export function gatherA2(context: AnalysisContext): ClaimSite[] {
  const out: ClaimSite[] = [];
  for (const tool of context.tools ?? []) {
    const desc = tool.description ?? "";
    if (desc.length < 10) continue;
    const tokens = tokenise(desc);
    const hasConstraints = hasTightConstraints(tool.input_schema);
    for (const spec of CLAIM_SPECS) {
      const hit = findClaim(tokens, spec, desc.length);
      if (!hit) continue;
      out.push({
        tool_name: tool.name,
        offset: hit.offset,
        length: hit.length,
        observed: desc.slice(hit.offset, hit.offset + hit.length).slice(0, 120),
        weight: spec.weight,
        label: spec.label,
        schema_has_constraints: hasConstraints,
      });
    }
  }
  return out;
}

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
