/**
 * A8 gather step — detect "read-only" claim + write-capable parameters.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  READ_ONLY_CLAIMS,
  WRITE_PARAM_TOKENS,
  NETWORK_PARAM_TOKENS,
  DANGEROUS_DEFAULTS,
  type ClaimPhrase,
} from "./data/capability-vocab.js";

export interface MismatchSite {
  tool_name: string;
  claim: { label: string; offset: number; observed: string; weight: number };
  write_params: string[];
  network_params: string[];
  dangerous_defaults: Array<{ name: string; label: string }>;
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

function findClaim(tokens: Token[], claim: ClaimPhrase): { offset: number; length: number } | null {
  const k = claim.tokens.length;
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].text !== claim.tokens[0]) continue;
    let idx = i;
    let ok = true;
    for (let t = 1; t < k; t++) {
      let j = idx + 1;
      const limit = Math.min(tokens.length, j + claim.max_gap + 1);
      let found = -1;
      while (j < limit) {
        if (tokens[j].text === claim.tokens[t]) {
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
      const end = endTok.offset + endTok.text.length;
      return { offset: start, length: end - start };
    }
  }
  return null;
}

function splitOnNonWord(s: string): string[] {
  const out: string[] = [];
  let buf = "";
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    if (isWord(cp)) {
      buf += lower(cp);
    } else {
      if (buf.length > 0) out.push(buf);
      buf = "";
    }
  }
  if (buf.length > 0) out.push(buf);
  return out;
}

function paramTokens(name: string): string[] {
  return splitOnNonWord(name);
}

export function gatherA8(context: AnalysisContext): MismatchSite[] {
  const out: MismatchSite[] = [];
  for (const tool of context.tools ?? []) {
    const desc = tool.description ?? "";
    if (desc.length < 5) continue;

    const tokens = tokenise(desc);
    // Find the first / highest-weight read-only claim
    let bestClaim: { label: string; offset: number; length: number; weight: number } | null = null;
    for (const c of READ_ONLY_CLAIMS) {
      const hit = findClaim(tokens, c);
      if (!hit) continue;
      if (!bestClaim || c.weight > bestClaim.weight) {
        bestClaim = { label: c.label, offset: hit.offset, length: hit.length, weight: c.weight };
      }
    }
    if (!bestClaim) continue;

    const schema = tool.input_schema;
    const props = (schema?.properties ?? null) as Record<string, Record<string, unknown>> | null;
    if (!props) continue;

    const writeParams: string[] = [];
    const networkParams: string[] = [];
    const dangerousDefaults: Array<{ name: string; label: string }> = [];

    for (const [paramName, paramDef] of Object.entries(props)) {
      const tks = paramTokens(paramName);
      for (const tok of tks) {
        if (WRITE_PARAM_TOKENS.has(tok) && !writeParams.includes(paramName)) {
          writeParams.push(paramName);
        }
        if (NETWORK_PARAM_TOKENS.has(tok) && !networkParams.includes(paramName)) {
          networkParams.push(paramName);
        }
      }
      // Default-value check
      for (const danger of Object.entries(DANGEROUS_DEFAULTS)) {
        const [tok, spec] = danger;
        if (!tks.includes(tok)) continue;
        if (paramDef.default === undefined) continue;
        const valStr = String(paramDef.default).toLowerCase();
        if (spec.value_tokens.includes(valStr)) {
          dangerousDefaults.push({ name: paramName, label: spec.label });
        }
      }
    }

    if (writeParams.length === 0 && networkParams.length === 0 && dangerousDefaults.length === 0) {
      continue;
    }

    const observed = desc.slice(bestClaim.offset, bestClaim.offset + bestClaim.length);
    out.push({
      tool_name: tool.name,
      claim: { label: bestClaim.label, offset: bestClaim.offset, observed, weight: bestClaim.weight },
      write_params: writeParams,
      network_params: networkParams,
      dangerous_defaults: dangerousDefaults,
    });
  }
  return out;
}

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
