import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  PROMPT_IDENTIFIERS,
  RETURN_SHAPED,
  DEV_GATE_KEYWORDS,
  M9_GATE_WINDOW_LINES,
  type PromptIdent,
} from "./data/prompt-identifiers.js";

export interface LeakSite {
  location: Location;
  line: number;
  line_text: string;
  prompt_ident: PromptIdent;
  return_fragment: string;
  gate_present: boolean;
  gate_label: string | null;
  gate_distance: number | null;
}

export interface M9Gathered {
  sites: LeakSite[];
}

function findGate(
  lines: string[],
  idx: number,
): { label: string; distance: number } | null {
  const lo = Math.max(0, idx - M9_GATE_WINDOW_LINES);
  const hi = Math.min(lines.length - 1, idx + M9_GATE_WINDOW_LINES);
  let best: { label: string; distance: number } | null = null;
  for (let i = lo; i <= hi; i++) {
    const lc = lines[i].toLowerCase();
    for (const [kw, label] of Object.entries(DEV_GATE_KEYWORDS)) {
      if (lc.indexOf(kw) !== -1) {
        const d = Math.abs(i - idx);
        if (!best || d < best.distance) best = { label, distance: d };
      }
    }
  }
  return best;
}

export function gatherM9(context: AnalysisContext): M9Gathered {
  const source = context.source_code;
  if (!source) return { sites: [] };
  const lcWhole = source.toLowerCase();
  if (lcWhole.indexOf("__tests__") !== -1 || lcWhole.indexOf(".test.") !== -1)
    return { sites: [] };

  const lines = source.split("\n");
  const sites: LeakSite[] = [];
  const returnKeys = Object.keys(RETURN_SHAPED);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const lc = raw.toLowerCase();
    // Skip lines that are function parameter declarations only —
    // those look like `function setSystemPrompt(system_prompt: string)`
    // and are not the leak path.
    if (lc.indexOf("function") !== -1 && lc.indexOf(":") !== -1 && lc.indexOf("(") !== -1) {
      continue;
    }
    let matchedIdent: PromptIdent | null = null;
    for (const [key, p] of Object.entries(PROMPT_IDENTIFIERS)) {
      if (lc.indexOf(key) !== -1) {
        matchedIdent = p;
        break;
      }
    }
    if (!matchedIdent) continue;

    let hitReturn: string | null = null;
    for (const rk of returnKeys) {
      if (lc.indexOf(rk) !== -1) {
        hitReturn = rk;
        break;
      }
    }
    if (!hitReturn) continue;

    // Also require the current line to be reachable as a return path —
    // skip assignment lines that merely set the variable.
    if (lc.indexOf(" = ") !== -1 && lc.indexOf("return") === -1 && hitReturn === "return") {
      continue;
    }

    const gate = findGate(lines, i);
    sites.push({
      location: { kind: "source", file: "<aggregated>", line: i + 1 },
      line: i + 1,
      line_text: raw.trim().slice(0, 160),
      prompt_ident: matchedIdent,
      return_fragment: hitReturn,
      gate_present: gate !== null,
      gate_label: gate?.label ?? null,
      gate_distance: gate?.distance ?? null,
    });
  }
  return { sites };
}
