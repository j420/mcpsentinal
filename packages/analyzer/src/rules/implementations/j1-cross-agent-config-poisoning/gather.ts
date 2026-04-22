/**
 * J1 — Cross-Agent Configuration Poisoning: fact gatherer.
 *
 * Uses the shared taint-rule-kit to obtain file_write flows, then post-
 * filters to those whose sink expression (or a propagation hop — the
 * path construction sometimes lives in a hop, not the sink itself)
 * references a KNOWN agent-config target path. The per-target host is
 * recorded on the fact so index.ts can name the victim agent in the
 * evidence rationale.
 *
 * Zero regex. All detection data lives in `./data/*.ts`.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  gatherTaintFacts,
  type TaintFact,
  type TaintGatherResult,
} from "../_shared/taint-rule-kit/index.js";
import type { Location } from "../../location.js";
import {
  AGENT_CONFIG_TARGETS,
  type AgentConfigTarget,
  type AgentHost,
} from "./data/agent-config-targets.js";
import {
  APPEND_FLAG_TOKENS,
  DYNAMIC_PATH_TOKENS,
  J1_AST_SINK_CATEGORIES,
  J1_CHARTER_SANITISERS,
  J1_LIGHTWEIGHT_SINK_CATEGORIES,
} from "./data/config.js";

// ─── Target registry derivation ────────────────────────────────────────────

const TARGET_ENTRIES: ReadonlyArray<readonly [string, AgentConfigTarget]> =
  Object.entries(AGENT_CONFIG_TARGETS);

// ─── Public types ──────────────────────────────────────────────────────────

/** A J1 enriched fact — a taint fact upgraded with agent-config target info. */
export interface J1Fact extends TaintFact {
  /** Which AI agent's config file this write targets. */
  targetHost: AgentHost;
  /** Short role description — "Claude Code per-project settings". */
  targetRole: string;
  /** Which suffix matched ("..claude/settings.local.json"). Used for auditor copy-paste. */
  targetSuffix: string;
  /** The config-kind Location pointing at the victim file. */
  targetLocation: Location;
  /**
   * Whether the write is in append mode or via appendFile. Stealth variant
   * that compounds the attack — CHARTER lethal edge case #3.
   */
  appendMode: boolean;
  /**
   * Whether the destination path was built dynamically (env var, homedir(),
   * string concatenation). CHARTER lethal edge case #4 — a factor that
   * escalates exploitability without invalidating the match.
   */
  dynamicPath: boolean;
}

export interface J1GatherResult {
  mode: TaintGatherResult["mode"];
  facts: J1Fact[];
}

// ─── Public API ────────────────────────────────────────────────────────────

export function gatherJ1(context: AnalysisContext): J1GatherResult {
  const gathered = gatherTaintFacts(context, {
    ruleId: "J1",
    astSinkCategories: J1_AST_SINK_CATEGORIES,
    lightweightSinkCategories: J1_LIGHTWEIGHT_SINK_CATEGORIES,
    charterSanitisers: J1_CHARTER_SANITISERS,
  });

  if (gathered.mode !== "facts") {
    return { mode: gathered.mode, facts: [] };
  }

  const facts: J1Fact[] = [];
  for (const fact of gathered.facts) {
    const combined = joinAllObservables(fact);
    const match = findAgentTarget(combined);
    if (match === null) continue;

    facts.push({
      ...fact,
      targetHost: match.target.host,
      targetRole: match.target.role,
      targetSuffix: match.suffix,
      targetLocation: toConfigLocation(match.suffix),
      appendMode: hasTokenFrom(combined, APPEND_FLAG_TOKENS),
      dynamicPath: hasTokenFrom(combined, DYNAMIC_PATH_TOKENS),
    });
  }

  return { mode: facts.length > 0 ? "facts" : "absent", facts };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/**
 * Combine every textual observable a taint fact exposes into one
 * lower-cased, forward-slash-normalised string. The sink expression and
 * the propagation hops may each carry a different fragment of the path
 * — we match against the union so a write whose path is built across
 * multiple hops still surfaces.
 */
function joinAllObservables(fact: TaintFact): string {
  const parts: string[] = [fact.sinkExpression, fact.sourceExpression];
  for (const hop of fact.path) parts.push(hop.expression);
  const combined = parts.join(" ");
  return normalisePath(combined);
}

/**
 * Lower-case + forward-slash normalisation. Windows backslashes in
 * observed expressions like `.claude\\settings.local.json` are mapped
 * to `.claude/settings.local.json` so the suffix matcher only needs
 * one canonical form. CHARTER lethal edge case #2.
 */
function normalisePath(text: string): string {
  let out = text.toLowerCase();
  out = out.split("\\\\").join("/");
  out = out.split("\\").join("/");
  return out;
}

/**
 * Return the first agent-config target whose key appears in `text`
 * on a path-component boundary. Returns null if none does.
 *
 * Boundary check: the suffix itself already contains "/", so a naive
 * `includes()` will match "my.claude/settings.local.json" when the
 * target key is ".claude/settings.local.json" only when the preceding
 * character is a path boundary. We enforce this by requiring the
 * character immediately before the match to be a separator OR the
 * match to sit at index 0.
 */
interface TargetMatch {
  suffix: string;
  target: AgentConfigTarget;
}

function findAgentTarget(text: string): TargetMatch | null {
  for (const [suffix, target] of TARGET_ENTRIES) {
    const idx = text.indexOf(suffix);
    if (idx < 0) continue;
    if (idx === 0) return { suffix, target };
    const before = text.charAt(idx - 1);
    // Accept match after a separator or a quote / backtick — the quotes
    // cover patterns like `writeFileSync("~/.claude/settings.local.json")`.
    if (before === "/" || before === "~" || before === "\"" || before === "'" || before === "`") {
      return { suffix, target };
    }
  }
  return null;
}

/**
 * Build a config-kind Location for the victim agent's config file. The
 * `file` field uses the normalised suffix (e.g. "~/.claude/settings.local.json")
 * so an auditor can copy-paste it. `json_pointer` stays at "/" — the
 * rule cannot statically resolve which key inside the JSON is written.
 */
function toConfigLocation(suffix: string): Location {
  return {
    kind: "config",
    file: suffix,
    json_pointer: "/",
  };
}

/** True when any token in `tokens` appears as a substring of `text`. */
function hasTokenFrom(text: string, tokens: ReadonlySet<string>): boolean {
  for (const t of tokens) {
    if (text.includes(t.toLowerCase())) return true;
  }
  return false;
}
