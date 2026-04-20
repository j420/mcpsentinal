/**
 * C1 evidence gathering — AST-taint first, regex-fallback second.
 *
 * CHARTER.md (sibling) lists the edge cases this module has to translate
 * into deterministic structural queries. The file produces *only* structured
 * facts — `index.ts` consumes these and assembles the evidence chain.
 *
 * No regex literals appear in this file; every pattern lives in `./data/*.ts`
 * which the no-static-patterns guard intentionally skips. No string-literal
 * arrays of length > 5 either.
 *
 * Detection pipeline:
 *
 *   1. If the source is absent → return empty.
 *
 *   2. If the whole file matches a TEST_FILE_SHAPES pattern → return empty.
 *      The rule only targets production code; the charter's obsolescence
 *      clause does not warrant flagging vitest/jest fixtures.
 *
 *   3. Run `analyzeASTTaint` — the deterministic source→sink taint analyser
 *      backed by the TypeScript compiler. Any flow whose sink.category is
 *      "command_execution" or "vm_escape" becomes an ASTFinding, carrying:
 *        • the structured Location of the source (file+line+col);
 *        • one propagation link per intermediate AST step;
 *        • the structured Location of the sink (same shape);
 *        • the sanitised flag + sanitiser name when the analyser detected
 *          one (so index.ts can set severity to `informational`).
 *
 *   4. If AST taint produced zero command-flows, scan each line against the
 *      FALLBACK_SINKS registry (template-literal-in-exec, spawn-shell-true,
 *      subprocess-shell-True, os.system, shelljs.exec, vm.run*). Each match
 *      produces a RegexFinding with:
 *        • the structured Location of the match (source file + line + col);
 *        • the FallbackSink metadata (description, baseConfidence,
 *          sinkType, impactFragment);
 *        • a `lineText` snippet capped at 200 chars for the evidence narrative.
 *      LINE_SAFE_PATTERNS suppress individual matches on the same line
 *      (execFile, // nosec, // safe:).
 *
 *   5. The gather result also carries `astFlowCount` so index.ts can emit
 *      the `regex_fallback_only` factor truthfully and so the evidence
 *      chain narrative can explain *why* the degraded path was taken.
 */

import {
  analyzeASTTaint,
  type ASTTaintFlow,
  type ASTFlowStep,
} from "../../analyzers/taint-ast.js";
import {
  analyzeTaint,
  type TaintFlow,
  type TaintPropagation,
} from "../../analyzers/taint.js";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { FALLBACK_SINKS, type FallbackSink } from "./data/sink-lexicon.js";
import { LINE_SAFE_PATTERNS, TEST_FILE_SHAPES } from "./data/safe-patterns.js";
import { KNOWN_SANITIZERS } from "./data/sanitizer-names.js";

// ─── Public fact types ─────────────────────────────────────────────────────

/** One propagation step along the AST taint path. */
export interface ASTPathStep {
  type: ASTFlowStep["type"];
  expression: string;
  location: Location; // kind: "source"
}

/** A single AST-taint-confirmed source→sink flow. */
export interface ASTFinding {
  /** Structured Location of the untrusted source. */
  sourceLocation: Location; // kind: "source"
  /** Short human label for the source ("req.body.command"). */
  sourceExpression: string;
  /** Category reported by taint-ast.ts (http_body, http_params, environment, …). */
  sourceCategory: string;

  /** Intermediate propagation links. Length 0 means direct source→sink. */
  path: ASTPathStep[];

  /** Structured Location of the dangerous call. */
  sinkLocation: Location; // kind: "source"
  /** Short human label for the sink ("exec(cmd)"). */
  sinkExpression: string;
  /** Sink category from taint-ast.ts ("command_execution" | "vm_escape"). */
  sinkCategory: "command_execution" | "vm_escape";

  /** Whether the taint analyser detected a sanitiser on the path. */
  sanitized: boolean;
  /** Name of the sanitiser function, if any (e.g., "escapeShell"). */
  sanitizerName: string | null;
  /** Whether the sanitiser name is a charter-recognised one. */
  sanitizerIsCharterKnown: boolean;

  /** Raw confidence reported by taint-ast.ts before index.ts applies adjustments. */
  astConfidence: number;
}

/** A single regex-fallback match. */
export interface RegexFinding {
  /** Which entry in data/sink-lexicon.ts this came from. */
  sinkId: FallbackSink["id"];
  sink: FallbackSink;
  /** Structured Location of the match. */
  location: Location; // kind: "source"
  /** The matched text, capped. */
  matchText: string;
  /** The enclosing line text, trimmed + capped. */
  lineText: string;
}

/** What gather returns. */
export interface C1Gathered {
  /** Source-code mode: "absent" (no source) | "ast" (AST flows found) | "regex" (regex fallback). */
  mode: "absent" | "ast" | "regex" | "test-file";
  /** Synthetic file name used when the context only carries concatenated source. */
  file: string;
  /** How many AST command flows were observed (0 triggers regex fallback). */
  astFlowCount: number;
  /** Zero or more AST-confirmed findings. */
  astFindings: ASTFinding[];
  /** Zero or more regex-fallback findings. Only populated when astFlowCount === 0. */
  regexFindings: RegexFinding[];
}

// ─── Entry point ──────────────────────────────────────────────────────────

/** Conventional filename the rule attributes regex/AST locations to. */
const SYNTHETIC_FILE = "<source>";

export function gatherC1(context: AnalysisContext): C1Gathered {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return emptyResult("absent");
  }

  if (isTestFileShape(source)) {
    return emptyResult("test-file");
  }

  const file = SYNTHETIC_FILE;

  // Phase 1: AST taint analysis. Any parse error falls through to regex.
  const astFindings: ASTFinding[] = [];
  try {
    const flows = analyzeASTTaint(source);
    for (const flow of flows) {
      if (flow.sink.category !== "command_execution" && flow.sink.category !== "vm_escape") {
        continue;
      }
      astFindings.push(toASTFinding(flow, file));
    }
  } catch {
    // Malformed code — proceed to regex fallback.
  }

  if (astFindings.length > 0) {
    return {
      mode: "ast",
      file,
      astFlowCount: astFindings.length,
      astFindings,
      regexFindings: [],
    };
  }

  // Phase 1.5: Lightweight (regex-based) taint analyser. Catches flows the
  // AST analyser misses because the source is a plain function parameter
  // (e.g. `function processInput(params) { ... params.input ... }`) or the
  // propagation chain threads through a method-call expression such as
  // `.trim()` that the AST walker does not follow. Unlike the pure-regex
  // phase below, this one DOES prove a source→sink flow end-to-end, so the
  // findings stay at severity "critical" and are reported as AST-class
  // evidence (`mode: "ast"`, negative "lightweight_taint_fallback" factor
  // applied in index.ts).
  try {
    const ltFlows = analyzeTaint(source);
    for (const flow of ltFlows) {
      if (flow.sink.category !== "command_execution" && flow.sink.category !== "code_eval") {
        continue;
      }
      astFindings.push(lightweightToASTFinding(flow, file));
    }
  } catch {
    // analyseTaint is defensive but keep the net anyway.
  }

  if (astFindings.length > 0) {
    return {
      mode: "ast",
      file,
      astFlowCount: astFindings.length,
      astFindings,
      regexFindings: [],
    };
  }

  // Phase 2: Regex fallback.
  const regexFindings = scanRegexFallback(source, file);

  return {
    mode: regexFindings.length > 0 ? "regex" : "ast",
    file,
    astFlowCount: 0,
    astFindings: [],
    regexFindings,
  };
}

// ─── AST flow conversion ──────────────────────────────────────────────────

function toASTFinding(flow: ASTTaintFlow, file: string): ASTFinding {
  const sourceLocation: Location = {
    kind: "source",
    file,
    line: flow.source.line,
    col: flow.source.column,
  };
  const sinkLocation: Location = {
    kind: "source",
    file,
    line: flow.sink.line,
    col: flow.sink.column,
  };

  const path: ASTPathStep[] = flow.path.map((step) => ({
    type: step.type,
    expression: step.expression,
    location: {
      kind: "source",
      file,
      line: step.line,
    } satisfies Location,
  }));

  const sanitizerName = flow.sanitizer_name ?? null;
  const sanitizerIsCharterKnown =
    sanitizerName !== null && KNOWN_SANITIZERS[sanitizerName] !== undefined;

  return {
    sourceLocation,
    sourceExpression: flow.source.expression,
    sourceCategory: flow.source.category,
    path,
    sinkLocation,
    sinkExpression: flow.sink.expression,
    sinkCategory: flow.sink.category === "vm_escape" ? "vm_escape" : "command_execution",
    sanitized: flow.sanitized,
    sanitizerName,
    sanitizerIsCharterKnown,
    astConfidence: flow.confidence,
  };
}

// ─── Lightweight (regex-based) taint conversion ───────────────────────────

/**
 * Convert a TaintFlow produced by the lightweight analyser into the same
 * ASTFinding shape the AST analyser produces, so index.ts can treat both
 * uniformly. The differences vs. toASTFinding():
 *
 *   - column is unknown for regex matches — defaults to 1;
 *   - sourceCategory is remapped from TaintSourceCategory to the string
 *     taxonomy that index.ts expects ("http_body" / "environment" / …);
 *   - propagation steps are derived from TaintPropagation chain, whose
 *     `type` space is narrower than ASTFlowStep['type'] — we normalise
 *     "function_return" → "return_value" and "string_concat" → "assignment".
 */
function lightweightToASTFinding(flow: TaintFlow, file: string): ASTFinding {
  const sourceLocation: Location = {
    kind: "source",
    file,
    line: flow.source.line,
    col: 1,
  };
  const sinkLocation: Location = {
    kind: "source",
    file,
    line: flow.sink.line,
    col: 1,
  };

  const path: ASTPathStep[] = flow.propagation_chain.map((prop) => ({
    type: mapPropagationTypeToAST(prop),
    expression: `${prop.from} → ${prop.to}`,
    location: {
      kind: "source",
      file,
      line: prop.line,
    } satisfies Location,
  }));

  const sanitizerName = flow.sanitizer?.expression ?? null;
  const sanitizerIsCharterKnown =
    sanitizerName !== null && KNOWN_SANITIZERS[sanitizerName] !== undefined;

  return {
    sourceLocation,
    sourceExpression: flow.source.expression,
    sourceCategory: mapLightweightSourceCategory(flow.source.category),
    path,
    sinkLocation,
    sinkExpression: flow.sink.expression,
    sinkCategory: flow.sink.category === "code_eval" ? "vm_escape" : "command_execution",
    sanitized: flow.sanitized,
    sanitizerName,
    sanitizerIsCharterKnown,
    astConfidence: flow.confidence,
  };
}

/** TaintPropagation.type → ASTFlowStep.type lossy map. */
function mapPropagationTypeToAST(prop: TaintPropagation): ASTFlowStep["type"] {
  switch (prop.type) {
    case "assignment":
      return "assignment";
    case "destructure":
      return "destructure";
    case "function_return":
      return "return_value";
    case "string_concat":
      return "template_embed";
    default:
      return "assignment";
  }
}

/**
 * The lightweight taint analyser uses broad categories like "http_request"
 * and "environment"; index.ts expects the AST-style strings "http_body" /
 * "http_query" / "http_params" / "environment". We can't recover whether
 * the original was body vs query vs params from the lightweight result —
 * "http_body" is the conservative default since it's the most common case
 * and maps to "user-parameter" in index.ts regardless.
 */
function mapLightweightSourceCategory(category: string): string {
  if (category === "environment") return "environment";
  if (category === "http_request") return "http_body";
  if (category === "user_input" || category === "command_line") return "http_body";
  if (category === "deserialization") return "http_body";
  if (category === "file_read" || category === "network_input" || category === "database_read") {
    return "http_body";
  }
  return "http_body";
}

// ─── Regex fallback scanner ───────────────────────────────────────────────

/**
 * Scan every line against every FALLBACK_SINKS entry. Return at most one
 * finding per (line, sink.id) pair to avoid flooding the chain when a
 * pattern matches many tokens on one line.
 */
function scanRegexFallback(source: string, file: string): RegexFinding[] {
  const out: RegexFinding[] = [];
  const seen = new Set<string>();

  for (const entry of Object.values(FALLBACK_SINKS)) {
    // Clone the regex so matches from earlier scans don't leak state.
    const re = new RegExp(entry.pattern.source, entry.pattern.flags);

    let match: RegExpExecArray | null;
    while ((match = re.exec(source)) !== null) {
      const line = offsetToLine(source, match.index);
      const key = `${entry.id}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const lineText = getLine(source, line);
      if (isLineSafe(lineText)) continue;

      const col = offsetToColumn(source, match.index);

      out.push({
        sinkId: entry.id,
        sink: entry,
        location: { kind: "source", file, line, col },
        matchText: match[0].slice(0, 160),
        lineText: lineText.trim().slice(0, 200),
      });

      // Break so the regex's internal lastIndex doesn't re-enter this line.
      if (!re.global) break;
    }
  }

  return out;
}

// ─── Safe-line + safe-file checks ─────────────────────────────────────────

function isTestFileShape(source: string): boolean {
  for (const entry of Object.values(TEST_FILE_SHAPES)) {
    if (entry.pattern.test(source)) return true;
  }
  return false;
}

function isLineSafe(line: string): boolean {
  for (const entry of Object.values(LINE_SAFE_PATTERNS)) {
    if (entry.pattern.test(line)) return true;
  }
  return false;
}

// ─── Position helpers ─────────────────────────────────────────────────────

/** Convert a byte offset in `source` into a 1-indexed line number. */
function offsetToLine(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source.charCodeAt(i) === 10 /* \n */) line++;
  }
  return line;
}

/** Convert a byte offset in `source` into a 1-indexed column number within its line. */
function offsetToColumn(source: string, offset: number): number {
  let col = 1;
  for (let i = offset - 1; i >= 0; i--) {
    if (source.charCodeAt(i) === 10 /* \n */) break;
    col++;
  }
  return col;
}

/** Get the raw text of the 1-indexed line `line` from `source`. */
function getLine(source: string, line: number): string {
  const lines = source.split("\n");
  return lines[line - 1] ?? "";
}

// ─── Empty-result builder ─────────────────────────────────────────────────

function emptyResult(mode: C1Gathered["mode"]): C1Gathered {
  return {
    mode,
    file: SYNTHETIC_FILE,
    astFlowCount: 0,
    astFindings: [],
    regexFindings: [],
  };
}
