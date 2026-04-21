/**
 * Shared taint-rule-kit — orchestration layer.
 *
 * Runs the two deterministic taint analysers (taint-ast.ts → taint.ts) in
 * order, filters the results by the rule-supplied sink category lists, and
 * produces uniform TaintFact[] that each rule's index.ts converts to v2
 * evidence chains.
 *
 * Contract:
 *   - Zero regex literals. Zero `new RegExp` calls. Zero string-literal
 *     arrays > 5. The analysers live under `analyzers/` and own their own
 *     regex patterns (exempt from the implementations-directory guard).
 *   - The only structural check performed here is the test-file skip:
 *     if the source carries markers typical of a vitest/jest fixture,
 *     return mode:"test-file" so the rule emits nothing.
 *     Charter: all six rules target production code, not fixtures.
 *
 * Test-file detection is performed by substring matching against the
 * structural markers in `./data/test-file-markers.ts` — no regex.
 */

import {
  analyzeASTTaint,
  type ASTTaintFlow,
  type ASTFlowStep,
} from "../../../analyzers/taint-ast.js";
import {
  analyzeTaint,
  type TaintFlow,
  type TaintPropagation,
} from "../../../analyzers/taint.js";
import type { AnalysisContext } from "../../../../engine.js";
import type { Location } from "../../../location.js";
import type {
  TaintFact,
  TaintPathStep,
  TaintGatherResult,
  TaintRuleConfig,
  SanitiserFact,
} from "./types.js";
import { TEST_FILE_MARKERS } from "./data/test-file-markers.js";

/** Synthetic file name used when the context only exposes concatenated source. */
const SYNTHETIC_FILE = "<source>";

/**
 * Detect test-fixture-shaped source without regex.
 *
 * We consult a small registry of structural markers (__tests__ segment,
 * .test. / .spec. filename, vitest/jest import) loaded from data/.
 * The markers are plain substrings — `String.prototype.includes()` only.
 */
function isTestFileShape(source: string): boolean {
  for (const marker of TEST_FILE_MARKERS) {
    if (source.includes(marker)) return true;
  }
  return false;
}

/**
 * Entry point. Calls analyzeASTTaint then analyzeTaint, filters by the
 * rule's configured sink categories, returns rule-agnostic facts.
 */
export function gatherTaintFacts(
  context: AnalysisContext,
  config: TaintRuleConfig,
): TaintGatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", file: SYNTHETIC_FILE, facts: [] };
  }
  if (isTestFileShape(source)) {
    return { mode: "test-file", file: SYNTHETIC_FILE, facts: [] };
  }

  const facts: TaintFact[] = [];

  // Phase 1: AST taint.
  try {
    const astFlows = analyzeASTTaint(source);
    const allowedAst = new Set(config.astSinkCategories);
    for (const flow of astFlows) {
      if (!allowedAst.has(flow.sink.category)) continue;
      facts.push(toFactFromAst(flow, SYNTHETIC_FILE, config.charterSanitisers));
    }
  } catch {
    // Parse error — fall through to lightweight taint.
  }

  if (facts.length > 0) {
    return { mode: "facts", file: SYNTHETIC_FILE, facts };
  }

  // Phase 2: Lightweight taint (handles Python + patterns AST misses).
  try {
    const lightweightFlows = analyzeTaint(source);
    const allowedLw = new Set(config.lightweightSinkCategories);
    for (const flow of lightweightFlows) {
      if (!allowedLw.has(flow.sink.category)) continue;
      facts.push(toFactFromLightweight(flow, SYNTHETIC_FILE, config.charterSanitisers));
    }
  } catch {
    // analyzeTaint is defensive but keep the net.
  }

  return {
    mode: facts.length > 0 ? "facts" : "absent",
    file: SYNTHETIC_FILE,
    facts,
  };
}

// ─── AST flow → TaintFact ────────────────────────────────────────────────

function toFactFromAst(
  flow: ASTTaintFlow,
  file: string,
  charterSanitisers: ReadonlySet<string>,
): TaintFact {
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

  const path: TaintPathStep[] = flow.path.map((step) => ({
    kind: mapAstStepKind(step),
    expression: step.expression,
    location: {
      kind: "source",
      file,
      line: step.line,
    } satisfies Location,
  }));

  const sanitiser: SanitiserFact | null = flow.sanitized && flow.sanitizer_name
    ? {
        name: flow.sanitizer_name,
        location: sinkLocation,
        charterKnown: charterSanitisers.has(flow.sanitizer_name),
      }
    : null;

  return {
    analyser: "ast",
    sourceLocation,
    sourceExpression: flow.source.expression,
    sourceCategory: flow.source.category,
    path,
    sinkLocation,
    sinkExpression: flow.sink.expression,
    sinkCategory: flow.sink.category,
    sanitiser,
    rawConfidence: flow.confidence,
  };
}

function mapAstStepKind(step: ASTFlowStep): TaintPathStep["kind"] {
  switch (step.type) {
    case "assignment":
      return "assignment";
    case "destructure":
      return "destructure";
    case "template_embed":
      return "template-embed";
    case "return_value":
    case "callback_arg":
    case "parameter_binding":
      return "function-call";
    case "spread":
    case "property_access":
      return "direct-pass";
    default:
      return "direct-pass";
  }
}

// ─── Lightweight flow → TaintFact ────────────────────────────────────────

function toFactFromLightweight(
  flow: TaintFlow,
  file: string,
  charterSanitisers: ReadonlySet<string>,
): TaintFact {
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

  const path: TaintPathStep[] = flow.propagation_chain.map((prop) => ({
    kind: mapLightweightStepKind(prop),
    expression: `${prop.from} → ${prop.to}`,
    location: {
      kind: "source",
      file,
      line: prop.line,
    } satisfies Location,
  }));

  const sanitiserName = flow.sanitizer?.expression ?? null;
  const sanitiser: SanitiserFact | null = flow.sanitized && sanitiserName
    ? {
        name: sanitiserName,
        location: {
          kind: "source",
          file,
          line: flow.sanitizer?.line ?? flow.sink.line,
        } satisfies Location,
        charterKnown: charterSanitisers.has(sanitiserName),
      }
    : null;

  return {
    analyser: "lightweight",
    sourceLocation,
    sourceExpression: flow.source.expression,
    sourceCategory: flow.source.category,
    path,
    sinkLocation,
    sinkExpression: flow.sink.expression,
    sinkCategory: flow.sink.category,
    sanitiser,
    rawConfidence: flow.confidence,
  };
}

function mapLightweightStepKind(prop: TaintPropagation): TaintPathStep["kind"] {
  switch (prop.type) {
    case "assignment":
      return "assignment";
    case "destructure":
      return "destructure";
    case "string_concat":
      return "template-embed";
    case "function_return":
      return "function-call";
    default:
      return "direct-pass";
  }
}
