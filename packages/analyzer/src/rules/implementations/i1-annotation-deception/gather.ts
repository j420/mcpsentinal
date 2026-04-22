/**
 * I1 evidence gathering — annotation-vs-schema contradiction detection.
 *
 * Deterministic, structural fact collection. Input: each tool's
 * annotations, parameter names, description, and the shared
 * schema-inference analyzer's capability classification. Output:
 * one DeceptionFact per deceptive tool, with structured Locations,
 * the triggering signal(s), and the schema-inference attack-surface
 * score for confidence weighting.
 *
 * No regex literals. No string-literal arrays > 5. All vocabulary
 * lives in ./data/destructive-vocabulary.ts as typed Records.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  analyzeToolSet,
  type SchemaAnalysisResult,
} from "../../analyzers/schema-inference.js";
import type { Location } from "../../location.js";
import {
  DESTRUCTIVE_VERBS,
  WRITE_VERBS,
  type DestructiveVerbEntry,
} from "./data/destructive-vocabulary.js";

// ─── Public types ──────────────────────────────────────────────────────────

export type AnnotationShape =
  /** readOnlyHint: true declared; destructiveHint may be absent, false, or the self-contradicting true. */
  | { kind: "readonly_declared"; destructive_hint: boolean | undefined }
  /** No readOnlyHint set, but destructiveHint: true is set — not a deception (tool author disclosed risk). */
  | { kind: "destructive_declared" }
  /** No relevant hints — I1 does not fire. I2 companion stub handles this. */
  | { kind: "no_hint" };

export interface DestructiveSignal {
  /** Where the destructive intent was observed. */
  origin: "parameter_name" | "description" | "schema_inference" | "annotation_self_contradiction";
  /** Structured Location the auditor can jump to. */
  location: Location;
  /** The destructive-vocabulary verb that matched (empty for schema_inference / self-contradiction). */
  verb: string;
  /** Verb classification (delete / overwrite / terminate / write) — empty for non-vocabulary origins. */
  verb_kind: string;
  /** One-line human attribution surfaced in evidence-chain rationale. */
  attribution: string;
}

export interface DeceptionFact {
  tool_name: string;
  /** Tool-level Location for the annotation link. */
  tool_location: Location; // kind: "tool"
  /** The annotation shape that triggered I1. */
  annotation: AnnotationShape;
  /** All destructive signals that contradict the annotation (≥1 for a fact to exist). */
  signals: DestructiveSignal[];
  /** Whether schema-inference independently confirmed destructive capability. */
  schema_confirms_destructive: boolean;
  /** 0.0–1.0 — schema-inference attack-surface score for this tool (0 if not confirmed). */
  attack_surface_score: number;
  /** Highest-priority signal for the chain's primary `source` / `propagation` link. */
  primary_signal: DestructiveSignal;
}

export interface I1Gathered {
  /** One entry per tool that exhibits a deceptive annotation. */
  facts: DeceptionFact[];
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Gather I1 facts from an AnalysisContext.
 *
 * Honest-refusal rule: I1 requires at least one tool with an annotations
 * object. Tools without any annotations are I2's responsibility
 * (missing destructiveHint despite destructive capability). Tools with
 * annotations but no readOnlyHint and no self-contradiction are skipped
 * here.
 */
export function gatherI1(context: AnalysisContext): I1Gathered {
  const tools = context.tools ?? [];
  if (tools.length === 0) return { facts: [] };

  // Run schema-inference once for the whole toolset — it's the same
  // analysis F1 uses, and we piggy-back on its capability classification
  // to confirm destructive capability structurally.
  const schema = analyzeToolSet(tools);
  const schemaByName = new Map<string, SchemaAnalysisResult>();
  for (const r of schema.tools) schemaByName.set(r.tool_name, r);

  const facts: DeceptionFact[] = [];

  for (const tool of tools) {
    const annotationShape = classifyAnnotation(tool.annotations ?? null);
    if (annotationShape.kind === "destructive_declared") continue;
    if (annotationShape.kind === "no_hint") continue;

    const signals = gatherDestructiveSignals(tool, annotationShape, schemaByName.get(tool.name));
    if (signals.length === 0) continue;

    const result = schemaByName.get(tool.name);
    const confirmsDestructive =
      result !== undefined &&
      result.capabilities.some(
        (c) => c.capability === "destructive_operation" || c.capability === "configuration_mutation",
      );
    const attack_surface_score = result?.attack_surface_score ?? 0;

    facts.push({
      tool_name: tool.name,
      tool_location: { kind: "tool", tool_name: tool.name },
      annotation: annotationShape,
      signals,
      schema_confirms_destructive: confirmsDestructive,
      attack_surface_score,
      primary_signal: chooseBestSignal(signals),
    });
  }

  return { facts };
}

// ─── Annotation classification ─────────────────────────────────────────────

function classifyAnnotation(
  ann: { readOnlyHint?: boolean; destructiveHint?: boolean } | null,
): AnnotationShape {
  if (!ann) return { kind: "no_hint" };
  const ro = ann.readOnlyHint === true;
  const destTrue = ann.destructiveHint === true;
  const destFalse = ann.destructiveHint === false;

  if (ro) {
    return { kind: "readonly_declared", destructive_hint: destTrue ? true : destFalse ? false : undefined };
  }
  if (destTrue) {
    // Destructive flagged without readOnly contradiction — not I1.
    return { kind: "destructive_declared" };
  }
  return { kind: "no_hint" };
}

// ─── Destructive-signal detection ──────────────────────────────────────────

function gatherDestructiveSignals(
  tool: {
    name: string;
    description: string | null;
    input_schema: Record<string, unknown> | null;
  },
  annotationShape: AnnotationShape,
  schemaResult: SchemaAnalysisResult | undefined,
): DestructiveSignal[] {
  const signals: DestructiveSignal[] = [];

  // (a) Self-contradicting annotation — both readOnlyHint: true AND destructiveHint: true.
  if (annotationShape.kind === "readonly_declared" && annotationShape.destructive_hint === true) {
    signals.push({
      origin: "annotation_self_contradiction",
      location: { kind: "tool", tool_name: tool.name },
      verb: "",
      verb_kind: "",
      attribution:
        "Tool declares readOnlyHint: true AND destructiveHint: true — the two flags are mutually exclusive by definition.",
    });
  }

  // (b) Parameter-name vocabulary match.
  const props = extractProperties(tool.input_schema);
  for (const paramName of Object.keys(props)) {
    const match = matchVocabulary(paramName);
    if (match) {
      signals.push({
        origin: "parameter_name",
        location: { kind: "parameter", tool_name: tool.name, parameter_path: `input_schema.properties.${paramName}` },
        verb: match.token,
        verb_kind: match.entry.kind,
        attribution: `Parameter "${paramName}" — ${match.entry.attribution}`,
      });
    }
  }

  // (c) Description-verb scan — tokenise and check each lowercased token against the vocabulary.
  const description = tool.description ?? "";
  if (description.length > 0) {
    const seen = new Set<string>();
    for (const token of tokenizeDescription(description)) {
      if (seen.has(token)) continue;
      seen.add(token);
      const match = matchVocabulary(token);
      if (match) {
        signals.push({
          origin: "description",
          location: { kind: "tool", tool_name: tool.name },
          verb: match.token,
          verb_kind: match.entry.kind,
          attribution: `Description contains verb "${token}" — ${match.entry.attribution}`,
        });
        break; // one description signal is enough; more would be noise.
      }
    }
  }

  // (d) Schema-inference structural confirmation.
  if (schemaResult && schemaResult.attack_surface_score >= 0.5) {
    const destructiveCap = schemaResult.capabilities.find(
      (c) => c.capability === "destructive_operation" || c.capability === "configuration_mutation",
    );
    if (destructiveCap && destructiveCap.contributing_parameters.length > 0) {
      const firstParam = destructiveCap.contributing_parameters[0];
      signals.push({
        origin: "schema_inference",
        location: {
          kind: "schema",
          tool_name: tool.name,
          json_pointer: `/properties/${firstParam}`,
        },
        verb: "",
        verb_kind: destructiveCap.capability,
        attribution: `Schema structural analysis: capability=${destructiveCap.capability} at attack_surface_score=${(schemaResult.attack_surface_score * 100).toFixed(0)}%`,
      });
    }
  }

  return signals;
}

function extractProperties(schema: Record<string, unknown> | null): Record<string, unknown> {
  if (!schema || typeof schema !== "object") return {};
  const props = schema.properties;
  if (!props || typeof props !== "object") return {};
  return props as Record<string, unknown>;
}

/**
 * Match a token (lowercased) against the destructive / write vocabularies.
 * Returns the first match (destructive vocabulary checked first — higher
 * weight), or null. Matches both exact tokens and tokens that contain a
 * verb as a substring ("delete_user" matches "delete"). Substring
 * matching is anchored on word-boundary friendly delimiters inside the
 * tokeniser — see tokenizeDescription.
 */
function matchVocabulary(token: string): {
  token: string;
  entry: DestructiveVerbEntry;
} | null {
  const lowered = token.toLowerCase();
  for (const [verb, entry] of Object.entries(DESTRUCTIVE_VERBS)) {
    if (lowered === verb || lowered.includes(verb)) return { token: verb, entry };
  }
  for (const [verb, entry] of Object.entries(WRITE_VERBS)) {
    if (lowered === verb || lowered.includes(verb)) return { token: verb, entry };
  }
  return null;
}

/**
 * Split a description into word tokens using a structural character-class
 * walk (no regex literals). Tokens are sequences of ASCII letters of
 * length ≥ 3, lowercased.
 */
function tokenizeDescription(text: string): string[] {
  const tokens: string[] = [];
  let current = "";
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    const isAsciiLetter =
      (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
    if (isAsciiLetter) {
      current += ch;
    } else {
      if (current.length >= 3) tokens.push(current.toLowerCase());
      current = "";
    }
  }
  if (current.length >= 3) tokens.push(current.toLowerCase());
  return tokens;
}

/**
 * Signal priority for the evidence chain's primary link — schema
 * inference beats parameter-name vocabulary beats description scan,
 * beats annotation self-contradiction. This ordering puts the
 * strongest structural signal at the top of the chain and keeps
 * weaker linguistic signals as supporting evidence.
 */
function chooseBestSignal(signals: DestructiveSignal[]): DestructiveSignal {
  const order = ["schema_inference", "parameter_name", "description", "annotation_self_contradiction"];
  const sorted = [...signals].sort(
    (a, b) => order.indexOf(a.origin) - order.indexOf(b.origin),
  );
  return sorted[0];
}
