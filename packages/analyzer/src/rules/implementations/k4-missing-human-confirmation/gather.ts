/**
 * K4 evidence gathering — deterministic, AST-only.
 *
 * Two collection surfaces:
 *
 *   1. Tools (schema surface) — classify each MCP tool as destructive based
 *      on its name tokenisation + description markers + schema introspection.
 *      Emit a DestructiveTool finding when the tool is destructive AND no
 *      confirmation parameter is REQUIRED in the schema.
 *
 *   2. Source code (AST surface) — walk the TypeScript AST for every
 *      supplied file, find CallExpressions whose call-symbol tokenises to
 *      contain a destructive verb, then walk the call's ancestor chain
 *      looking for a confirmation guard. Emit a DestructiveCallSite
 *      finding when NO guard dominates the call.
 *
 * No regex literals. No string-literal arrays > 5. Canonical lists live in
 * `./data/*.ts` as Record<string, X> object literals, imported here and
 * projected to ReadonlySet<string> at module load.
 *
 * `index.ts` consumes the gathered facts and constructs EvidenceChains.
 * This file produces only structured raw evidence — zero narrative.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  DESTRUCTIVE_VERBS,
  BULK_MARKERS,
  SOFT_MARKERS,
  IRREVERSIBILITY_MARKERS,
  type VerbClass,
  type VerbEntry,
} from "./data/destructive-vocabulary.js";
import {
  CONFIRMATION_PARAM_TOKENS,
  type ConfirmationKind,
} from "./data/confirmation-tokens.js";
import { gatherFile } from "./gather-ast.js";

// ─── Registry derivation (module-load, cost-amortised) ─────────────────────

const DESTRUCTIVE_VERB_SET: ReadonlySet<string> = new Set(Object.keys(DESTRUCTIVE_VERBS));
const BULK_MARKER_SET: ReadonlySet<string> = new Set(Object.keys(BULK_MARKERS));
const SOFT_MARKER_SET: ReadonlySet<string> = new Set(Object.keys(SOFT_MARKERS));
const IRREVERSIBILITY_MARKER_SET: ReadonlySet<string> = new Set(Object.keys(IRREVERSIBILITY_MARKERS));
const CONFIRMATION_PARAM_SET: ReadonlySet<string> = new Set(Object.keys(CONFIRMATION_PARAM_TOKENS));

// ─── Public types ──────────────────────────────────────────────────────────

export interface VerbMatch {
  verb: string;
  klass: VerbClass;
  implicitBulk: boolean;
}

export interface ClassifiedName {
  /** The original symbol — tool name, function name, method identifier. */
  raw: string;
  /** Lowercased token list after tokenisation. */
  tokens: string[];
  /** First destructive verb detected, if any. */
  destructive: VerbMatch | null;
  /** Whether the tokens carry a bulk marker or the verb itself is implicitly bulk. */
  bulk: boolean;
  /** Any soft marker tokens detected (reduce confidence). */
  softMarkers: string[];
}

export interface ConfirmationParam {
  name: string;
  kind: ConfirmationKind;
  required: boolean;
  /** RFC 6901 pointer into the input_schema: "/properties/<name>". */
  jsonPointer: string;
}

export interface DestructiveTool {
  toolName: string;
  classification: ClassifiedName;
  /** Irreversibility markers found in the tool description (if any). */
  irreversibilityMarkers: string[];
  /** Confirmation params found in the input_schema (may be empty). */
  confirmationParams: ConfirmationParam[];
  /** destructiveHint annotation value (if annotations surface was populated). */
  hasDestructiveHintAnnotation: boolean;
  hasReadOnlyHintAnnotation: boolean;
  /** Location of the tool itself. */
  toolLocation: Location; // kind: "tool"
  /** Location of the input_schema root (useful for "no mitigation" evidence). */
  schemaLocation: Location; // kind: "schema"
}

export interface GuardEvidence {
  /** "if (force)" / "if (approved)" condition match. */
  conditionIdentifiers: string[];
  /** Bare function calls in the guarded ancestor (e.g. confirm()). */
  guardCalls: string[];
  /** Receiver.method calls matched against GUARD_RECEIVER_METHODS. */
  guardReceiverMethods: string[];
  /** Source Location of the guard (the IfStatement or CallExpression). */
  guardLocation: Location | null; // kind: "source"
}

export interface DestructiveCallSite {
  /** Source Location of the call itself. */
  location: Location; // kind: "source"
  /** The call's symbol (method name or function name) and its classification. */
  callSymbol: ClassifiedName;
  /** Verbatim source line (trimmed + length-capped) for human display. */
  observed: string;
  /** Guard evidence — when guardLocation is non-null, the site is mitigated. */
  guard: GuardEvidence;
  /** True if the call is inside the body of a structurally-identified test. */
  inTestFile: boolean;
  /** File path the call lives in. */
  file: string;
}

export interface FileEvidence {
  file: string;
  callSites: DestructiveCallSite[];
  isTestFile: boolean;
}

export interface K4Gathered {
  /** Destructive tools from context.tools — schema-surface findings. */
  destructiveTools: DestructiveTool[];
  /** Per-source-file destructive call sites. */
  perFile: FileEvidence[];
}

// ─── Entry points ──────────────────────────────────────────────────────────

/**
 * Top-level gather. Safe to call with an incomplete context — each branch
 * exits cleanly when its surface is absent, so the rule can run against
 * tools-only, source-only, or both.
 */
export function gatherK4(context: AnalysisContext): K4Gathered {
  const destructiveTools: DestructiveTool[] = [];

  for (const tool of context.tools) {
    const classification = classifyName(tool.name);
    if (!classification.destructive) continue;

    const irreversibilityMarkers = findIrreversibilityMarkers(tool.description ?? "");
    const confirmationParams = findConfirmationParams(tool.input_schema ?? null);
    const hasDestructiveHint = tool.annotations?.destructiveHint === true;
    const hasReadOnlyHint = tool.annotations?.readOnlyHint === true;

    destructiveTools.push({
      toolName: tool.name,
      classification,
      irreversibilityMarkers,
      confirmationParams,
      hasDestructiveHintAnnotation: hasDestructiveHint,
      hasReadOnlyHintAnnotation: hasReadOnlyHint,
      toolLocation: { kind: "tool", tool_name: tool.name },
      schemaLocation: { kind: "schema", tool_name: tool.name, json_pointer: "" },
    });
  }

  const perFile: FileEvidence[] = [];
  const files = collectSourceFiles(context);
  for (const [file, text] of files) {
    perFile.push(gatherFile(file, text));
  }

  return { destructiveTools, perFile };
}

/**
 * Collect source files from the context. Prefer `source_files` (per-file
 * map) when present; fall back to the concatenated blob when the pipeline
 * only supplied one.
 */
function collectSourceFiles(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) out.set(k, v);
    return out;
  }
  if (context.source_code) {
    out.set("<concatenated-source>", context.source_code);
  }
  return out;
}

// ─── Tokenisation ──────────────────────────────────────────────────────────

/**
 * Tokenise an identifier or tool name into lowercase token list. Splits on:
 *
 *   - underscore `_`
 *   - hyphen `-`
 *   - dot `.`
 *   - case boundaries (lower→Upper, letter→Digit, Digit→letter, consecutive
 *     uppercase followed by lowercase — handles acronym+word like `XMLHttp`).
 *
 * The algorithm is AST-free character scanning; it does not rely on any
 * external tokenisation library and is deterministic on all inputs.
 */
export function tokenise(name: string): string[] {
  if (!name) return [];
  const tokens: string[] = [];
  let buf = "";
  const push = (): void => {
    if (buf.length > 0) {
      tokens.push(buf.toLowerCase());
      buf = "";
    }
  };

  for (let i = 0; i < name.length; i++) {
    const ch = name[i];
    if (ch === "_" || ch === "-" || ch === "." || ch === " " || ch === "/") {
      push();
      continue;
    }
    if (buf.length === 0) {
      buf = ch;
      continue;
    }
    const prev = buf[buf.length - 1];
    const prevIsLower = prev >= "a" && prev <= "z";
    const prevIsUpper = prev >= "A" && prev <= "Z";
    const prevIsDigit = prev >= "0" && prev <= "9";
    const chIsLower = ch >= "a" && ch <= "z";
    const chIsUpper = ch >= "A" && ch <= "Z";
    const chIsDigit = ch >= "0" && ch <= "9";

    // lower→Upper transition: "deleteAll" → ["delete", "All"]
    if (prevIsLower && chIsUpper) {
      push();
      buf = ch;
      continue;
    }
    // Digit/letter transitions
    if (prevIsDigit !== chIsDigit && (prevIsDigit || chIsDigit)) {
      push();
      buf = ch;
      continue;
    }
    // Acronym boundary: "XMLHttp" — when we have UPPER UPPER lower, split before the last upper.
    if (prevIsUpper && chIsLower && buf.length >= 2) {
      const secondLast = buf[buf.length - 2];
      const secondLastIsUpper = secondLast >= "A" && secondLast <= "Z";
      if (secondLastIsUpper) {
        const tail = buf[buf.length - 1];
        buf = buf.slice(0, -1);
        push();
        buf = tail + ch;
        continue;
      }
    }
    buf += ch;
  }
  push();
  return tokens;
}

/**
 * Classify a raw identifier: find its first destructive verb, note bulk
 * markers, note soft markers. Returns ClassifiedName with
 * `destructive = null` when no destructive verb appears.
 */
export function classifyName(raw: string): ClassifiedName {
  const tokens = tokenise(raw);
  let destructive: VerbMatch | null = null;
  let bulk = false;
  const softMarkers: string[] = [];

  for (const tok of tokens) {
    if (!destructive && DESTRUCTIVE_VERB_SET.has(tok)) {
      const entry: VerbEntry = DESTRUCTIVE_VERBS[tok];
      destructive = { verb: tok, klass: entry.klass, implicitBulk: entry.implicitBulk };
      if (entry.implicitBulk) bulk = true;
    }
    if (BULK_MARKER_SET.has(tok)) bulk = true;
    if (SOFT_MARKER_SET.has(tok)) softMarkers.push(tok);
  }

  return { raw, tokens, destructive, bulk, softMarkers };
}

// ─── Description & schema introspection ────────────────────────────────────

/**
 * Walk a tool description word-by-word, emitting irreversibility markers.
 * Two-word markers (e.g. "cannot be undone") are joined with "_" to match
 * entries in IRREVERSIBILITY_MARKERS — the table keys are written in that
 * canonical form.
 */
export function findIrreversibilityMarkers(description: string): string[] {
  if (!description) return [];
  const normalised = description.toLowerCase();
  // Split on whitespace and punctuation we can't tokenise further. The
  // scanner walks positions manually to avoid producing an array literal
  // that would count toward the no-static-patterns guard.
  const words: string[] = [];
  let buf = "";
  for (let i = 0; i < normalised.length; i++) {
    const ch = normalised[i];
    const isLetter = (ch >= "a" && ch <= "z") || (ch >= "0" && ch <= "9");
    if (isLetter) {
      buf += ch;
    } else {
      if (buf) words.push(buf);
      buf = "";
    }
  }
  if (buf) words.push(buf);

  const found = new Set<string>();
  for (let i = 0; i < words.length; i++) {
    if (IRREVERSIBILITY_MARKER_SET.has(words[i])) {
      found.add(words[i]);
      continue;
    }
    // Try bigram and trigram joins for compound markers.
    if (i + 1 < words.length) {
      const bi = `${words[i]}_${words[i + 1]}`;
      if (IRREVERSIBILITY_MARKER_SET.has(bi)) found.add(bi);
    }
    if (i + 2 < words.length) {
      const tri = `${words[i]}_${words[i + 1]}_${words[i + 2]}`;
      if (IRREVERSIBILITY_MARKER_SET.has(tri)) found.add(tri);
    }
  }
  return [...found];
}

/**
 * Scan an input_schema for confirmation parameters. Returns one entry per
 * property whose NAME tokenises to any CONFIRMATION_PARAM_TOKENS key.
 * `required` is true when the schema's `required` array lists the param.
 */
export function findConfirmationParams(
  inputSchema: Record<string, unknown> | null,
): ConfirmationParam[] {
  if (!inputSchema || typeof inputSchema !== "object") return [];
  const props = inputSchema.properties;
  if (!props || typeof props !== "object") return [];
  const requiredList = Array.isArray(inputSchema.required)
    ? (inputSchema.required as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const required = new Set(requiredList);

  const out: ConfirmationParam[] = [];
  for (const paramName of Object.keys(props)) {
    const tokens = tokenise(paramName);
    // Also try the full lowercased name — handles dotted/underscored compounds
    // like `dry_run` that tokenise to ["dry", "run"] but appear in the set as
    // `dry_run` directly.
    const full = paramName.toLowerCase();
    let hit: ConfirmationKind | null = null;
    if (CONFIRMATION_PARAM_SET.has(full)) {
      hit = CONFIRMATION_PARAM_TOKENS[full];
    } else {
      for (const tok of tokens) {
        if (CONFIRMATION_PARAM_SET.has(tok)) {
          hit = CONFIRMATION_PARAM_TOKENS[tok];
          break;
        }
      }
    }
    if (hit) {
      out.push({
        name: paramName,
        kind: hit,
        required: required.has(paramName),
        jsonPointer: `/properties/${escapePointerSegment(paramName)}`,
      });
    }
  }
  return out;
}

/** Encode an RFC 6901 path segment: `~` → `~0`, `/` → `~1`. */
function escapePointerSegment(seg: string): string {
  let out = "";
  for (const ch of seg) {
    if (ch === "~") out += "~0";
    else if (ch === "/") out += "~1";
    else out += ch;
  }
  return out;
}
