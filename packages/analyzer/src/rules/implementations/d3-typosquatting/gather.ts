/**
 * D3 evidence gathering — deterministic similarity classification.
 *
 * The threat researcher's charter (CHARTER.md) specifies the edge cases.
 * This file is the engineer's translation into structural queries over
 * the dependency list and the shared similarity toolkit. It does NOT
 * produce findings — `index.ts` consumes the gathered facts and builds
 * the evidence chain.
 *
 * No regex literals. No string-literal arrays of length > 5.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  damerauLevenshtein,
  jaroWinkler,
  normalizeName,
} from "../../analyzers/similarity.js";
import { normalizeConfusables } from "../../analyzers/unicode.js";
import {
  ALL_TARGETS,
  type Ecosystem,
  type TargetPackage,
} from "./data/target-packages.js";
import { CONFIRMED_TYPOSQUATS } from "./data/confirmed-typosquats.js";
import {
  LEGITIMATE_FORKS,
  LEGITIMATE_PREFIX_TOKENS,
  LEGITIMATE_SUFFIX_TOKENS,
} from "./data/legitimate-forks.js";
import { visuallyConfusableVariants } from "./data/visual-confusables.js";

/** Algorithmic agreement gate — Jaro-Winkler must clear this to emit a distance-only finding. */
const JARO_WINKLER_AGREEMENT_FLOOR = 0.8;

/** Classification of how a typosquat candidate was matched. */
export type TyposquatClassifier =
  | "confirmed-typosquat"
  | "scope-squat"
  | "levenshtein-near"
  | "visual-confusable"
  | "unicode-confusable";

export interface TyposquatSite {
  /** Structured Location for the dependency entry. */
  dependencyLocation: Location; // kind: "dependency"
  /** Structured Location for the package.json dependency pointer. */
  configLocation: Location; // kind: "config"
  /** Declared dependency name (raw, as it appears in the manifest). */
  candidate: string;
  /** Ecosystem the dependency belongs to. */
  ecosystem: Ecosystem;
  /** Package version as declared (or null if not declared). */
  version: string;
  /** The canonical target the candidate shadows. */
  target: string;
  /** Target metadata, copied for convenience. */
  targetMeta: TargetPackage;
  /** Classifier that produced this finding. */
  classifier: TyposquatClassifier;
  /** Damerau-Levenshtein distance between candidate and target (or between normalised names). */
  distance: number;
  /** Jaro-Winkler similarity between candidate and target. */
  jaroWinklerScore: number;
  /** When visual-confusable matched: the normalised variant that hit the target. */
  visualVariant: string | null;
  /** When Unicode-confusable matched: the normalised variant. */
  unicodeVariant: string | null;
}

export interface D3Gathered {
  sites: TyposquatSite[];
}

// ─── Public entry point ────────────────────────────────────────────────────

export function gatherD3(context: AnalysisContext): D3Gathered {
  const sites: TyposquatSite[] = [];

  for (const dep of context.dependencies) {
    const name = dep.name;
    if (!name) continue;

    // Legitimate-fork allowlist — drop candidate entirely.
    if (LEGITIMATE_FORKS[name]) continue;

    // Exact canonical hit — not a typosquat.
    if (ALL_TARGETS[name]) continue;

    // Structural suffix/prefix tokens that indicate a legitimate variant.
    if (hasLegitimateShape(name)) continue;

    // Version-suffix strip (react-18, webpack-5) — strip numeric suffix before comparisons.
    const stripped = stripNumericSuffix(name);

    const site = classify(dep, name, stripped);
    if (site) sites.push(site);
  }

  return { sites };
}

// ─── Classifiers ───────────────────────────────────────────────────────────

function classify(
  dep: { name: string; version: string | null },
  candidate: string,
  stripped: string,
): TyposquatSite | null {
  const version = dep.version ?? "unknown";

  // 1. CONFIRMED-TYPOSQUAT — external advisory registry hit.
  const confirmed = CONFIRMED_TYPOSQUATS[candidate];
  if (confirmed) {
    const targetMeta: TargetPackage = ALL_TARGETS[confirmed.shadows] ?? {
      ecosystem: confirmed.ecosystem,
      max_distance: 3,
    };
    return makeSite({
      candidate,
      version,
      target: confirmed.shadows,
      targetMeta,
      classifier: "confirmed-typosquat",
      distance: damerauLevenshtein(candidate, confirmed.shadows),
      jaroWinklerScore: jaroWinkler(candidate, confirmed.shadows),
      visualVariant: null,
      unicodeVariant: null,
    });
  }

  // 2. SCOPE-SQUAT — candidate's unscoped tail matches a scoped_official's tail
  //    under a different scope.
  const scopeSquat = findScopeSquatTarget(candidate);
  if (scopeSquat) {
    return makeSite({
      candidate,
      version,
      target: scopeSquat.target,
      targetMeta: scopeSquat.targetMeta,
      classifier: "scope-squat",
      distance: damerauLevenshtein(candidate, scopeSquat.target),
      jaroWinklerScore: jaroWinkler(candidate, scopeSquat.target),
      visualVariant: null,
      unicodeVariant: null,
    });
  }

  // 3. UNICODE-CONFUSABLE — Cyrillic/Greek lookalike normalises to a target.
  const unicodeNormalised = normalizeConfusables(candidate);
  if (unicodeNormalised !== candidate) {
    const hit = ALL_TARGETS[unicodeNormalised]
      ? unicodeNormalised
      : findTargetByNormalisedName(unicodeNormalised);
    if (hit) {
      return makeSite({
        candidate,
        version,
        target: hit,
        targetMeta: ALL_TARGETS[hit],
        classifier: "unicode-confusable",
        distance: damerauLevenshtein(candidate, hit),
        jaroWinklerScore: jaroWinkler(candidate, hit),
        visualVariant: null,
        unicodeVariant: unicodeNormalised,
      });
    }
  }

  // 4. LEVENSHTEIN-NEAR — Damerau-Levenshtein under the target's declared ceiling,
  //    with Jaro-Winkler agreement > 0.80.
  const best = findBestDistanceTarget(stripped);
  if (best) {
    return makeSite({
      candidate,
      version,
      target: best.target,
      targetMeta: best.targetMeta,
      classifier: "levenshtein-near",
      distance: best.distance,
      jaroWinklerScore: best.jaroWinkler,
      visualVariant: null,
      unicodeVariant: null,
    });
  }

  // 5. VISUAL-CONFUSABLE — ASCII grapheme replacement yields a target match.
  const visual = findVisualConfusableTarget(candidate);
  if (visual) {
    return makeSite({
      candidate,
      version,
      target: visual.target,
      targetMeta: visual.targetMeta,
      classifier: "visual-confusable",
      distance: damerauLevenshtein(candidate, visual.target),
      jaroWinklerScore: jaroWinkler(candidate, visual.target),
      visualVariant: visual.variant,
      unicodeVariant: null,
    });
  }

  return null;
}

// ─── Structural filters ────────────────────────────────────────────────────

function hasLegitimateShape(name: string): boolean {
  for (const suffix of LEGITIMATE_SUFFIX_TOKENS) {
    if (name.endsWith(suffix)) {
      // The stripped core must correspond to a target OR a known package
      // family. Otherwise treat suffix as not meaningful.
      const core = name.slice(0, name.length - suffix.length);
      if (ALL_TARGETS[core]) return true;
    }
  }
  for (const prefix of LEGITIMATE_PREFIX_TOKENS) {
    if (name.startsWith(prefix)) {
      const tail = name.slice(prefix.length);
      if (ALL_TARGETS[tail]) return true;
    }
  }
  return false;
}

function stripNumericSuffix(name: string): string {
  // Strip trailing `-<digits>` or `.<digits>` for version-suffixed packages.
  // Hand-rolled (no regex) — walk from the end.
  let end = name.length;
  let sawDigit = false;
  while (end > 0 && isAsciiDigit(name.charCodeAt(end - 1))) {
    sawDigit = true;
    end--;
  }
  if (!sawDigit || end === 0) return name;
  const sep = name.charCodeAt(end - 1);
  if (sep === 0x2d /* - */ || sep === 0x2e /* . */) {
    const core = name.slice(0, end - 1);
    return core.length >= 3 ? core : name;
  }
  return name;
}

function isAsciiDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

// ─── Similarity engines ────────────────────────────────────────────────────

function findBestDistanceTarget(stripped: string): {
  target: string;
  targetMeta: TargetPackage;
  distance: number;
  jaroWinkler: number;
} | null {
  let best: {
    target: string;
    targetMeta: TargetPackage;
    distance: number;
    jaroWinkler: number;
  } | null = null;

  for (const [target, meta] of Object.entries(ALL_TARGETS)) {
    const normTarget = normalizeName(target);
    const normCand = normalizeName(stripped);

    // Quick pre-filter — avoid quadratic Damerau on obviously disjoint names.
    if (Math.abs(normTarget.length - normCand.length) > meta.max_distance + 1) continue;
    // Normalisation-equivalent hit — this is an exact match after stripping.
    if (normTarget === normCand) continue;

    const distance = damerauLevenshtein(normCand, normTarget);
    if (distance === 0 || distance > meta.max_distance) continue;

    const jw = jaroWinkler(stripped, target);
    if (jw < JARO_WINKLER_AGREEMENT_FLOOR) continue;

    if (!best || distance < best.distance || (distance === best.distance && jw > best.jaroWinkler)) {
      best = { target, targetMeta: meta, distance, jaroWinkler: jw };
    }
  }

  return best;
}

function findTargetByNormalisedName(unicodeNormalised: string): string | null {
  const key = normalizeName(unicodeNormalised);
  for (const target of Object.keys(ALL_TARGETS)) {
    if (normalizeName(target) === key) return target;
  }
  return null;
}

function findScopeSquatTarget(candidate: string): {
  target: string;
  targetMeta: TargetPackage;
} | null {
  // Extract the candidate's unscoped tail.
  const candScope = extractScope(candidate);
  const candTail = extractUnscopedTail(candidate);
  if (!candTail) return null;

  for (const [target, meta] of Object.entries(ALL_TARGETS)) {
    if (!meta.scoped_official) continue;
    const targetScope = extractScope(target);
    const targetTail = extractUnscopedTail(target);
    if (!targetTail) continue;

    // Same tail, different scope (including no scope at all on the candidate) — scope squat.
    if (candTail === targetTail && candScope !== targetScope) {
      return { target, targetMeta: meta };
    }

    // Unscoped-alias match — the target declares an explicit unscoped alias
    // (for cases where the tail alone is too generic, the alias is stricter).
    if (meta.unscoped_alias && candTail === meta.unscoped_alias && candScope !== targetScope) {
      return { target, targetMeta: meta };
    }
  }

  return null;
}

function findVisualConfusableTarget(
  candidate: string,
): { target: string; targetMeta: TargetPackage; variant: string } | null {
  const variants = visuallyConfusableVariants(candidate);
  for (const variant of variants) {
    if (ALL_TARGETS[variant]) {
      return { target: variant, targetMeta: ALL_TARGETS[variant], variant };
    }
    // Damerau-Levenshtein on the variant — catch cases where the grapheme
    // swap lands within distance 1 of a target.
    for (const [target, meta] of Object.entries(ALL_TARGETS)) {
      const d = damerauLevenshtein(variant, target);
      if (d <= 1 && variant.length >= 3) {
        return { target, targetMeta: meta, variant };
      }
    }
  }
  return null;
}

// ─── Location plumbing ─────────────────────────────────────────────────────

function makeSite(args: {
  candidate: string;
  version: string;
  target: string;
  targetMeta: TargetPackage;
  classifier: TyposquatClassifier;
  distance: number;
  jaroWinklerScore: number;
  visualVariant: string | null;
  unicodeVariant: string | null;
}): TyposquatSite {
  const ecosystem = args.targetMeta.ecosystem;
  const dependencyLocation: Location = {
    kind: "dependency",
    ecosystem,
    name: args.candidate,
    version: args.version,
  };
  const configLocation: Location = {
    kind: "config",
    file: ecosystem === "npm" ? "package.json" : "pyproject.toml",
    json_pointer: buildDependencyPointer(ecosystem, args.candidate),
  };
  return {
    dependencyLocation,
    configLocation,
    candidate: args.candidate,
    ecosystem,
    version: args.version,
    target: args.target,
    targetMeta: args.targetMeta,
    classifier: args.classifier,
    distance: args.distance,
    jaroWinklerScore: args.jaroWinklerScore,
    visualVariant: args.visualVariant,
    unicodeVariant: args.unicodeVariant,
  };
}

function buildDependencyPointer(ecosystem: Ecosystem, name: string): string {
  const escaped = escapeJsonPointerSegment(name);
  return ecosystem === "npm" ? `/dependencies/${escaped}` : `/project/dependencies/${escaped}`;
}

function escapeJsonPointerSegment(segment: string): string {
  // RFC 6901: '~' → '~0', '/' → '~1'. Build by scan so we don't use regex.
  const chars: string[] = [];
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (ch === "~") chars.push("~0");
    else if (ch === "/") chars.push("~1");
    else chars.push(ch);
  }
  return chars.join("");
}

// ─── Scope utilities (hand-rolled — no regex) ──────────────────────────────

function extractScope(name: string): string | null {
  if (name.length === 0 || name.charCodeAt(0) !== 0x40 /* @ */) return null;
  const slash = name.indexOf("/");
  if (slash <= 1) return null;
  return name.slice(0, slash);
}

function extractUnscopedTail(name: string): string | null {
  const slash = name.indexOf("/");
  if (slash === -1) return name || null;
  if (name.charCodeAt(0) !== 0x40 /* @ */) return name;
  const tail = name.slice(slash + 1);
  return tail.length > 0 ? tail : null;
}
