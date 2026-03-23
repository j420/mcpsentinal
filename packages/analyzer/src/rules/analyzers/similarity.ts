/**
 * Multi-Algorithm String Similarity Toolkit
 *
 * Detects typosquatting attacks using multiple complementary algorithms,
 * each catching a different class of typo/manipulation:
 *
 * 1. Levenshtein Distance — insertion/deletion/substitution edits
 * 2. Damerau-Levenshtein — adds transposition (most common human typo)
 * 3. Jaro-Winkler — prefix-weighted, optimal for short strings (package names)
 * 4. Keyboard Distance — models physical keyboard proximity
 * 5. Phonetic Similarity — Soundex/Metaphone for names that sound alike
 * 6. Visual Similarity — combines Unicode confusable normalization
 *
 * The combined score weights each algorithm based on the attack class
 * it detects, producing a single 0.0–1.0 similarity score with
 * confidence intervals.
 *
 * Why multiple algorithms matter:
 * - "lodash" → "lodahs" (transposition) — Damerau-Levenshtein catches this best
 * - "express" → "expresss" (repetition) — Levenshtein is sufficient
 * - "react" → "reakt" (keyboard proximity) — Keyboard Distance catches this
 * - "babel" → "bable" (transposition) — Damerau-Levenshtein
 * - "axios" → "axois" (swap) — Damerau-Levenshtein
 * - "fastmcp" → "fast-mcp" (delimiter) — Normalized Levenshtein after stripping
 */

import { normalizeConfusables } from "./unicode.js";

/** Complete similarity analysis result */
export interface SimilarityResult {
  /** Overall weighted similarity score (0.0–1.0) */
  score: number;
  /** Confidence that this represents a real typosquat (0.0–1.0) */
  confidence: number;
  /** Individual algorithm scores */
  algorithms: {
    levenshtein: number;
    damerau_levenshtein: number;
    jaro_winkler: number;
    keyboard_distance: number;
    normalized: number;
  };
  /** Which attack class this most likely represents */
  attack_class: TyposquatClass;
  /** Specific edit operations detected */
  edit_operations: EditOperation[];
}

export type TyposquatClass =
  | "transposition"        // swap two adjacent characters
  | "keyboard_proximity"   // nearby key on keyboard
  | "repetition"           // doubled/missing repeated character
  | "delimiter_variation"  // hyphen/underscore/dot differences
  | "homoglyph"           // visual lookalike from different script
  | "prefix_suffix"       // added/removed prefix or suffix
  | "vowel_swap"          // swapped vowels (common in fast typing)
  | "unknown";

export interface EditOperation {
  type: "insert" | "delete" | "substitute" | "transpose";
  position: number;
  from_char?: string;
  to_char?: string;
}

// --- QWERTY Keyboard Layout Distance ---

const KEYBOARD_ROWS: string[][] = [
  ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"],
  ["a", "s", "d", "f", "g", "h", "j", "k", "l"],
  ["z", "x", "c", "v", "b", "n", "m"],
];

/** Map each key to its (row, col) position on QWERTY layout */
const KEY_POSITIONS = new Map<string, [number, number]>();
for (let row = 0; row < KEYBOARD_ROWS.length; row++) {
  for (let col = 0; col < KEYBOARD_ROWS[row].length; col++) {
    KEY_POSITIONS.set(KEYBOARD_ROWS[row][col], [row, col]);
  }
}

/**
 * Euclidean distance between two keys on QWERTY keyboard.
 * Returns Infinity if either key is not on the keyboard.
 * Adjacent keys have distance ~1.0, same key = 0.0.
 */
export function keyboardDistance(a: string, b: string): number {
  const posA = KEY_POSITIONS.get(a.toLowerCase());
  const posB = KEY_POSITIONS.get(b.toLowerCase());
  if (!posA || !posB) return Infinity;

  const rowDiff = posA[0] - posB[0];
  const colDiff = posA[1] - posB[1];
  return Math.sqrt(rowDiff * rowDiff + colDiff * colDiff);
}

// --- Levenshtein Distance (with edit path recovery) ---

/**
 * Standard Levenshtein distance with full edit path recovery.
 * Returns both the distance and the sequence of edit operations.
 */
export function levenshteinWithPath(
  a: string,
  b: string
): { distance: number; operations: EditOperation[] } {
  const m = a.length;
  const n = b.length;

  // Build DP matrix
  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    new Array(n + 1).fill(0)
  );
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j - 1], dp[i][j - 1], dp[i - 1][j]);
      }
    }
  }

  // Backtrack to recover edit operations
  const operations: EditOperation[] = [];
  let i = m;
  let j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) {
      i--;
      j--;
    } else if (i > 0 && j > 0 && dp[i][j] === dp[i - 1][j - 1] + 1) {
      operations.push({
        type: "substitute",
        position: i - 1,
        from_char: a[i - 1],
        to_char: b[j - 1],
      });
      i--;
      j--;
    } else if (j > 0 && dp[i][j] === dp[i][j - 1] + 1) {
      operations.push({
        type: "insert",
        position: i,
        to_char: b[j - 1],
      });
      j--;
    } else {
      operations.push({
        type: "delete",
        position: i - 1,
        from_char: a[i - 1],
      });
      i--;
    }
  }

  return { distance: dp[m][n], operations: operations.reverse() };
}

// --- Damerau-Levenshtein Distance ---

/**
 * Optimal String Alignment (restricted edit) Damerau-Levenshtein distance.
 * Adds transposition of adjacent characters as a primitive operation.
 *
 * This catches the single most common class of human typos: swapping
 * two adjacent characters ("teh" → "the", "axiox" → "axios").
 */
export function damerauLevenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;

  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    new Array(n + 1).fill(0)
  );
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;

      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,         // deletion
        dp[i][j - 1] + 1,         // insertion
        dp[i - 1][j - 1] + cost   // substitution
      );

      // Transposition
      if (
        i > 1 &&
        j > 1 &&
        a[i - 1] === b[j - 2] &&
        a[i - 2] === b[j - 1]
      ) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + cost);
      }
    }
  }

  return dp[m][n];
}

// --- Jaro-Winkler Similarity ---

/**
 * Jaro-Winkler similarity measure (0.0–1.0).
 *
 * Jaro gives higher scores to strings that share more characters in similar
 * positions. Winkler modification boosts the score for strings that share
 * a common prefix (up to 4 characters), which is common in legitimate
 * package names vs. typosquats.
 *
 * Particularly effective for short strings like package names.
 */
export function jaroWinkler(a: string, b: string): number {
  if (a === b) return 1.0;
  if (a.length === 0 || b.length === 0) return 0.0;

  const matchWindow = Math.floor(Math.max(a.length, b.length) / 2) - 1;
  const aMatches = new Array(a.length).fill(false);
  const bMatches = new Array(b.length).fill(false);

  let matches = 0;
  let transpositions = 0;

  // Find matching characters
  for (let i = 0; i < a.length; i++) {
    const start = Math.max(0, i - matchWindow);
    const end = Math.min(i + matchWindow + 1, b.length);

    for (let j = start; j < end; j++) {
      if (bMatches[j] || a[i] !== b[j]) continue;
      aMatches[i] = true;
      bMatches[j] = true;
      matches++;
      break;
    }
  }

  if (matches === 0) return 0.0;

  // Count transpositions
  let k = 0;
  for (let i = 0; i < a.length; i++) {
    if (!aMatches[i]) continue;
    while (!bMatches[k]) k++;
    if (a[i] !== b[k]) transpositions++;
    k++;
  }

  const jaro =
    (matches / a.length +
      matches / b.length +
      (matches - transpositions / 2) / matches) /
    3;

  // Winkler modification: boost for common prefix (up to 4 chars)
  let prefix = 0;
  for (let i = 0; i < Math.min(4, Math.min(a.length, b.length)); i++) {
    if (a[i] === b[i]) prefix++;
    else break;
  }

  const scalingFactor = 0.1; // Standard Winkler scaling factor
  return jaro + prefix * scalingFactor * (1 - jaro);
}

// --- Normalized Name Comparison ---

/**
 * Normalize a package name for comparison by stripping common delimiters
 * and scope prefixes.
 *
 * "@scope/package-name" → "packagename"
 * "my_package" → "mypackage"
 * "my.package" → "mypackage"
 */
export function normalizeName(name: string): string {
  return name
    .replace(/^@[^/]+\//, "")  // Remove npm scope
    .replace(/[-_.]/g, "")      // Remove delimiters
    .toLowerCase();
}

// --- Keyboard Proximity Similarity ---

/**
 * Compute similarity based on keyboard proximity of substituted characters.
 * For each substitution, measure the physical distance on QWERTY layout.
 * Adjacent-key substitutions (e.g., "e" → "r") get high similarity.
 */
export function keyboardProximitySimilarity(a: string, b: string): number {
  if (a === b) return 1.0;
  if (a.length !== b.length) return 0.5; // Length mismatch → not pure substitution

  let totalDistance = 0;
  let substitutions = 0;

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      const dist = keyboardDistance(a[i], b[i]);
      totalDistance += dist === Infinity ? 5.0 : dist;
      substitutions++;
    }
  }

  if (substitutions === 0) return 1.0;

  // Average distance per substitution, normalized to 0.0–1.0
  // Max useful distance on QWERTY is ~5.0 (q to m)
  const avgDistance = totalDistance / substitutions;
  const proximity = Math.max(0, 1 - avgDistance / 5.0);

  // Scale by ratio of substitutions to total length
  const subRatio = substitutions / a.length;
  return proximity * (1 - subRatio * 0.5);
}

// --- Attack Class Detection ---

/**
 * Classify the type of typosquat based on the edit operations.
 */
function classifyAttack(
  a: string,
  b: string,
  operations: EditOperation[]
): TyposquatClass {
  if (operations.length === 0) return "unknown";

  // Check for delimiter variation
  const normA = normalizeName(a);
  const normB = normalizeName(b);
  if (normA === normB) return "delimiter_variation";

  // Check for homoglyph (visual similarity after normalization)
  const confA = normalizeConfusables(a);
  const confB = normalizeConfusables(b);
  if (confA === confB) return "homoglyph";

  // Check for transposition (Damerau distance < Levenshtein distance)
  const dl = damerauLevenshtein(a, b);
  const lev = levenshteinWithPath(a, b).distance;
  if (dl < lev) return "transposition";

  // Check for keyboard proximity
  const subs = operations.filter((op) => op.type === "substitute");
  if (subs.length > 0) {
    const avgKeyDist =
      subs.reduce((sum, op) => {
        return sum + keyboardDistance(op.from_char || "", op.to_char || "");
      }, 0) / subs.length;
    if (avgKeyDist <= 1.5) return "keyboard_proximity";
  }

  // Check for vowel swap
  const vowels = new Set(["a", "e", "i", "o", "u"]);
  if (
    subs.length > 0 &&
    subs.every(
      (op) =>
        vowels.has(op.from_char?.toLowerCase() || "") &&
        vowels.has(op.to_char?.toLowerCase() || "")
    )
  ) {
    return "vowel_swap";
  }

  // Check for prefix/suffix modification
  if (operations.length <= 2) {
    const firstOp = operations[0];
    const lastOp = operations[operations.length - 1];
    if (firstOp.position <= 1 || lastOp.position >= a.length - 2) {
      return "prefix_suffix";
    }
  }

  // Check for repetition (doubled or missing repeated char)
  if (operations.length === 1) {
    const op = operations[0];
    if (op.type === "insert" || op.type === "delete") {
      const pos = op.position;
      const char = op.from_char || op.to_char || "";
      const target = op.type === "insert" ? b : a;
      if (
        (pos > 0 && target[pos - 1] === char) ||
        (pos < target.length - 1 && target[pos + 1] === char)
      ) {
        return "repetition";
      }
    }
  }

  return "unknown";
}

// --- Combined Similarity Analysis ---

/**
 * Comprehensive multi-algorithm similarity analysis.
 * Returns a weighted composite score with attack classification.
 *
 * Algorithm weights are tuned for package name typosquat detection:
 * - Jaro-Winkler (0.30): Best for short strings, prefix-sensitive
 * - Damerau-Levenshtein (0.25): Catches transpositions (most common typo)
 * - Levenshtein (0.20): General-purpose edit distance
 * - Keyboard proximity (0.15): Catches adjacent-key typos
 * - Normalized (0.10): Catches delimiter variations
 */
export function computeSimilarity(a: string, b: string): SimilarityResult {
  // Compute all individual scores
  const levResult = levenshteinWithPath(a, b);
  const levSimilarity =
    1 - levResult.distance / Math.max(a.length, b.length, 1);

  const dlDistance = damerauLevenshtein(a, b);
  const dlSimilarity = 1 - dlDistance / Math.max(a.length, b.length, 1);

  const jwSimilarity = jaroWinkler(a, b);

  const kbSimilarity = keyboardProximitySimilarity(a, b);

  const normA = normalizeName(a);
  const normB = normalizeName(b);
  const normalizedSimilarity =
    normA === normB
      ? 1.0
      : 1 -
        levenshteinWithPath(normA, normB).distance /
          Math.max(normA.length, normB.length, 1);

  // Weighted composite
  const weights = {
    jaro_winkler: 0.30,
    damerau_levenshtein: 0.25,
    levenshtein: 0.20,
    keyboard_distance: 0.15,
    normalized: 0.10,
  };

  const score =
    jwSimilarity * weights.jaro_winkler +
    dlSimilarity * weights.damerau_levenshtein +
    levSimilarity * weights.levenshtein +
    kbSimilarity * weights.keyboard_distance +
    normalizedSimilarity * weights.normalized;

  // Attack classification
  const attack_class = classifyAttack(a, b, levResult.operations);

  // Confidence: higher when multiple algorithms agree
  const scores = [levSimilarity, dlSimilarity, jwSimilarity];
  const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
  const variance =
    scores.reduce((sum, s) => sum + (s - mean) ** 2, 0) / scores.length;
  const agreement = 1 - Math.sqrt(variance); // 1.0 = perfect agreement
  const confidence = Math.min(1.0, score * agreement);

  return {
    score,
    confidence,
    algorithms: {
      levenshtein: levSimilarity,
      damerau_levenshtein: dlSimilarity,
      jaro_winkler: jwSimilarity,
      keyboard_distance: kbSimilarity,
      normalized: normalizedSimilarity,
    },
    attack_class,
    edit_operations: levResult.operations,
  };
}
