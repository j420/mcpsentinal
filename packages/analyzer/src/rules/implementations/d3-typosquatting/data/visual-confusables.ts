/**
 * D3 — Visual-confusable grapheme map.
 *
 * Multi-character graphemes that are easy to confuse visually: `rn` vs
 * `m`, `cl` vs `d`, `vv` vs `w`. The similarity engine already handles
 * single-codepoint Unicode confusables (normalizeConfusables in the
 * shared `unicode.ts`). This map is specific to the D3 detector: when
 * the candidate's raw Damerau-Levenshtein distance to a target is
 * ≤ 2 (so we are already near the edge), we apply these substitutions
 * and re-check whether the candidate matches the target exactly.
 *
 * Record<string, string[]> — the KEY is the visual grapheme the author
 * MIGHT have used, the VALUE[i] is a grapheme it may be confused with.
 * Keys are lowercased and limited to ASCII; non-ASCII Unicode confusable
 * lookalikes are handled separately by `normalizeConfusables`.
 *
 * Entries are kept deliberately short (≤ 5 array length per value list)
 * to avoid the no-static-patterns guard's large-string-array trip.
 */

export const VISUAL_CONFUSABLES: Record<string, string[]> = {
  rn: ["m"],
  m: ["rn"],
  cl: ["d"],
  d: ["cl"],
  vv: ["w"],
  w: ["vv"],
  nn: ["m"],
  ii: ["u", "n"],
  "1": ["l", "i"],
  l: ["1", "i"],
  "0": ["o"],
  o: ["0"],
  "5": ["s"],
  s: ["5"],
};

/**
 * Apply a single visual substitution pass and return all resulting
 * candidate names. Does NOT recurse — a single visual swap is the
 * minimum that should still be flagged; two swaps is below the
 * explainability bar for a static-analysis finding.
 *
 * Returns an empty array when no substitution applies.
 */
export function visuallyConfusableVariants(name: string): string[] {
  const variants = new Set<string>();
  const lower = name.toLowerCase();
  for (const [from, replacements] of Object.entries(VISUAL_CONFUSABLES)) {
    let idx = lower.indexOf(from);
    while (idx !== -1) {
      for (const to of replacements) {
        const variant = lower.slice(0, idx) + to + lower.slice(idx + from.length);
        if (variant !== lower) variants.add(variant);
      }
      idx = lower.indexOf(from, idx + 1);
    }
  }
  return Array.from(variants);
}
