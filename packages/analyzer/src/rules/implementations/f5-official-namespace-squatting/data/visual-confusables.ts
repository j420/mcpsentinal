/**
 * F5 visual-confusable substitution table.
 *
 * A small, curated set of single-character ASCII substitutions that
 * render visually identical (or near-identical) in the monospaced
 * fonts most MCP client approval dialogs use. The rule applies these
 * substitutions in both directions before re-running the distance
 * comparison, catching attacks where byte-space distance is >2 but
 * visual distance is 0.
 *
 * This is NOT a full Unicode confusables table — that belongs to A6
 * and D3. F5 needs only the ASCII variants because server names in
 * public MCP registries are predominantly ASCII.
 *
 * Keep the map short — the no-static-patterns guard tolerates long
 * Record literals but not long string arrays.
 */

export const VISUAL_ASCII_CONFUSABLES: Record<string, string> = {
  "0": "o",
  "1": "l",
  "5": "s",
  rn: "m",
};
