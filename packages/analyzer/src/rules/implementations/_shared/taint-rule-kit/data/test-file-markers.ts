/**
 * Test-file marker registry (shared across all six taint-based rules).
 *
 * Lives in `data/` so the no-static-patterns guard skips it. The markers
 * themselves are plain substrings — no regex. gather.ts uses
 * `String.prototype.includes()` against each marker in turn; any hit
 * short-circuits the rule and the finding list stays empty.
 *
 * The array is allowed to be > 5 elements because this file is under
 * `data/`. Callers receive the data as a typed export so the rest of the
 * kit stays entirely data-pattern-free.
 */

export const TEST_FILE_MARKERS: readonly string[] = [
  "__tests__",
  "__test__",
  ".test.",
  ".spec.",
  "from 'vitest'",
  'from "vitest"',
  "describe(",
  "it.only(",
  "it.each(",
  "test(",
  "beforeEach(",
  "afterEach(",
];
