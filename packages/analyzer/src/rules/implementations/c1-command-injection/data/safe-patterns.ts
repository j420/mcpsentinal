/**
 * C1 safe-pattern registry — patterns that, when present on a line, suppress
 * a regex-fallback finding for that line.
 *
 * Loaded at module scope by gather.ts. The regex literals live in this `data/`
 * file so the no-static-patterns guard (which skips the data directory) leaves
 * them alone, while keeping every other file in the rule directory regex-free.
 *
 * Two tiers:
 *   - TEST_FILE_SHAPE — if the entire source file matches any of these, skip
 *     the rule altogether. Applies to whole-file heuristics.
 *   - LINE_SAFE — if a line matches, drop any fallback finding that would
 *     otherwise fire on that line (e.g. `execFile`, `// nosec`).
 */

export interface SafePattern {
  id: string;
  pattern: RegExp;
  rationale: string;
}

/** Whole-file shape that tells us this is a test fixture, not production code. */
export const TEST_FILE_SHAPES: Record<string, SafePattern> = {
  testsDirectory: {
    id: "tests-directory",
    pattern: /__tests?__/,
    rationale: "path segment indicates a dedicated test directory",
  },
  testSpecExtension: {
    id: "test-spec-extension",
    pattern: /\.(?:test|spec)\./,
    rationale: "file extension tags this as a vitest/jest/mocha fixture",
  },
};

/** Line-level safety — the match is shadowed by an adjacent safe alternative. */
export const LINE_SAFE_PATTERNS: Record<string, SafePattern> = {
  execFile: {
    id: "execFile",
    pattern: /exec(?:File|FileSync)\s*\(/,
    rationale: "execFile / execFileSync is the safe argv-form alternative to exec()",
  },
  nosecDirective: {
    id: "nosec",
    pattern: /\/\/\s*nosec/,
    rationale: "developer annotated the line with // nosec — treat as audited-safe",
  },
  developerSafeComment: {
    id: "developer-safe-comment",
    pattern: /\/\/\s*safe:/,
    rationale: "developer annotated the line with // safe: — treat as audited-safe",
  },
};
