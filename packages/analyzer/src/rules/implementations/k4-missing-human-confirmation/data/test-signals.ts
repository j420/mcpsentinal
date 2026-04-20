/**
 * K4 test-file structural signals.
 *
 * K4 must not fire inside test files — a test that `await db.deleteAll()`
 * against a fixture database is a legitimate engineering practice, not a
 * compliance gap. BUT: naming a production entry point `*.test.ts` is a
 * trivial attacker camouflage, so the rule identifies test files
 * STRUCTURALLY (AST-derived signals) rather than by filename.
 *
 * A file is considered a test file when BOTH hold:
 *
 *   (1) a top-level statement calls a test-runner function by bare name —
 *       `describe(...)`, `it(...)`, `test(...)`, `suite(...)`, `specify(...)`;
 *
 *   (2) AND the file contains at least one of:
 *        - an import/require specifier from TEST_RUNNER_MODULES below,
 *        - a test-sentinel variable declaration (e.g. `const { expect }`
 *          destructured from a runner module),
 *        - multiple top-level test-runner calls (>=2 — implausible for
 *          an attacker to camouflage).
 *
 * This is pure AST analysis — no regex, no filename peek.
 */

/** Test-runner module specifiers we recognise in `import ... from "..."` / `require("...")`. */
export const TEST_RUNNER_MODULES: Record<string, true> = {
  vitest: true,
  jest: true,
  "@jest/globals": true,
  mocha: true,
  "node:test": true,
  tap: true,
  ava: true,
  jasmine: true,
  uvu: true,
  "bun:test": true,
};

/**
 * Bare identifiers that, when called as top-level statements, signal a
 * test-framework suite declaration. Check at AST level: the statement
 * must be an ExpressionStatement whose expression is a CallExpression
 * whose callee is an Identifier in this set.
 */
export const TEST_TOPLEVEL_FUNCTIONS: Record<string, true> = {
  describe: true,
  it: true,
  test: true,
  suite: true,
  specify: true,
  context: true,
};
