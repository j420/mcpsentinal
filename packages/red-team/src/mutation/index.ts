/**
 * Mutation suite — public exports.
 *
 * The mutation auditor is imported by:
 *   - `packages/red-team/src/mutation/cli.ts` (CLI entry)
 *   - `packages/analyzer/__tests__/mutation-charter-parity.test.ts` (parity guard)
 *   - per-mutation unit tests under `__tests__/`
 */

export { MUTATION_CATALOGUE } from "./mutations/index.js";
export {
  runMutationAudit,
  renderMarkdownReport,
  type MutationRunOptions,
} from "./runner.js";
export {
  MUTATION_IDS,
  type MutationId,
  type MutationFn,
  type MutationResult,
  type MutationOutcome,
  type MutationOutcomeLabel,
  type MutationReport,
  type PerRuleSummary,
} from "./types.js";
export {
  loadFixture,
  buildContextFromSource,
  classifyFixture,
  listTruePositiveFixtures,
  type LoadedFixture,
  type FixtureKind,
} from "./fixture-loader.js";
