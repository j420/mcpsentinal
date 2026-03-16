import { ALL_A_FIXTURES } from "./a-description.js";
import { ALL_B_FIXTURES } from "./b-schema.js";
import { ALL_C_FIXTURES } from "./c-code.js";
import { ALL_D_FIXTURES } from "./d-dependency.js";
import { ALL_E_FIXTURES } from "./e-behavioral.js";
import { ALL_G_FIXTURES } from "./g-adversarial.js";
import { ALL_I_FIXTURES } from "./i-protocol.js";
import { ALL_J_FIXTURES } from "./j-threat-intel.js";
import type { RuleFixtureSet } from "../types.js";

/**
 * All red team fixtures across all rule categories.
 *
 * Coverage:
 *   A (description-analysis) — A1-A9:  9 rules, ~70 fixtures
 *   B (schema-analysis)      — B1,B2,B5,B7: 4 sampled, ~20 fixtures
 *   C (code-analysis)        — C1,C2,C4,C5,C10,C12,C14,C16: 8 sampled, ~60 fixtures
 *   D (dependency-analysis)  — D1,D2,D5,D7: 4 sampled, ~20 fixtures
 *   E (behavioral-analysis)  — E1-E4: 4 rules, ~12 fixtures
 *   G (adversarial-ai)       — G1,G2,G4,G5,G7: 5 sampled, ~25 fixtures
 *   I (protocol-surface)     — I1,I2,I3,I4,I9,I11,I16: 7 sampled, ~35 fixtures
 *   J (threat-intelligence)  — J1-J7: 7 rules, ~42 fixtures
 *
 * F/H/K fixtures are covered via the composite/regex engine integration tests
 * in packages/analyzer — they require multi-tool context construction that is
 * better expressed as unit tests against the composite rule handlers directly.
 */
export const ALL_FIXTURES: RuleFixtureSet[] = [
  ...ALL_A_FIXTURES,
  ...ALL_B_FIXTURES,
  ...ALL_C_FIXTURES,
  ...ALL_D_FIXTURES,
  ...ALL_E_FIXTURES,
  ...ALL_G_FIXTURES,
  ...ALL_I_FIXTURES,
  ...ALL_J_FIXTURES,
];

export {
  ALL_A_FIXTURES,
  ALL_B_FIXTURES,
  ALL_C_FIXTURES,
  ALL_D_FIXTURES,
  ALL_E_FIXTURES,
  ALL_G_FIXTURES,
  ALL_I_FIXTURES,
  ALL_J_FIXTURES,
};

/** Quick lookup: rule_id → fixture set */
export function getFixturesForRule(ruleId: string): RuleFixtureSet | undefined {
  return ALL_FIXTURES.find((fs) => fs.rule_id === ruleId);
}
