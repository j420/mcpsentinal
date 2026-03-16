import { ALL_A_FIXTURES } from "./a-description.js";
import { ALL_B_FIXTURES } from "./b-schema.js";
import { ALL_C_FIXTURES } from "./c-code.js";
import { ALL_D_FIXTURES } from "./d-dependency.js";
import { ALL_E_FIXTURES } from "./e-behavioral.js";
import { ALL_F_FIXTURES } from "./f-ecosystem.js";
import { ALL_G_FIXTURES } from "./g-adversarial.js";
import { ALL_H_FIXTURES } from "./h-2026.js";
import { ALL_I_FIXTURES } from "./i-protocol.js";
import { ALL_J_FIXTURES } from "./j-threat-intel.js";
import { ALL_K_FIXTURES } from "./k-compliance.js";
import type { RuleFixtureSet } from "../types.js";

/**
 * All red team fixtures across all rule categories.
 *
 * Coverage:
 *   A (description-analysis)    — A1-A9:   9 rules, ~70 fixtures
 *   B (schema-analysis)         — B1-B7:   7 rules, ~35 fixtures
 *   C (code-analysis)           — C1-C16: 16 rules, ~120 fixtures
 *   D (dependency-analysis)     — D1-D7:   7 rules, ~35 fixtures
 *   E (behavioral-analysis)     — E1-E4:   4 rules, ~12 fixtures
 *   F (ecosystem-context)       — F1-F7:   7 rules, ~30 fixtures
 *   G (adversarial-ai)          — G1-G7:   7 rules, ~35 fixtures
 *   H (2026-attack-surface)     — H1-H3:   3 rules, ~20 fixtures
 *   I (protocol-surface)        — I1-I16: 16 rules, ~70 fixtures
 *   J (threat-intelligence)     — J1-J7:   7 rules, ~42 fixtures
 *   K (compliance-governance)   — K1-K20: 20 rules, ~60 fixtures
 *
 *   Total: 103 rules across 11 categories
 */
export const ALL_FIXTURES: RuleFixtureSet[] = [
  ...ALL_A_FIXTURES,
  ...ALL_B_FIXTURES,
  ...ALL_C_FIXTURES,
  ...ALL_D_FIXTURES,
  ...ALL_E_FIXTURES,
  ...ALL_F_FIXTURES,
  ...ALL_G_FIXTURES,
  ...ALL_H_FIXTURES,
  ...ALL_I_FIXTURES,
  ...ALL_J_FIXTURES,
  ...ALL_K_FIXTURES,
];

export {
  ALL_A_FIXTURES,
  ALL_B_FIXTURES,
  ALL_C_FIXTURES,
  ALL_D_FIXTURES,
  ALL_E_FIXTURES,
  ALL_F_FIXTURES,
  ALL_G_FIXTURES,
  ALL_H_FIXTURES,
  ALL_I_FIXTURES,
  ALL_J_FIXTURES,
  ALL_K_FIXTURES,
};

/** Quick lookup: rule_id → fixture set */
export function getFixturesForRule(ruleId: string): RuleFixtureSet | undefined {
  return ALL_FIXTURES.find((fs) => fs.rule_id === ruleId);
}
