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
import { ALL_L_FIXTURES } from "./l-supply-chain.js";
import { ALL_M_FIXTURES } from "./m-ai-runtime.js";
import { ALL_N_FIXTURES } from "./n-protocol-edge.js";
import { ALL_O_FIXTURES } from "./o-data-privacy.js";
import { ALL_P_FIXTURES } from "./p-infrastructure.js";
import { ALL_Q_FIXTURES } from "./q-cross-ecosystem.js";
import type { RuleFixtureSet } from "../types.js";

/**
 * All red team fixtures across all rule categories.
 *
 * Coverage:
 *   A (description-analysis)       — A1-A9:   9 rules, ~70 fixtures
 *   B (schema-analysis)            — B1-B7:   7 rules, ~35 fixtures
 *   C (code-analysis)              — C1-C16: 16 rules, ~120 fixtures
 *   D (dependency-analysis)        — D1-D7:   7 rules, ~35 fixtures
 *   E (behavioral-analysis)        — E1-E4:   4 rules, ~12 fixtures
 *   F (ecosystem-context)          — F1-F7:   7 rules, ~30 fixtures
 *   G (adversarial-ai)             — G1-G7:   7 rules, ~35 fixtures
 *   H (2026-attack-surface)        — H1-H3:   3 rules, ~20 fixtures
 *   I (protocol-surface)           — I1-I16: 16 rules, ~70 fixtures
 *   J (threat-intelligence)        — J1-J7:   7 rules, ~42 fixtures
 *   K (compliance-governance)      — K1-K20: 20 rules, ~60 fixtures
 *   L (supply-chain-advanced)      — L1-L15: 15 rules, ~75 fixtures
 *   M (ai-runtime-exploitation)    — M1-M9:   9 rules, ~37 fixtures
 *   N (protocol-edge-cases)        — N1-N15: 15 rules, ~75 fixtures
 *   O (data-privacy-attacks)       — O1-O10: 10 rules, ~50 fixtures
 *   P (infrastructure-runtime)     — P1-P10: 10 rules, ~50 fixtures
 *   Q (cross-ecosystem-emergent)   — Q1-Q15: 15 rules, ~81 fixtures
 *
 *   Total: 177 rules across 17 categories
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
  ...ALL_L_FIXTURES,
  ...ALL_M_FIXTURES,
  ...ALL_N_FIXTURES,
  ...ALL_O_FIXTURES,
  ...ALL_P_FIXTURES,
  ...ALL_Q_FIXTURES,
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
  ALL_L_FIXTURES,
  ALL_M_FIXTURES,
  ALL_N_FIXTURES,
  ALL_O_FIXTURES,
  ALL_P_FIXTURES,
  ALL_Q_FIXTURES,
};

/** Quick lookup: rule_id → fixture set */
export function getFixturesForRule(ruleId: string): RuleFixtureSet | undefined {
  return ALL_FIXTURES.find((fs) => fs.rule_id === ruleId);
}
