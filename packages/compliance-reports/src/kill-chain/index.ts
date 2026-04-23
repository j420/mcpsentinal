/**
 * Public entry point for the Phase 5 kill-chain narrative synthesizer.
 *
 * Consumers (Agent 1's `buildReport`, Agent 2's renderers, Agent 4's API
 * endpoints) should import from this module only — the sub-paths are
 * implementation details.
 */
export { synthesizeKillChains } from "./synthesizer.js";
export type { SynthesizeInput } from "./synthesizer.js";

export { buildNarrative, uniqSorted } from "./narrative-builder.js";

export { KILL_CHAIN_TO_CVE_PATTERNS } from "./data/kc-cve-mapping.js";

export { ALL_KC_IDS } from "./types.js";
export type {
  AttackChainRow,
  KCId,
  KillChainNarrative,
  KillChainPattern,
} from "./types.js";
