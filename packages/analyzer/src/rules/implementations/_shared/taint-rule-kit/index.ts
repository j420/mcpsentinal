/**
 * Shared taint-rule-kit public surface.
 *
 * Consumed by six rule implementations: C4, C12, C13, C16, K9, J2. Each
 * rule imports the types + the two primary helpers (gatherTaintFacts,
 * buildTaintChain) and composes them with its own charter-mandated
 * severity / remediation / edge-case handling.
 *
 * Nothing in this file — or in its siblings — contains regex literals
 * or string-literal arrays > 5. All sink / source / sanitiser data is
 * passed in via typed config and lives in each rule's own data/*.json.
 */

export type {
  TaintFact,
  TaintPathStep,
  TaintGatherResult,
  TaintRuleConfig,
  SanitiserFact,
} from "./types.js";

export { gatherTaintFacts } from "./gather.js";

export {
  buildTaintChain,
  capConfidence,
  stepInspectTaintSource,
  stepInspectTaintSink,
  stepTraceTaintPath,
  stepInspectTaintSanitiser,
  type TaintChainDescriptor,
} from "./build-chain.js";
