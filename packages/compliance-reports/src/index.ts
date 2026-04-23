// ─── Data model ────────────────────────────────────────────────────────────
export type {
  ComplianceReport,
  ConfidenceBand,
  ControlEvidence,
  ControlResult,
  ControlStatus,
  FrameworkId,
  KillChainNarrative,
  OverallStatus,
  ReportAssessment,
  ReportFramework,
  ReportInputFinding,
  ReportServer,
  ReportSummary,
  SignedComplianceReport,
} from "./types.js";
export { FRAMEWORK_IDS } from "./types.js";

// ─── Canonicalization + attestation ───────────────────────────────────────
export { canonicalize, CanonicalizationError } from "./canonicalize.js";
export {
  resolveSigningContextFromEnv,
  signReport,
  verifyReport,
} from "./attestation.js";
export type { SigningContext } from "./attestation.js";

// ─── Framework registry ───────────────────────────────────────────────────
export type { Framework, FrameworkControl } from "./frameworks/index.js";
export { FRAMEWORKS, getAllFrameworks, getFramework } from "./frameworks/index.js";

// ─── Report builder ───────────────────────────────────────────────────────
export { buildReport } from "./build-report.js";
export type { BuildReportInput } from "./build-report.js";

// ─── Renderer & badge contracts ───────────────────────────────────────────
export type {
  ComplianceReportRenderer,
  RendererFormat,
} from "./render/types.js";
export {
  getAllRenderers,
  getRenderer,
  registerRenderer,
} from "./render/types.js";

export type { ComplianceBadgeRenderer } from "./badges/types.js";
export { getBadge, registerBadge } from "./badges/types.js";

// ─── Kill-chain narrative synthesizer (Phase 5.3) ────────────────────────
export {
  ALL_KC_IDS,
  KILL_CHAIN_TO_CVE_PATTERNS,
  buildNarrative,
  synthesizeKillChains,
  uniqSorted,
} from "./kill-chain/index.js";
export type {
  AttackChainRow,
  KCId,
  KillChainPattern,
  SynthesizeInput,
} from "./kill-chain/index.js";
