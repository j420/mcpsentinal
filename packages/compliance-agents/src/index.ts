/**
 * @mcp-sentinel/compliance-agents — public exports.
 *
 * The Adversarial Compliance Framework. See `./CLAUDE.md` for the package
 * guide and `agent_docs/architecture.md` ADR-009 for the LLM exception.
 */

export * from "./types.js";
export {
  ComplianceRule,
  makeBundleId,
  type ComplianceRuleMetadata,
  type ThreatRef,
} from "./rules/base-rule.js";
export {
  registerComplianceRule,
  rulesForFramework,
  rulesForFrameworks,
} from "./rules/registry.js";
export { ensureRulesRegistered } from "./rules/index.js";
export {
  getFrameworkAgent,
  getAllFrameworkAgents,
} from "./frameworks/index.js";
export { ComplianceOrchestrator } from "./orchestrator.js";
export { renderTextReport, renderReport } from "./reporter.js";
export {
  type LLMClient,
  type LLMRequest,
  MockLLMClient,
  LiveLLMClient,
} from "./llm/client.js";
export { InMemoryAuditLog, type LLMAuditLog } from "./llm/audit-log.js";
export {
  LLM_CONFIDENCE_CAP,
  applyLLMCap,
} from "./llm/confidence.js";
export {
  persistComplianceScanResult,
  loadAnalysisContextFromDb,
  type PersistComplianceScanInput,
  type PersistComplianceScanReport,
  type PersistLogger,
  type LoadContextResult,
} from "./persistence.js";
