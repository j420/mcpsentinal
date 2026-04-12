/**
 * Rules barrel — imports every rule module for its side effect
 * (registration into the central registry) and re-exports the rule
 * instances for tests.
 *
 * To add a new rule:
 *   1. Create `<rule>/CHARTER.md` (Senior MCP Threat Researcher)
 *   2. Create `<rule>/index.ts` (Senior MCP Security Engineer)
 *      that exports a `ComplianceRule` instance.
 *   3. Add the import + `registerComplianceRule(...)` call here.
 *   4. The charter-traceability test will fail until the CHARTER.md
 *      and the rule code agree on id, threat_refs, and strategies.
 */

import { registerComplianceRule } from "./registry.js";

// Shared rules — Phase A (original)
import { humanOversightPresenceRule } from "./shared/human-oversight-presence/index.js";
import { promptInjectionResilienceRule } from "./shared/prompt-injection-resilience/index.js";
import { auditTrailIntegrityRule } from "./shared/audit-trail-integrity/index.js";
import { crossAgentConfigPoisoningRule } from "./shared/cross-agent-config-poisoning/index.js";

// Shared rules — Phase B batch 1
import { credentialLifecycleHygieneRule } from "./shared/credential-lifecycle-hygiene/index.js";
import { supplyChainIntegrityAttestationRule } from "./shared/supply-chain-integrity-attestation/index.js";
import { consentFatigueResistanceRule } from "./shared/consent-fatigue-resistance/index.js";
import { samplingCapabilitySafetyRule } from "./shared/sampling-capability-safety/index.js";

// Shared rules — Phase B batch 2
import { multiAgentTrustBoundaryRule } from "./shared/multi-agent-trust-boundary/index.js";
import { elicitationSocialEngineeringRule } from "./shared/elicitation-social-engineering/index.js";
import { secretExfiltrationChannelsRule } from "./shared/secret-exfiltration-channels/index.js";
import { destructiveOperationGatingRule } from "./shared/destructive-operation-gating/index.js";

// Shared rules — Phase B batch 3
import { annotationIntegrityRule } from "./shared/annotation-integrity/index.js";
import { capabilityDeclarationHonestyRule } from "./shared/capability-declaration-honesty/index.js";
import { robustnessBoundsRule } from "./shared/robustness-bounds/index.js";
import { inferenceCostAttackSurfaceRule } from "./shared/inference-cost-attack-surface/index.js";

// Shared rules — Phase B batch 4
import { toolShadowingNamespaceRule } from "./shared/tool-shadowing-namespace/index.js";
import { unsandboxedExecutionSurfaceRule } from "./shared/unsandboxed-execution-surface/index.js";
import { crossFrameworkKillChainRule } from "./shared/cross-framework-kill-chain/index.js";
import { rugPullDriftDetectionRule } from "./shared/rug-pull-drift-detection/index.js";

// Framework-specific rules
import { euAIActArt12RecordKeepingRule } from "./framework-specific/eu-ai-act-art12-record-keeping/index.js";
import { mitreAMLT0058ContextPoisoningRule } from "./framework-specific/mitre-aml-t0058-context-poisoning/index.js";
import { euAIActArt9RiskManagementRule } from "./framework-specific/eu-ai-act-art9-risk-management/index.js";
import { euAIActArt13TransparencyRule } from "./framework-specific/eu-ai-act-art13-transparency/index.js";
import { maestroL4DeploymentIntegrityRule } from "./framework-specific/maestro-l4-deployment-integrity/index.js";
import { mitreAMLT0057LLMDataLeakageRule } from "./framework-specific/mitre-aml-t0057-llm-data-leakage/index.js";

let registered = false;

export function ensureRulesRegistered(): void {
  if (registered) return;

  // Shared — original
  registerComplianceRule(humanOversightPresenceRule);
  registerComplianceRule(promptInjectionResilienceRule);
  registerComplianceRule(auditTrailIntegrityRule);
  registerComplianceRule(crossAgentConfigPoisoningRule);

  // Shared — batch 1
  registerComplianceRule(credentialLifecycleHygieneRule);
  registerComplianceRule(supplyChainIntegrityAttestationRule);
  registerComplianceRule(consentFatigueResistanceRule);
  registerComplianceRule(samplingCapabilitySafetyRule);

  // Shared — batch 2
  registerComplianceRule(multiAgentTrustBoundaryRule);
  registerComplianceRule(elicitationSocialEngineeringRule);
  registerComplianceRule(secretExfiltrationChannelsRule);
  registerComplianceRule(destructiveOperationGatingRule);

  // Shared — batch 3
  registerComplianceRule(annotationIntegrityRule);
  registerComplianceRule(capabilityDeclarationHonestyRule);
  registerComplianceRule(robustnessBoundsRule);
  registerComplianceRule(inferenceCostAttackSurfaceRule);

  // Shared — batch 4
  registerComplianceRule(toolShadowingNamespaceRule);
  registerComplianceRule(unsandboxedExecutionSurfaceRule);
  registerComplianceRule(crossFrameworkKillChainRule);
  registerComplianceRule(rugPullDriftDetectionRule);

  // Framework-specific
  registerComplianceRule(euAIActArt12RecordKeepingRule);
  registerComplianceRule(mitreAMLT0058ContextPoisoningRule);
  registerComplianceRule(euAIActArt9RiskManagementRule);
  registerComplianceRule(euAIActArt13TransparencyRule);
  registerComplianceRule(maestroL4DeploymentIntegrityRule);
  registerComplianceRule(mitreAMLT0057LLMDataLeakageRule);

  registered = true;
}

ensureRulesRegistered();

export {
  // shared
  humanOversightPresenceRule,
  promptInjectionResilienceRule,
  auditTrailIntegrityRule,
  crossAgentConfigPoisoningRule,
  credentialLifecycleHygieneRule,
  supplyChainIntegrityAttestationRule,
  consentFatigueResistanceRule,
  samplingCapabilitySafetyRule,
  multiAgentTrustBoundaryRule,
  elicitationSocialEngineeringRule,
  secretExfiltrationChannelsRule,
  destructiveOperationGatingRule,
  annotationIntegrityRule,
  capabilityDeclarationHonestyRule,
  robustnessBoundsRule,
  inferenceCostAttackSurfaceRule,
  toolShadowingNamespaceRule,
  unsandboxedExecutionSurfaceRule,
  crossFrameworkKillChainRule,
  rugPullDriftDetectionRule,
  // framework-specific
  euAIActArt12RecordKeepingRule,
  mitreAMLT0058ContextPoisoningRule,
  euAIActArt9RiskManagementRule,
  euAIActArt13TransparencyRule,
  maestroL4DeploymentIntegrityRule,
  mitreAMLT0057LLMDataLeakageRule,
};
