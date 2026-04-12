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

// Shared rules
import { humanOversightPresenceRule } from "./shared/human-oversight-presence/index.js";
import { promptInjectionResilienceRule } from "./shared/prompt-injection-resilience/index.js";
import { auditTrailIntegrityRule } from "./shared/audit-trail-integrity/index.js";
import { crossAgentConfigPoisoningRule } from "./shared/cross-agent-config-poisoning/index.js";

// Framework-specific rules
import { euAIActArt12RecordKeepingRule } from "./framework-specific/eu-ai-act-art12-record-keeping/index.js";
import { mitreAMLT0058ContextPoisoningRule } from "./framework-specific/mitre-aml-t0058-context-poisoning/index.js";

let registered = false;

export function ensureRulesRegistered(): void {
  if (registered) return;
  registerComplianceRule(humanOversightPresenceRule);
  registerComplianceRule(promptInjectionResilienceRule);
  registerComplianceRule(auditTrailIntegrityRule);
  registerComplianceRule(crossAgentConfigPoisoningRule);
  registerComplianceRule(euAIActArt12RecordKeepingRule);
  registerComplianceRule(mitreAMLT0058ContextPoisoningRule);
  registered = true;
}

ensureRulesRegistered();

export {
  humanOversightPresenceRule,
  promptInjectionResilienceRule,
  auditTrailIntegrityRule,
  crossAgentConfigPoisoningRule,
  euAIActArt12RecordKeepingRule,
  mitreAMLT0058ContextPoisoningRule,
};
