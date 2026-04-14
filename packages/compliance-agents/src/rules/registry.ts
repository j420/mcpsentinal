/**
 * ComplianceRule registry — central registration of all rules.
 *
 * Rules self-register at module-load time. The orchestrator imports
 * `./index.js` to side-effect-load every rule file, then queries this
 * registry to compute the rule union for a given framework set.
 */

import type { FrameworkId } from "../types.js";
import type { ComplianceRule } from "./base-rule.js";

const registry = new Map<string, ComplianceRule>();

export function registerComplianceRule(rule: ComplianceRule): void {
  if (registry.has(rule.metadata.id)) {
    throw new Error(
      `Duplicate compliance rule id: ${rule.metadata.id}. Each rule must have a unique id.`,
    );
  }
  if (rule.metadata.threat_refs.length === 0) {
    throw new Error(
      `Rule ${rule.metadata.id} has empty threat_refs. Every compliance rule must cite at least one CVE, paper, or incident.`,
    );
  }
  if (rule.metadata.applies_to.length === 0) {
    throw new Error(
      `Rule ${rule.metadata.id} has empty applies_to. Every compliance rule must map to at least one framework control.`,
    );
  }
  if (rule.metadata.strategies.length === 0) {
    throw new Error(
      `Rule ${rule.metadata.id} declares no edge-case strategies. Add at least one to metadata.strategies.`,
    );
  }
  registry.set(rule.metadata.id, rule);
}

export function getComplianceRule(id: string): ComplianceRule | undefined {
  return registry.get(id);
}

export function getAllComplianceRules(): ComplianceRule[] {
  return Array.from(registry.values());
}

/**
 * Compute the rule set for a given framework. Used in isolation mode.
 */
export function rulesForFramework(framework: FrameworkId): ComplianceRule[] {
  return getAllComplianceRules().filter((r) => r.appliesToFramework(framework));
}

/**
 * Compute the deduplicated rule union for a set of frameworks. Used in
 * combined mode — every rule runs once even if it satisfies multiple
 * frameworks.
 */
export function rulesForFrameworks(frameworks: FrameworkId[]): ComplianceRule[] {
  const set = new Map<string, ComplianceRule>();
  for (const rule of getAllComplianceRules()) {
    if (frameworks.some((f) => rule.appliesToFramework(f))) {
      set.set(rule.metadata.id, rule);
    }
  }
  return Array.from(set.values());
}

/** Test helper — clears the registry. Do not use in production code. */
export function __resetRegistryForTests(): void {
  registry.clear();
}
