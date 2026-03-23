/**
 * TypedRule Framework — Replaces YAML regex rules with real analysis code.
 *
 * Design:
 * - YAML still defines metadata (id, severity, owasp, mitre, test_cases)
 * - TypeScript implements detection logic with actual algorithms
 * - Engine dispatches to TypedRule when detect.type === "typed"
 * - Each TypedRule produces findings with precise, evidence-rich explanations
 */

import type { AnalysisContext } from "../engine.js";
import type { Severity, OwaspCategory } from "@mcp-sentinel/database";

/** A single finding produced by a typed rule */
export interface TypedFinding {
  rule_id: string;
  severity: Severity;
  evidence: string;
  remediation: string;
  owasp_category: OwaspCategory | null;
  mitre_technique: string | null;
  /** Confidence score 0.0–1.0 for Bayesian aggregation */
  confidence: number;
  /** Structured metadata for downstream analysis */
  metadata?: Record<string, unknown>;
}

/** Base interface for all typed detection rules */
export interface TypedRule {
  /** Rule identifier matching YAML definition (e.g., "C1", "A6") */
  readonly id: string;

  /** Human-readable rule name */
  readonly name: string;

  /** Execute the rule against an analysis context, returning zero or more findings */
  analyze(context: AnalysisContext): TypedFinding[];
}

/**
 * Registry of all typed rule implementations.
 * The engine checks this before falling back to YAML-interpreted rules.
 */
const typedRuleRegistry = new Map<string, TypedRule>();

/** Register a typed rule implementation */
export function registerTypedRule(rule: TypedRule): void {
  typedRuleRegistry.set(rule.id, rule);
}

/** Look up a typed rule by ID */
export function getTypedRule(id: string): TypedRule | undefined {
  return typedRuleRegistry.get(id);
}

/** Get all registered typed rules */
export function getAllTypedRules(): TypedRule[] {
  return Array.from(typedRuleRegistry.values());
}

/** Check if a rule ID has a typed implementation */
export function hasTypedRule(id: string): boolean {
  return typedRuleRegistry.has(id);
}
