/**
 * Prompt builders for the compliance-agents package.
 *
 * Two prompt families:
 *   1. Synthesis prompts — produce N adversarial tests from an evidence bundle
 *   2. Verdict prompts — evaluate one test against the bundle
 *
 * The persona system prompts are written by a senior MCP threat researcher
 * persona. They constrain the model to produce edge cases only and forbid
 * generic textbook examples.
 */

import type { ComplianceRuleMetadata } from "../rules/base-rule.js";
import type { ComplianceTest, EvidenceBundle, FrameworkId } from "../types.js";
import { describeStrategies, EDGE_CASE_STRATEGIES } from "../tests/edge-case-strategies.js";

export interface SynthesisPromptInput {
  framework: FrameworkId;
  framework_control_text: string;
  rule_metadata: ComplianceRuleMetadata;
  bundle: EvidenceBundle;
  max_tests: number;
}

export interface VerdictPromptInput {
  framework: FrameworkId;
  framework_control_text: string;
  rule_metadata: ComplianceRuleMetadata;
  bundle: EvidenceBundle;
  test: ComplianceTest;
}

const SYNTHESIS_SYSTEM = `You are a senior MCP threat researcher specialized in adversarial testing of MCP servers against compliance frameworks.

Your job: read a deterministic evidence bundle about ONE rule on ONE server and synthesize the most lethal edge-case tests that would prove or disprove a compliance violation.

ABSOLUTE CONSTRAINTS:
1. You may ONLY pick from the strategies listed below. Inventing a new strategy is forbidden.
2. Tests must be EDGE CASES — not textbook examples. If you produce a generic example you have failed.
3. Every test must reference a SPECIFIC pointer in the evidence bundle. Generic claims about "the server" are forbidden — point at a tool name, a file path, a parameter name.
4. You judge based on the bundle ONLY. You cannot ask for additional data.
5. Return STRICT JSON matching the schema. No prose, no markdown, no comments.
6. If the bundle gives you no plausible attack surface for this rule, return an empty test array.`;

const VERDICT_SYSTEM = `You are a senior MCP threat researcher evaluating whether ONE specific adversarial test, generated for ONE compliance rule, is supported by the evidence bundle for ONE server.

Your job: return a structured verdict.

ABSOLUTE CONSTRAINTS:
1. Verdict must be one of: "fail" (the test demonstrates the rule is violated), "pass" (the test demonstrates the rule is satisfied), "inconclusive" (the bundle does not support either conclusion).
2. The "evidence_path_used" field must be a literal pointer that exists in the bundle. If you reference something not in the bundle, that is a hallucination — return "inconclusive".
3. Return STRICT JSON. No prose, no markdown.
4. The bundle is your ONLY source of truth. Do not appeal to general knowledge about the server.`;

export function buildSynthesisPrompt(input: SynthesisPromptInput): {
  system: string;
  user: string;
} {
  const strategies = input.rule_metadata.strategies;
  const strategyDescriptions = describeStrategies(strategies);

  const user = [
    `# Framework`,
    `${input.framework}`,
    ``,
    `# Framework control text`,
    input.framework_control_text,
    ``,
    `# Rule`,
    `id: ${input.rule_metadata.id}`,
    `name: ${input.rule_metadata.name}`,
    `severity: ${input.rule_metadata.severity}`,
    `intent: ${input.rule_metadata.intent}`,
    ``,
    `# Allowed adversarial strategies`,
    strategyDescriptions,
    ``,
    `# Evidence bundle (deterministic, the ONLY thing you may reason over)`,
    `bundle_id: ${input.bundle.bundle_id}`,
    `summary: ${input.bundle.summary}`,
    `deterministic_violation_already_detected: ${input.bundle.deterministic_violation}`,
    ``,
    `## Facts`,
    JSON.stringify(input.bundle.facts, null, 2),
    ``,
    `## Pointers (use these in your test references)`,
    JSON.stringify(input.bundle.pointers, null, 2),
    ``,
    `# Task`,
    `Synthesize up to ${input.max_tests} adversarial tests. Return strict JSON:`,
    ``,
    `{`,
    `  "tests": [`,
    `    {`,
    `      "test_id": "<rule_id>-<short slug>",`,
    `      "rule_id": "${input.rule_metadata.id}",`,
    `      "strategy": "<one of: ${strategies.join(", ")}>",`,
    `      "hypothesis": "<one sentence>",`,
    `      "evidence_path": "<dotted path into bundle.facts or pointer label>",`,
    `      "scenario": "<concrete attack scenario referencing this server's actual surface>",`,
    `      "expected_violation_signature": "<exact signal in bundle that would prove violation>",`,
    `      "criticality_justification": "<why this is an edge case, not a textbook example>"`,
    `    }`,
    `  ]`,
    `}`,
  ].join("\n");

  return { system: SYNTHESIS_SYSTEM, user };
}

export function buildVerdictPrompt(input: VerdictPromptInput): {
  system: string;
  user: string;
} {
  const user = [
    `# Framework`,
    `${input.framework}`,
    ``,
    `# Framework control text`,
    input.framework_control_text,
    ``,
    `# Rule`,
    `id: ${input.rule_metadata.id}`,
    `name: ${input.rule_metadata.name}`,
    `intent: ${input.rule_metadata.intent}`,
    ``,
    `# Test`,
    JSON.stringify(input.test, null, 2),
    ``,
    `# Evidence bundle (your ONLY source of truth)`,
    `bundle_id: ${input.bundle.bundle_id}`,
    `summary: ${input.bundle.summary}`,
    ``,
    `## Facts`,
    JSON.stringify(input.bundle.facts, null, 2),
    ``,
    `## Pointers`,
    JSON.stringify(input.bundle.pointers, null, 2),
    ``,
    `# Task`,
    `Return strict JSON:`,
    ``,
    `{`,
    `  "test_id": "${input.test.test_id}",`,
    `  "verdict": "fail" | "pass" | "inconclusive",`,
    `  "rationale": "<one paragraph>",`,
    `  "evidence_path_used": "<exact pointer or facts path from the bundle>"`,
    `}`,
  ].join("\n");

  return { system: VERDICT_SYSTEM, user };
}

/** Touch the strategies catalog so unused-import linters don't strip it. */
export function strategiesAreLoaded(): number {
  return Object.keys(EDGE_CASE_STRATEGIES).length;
}
