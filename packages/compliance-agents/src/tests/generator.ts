/**
 * Runtime adversarial test generator.
 *
 * Calls the LLM with a synthesis prompt produced from the rule's evidence
 * bundle and returns a list of `ComplianceTest`s. The Zod schema validates
 * the LLM response so malformed output is rejected before the executor
 * sees it.
 */

import { z } from "zod";
import type { ComplianceRule } from "../rules/base-rule.js";
import type { LLMClient } from "../llm/client.js";
import { buildSynthesisPrompt } from "../llm/prompts.js";
import type {
  ComplianceTest,
  EvidenceBundle,
  EdgeCaseStrategy,
  FrameworkId,
} from "../types.js";

const ComplianceTestSchema = z.object({
  test_id: z.string().min(1),
  rule_id: z.string().min(1),
  strategy: z.string().min(1),
  hypothesis: z.string().min(1),
  evidence_path: z.string().min(1),
  scenario: z.string().min(1),
  expected_violation_signature: z.string().min(1),
  criticality_justification: z.string().min(1),
});

const SynthesisResponseSchema = z.object({
  tests: z.array(ComplianceTestSchema),
});

export interface GenerateTestsInput {
  rule: ComplianceRule;
  bundle: EvidenceBundle;
  framework: FrameworkId;
  framework_control_text: string;
  scan_id: string;
  max_tests: number;
}

export class TestGenerator {
  constructor(
    private readonly llm: LLMClient,
    private readonly model: string = "claude-opus-4-6",
  ) {}

  async generate(input: GenerateTestsInput): Promise<ComplianceTest[]> {
    const allowedStrategies = new Set(input.rule.testStrategies(input.bundle));
    const prompt = buildSynthesisPrompt({
      framework: input.framework,
      framework_control_text: input.framework_control_text,
      rule_metadata: input.rule.metadata,
      bundle: input.bundle,
      max_tests: input.max_tests,
    });

    const cacheKey = `synthesis::${input.rule.metadata.id}::${input.bundle.bundle_id}::${input.framework}`;

    const response = await this.llm.complete<{ tests: ComplianceTest[] }>({
      model: this.model,
      system: prompt.system,
      user: prompt.user,
      temperature: 0.2,
      max_tokens: 2048,
      response_schema: SynthesisResponseSchema,
      cache_key: cacheKey,
      rule_id: input.rule.metadata.id,
      server_id: input.bundle.server_id,
      scan_id: input.scan_id,
    });

    // Reject any test that uses a strategy outside the rule's allowed set —
    // the LLM is forbidden from inventing strategies but we double-check.
    const filtered = response.parsed.tests.filter((t) =>
      allowedStrategies.has(t.strategy as EdgeCaseStrategy),
    );

    return filtered.slice(0, input.max_tests).map((t) => ({
      ...t,
      strategy: t.strategy as EdgeCaseStrategy,
    }));
  }
}
