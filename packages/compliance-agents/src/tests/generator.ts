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
  /** Maximum refinement turns in the agentic loop (default 1 = no refinement) */
  max_turns?: number;
}

export class TestGenerator {
  constructor(
    private readonly llm: LLMClient,
    private readonly model: string = "claude-opus-4-6",
  ) {}

  /**
   * Multi-turn agentic test synthesis.
   *
   * Turn 1: synthesize initial tests from the evidence bundle.
   * Turn 2+ (optional): probe the synthesized tests against the rule's
   *   deterministic judge on a dry-run basis. If any test fails the dry
   *   run (because the evidence does NOT support the hypothesis), ask the
   *   LLM to refine — producing tighter, more evidence-grounded tests.
   *
   * The refinement loop is capped by `max_turns` AND by the LLM budget
   * guardrails in `BudgetedLLMClient`. If the budget is exhausted we
   * return whatever valid tests we have.
   */
  async generate(input: GenerateTestsInput): Promise<ComplianceTest[]> {
    const allowedStrategies = new Set(input.rule.testStrategies(input.bundle));
    const maxTurns = Math.max(1, input.max_turns ?? 1);

    let accepted: ComplianceTest[] = [];
    let refinementHints: string[] = [];

    for (let turn = 1; turn <= maxTurns; turn += 1) {
      const prompt = buildSynthesisPrompt({
        framework: input.framework,
        framework_control_text: input.framework_control_text,
        rule_metadata: input.rule.metadata,
        bundle: input.bundle,
        max_tests: input.max_tests,
        refinement_hints: turn > 1 ? refinementHints : undefined,
      });

      const cacheKey = `synthesis::${input.rule.metadata.id}::${input.bundle.bundle_id}::${input.framework}::turn${turn}`;

      let response;
      try {
        response = await this.llm.complete<{ tests: ComplianceTest[] }>({
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
      } catch (err) {
        // Budget exhausted or recording missing → return what we have
        break;
      }

      const filtered = response.parsed.tests.filter((t) =>
        allowedStrategies.has(t.strategy as EdgeCaseStrategy),
      );

      // Dry-run judge to see which tests are evidence-grounded. Tests that
      // reference nothing in the bundle's pointers are flagged for refinement.
      const pointerLocations = new Set(
        input.bundle.pointers.map((p) => p.location),
      );
      const pointerLabels = new Set(input.bundle.pointers.map((p) => p.label));
      const grounded: typeof filtered = [];
      const ungrounded: typeof filtered = [];
      for (const t of filtered) {
        const refs =
          pointerLocations.has(t.evidence_path) ||
          pointerLabels.has(t.evidence_path) ||
          input.bundle.pointers.some((p) =>
            t.evidence_path.includes(p.location),
          );
        if (refs) grounded.push(t);
        else ungrounded.push(t);
      }

      accepted = grounded.slice(0, input.max_tests).map((t) => ({
        ...t,
        strategy: t.strategy as EdgeCaseStrategy,
      }));

      // If all tests were grounded or we ran out of turns, stop.
      if (ungrounded.length === 0 || turn === maxTurns) break;

      refinementHints = ungrounded.map(
        (t) =>
          `Test ${t.test_id} referenced '${t.evidence_path}' which is not in the bundle pointers. Rewrite it to reference one of: ${input.bundle.pointers
            .map((p) => p.location)
            .slice(0, 3)
            .join(", ")}`,
      );
    }

    return accepted;
  }
}
