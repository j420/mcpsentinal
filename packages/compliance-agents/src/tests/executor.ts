/**
 * Test executor.
 *
 * For each synthesized test, calls the LLM with a verdict prompt and
 * returns a `RawTestResult`. The orchestrator then runs each rule's
 * `judge()` against the raw result to produce a `JudgedTestResult` —
 * the hallucination firewall.
 */

import { z } from "zod";
import type { LLMClient } from "../llm/client.js";
import { buildVerdictPrompt } from "../llm/prompts.js";
import type {
  ComplianceTest,
  EvidenceBundle,
  FrameworkId,
  RawTestResult,
} from "../types.js";
import type { ComplianceRule } from "../rules/base-rule.js";

const VerdictResponseSchema = z.object({
  test_id: z.string(),
  verdict: z.enum(["fail", "pass", "inconclusive"]),
  rationale: z.string().min(1),
  evidence_path_used: z.string().min(1),
});

export interface ExecuteTestInput {
  rule: ComplianceRule;
  bundle: EvidenceBundle;
  test: ComplianceTest;
  framework: FrameworkId;
  framework_control_text: string;
  scan_id: string;
}

export class TestExecutor {
  constructor(
    private readonly llm: LLMClient,
    private readonly model: string = "claude-opus-4-6",
  ) {}

  async execute(input: ExecuteTestInput): Promise<RawTestResult> {
    const prompt = buildVerdictPrompt({
      framework: input.framework,
      framework_control_text: input.framework_control_text,
      rule_metadata: input.rule.metadata,
      bundle: input.bundle,
      test: input.test,
    });

    const cacheKey = `verdict::${input.rule.metadata.id}::${input.bundle.bundle_id}::${input.test.test_id}`;

    const response = await this.llm.complete<RawTestResult>({
      model: this.model,
      system: prompt.system,
      user: prompt.user,
      temperature: 0.0,
      max_tokens: 1024,
      response_schema: VerdictResponseSchema,
      cache_key: cacheKey,
      rule_id: input.rule.metadata.id,
      server_id: input.bundle.server_id,
      scan_id: input.scan_id,
    });

    return response.parsed;
  }
}
