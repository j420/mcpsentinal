/**
 * LLM client wrapper.
 *
 * The ONLY module in the repo allowed to call the Anthropic API. ADR-009
 * scopes this exception to the compliance-agents package. The CLI flag
 * `--use-llm-mock` swaps in `MockLLMClient` so unit tests and CI runs are
 * fully deterministic.
 *
 * Every call goes through `complete()` which:
 *   1. Records the request in the audit log
 *   2. Hits the cache if a previous identical call has been recorded
 *   3. Otherwise calls the API (or the mock)
 *   4. Records the response in the audit log
 *   5. Returns the parsed JSON
 */

import { z } from "zod";
import type { ComplianceAgentPhase, ComplianceFrameworkId } from "@mcp-sentinel/database";
import type { LLMAuditEvent, LLMAuditLog } from "./audit-log.js";

export interface LLMRequest {
  /** Model id (e.g. "claude-opus-4-6") */
  model: string;
  /** System prompt — sets persona and constraints */
  system: string;
  /** User content — bundle + task description */
  user: string;
  /** 0..1, defaults to 0.2 for synthesis and 0.0 for verdicts */
  temperature: number;
  max_tokens: number;
  /** Zod schema the response must validate against */
  response_schema: z.ZodTypeAny;
  /** Stable cache key — same key + same prompt = cached */
  cache_key: string;
  /** Correlation tags for the audit log */
  rule_id: string;
  server_id: string;
  scan_id: string;
  /** Framework agent that originated this call — required for audit trail */
  framework: ComplianceFrameworkId;
  /** synthesis = test generation, execution = verdict rendering */
  phase: ComplianceAgentPhase;
}

export interface LLMResponse<T> {
  parsed: T;
  raw_text: string;
  duration_ms: number;
  cached: boolean;
  /** Token counts (when available) */
  input_tokens?: number;
  output_tokens?: number;
}

export interface LLMClient {
  complete<T>(req: LLMRequest): Promise<LLMResponse<T>>;
}

// ─── Budget guardrails ─────────────────────────────────────────────────────

/**
 * Per-scan budget — hard stop on runaway LLM consumption. A rule that
 * somehow synthesizes an infinite loop of tests (e.g. via multi-turn
 * refinement) cannot exhaust the budget beyond these caps.
 */
export interface LLMBudget {
  /** Maximum LLM calls allowed for one entire scan */
  max_calls_per_scan: number;
  /** Maximum LLM calls allowed for a single rule invocation */
  max_calls_per_rule: number;
  /** Soft token cap (estimated input+output tokens) for one scan */
  max_tokens_per_scan: number;
}

export const DEFAULT_BUDGET: LLMBudget = {
  max_calls_per_scan: 200,
  max_calls_per_rule: 15,
  max_tokens_per_scan: 200_000,
};

export class BudgetExceededError extends Error {
  constructor(
    public readonly reason: "calls-per-scan" | "calls-per-rule" | "tokens-per-scan",
    public readonly budget: LLMBudget,
    public readonly observed: number,
  ) {
    super(
      `LLM budget exceeded (${reason}): observed ${observed} vs cap ${
        reason === "calls-per-scan"
          ? budget.max_calls_per_scan
          : reason === "calls-per-rule"
            ? budget.max_calls_per_rule
            : budget.max_tokens_per_scan
      }`,
    );
    this.name = "BudgetExceededError";
  }
}

/**
 * BudgetedLLMClient — wraps any LLMClient and enforces a per-scan +
 * per-rule call cap. The orchestrator instantiates one of these per scan
 * so running `compliance-scan --framework=all` against a pathological
 * server cannot blow past the budget.
 */
export class BudgetedLLMClient implements LLMClient {
  private totalCalls = 0;
  private totalTokens = 0;
  private perRuleCalls = new Map<string, number>();

  constructor(
    private readonly inner: LLMClient,
    private readonly budget: LLMBudget = DEFAULT_BUDGET,
  ) {}

  async complete<T>(req: LLMRequest): Promise<LLMResponse<T>> {
    const perRule = (this.perRuleCalls.get(req.rule_id) ?? 0) + 1;
    if (perRule > this.budget.max_calls_per_rule) {
      throw new BudgetExceededError("calls-per-rule", this.budget, perRule);
    }
    if (this.totalCalls + 1 > this.budget.max_calls_per_scan) {
      throw new BudgetExceededError(
        "calls-per-scan",
        this.budget,
        this.totalCalls + 1,
      );
    }
    if (this.totalTokens > this.budget.max_tokens_per_scan) {
      throw new BudgetExceededError(
        "tokens-per-scan",
        this.budget,
        this.totalTokens,
      );
    }

    this.perRuleCalls.set(req.rule_id, perRule);
    this.totalCalls += 1;

    const resp = await this.inner.complete<T>(req);
    this.totalTokens += (resp.input_tokens ?? 0) + (resp.output_tokens ?? 0);
    return resp;
  }

  /** Accessor so the orchestrator can surface budget usage in the report */
  usage(): { calls: number; tokens: number } {
    return { calls: this.totalCalls, tokens: this.totalTokens };
  }
}

// ─── Mock client (for tests + offline runs) ────────────────────────────────

/**
 * MockLLMClient — looks up a recorded response by cache_key. If no recording
 * exists, throws so tests fail loudly rather than producing garbage.
 *
 * Recordings live in __tests__/llm-mocks/ as JSON files keyed by cache_key.
 */
export class MockLLMClient implements LLMClient {
  constructor(
    private readonly recordings: Map<string, unknown>,
    private readonly audit: LLMAuditLog,
  ) {}

  async complete<T>(req: LLMRequest): Promise<LLMResponse<T>> {
    const recording = this.recordings.get(req.cache_key);
    if (recording === undefined) {
      throw new Error(
        `No mock recording for cache_key="${req.cache_key}". ` +
          `Record one in __tests__/llm-mocks/ or run with --live and a real ANTHROPIC_API_KEY.`,
      );
    }
    const validated = req.response_schema.parse(recording) as T;
    const event: LLMAuditEvent = {
      scan_id: req.scan_id,
      rule_id: req.rule_id,
      server_id: req.server_id,
      framework: req.framework,
      phase: req.phase,
      cache_key: req.cache_key,
      model: req.model,
      temperature: req.temperature,
      max_tokens: req.max_tokens,
      system: req.system,
      user: req.user,
      response_text: JSON.stringify(recording),
      cached: true,
      duration_ms: 0,
      created_at: new Date(),
    };
    this.audit.record(event);
    return {
      parsed: validated,
      raw_text: JSON.stringify(recording),
      duration_ms: 0,
      cached: true,
    };
  }
}

// ─── Live client (Anthropic SDK) ───────────────────────────────────────────

/**
 * LiveLLMClient — calls the real Anthropic API. Lazy-imports the SDK so
 * the dependency is optional in environments that only ever use the mock
 * (CI, fixture runs).
 *
 * The SDK is NOT a hard dependency in package.json — operators install it
 * when they want to run live scans. This keeps the package buildable in
 * stripped-down environments.
 */
export class LiveLLMClient implements LLMClient {
  private cache = new Map<string, unknown>();

  constructor(
    private readonly apiKey: string,
    private readonly audit: LLMAuditLog,
  ) {}

  async complete<T>(req: LLMRequest): Promise<LLMResponse<T>> {
    const start = Date.now();

    // Cache hit?
    if (this.cache.has(req.cache_key)) {
      const cached = this.cache.get(req.cache_key);
      const validated = req.response_schema.parse(cached) as T;
      this.audit.record({
        scan_id: req.scan_id,
        rule_id: req.rule_id,
        server_id: req.server_id,
        framework: req.framework,
        phase: req.phase,
        cache_key: req.cache_key,
        model: req.model,
        temperature: req.temperature,
        max_tokens: req.max_tokens,
        system: req.system,
        user: req.user,
        response_text: JSON.stringify(cached),
        cached: true,
        duration_ms: 0,
        created_at: new Date(),
      });
      return {
        parsed: validated,
        raw_text: JSON.stringify(cached),
        duration_ms: 0,
        cached: true,
      };
    }

    // Lazy import so the package builds without @anthropic-ai/sdk installed.
    // Typed as `any` because the SDK is an optional runtime dependency — the
    // package compiles in mock-only mode without it.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let Anthropic: any;
    try {
      const sdkSpecifier = "@anthropic-ai/sdk";
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const mod: any = await import(/* @vite-ignore */ sdkSpecifier);
      Anthropic = mod.default ?? mod;
    } catch (err) {
      throw new Error(
        "LiveLLMClient requires @anthropic-ai/sdk to be installed. " +
          "Run `pnpm add @anthropic-ai/sdk --filter=@mcp-sentinel/compliance-agents` " +
          "or use --use-llm-mock for offline runs.",
      );
    }

    const client = new Anthropic({ apiKey: this.apiKey });
    const response = await client.messages.create({
      model: req.model,
      system: req.system,
      messages: [{ role: "user", content: req.user }],
      max_tokens: req.max_tokens,
      temperature: req.temperature,
    });

    const text = response.content
      .filter((b: { type: string }) => b.type === "text")
      .map((b: { text: string }) => b.text)
      .join("");

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      throw new Error(
        `LLM returned non-JSON for cache_key="${req.cache_key}": ${text.slice(0, 200)}`,
      );
    }

    const validated = req.response_schema.parse(parsed) as T;
    const duration = Date.now() - start;

    this.cache.set(req.cache_key, parsed);
    this.audit.record({
      scan_id: req.scan_id,
      rule_id: req.rule_id,
      server_id: req.server_id,
      framework: req.framework,
      phase: req.phase,
      cache_key: req.cache_key,
      model: req.model,
      temperature: req.temperature,
      max_tokens: req.max_tokens,
      system: req.system,
      user: req.user,
      response_text: text,
      cached: false,
      duration_ms: duration,
      input_tokens: response.usage?.input_tokens,
      output_tokens: response.usage?.output_tokens,
      created_at: new Date(),
    });

    return {
      parsed: validated,
      raw_text: text,
      duration_ms: duration,
      cached: false,
      input_tokens: response.usage?.input_tokens,
      output_tokens: response.usage?.output_tokens,
    };
  }
}
