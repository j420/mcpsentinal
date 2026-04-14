/**
 * LLM Audit Log
 *
 * Every LLM call must be recorded so a regulator can replay any compliance
 * scan from the archived prompts. The in-memory implementation buffers
 * events; `persistComplianceScanResult()` drains the buffer and writes
 * every event to `compliance_agent_runs` at the end of a scan.
 *
 * `framework` and `phase` are intentionally first-class fields here
 * (rather than being parsed back out of `cache_key`) because the verdict
 * cache key does not encode the framework — the only reliable source of
 * both fields is the caller that originated the LLMRequest. Making them
 * required on `LLMAuditEvent` prevents the persistence layer from
 * guessing and keeps the regulator-replay contract tight.
 */

import type { ComplianceAgentPhase, ComplianceFrameworkId } from "@mcp-sentinel/database";

export interface LLMAuditEvent {
  scan_id: string;
  rule_id: string;
  server_id: string;
  /** Which framework agent originated this call */
  framework: ComplianceFrameworkId;
  /** synthesis = test generation, execution = verdict rendering */
  phase: ComplianceAgentPhase;
  /** Stable cache key — same key + same prompt = cached */
  cache_key: string;
  model: string;
  temperature: number;
  max_tokens: number;
  system: string;
  user: string;
  response_text: string;
  cached: boolean;
  duration_ms: number;
  input_tokens?: number;
  output_tokens?: number;
  created_at: Date;
}

export interface LLMAuditLog {
  record(event: LLMAuditEvent): void;
  drain(): LLMAuditEvent[];
  count(): number;
  cachedCount(): number;
}

export class InMemoryAuditLog implements LLMAuditLog {
  private buffer: LLMAuditEvent[] = [];

  record(event: LLMAuditEvent): void {
    this.buffer.push(event);
  }

  drain(): LLMAuditEvent[] {
    const out = this.buffer;
    this.buffer = [];
    return out;
  }

  count(): number {
    return this.buffer.length;
  }

  cachedCount(): number {
    return this.buffer.filter((e) => e.cached).length;
  }
}
