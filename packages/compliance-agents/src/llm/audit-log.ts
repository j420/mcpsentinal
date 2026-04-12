/**
 * LLM Audit Log
 *
 * Every LLM call must be recorded so a regulator can replay any compliance
 * scan from the archived prompts. The in-memory implementation buffers
 * events; the orchestrator flushes them to the `compliance_agent_runs`
 * table at the end of a scan.
 */

export interface LLMAuditEvent {
  scan_id: string;
  rule_id: string;
  server_id: string;
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
