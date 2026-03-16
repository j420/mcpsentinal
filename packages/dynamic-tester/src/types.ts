import { z } from "zod";

// ── Consent ───────────────────────────────────────────────────────────────────

/** How the server signals opt-in consent for dynamic testing */
export const ConsentMethodSchema = z.enum([
  "allowlist",        // Server ID is in the explicit allowlist
  "tool_declaration", // Server exposes a 'mcp_sentinel_consent' tool
  "wellknown",        // GET /.well-known/mcp-sentinel.json returns { consent: true }
]);
export type ConsentMethod = z.infer<typeof ConsentMethodSchema>;

export const ConsentResultSchema = z.object({
  consented: z.boolean(),
  method: ConsentMethodSchema.nullable(),
  /** ISO timestamp when consent was granted */
  consented_at: z.string().nullable(),
  /** Free-form note from the consent signal (e.g. author contact) */
  note: z.string().nullable(),
});
export type ConsentResult = z.infer<typeof ConsentResultSchema>;

// ── Canary inputs ─────────────────────────────────────────────────────────────

/** A safe canary input value for a single tool invocation */
export const CanaryInputSchema = z.object({
  tool_name: z.string(),
  /** The generated safe input object to pass to the tool */
  input: z.record(z.unknown()),
  /** Which parameter types are covered */
  coverage: z.array(
    z.enum(["string", "number", "boolean", "object", "array", "path", "url", "sql", "command"])
  ),
});
export type CanaryInput = z.infer<typeof CanaryInputSchema>;

// ── Probe results ─────────────────────────────────────────────────────────────

export const ProbeStatusSchema = z.enum([
  "success",          // Tool responded with any output
  "error",            // Tool returned an error (still counts as a response)
  "timeout",          // Tool timed out
  "consent_denied",   // Server did not grant consent
  "skipped",          // Excluded by probe config (e.g. destructive tools)
]);
export type ProbeStatus = z.infer<typeof ProbeStatusSchema>;

export const InjectionProbeResultSchema = z.object({
  probe_type: z.enum(["command_injection", "path_traversal", "sql_injection", "xss", "ssti"]),
  payload: z.string(),
  /** Was the payload echoed back or executed in the response? */
  reflected: z.boolean(),
  evidence: z.string().nullable(),
});
export type InjectionProbeResult = z.infer<typeof InjectionProbeResultSchema>;

export const ProbeResultSchema = z.object({
  tool_name: z.string(),
  status: ProbeStatusSchema,
  canary_input: z.record(z.unknown()),
  raw_output: z.string().nullable(),
  response_time_ms: z.number(),
  /** Output scanning findings (run analyzer over the raw output) */
  output_findings: z.array(
    z.object({
      rule_id: z.string(),
      severity: z.string(),
      evidence: z.string(),
    })
  ),
  /** Injection probe results — only present if injection probing was enabled */
  injection_probes: z.array(InjectionProbeResultSchema),
  error: z.string().nullable(),
  tested_at: z.string(),
});
export type ProbeResult = z.infer<typeof ProbeResultSchema>;

// ── Dynamic report ────────────────────────────────────────────────────────────

export const DynamicReportSchema = z.object({
  server_id: z.string(),
  server_name: z.string(),
  endpoint: z.string(),
  consent: ConsentResultSchema,
  tested_at: z.string(),
  elapsed_ms: z.number(),
  tools_tested: z.number(),
  tools_skipped: z.number(),
  /** Total findings surfaced in tool outputs */
  output_findings_count: z.number(),
  /** Tools where injection payloads were reflected */
  injection_vulnerable_count: z.number(),
  probes: z.array(ProbeResultSchema),
  /** Aggregate risk summary */
  risk_summary: z.object({
    output_injection_risk: z.enum(["none", "low", "medium", "high", "critical"]),
    injection_vulnerability: z.enum(["none", "low", "medium", "high", "critical"]),
    schema_compliance: z.enum(["pass", "warn", "fail"]),
    timing_anomalies: z.number(),
  }),
});
export type DynamicReport = z.infer<typeof DynamicReportSchema>;

// ── Tester config ─────────────────────────────────────────────────────────────

export interface DynamicTesterConfig {
  /** Server IDs that have been explicitly pre-approved */
  allowlist?: string[];
  /** Max ms to wait for a tool response */
  tool_timeout_ms?: number;
  /** Whether to run injection probing (sends semi-adversarial inputs) */
  enable_injection_probes?: boolean;
  /** Tools to never invoke even if server consented (e.g. delete, purge) */
  blocklist_tool_patterns?: RegExp[];
  /** Max tools to test per server (prevents excessive API usage) */
  max_tools_per_server?: number;
  /** Path to append-only audit log file */
  audit_log_path?: string;
}

export const DEFAULT_CONFIG: Required<DynamicTesterConfig> = {
  allowlist: [],
  tool_timeout_ms: 30_000,
  enable_injection_probes: true,
  blocklist_tool_patterns: [
    /delete/i,
    /remove/i,
    /drop/i,
    /purge/i,
    /destroy/i,
    /wipe/i,
    /format/i,
    /shutdown/i,
    /reboot/i,
    /kill/i,
  ],
  max_tools_per_server: 10,
  audit_log_path: "./dynamic-test-audit.jsonl",
};
