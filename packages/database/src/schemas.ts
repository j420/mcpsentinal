import { z } from "zod";

// ─── Enums ───────────────────────────────────────────────────────────────────

export const ServerCategory = z.enum([
  "database",
  "filesystem",
  "api-integration",
  "dev-tools",
  "ai-ml",
  "communication",
  "cloud-infra",
  "security",
  "data-processing",
  "monitoring",
  "search",
  "browser-web",
  "code-execution",
  "other",
]);
export type ServerCategory = z.infer<typeof ServerCategory>;

export const Severity = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "informational",
]);
export type Severity = z.infer<typeof Severity>;

export const ScanStatus = z.enum([
  "pending",
  "running",
  "completed",
  "failed",
]);
export type ScanStatus = z.infer<typeof ScanStatus>;

export const CapabilityTag = z.enum([
  "reads-data",
  "writes-data",
  "executes-code",
  "sends-network",
  "accesses-filesystem",
  "manages-credentials",
]);
export type CapabilityTag = z.infer<typeof CapabilityTag>;

export const SourceName = z.enum([
  "pulsemcp",
  "zarq",
  "smithery",
  "glama",
  "npm",
  "pypi",
  "github",
  "docker-hub",
  "official-registry",
  "awesome-mcp-servers",
  "manual",
  "other",
]);
export type SourceName = z.infer<typeof SourceName>;

export const OwaspCategory = z.enum([
  "MCP01-prompt-injection",
  "MCP02-tool-poisoning",
  "MCP03-command-injection",
  "MCP04-data-exfiltration",
  "MCP05-privilege-escalation",
  "MCP06-excessive-permissions",
  "MCP07-insecure-config",   // canonical value — used by 13 rules + H1 (H1 yaml fixed in same commit)
  "MCP08-dependency-vuln",
  "MCP09-logging-monitoring",
  "MCP10-supply-chain",
  // OWASP Agentic Applications Top 10 (December 2025)
  "ASI01-agent-goal-hijack",
  "ASI02-tool-misuse",
  "ASI03-identity-privilege-abuse",
  "ASI04-agentic-supply-chain",
  "ASI05-unexpected-code-execution",
  "ASI06-memory-context-poisoning",
  "ASI07-insecure-inter-agent-comms",
  "ASI08-agentic-dos",
  "ASI09-human-oversight-bypass",
  "ASI10-agentic-data-poisoning",
]);
export type OwaspCategory = z.infer<typeof OwaspCategory>;

// ─── Core Entities ───────────────────────────────────────────────────────────

export const ServerSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(500),
  slug: z.string().min(1).max(500),
  description: z.string().max(10000).nullable(),
  author: z.string().max(500).nullable(),
  github_url: z.string().url().nullable(),
  npm_package: z.string().max(500).nullable(),
  pypi_package: z.string().max(500).nullable(),
  category: ServerCategory.nullable(),
  language: z.string().nullable(),
  license: z.string().nullable(),
  github_stars: z.number().int().nonnegative().nullable(),
  npm_downloads: z.number().int().nonnegative().nullable(),
  last_commit: z.coerce.date().nullable(),
  latest_score: z.number().int().min(0).max(100).nullable(),
  // Scan pipeline denormalized fields (migration 004)
  last_scanned_at: z.coerce.date().nullable(),
  endpoint_url: z.string().nullable(),
  tool_count: z.number().int().nonnegative().default(0),
  connection_status: z.enum(["success", "failed", "timeout", "no_endpoint"]).nullable(),
  server_version: z.string().nullable(),
  server_instructions: z.string().nullable(),
  created_at: z.coerce.date(),
  updated_at: z.coerce.date(),
});
export type Server = z.infer<typeof ServerSchema>;

export const ToolSchema = z.object({
  id: z.string().uuid(),
  server_id: z.string().uuid(),
  name: z.string().min(1).max(500),
  description: z.string().max(10000).nullable(),
  input_schema: z.record(z.unknown()).nullable(),
  capability_tags: z.array(CapabilityTag),
  created_at: z.coerce.date(),
  updated_at: z.coerce.date(),
});
export type Tool = z.infer<typeof ToolSchema>;

export const ParameterSchema = z.object({
  id: z.string().uuid(),
  tool_id: z.string().uuid(),
  name: z.string().min(1).max(500),
  type: z.string().max(100),
  required: z.boolean(),
  description: z.string().max(5000).nullable(),
  constraints: z.record(z.unknown()).nullable(),
});
export type Parameter = z.infer<typeof ParameterSchema>;

export const FindingSchema = z.object({
  id: z.string().uuid(),
  server_id: z.string().uuid(),
  scan_id: z.string().uuid(),
  rule_id: z.string().min(1).max(50),
  severity: Severity,
  evidence: z.string().min(1).max(10000),
  remediation: z.string().min(1).max(5000),
  owasp_category: OwaspCategory.nullable(),
  mitre_technique: z.string().max(100).nullable(),
  disputed: z.boolean().default(false),
  // Phase 1: Evidence chain support (migration 011)
  confidence: z.number().min(0).max(1).default(1.0),
  evidence_chain: z.record(z.unknown()).nullable().default(null),
  created_at: z.coerce.date(),
});
export type Finding = z.infer<typeof FindingSchema>;

export const ScanSchema = z.object({
  id: z.string().uuid(),
  server_id: z.string().uuid(),
  status: ScanStatus,
  started_at: z.coerce.date(),
  completed_at: z.coerce.date().nullable(),
  rules_version: z.string().max(50),
  error: z.string().max(5000).nullable(),
  findings_count: z.number().int().nonnegative().default(0),
  // Pipeline stage completion (migration 004) — null for scans run before this migration
  stages: z.object({
    source_fetched: z.boolean(),
    connection_attempted: z.boolean(),
    connection_succeeded: z.boolean(),
    dependencies_audited: z.boolean(),
  }).nullable(),
});
export type Scan = z.infer<typeof ScanSchema>;

/**
 * Confidence / coverage band — derived from the analyzer's coverage signal.
 * Stable, regulator-readable string union. Used by the public registry to
 * label scores honestly: "85/100 (high confidence)" vs "85/100 (low confidence)".
 *
 * Authoritative source: `AnalysisCoverageInput.confidence_band` produced by the
 * scorer. Persisted alongside the score for downstream API consumption.
 */
export const CoverageBand = z.enum(["high", "medium", "low", "minimal"]);
export type CoverageBand = z.infer<typeof CoverageBand>;

/**
 * The 8 v2 sub-scores. These REPLACE the single `config_score` bucket once
 * v2 is the default everywhere; until then they coexist with the legacy
 * 5 sub-scores and are exposed additively on the API.
 *
 * Each value is an integer 0..100 clamped at the storage boundary (matches
 * the scorer's `Math.round` + 0..100 invariant).
 *
 * `code_score` is duplicated here (also present on the legacy ScoreSchema)
 * because the v2 hero renders all 8 buckets in one breakdown — keeping it
 * inside this object means the UI only has to read one shape, and the
 * scorer's `ScoreResult` (the source of truth) emits all 8 together.
 *
 * `.passthrough()` is intentional: future scorer additions (new bucket,
 * new metadata) MUST NOT cause `safeParse` in `shapeScoreDetail` to silently
 * null the whole field. Unknown keys are forwarded to the API consumer.
 *
 * Authoritative source: `ScoreResult` in `packages/scorer/src/scorer.ts`.
 */
export const V2SubScoresSchema = z
  .object({
    schema_score: z.number().int().min(0).max(100),
    ecosystem_score: z.number().int().min(0).max(100),
    protocol_score: z.number().int().min(0).max(100),
    adversarial_score: z.number().int().min(0).max(100),
    compliance_score: z.number().int().min(0).max(100),
    supply_chain_score: z.number().int().min(0).max(100),
    infrastructure_score: z.number().int().min(0).max(100),
    code_score: z.number().int().min(0).max(100),
  })
  .passthrough();
export type V2SubScores = z.infer<typeof V2SubScoresSchema>;

/**
 * Analysis coverage — what the analyzer was able to inspect for this scan.
 * Drives the `coverage_band` label and is exposed verbatim on the API so
 * regulators can audit the basis of any given score.
 *
 * `.passthrough()` for the same reason as V2SubScoresSchema: future scorer
 * additions to `AnalysisCoverageInput` (new technique tag, new "skipped
 * because" reason) must not silently null the field at the response seam.
 *
 * Authoritative source: `AnalysisCoverageInput` in `packages/scorer/src/scorer.ts`
 * (minus `confidence_band`, which we surface as `coverage_band` at the API layer).
 */
export const AnalysisCoverageSchema = z
  .object({
    had_source_code: z.boolean(),
    had_connection: z.boolean(),
    had_dependencies: z.boolean(),
    coverage_ratio: z.number().min(0).max(1),
    techniques_run: z.array(z.string()),
    rules_executed: z.number().int().nonnegative(),
    rules_skipped_no_data: z.number().int().nonnegative(),
  })
  .passthrough();
export type AnalysisCoverage = z.infer<typeof AnalysisCoverageSchema>;

export const ScoreSchema = z.object({
  id: z.string().uuid(),
  server_id: z.string().uuid(),
  scan_id: z.string().uuid(),
  total_score: z.number().int().min(0).max(100),
  code_score: z.number().int().min(0).max(100),
  deps_score: z.number().int().min(0).max(100),
  config_score: z.number().int().min(0).max(100),
  description_score: z.number().int().min(0).max(100),
  behavior_score: z.number().int().min(0).max(100),
  owasp_coverage: z.record(z.boolean()),
  created_at: z.coerce.date(),
  // Phase 0, chunk 0.2 — shadow score from engine_v2 rules only. Null until
  // at least one rule has engine_v2:true. When populated it is computed with
  // the same 100 - Σ(penalty) formula as total_score but scoped to v2 rules.
  total_score_v2: z.number().int().min(0).max(100).nullable().default(null),
  // Technique attribution for the v2 findings that contributed to total_score_v2.
  // Shape: Record<ruleId, AnalysisTechnique> — the analyzer's technique taxonomy.
  techniques_v2: z.record(z.string()).nullable().default(null),
  // CISO-facing detail-page upgrade — additive, nullable until migration
  // <NNN>_add_v2_score_fields.sql lands. Populated by the scorer (already produces
  // these values today; the persistence column is the missing piece). Until the
  // migration ships, the API surfaces null for older scans, which the web layer
  // renders as "v2 detail not available for this scan".
  coverage_band: CoverageBand.nullable().default(null),
  v2_sub_scores: V2SubScoresSchema.nullable().default(null),
  analysis_coverage: AnalysisCoverageSchema.nullable().default(null),
});
export type Score = z.infer<typeof ScoreSchema>;

/**
 * Subset of the `scores` row exposed on `GET /api/v1/servers/:slug` under
 * `data.score_detail`. Keeps the public API contract small and additive.
 *
 * NOTE: changes to this shape are a public API change. Bump the API version
 * before removing or renaming any field. Adding a new nullable field is safe.
 */
export const ScoreDetailResponseSchema = z.object({
  total_score: z.number().int().min(0).max(100),
  code_score: z.number().int().min(0).max(100),
  deps_score: z.number().int().min(0).max(100),
  config_score: z.number().int().min(0).max(100),
  description_score: z.number().int().min(0).max(100),
  behavior_score: z.number().int().min(0).max(100),
  owasp_coverage: z.record(z.boolean()),
  // Additive fields (nullable by default — unpopulated for pre-migration scans).
  coverage_band: CoverageBand.nullable(),
  v2_sub_scores: V2SubScoresSchema.nullable(),
  analysis_coverage: AnalysisCoverageSchema.nullable(),
});
export type ScoreDetailResponse = z.infer<typeof ScoreDetailResponseSchema>;

export const SourceSchema = z.object({
  id: z.string().uuid(),
  server_id: z.string().uuid(),
  source_name: SourceName,
  source_url: z.string().url().nullable(),
  external_id: z.string().max(500).nullable(),
  raw_metadata: z.record(z.unknown()),
  last_synced: z.coerce.date(),
  created_at: z.coerce.date(),
});
export type Source = z.infer<typeof SourceSchema>;

export const DependencySchema = z.object({
  id: z.string().uuid(),
  server_id: z.string().uuid(),
  name: z.string().min(1).max(500),
  version: z.string().max(100).nullable(),
  ecosystem: z.enum(["npm", "pypi", "cargo", "go"]),
  has_known_cve: z.boolean().default(false),
  cve_ids: z.array(z.string()),
  last_updated: z.coerce.date().nullable(),
  // migration 004: direct vs. transitive; CVE severity from OSV
  is_direct: z.boolean().default(true),
  cve_severity: Severity.nullable(),
});
export type Dependency = z.infer<typeof DependencySchema>;

export const IncidentSchema = z.object({
  id: z.string().uuid(),
  server_id: z.string().uuid().nullable(),
  date: z.coerce.date(),
  description: z.string().min(1).max(10000),
  root_cause: z.string().max(5000).nullable(),
  owasp_category: OwaspCategory.nullable(),
  mitre_technique: z.string().max(100).nullable(),
  source_url: z.string().url().nullable(),
  created_at: z.coerce.date(),
});
export type Incident = z.infer<typeof IncidentSchema>;

export const ScoreHistorySchema = z.object({
  id: z.string().uuid(),
  server_id: z.string().uuid(),
  score: z.number().int().min(0).max(100),
  findings_count: z.number().int().nonnegative(),
  rules_version: z.string().nullable(), // migration 004: attribute score change to rule update vs. server change
  recorded_at: z.coerce.date(),
});
export type ScoreHistory = z.infer<typeof ScoreHistorySchema>;

// ─── Pipeline DTOs ───────────────────────────────────────────────────────────

export const DiscoveredServerSchema = z.object({
  name: z.string().min(1),
  description: z.string().nullable().default(null),
  author: z.string().nullable().default(null),
  github_url: z.string().url().nullable().default(null),
  npm_package: z.string().nullable().default(null),
  pypi_package: z.string().nullable().default(null),
  category: ServerCategory.nullable().default(null),
  language: z.string().nullable().default(null),
  license: z.string().nullable().default(null),
  source_name: SourceName,
  source_url: z.string().url().nullable().default(null),
  external_id: z.string().nullable().default(null),
  raw_metadata: z.record(z.unknown()).default({}),
});
export type DiscoveredServer = z.infer<typeof DiscoveredServerSchema>;

export const ToolEnumerationSchema = z.object({
  server_id: z.string().uuid(),
  tools: z.array(
    z.object({
      name: z.string(),
      description: z.string().nullable(),
      input_schema: z.record(z.unknown()).nullable(),
      // MCP 2025-11-25 spec: structured output schema for tool results
      output_schema: z.record(z.unknown()).nullable().optional(),
      annotations: z.object({
        readOnlyHint: z.boolean().optional(),
        destructiveHint: z.boolean().optional(),
        idempotentHint: z.boolean().optional(),
        openWorldHint: z.boolean().optional(),
      }).passthrough().nullable().optional(),
    })
  ),
  connection_success: z.boolean(),
  connection_error: z.string().nullable(),
  response_time_ms: z.number(),
  // H2: Fields from the MCP initialize handshake (null when connection failed)
  server_version: z.string().nullable().optional(),
  server_instructions: z.string().nullable().optional(),
  // Category I: Protocol surface data captured during enumeration
  // Tool annotations (I1, I2) — from MCP spec 2025-03-26
  resources: z.array(z.object({
    uri: z.string(),
    name: z.string(),
    description: z.string().nullable().optional(),
    mimeType: z.string().nullable().optional(),
  })).optional().default([]),
  // MCP prompts (I5, I6)
  prompts: z.array(z.object({
    name: z.string(),
    description: z.string().nullable().optional(),
    arguments: z.array(z.object({
      name: z.string(),
      description: z.string().nullable().optional(),
      required: z.boolean().optional(),
    })).optional().default([]),
  })).optional().default([]),
  roots: z.array(z.object({
    uri: z.string(),
    name: z.string().nullable().optional(),
  })).optional().default([]),
  // Declared capabilities from initialize response (I12)
  declared_capabilities: z.object({
    tools: z.boolean().optional(),
    resources: z.boolean().optional(),
    prompts: z.boolean().optional(),
    sampling: z.boolean().optional(),
    logging: z.boolean().optional(),
  }).passthrough().nullable().optional(),
});
export type ToolEnumeration = z.infer<typeof ToolEnumerationSchema>;

export const FindingInputSchema = z.object({
  rule_id: z.string().min(1),
  severity: Severity,
  evidence: z.string().min(1),
  remediation: z.string().min(1),
  owasp_category: OwaspCategory.nullable().default(null),
  mitre_technique: z.string().nullable().default(null),
  // Phase 1: Optional evidence chain fields (migration 011).
  // Optional so existing FindingInput construction sites don't need changes.
  // Pipeline fills defaults (1.0, null) when persisting to DB.
  confidence: z.number().min(0).max(1).optional(),
  evidence_chain: z.record(z.unknown()).nullable().optional(),
});
export type FindingInput = z.infer<typeof FindingInputSchema>;

// ─── Server Profile Schema ─────────────────────────────────────────────────

export const ServerProfileSchema = z.object({
  id: z.string().uuid(),
  server_id: z.string().uuid(),
  scan_id: z.string().uuid(),
  profile_type: z.string().min(1).max(200),
  capabilities: z.array(z.object({
    capability: z.string(),
    confidence: z.number().min(0).max(1),
    evidence: z.array(z.object({
      source: z.string(),
      tool_name: z.string().nullable(),
      detail: z.string(),
      weight: z.number().min(0).max(1),
    })),
  })),
  attack_surfaces: z.array(z.string()),
  data_flow_pairs: z.array(z.object({
    source_tool: z.string(),
    sink_tool: z.string(),
    flow_type: z.string(),
  })),
  threats: z.array(z.object({
    id: z.string(),
    name: z.string(),
    description: z.string(),
    rule_ids: z.array(z.string()),
  })),
  summary: z.string(),
  has_source_code: z.boolean(),
  has_connection: z.boolean(),
  has_dependencies: z.boolean(),
  tool_count: z.number().int().nonnegative(),
  created_at: z.coerce.date(),
});
export type ServerProfileRecord = z.infer<typeof ServerProfileSchema>;

export const ServerProfileInputSchema = z.object({
  server_id: z.string().uuid(),
  scan_id: z.string().uuid(),
  profile_type: z.string().min(1).max(200),
  capabilities: z.array(z.object({
    capability: z.string(),
    confidence: z.number().min(0).max(1),
    evidence: z.array(z.object({
      source: z.string(),
      tool_name: z.string().nullable(),
      detail: z.string(),
      weight: z.number().min(0).max(1),
    })),
  })),
  attack_surfaces: z.array(z.string()),
  data_flow_pairs: z.array(z.object({
    source_tool: z.string(),
    sink_tool: z.string(),
    flow_type: z.string(),
  })),
  threats: z.array(z.object({
    id: z.string(),
    name: z.string(),
    description: z.string(),
    rule_ids: z.array(z.string()),
  })),
  summary: z.string(),
  has_source_code: z.boolean(),
  has_connection: z.boolean(),
  has_dependencies: z.boolean(),
  tool_count: z.number().int().nonnegative(),
});
export type ServerProfileInput = z.infer<typeof ServerProfileInputSchema>;

// ─── Detection Rule Schema ──────────────────────────────────────────────────

// ─── Risk Domain Categories ─────────────────────────────────────────────────
// 13 risk domains derived from cross-referencing 6 compliance frameworks
// (OWASP MCP, OWASP ASI, CoSAI, EU AI Act, MITRE ATLAS, MAESTRO).
// See rules/framework-registry.yaml for the complete many-to-many mapping.
export const RiskDomain = z.enum([
  "prompt-injection",
  "tool-poisoning",
  "code-vulnerabilities",
  "data-exfiltration",
  "authentication",
  "supply-chain-security",
  "human-oversight",
  "audit-logging",
  "multi-agent-security",
  "protocol-transport",
  "denial-of-service",
  "container-runtime",
  "model-manipulation",
]);
export type RiskDomain = z.infer<typeof RiskDomain>;

export const DetectionRuleSchema = z.object({
  id: z.string().min(1).max(50),
  name: z.string().min(1),
  category: z.enum([
    "description-analysis",
    "schema-analysis",
    "code-analysis",
    "dependency-analysis",
    "behavioral-analysis",
    "ecosystem-context",
    "adversarial-ai",
    "auth-analysis",
    "protocol-surface",
    "2026-attack-surface",
    "threat-intelligence",
    "compliance-governance",
    "supply-chain-advanced",
    "ai-runtime-exploitation",
    "protocol-edge-cases",
    "data-privacy-attacks",
    "infrastructure-runtime",
    "cross-ecosystem-emergent",
  ]),
  severity: Severity,
  owasp: OwaspCategory.nullable().default(null),
  mitre: z.string().nullable().default(null),
  detect: z.object({
    type: z.enum(["regex", "ast", "typed", "schema-check", "behavioral", "composite"]),
    patterns: z.array(z.string()).optional(),
    context: z
      .enum([
        "source_code",
        "tool_description",
        "parameter_schema",
        "metadata",
        "parameter_description",
        "server_initialize_fields",
        "resource_metadata",
        "prompt_metadata",
        "tool_annotations",
      ])
      .optional(),
    exclude_patterns: z.array(z.string()).optional(),
    conditions: z.record(z.unknown()).optional(),
  }),
  remediation: z.string().min(1),
  enabled: z.boolean().default(true),
  // Phase 0, chunk 0.2 — per-rule opt-in to the v2 engine path. When true,
  // findings produced by this rule are counted toward the shadow `score_v2`
  // in addition to the public score. Always false until a rule has been
  // migrated to the Rule Standard v2 contract (see docs/standards/rule-standard-v2.md).
  engine_v2: z.boolean().default(false),
});
export type DetectionRule = z.infer<typeof DetectionRuleSchema>;

// ─── Dynamic Test Results ────────────────────────────────────────────────────

/**
 * Persisted result of a dynamic tool invocation test session.
 * Append-only (ADR-008) — one row per DynamicTester.test() execution.
 * The raw_report column holds the full DynamicReport for audit purposes.
 */
export const DynamicTestResultSchema = z.object({
  id: z.string().uuid(),
  server_id: z.string().uuid(),
  /** Scan that triggered this dynamic test — null when run standalone */
  scan_id: z.string().uuid().nullable(),
  endpoint: z.string().url(),
  consented: z.boolean(),
  /** Which of the three consent mechanisms granted access */
  consent_method: z.enum(["allowlist", "tool_declaration", "wellknown"]).nullable(),
  tested_at: z.coerce.date(),
  elapsed_ms: z.number().int().nonnegative(),
  tools_tested: z.number().int().nonnegative().default(0),
  tools_skipped: z.number().int().nonnegative().default(0),
  output_findings_count: z.number().int().nonnegative().default(0),
  injection_vulnerable_count: z.number().int().nonnegative().default(0),
  output_injection_risk: z.enum(["none", "low", "medium", "high", "critical"]),
  injection_vulnerability: z.enum(["none", "low", "medium", "high", "critical"]),
  schema_compliance: z.enum(["pass", "warn", "fail"]),
  timing_anomalies: z.number().int().nonnegative().default(0),
  /** Full DynamicReport JSON for audit trail — never queried, only fetched for export */
  raw_report: z.record(z.unknown()).nullable(),
  created_at: z.coerce.date(),
});
export type DynamicTestResult = z.infer<typeof DynamicTestResultSchema>;

// ─── Attack Chain Schema ────────────────────────────────────────────────────

export const AttackChainSchema = z.object({
  id: z.string().uuid(),
  chain_id: z.string().max(16),
  config_id: z.string().max(16),
  kill_chain_id: z.string().max(10),
  kill_chain_name: z.string(),
  steps: z.array(z.unknown()),
  exploitability_overall: z.number().min(0).max(1),
  exploitability_rating: z.enum(["critical", "high", "medium", "low"]),
  exploitability_factors: z.array(z.unknown()),
  narrative: z.string(),
  mitigations: z.array(z.unknown()),
  owasp_refs: z.array(z.string()),
  mitre_refs: z.array(z.string()),
  evidence: z.unknown(),
  created_at: z.date(),
});
export type AttackChainRecord = z.infer<typeof AttackChainSchema>;

export const AttackChainInputSchema = z.object({
  chain_id: z.string().max(16),
  config_id: z.string().max(16),
  kill_chain_id: z.string().max(10),
  kill_chain_name: z.string(),
  steps: z.array(z.unknown()),
  exploitability_overall: z.number().min(0).max(1),
  exploitability_rating: z.enum(["critical", "high", "medium", "low"]),
  exploitability_factors: z.array(z.unknown()),
  narrative: z.string(),
  mitigations: z.array(z.unknown()),
  owasp_refs: z.array(z.string()),
  mitre_refs: z.array(z.string()),
  evidence: z.unknown(),
});
export type AttackChainInput = z.infer<typeof AttackChainInputSchema>;

// ─── API Response Schemas ────────────────────────────────────────────────────

export const ServerListQuerySchema = z.object({
  q: z.string().optional(),
  category: ServerCategory.optional(),
  min_score: z.coerce.number().int().min(0).max(100).optional(),
  max_score: z.coerce.number().int().min(0).max(100).optional(),
  sort: z
    .enum(["score", "name", "stars", "updated", "downloads"])
    .default("score"),
  order: z.enum(["asc", "desc"]).default("desc"),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});
export type ServerListQuery = z.infer<typeof ServerListQuerySchema>;

// ─── Compliance Agents (ADR-009) ────────────────────────────────────────────

/**
 * Framework agent identifiers — kept here so other packages can validate
 * compliance scan inputs without importing from `@mcp-sentinel/compliance-agents`
 * (which would create a circular dependency on `@mcp-sentinel/database`).
 */
export const ComplianceFrameworkId = z.enum([
  "owasp_mcp",
  "owasp_asi",
  "cosai",
  "maestro",
  "eu_ai_act",
  "mitre_atlas",
]);
export type ComplianceFrameworkId = z.infer<typeof ComplianceFrameworkId>;

export const ComplianceAgentPhase = z.enum(["synthesis", "execution"]);
export type ComplianceAgentPhase = z.infer<typeof ComplianceAgentPhase>;

export const ComplianceFindingRecordSchema = z.object({
  id: z.string().uuid(),
  scan_id: z.string().uuid(),
  server_id: z.string().uuid(),
  framework: ComplianceFrameworkId,
  rule_id: z.string().min(1).max(120),
  category_control: z.string().min(1).max(120),
  severity: Severity,
  confidence: z.number().min(0).max(1),
  bundle_id: z.string().min(1).max(120),
  test_id: z.string().min(1).max(120),
  test_hypothesis: z.string(),
  judge_rationale: z.string(),
  evidence_chain: z.record(z.unknown()),
  remediation: z.string(),
  created_at: z.coerce.date(),
});
export type ComplianceFindingRecord = z.infer<typeof ComplianceFindingRecordSchema>;

export const ComplianceAgentRunSchema = z.object({
  id: z.string().uuid(),
  scan_id: z.string().uuid(),
  server_id: z.string().uuid(),
  rule_id: z.string().min(1).max(120),
  framework: ComplianceFrameworkId,
  phase: ComplianceAgentPhase,
  cache_key: z.string().min(1).max(200),
  model: z.string().min(1).max(80),
  temperature: z.number().min(0).max(2),
  max_tokens: z.number().int().nonnegative(),
  prompt: z.record(z.unknown()),
  response: z.record(z.unknown()),
  cached: z.boolean().default(false),
  duration_ms: z.number().int().nonnegative().default(0),
  input_tokens: z.number().int().nonnegative().nullable(),
  output_tokens: z.number().int().nonnegative().nullable(),
  created_at: z.coerce.date(),
});
export type ComplianceAgentRun = z.infer<typeof ComplianceAgentRunSchema>;

export const ComplianceTestCacheSchema = z.object({
  id: z.string().uuid(),
  cache_key: z.string().min(1).max(200),
  server_id: z.string().uuid(),
  rule_id: z.string().min(1).max(120),
  framework: ComplianceFrameworkId,
  bundle_id: z.string().min(1).max(120),
  content_hash: z.string().min(1).max(64),
  tests: z.array(z.record(z.unknown())),
  model: z.string().min(1).max(80),
  created_at: z.coerce.date(),
});
export type ComplianceTestCache = z.infer<typeof ComplianceTestCacheSchema>;

// ─── Compliance Posture Matrix (Cluster B) ──────────────────────────────────
//
// Aggregate response for `GET /api/v1/servers/:slug/compliance` — a one-shot
// summary across all 7 compliance frameworks so the public registry can
// render the Framework Posture Matrix without 7 round-trips to the per-
// framework signed endpoints.
//
// This is a NAVIGATIONAL summary, not an auditable artifact. The signed,
// HMAC-attested artifacts continue to live at the per-framework
// `/compliance/:framework.{json,html,pdf}` endpoints.
//
// `.passthrough()` on every schema is deliberate (Cluster A B3 lesson):
//   - future scorer additions, future framework registry additions, and
//     future control-status fields MUST NOT silently null any field at the
//     response seam. Unknown keys are forwarded verbatim to consumers.
// ────────────────────────────────────────────────────────────────────────────

/**
 * One row of the per-framework matrix entry. The framework_id union is the
 * exact set produced by `@mcp-sentinel/compliance-reports`'s `FrameworkId`
 * type — duplicated here as a string-literal union so the database package
 * does not need to import the compliance-reports package (which would create
 * a layering violation: database is the lowest tier, compliance-reports
 * depends on it).
 */
export const ComplianceFrameworkMatrixIdSchema = z.enum([
  "eu_ai_act",
  "iso_27001",
  "owasp_mcp",
  "owasp_asi",
  "cosai_mcp",
  "maestro",
  "mitre_atlas",
]);
export type ComplianceFrameworkMatrixId = z.infer<typeof ComplianceFrameworkMatrixIdSchema>;

/**
 * Per-control status counts within a single framework, shaped for the
 * Posture Matrix grid cell (met / partial / unmet / not_applicable + total).
 *
 * `not_applicable` is rendered explicitly — never hidden — because a
 * regulator-grade product must surface honest gaps (e.g. ASI10 has no
 * static-analysis assessor in the current rule set).
 */
export const ComplianceControlCountsSchema = z
  .object({
    met: z.number().int().nonnegative(),
    partial: z.number().int().nonnegative(),
    unmet: z.number().int().nonnegative(),
    not_applicable: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
  })
  .passthrough();
export type ComplianceControlCounts = z.infer<typeof ComplianceControlCountsSchema>;

/**
 * Relative paths for the per-framework signed artifacts. Paths are
 * relative (no host) so the frontend uses its own apiUrl env var rather
 * than baking the API origin into the response.
 */
export const ComplianceFrameworkDownloadPathsSchema = z
  .object({
    json: z.string().min(1),
    html: z.string().min(1),
    pdf: z.string().min(1),
    badge_svg: z.string().min(1),
  })
  .passthrough();
export type ComplianceFrameworkDownloadPaths = z.infer<typeof ComplianceFrameworkDownloadPathsSchema>;

/**
 * One row of the Posture Matrix — one framework's summary plus
 * navigational links into the signed-pack endpoints.
 *
 * `coverage_band` mirrors the same `CoverageBand` enum used by score
 * detail (ScoreDetailResponseSchema.coverage_band) to keep the public API
 * vocabulary consistent.
 */
export const ComplianceFrameworkMatrixEntrySchema = z
  .object({
    framework_id: ComplianceFrameworkMatrixIdSchema,
    framework_name: z.string().min(1),
    framework_version: z.string().min(1),
    controls: ComplianceControlCountsSchema,
    overall_status: z.enum(["met", "partial", "unmet", "not_applicable"]),
    coverage_band: CoverageBand,
    download_paths: ComplianceFrameworkDownloadPathsSchema,
  })
  .passthrough();
export type ComplianceFrameworkMatrixEntry = z.infer<typeof ComplianceFrameworkMatrixEntrySchema>;

/**
 * Full response body for `GET /api/v1/servers/:slug/compliance`. The
 * frontend Framework Posture Matrix consumes this directly; per-framework
 * detail still requires a round-trip to the signed-pack endpoint.
 */
export const ComplianceMatrixResponseSchema = z
  .object({
    server_slug: z.string().min(1),
    server_name: z.string().min(1),
    /** ISO 8601; mirrors the signed report `assessed_at` field. Null when no scan exists. */
    last_assessed_at: z.string().nullable(),
    rules_version: z.string().min(1),
    frameworks: z.array(ComplianceFrameworkMatrixEntrySchema),
  })
  .passthrough();
export type ComplianceMatrixResponse = z.infer<typeof ComplianceMatrixResponseSchema>;

/**
 * One framework-control mapping cited by a finding. Used inside the
 * `framework_controls[]` array attached to every row of
 * `GET /api/v1/servers/:slug/findings`.
 *
 * The string-typed `framework_id` allows future framework additions
 * without forcing a database migration (the matrix endpoint uses the
 * stricter enum because it is the source of truth for the matrix grid).
 */
export const FrameworkControlMappingSchema = z
  .object({
    framework_id: z.string().min(1),
    control_id: z.string().min(1),
    control_title: z.string().min(1),
  })
  .passthrough();
export type FrameworkControlMapping = z.infer<typeof FrameworkControlMappingSchema>;

/**
 * Per-finding detection-quality footer (Cluster C invention #4).
 *
 * Every finding row on `GET /api/v1/servers/:slug` and
 * `GET /api/v1/servers/:slug/findings` carries this object so the
 * frontend can render the regulator-grade footer:
 *
 *   "Backed by N red-team fixtures, CVE-x,y,z, precision p, recall r;
 *    last validated ${last_validated_at}."
 *
 * Two distinct empty states are surfaced — the frontend treats them
 * differently:
 *
 *   1. The whole field is `null` → the rule is NOT YET WIRED into either
 *      the red-team corpus or the CVE replay manifest (an honest gap;
 *      the frontend renders "detection quality not yet measured").
 *
 *   2. The field is non-null but `precision`/`recall`/`last_validated_at`
 *      are null and `fixture_count: 0`/`cve_replay_ids: []` → the rule
 *      is wired but has no validation data on file yet. The frontend
 *      renders "no validations on file" rather than hiding.
 *
 * `precision` and `recall` are `[0..1]` ratios (not percentages) per the
 * red-team `RuleAccuracy` contract.
 */
export const DetectionQualitySchema = z
  .object({
    precision: z.number().min(0).max(1).nullable(),
    recall: z.number().min(0).max(1).nullable(),
    fixture_count: z.number().int().nonnegative(),
    cve_replay_ids: z.array(z.string().min(1)),
    last_validated_at: z.string().nullable(),
  })
  .passthrough();
export type DetectionQuality = z.infer<typeof DetectionQualitySchema>;

/**
 * Public shape of one finding row returned by
 * `GET /api/v1/servers/:slug/findings`. Mirrors the persisted Finding
 * schema and adds the `framework_controls[]` cross-walk computed at the
 * API layer from `compliance-reports/frameworks/*.ts`.
 *
 * The schema is intentionally additive on top of the persistence shape:
 *   - every existing field on `findings` rows must still pass through
 *   - `framework_controls` is ALWAYS an array, never null/undefined; an
 *     empty array means the rule has no framework alignment yet (an
 *     honest gap — the frontend renders "no framework cross-walk" only
 *     on empty arrays).
 *   - `detection_quality` is nullable: `null` = the rule is not yet
 *     wired into red-team/CVE-replay validation; a populated object
 *     = the rule has validation data on file (with its own internal
 *     "no data yet" state — see DetectionQualitySchema).
 */
export const FindingResponseSchema = z
  .object({
    id: z.string().uuid(),
    server_id: z.string().uuid(),
    scan_id: z.string().uuid(),
    rule_id: z.string().min(1).max(50),
    severity: Severity,
    evidence: z.string().min(1).max(10000),
    remediation: z.string().min(1).max(5000),
    owasp_category: OwaspCategory.nullable(),
    mitre_technique: z.string().max(100).nullable(),
    disputed: z.boolean(),
    confidence: z.number().min(0).max(1),
    evidence_chain: z.record(z.unknown()).nullable(),
    created_at: z.coerce.date(),
    framework_controls: z.array(FrameworkControlMappingSchema),
    detection_quality: DetectionQualitySchema.nullable(),
  })
  .passthrough();
export type FindingResponse = z.infer<typeof FindingResponseSchema>;

// ─── Risk Boundary (Cluster C invention #3) ─────────────────────────────────
//
// Surfaces this server's involvement in cross-server risk patterns
// (P01-P12 from packages/risk-matrix) and kill chains (KC01-KC07 from
// packages/attack-graph). The Risk Boundary tab on the server detail
// page consumes the response shape verbatim.
//
// Empty-state contract: when neither cross-server analysis nor kill
// chains have ever been computed for this server, both arrays are
// empty. Frontend renders that as "no cross-config exposure on file" —
// this empty state IS a feature, not a bug.

export const RiskBoundaryPatternPairingSchema = z
  .object({
    slug: z.string().min(1),
    name: z.string().min(1),
  })
  .passthrough();
export type RiskBoundaryPatternPairing = z.infer<typeof RiskBoundaryPatternPairingSchema>;

export const RiskBoundaryPatternSchema = z
  .object({
    pattern_id: z.string().min(1),
    pattern_name: z.string().min(1),
    pattern_summary: z.string().min(1),
    severity: z.enum(["critical", "high", "medium", "low"]),
    /**
     * Number of OTHER registry servers that, paired with this server in
     * the same client config, would trigger this pattern. May be 0 — an
     * honest "this pattern has no current pair candidates" signal.
     */
    paired_with_count: z.number().int().nonnegative(),
    /**
     * Up to 5 sample paired servers (slug + name only). Capped because a
     * 47-line list is not useful UX. The frontend renders these as "if
     * you co-deploy with these, you trip P0X".
     */
    sample_pairings: z.array(RiskBoundaryPatternPairingSchema).max(5),
  })
  .passthrough();
export type RiskBoundaryPattern = z.infer<typeof RiskBoundaryPatternSchema>;

export const RiskBoundaryKillChainSchema = z
  .object({
    kc_id: z.string().min(1),
    name: z.string().min(1),
    severity_score: z.number().min(0).max(100),
    narrative: z.string().min(1),
    contributing_rule_ids: z.array(z.string().min(1)),
    cve_evidence_ids: z.array(z.string().min(1)),
    mitigations: z.array(z.string().min(1)),
  })
  .passthrough();
export type RiskBoundaryKillChain = z.infer<typeof RiskBoundaryKillChainSchema>;

export const RiskBoundaryResponseSchema = z
  .object({
    server_slug: z.string().min(1),
    server_name: z.string().min(1),
    same_config_patterns: z.array(RiskBoundaryPatternSchema),
    kill_chains: z.array(RiskBoundaryKillChainSchema),
  })
  .passthrough();
export type RiskBoundaryResponse = z.infer<typeof RiskBoundaryResponseSchema>;

// ─── Drift & History (Cluster C invention #8) ──────────────────────────────
//
// Surfaces G6 (rug-pull) + I14 (rolling capability drift) signals as a
// regulator-grade headline list, plus a compact score history. The
// Drift & History tab on the server detail page consumes this directly.
//
// Resilience: when there are fewer than 2 scans in the requested
// window, `headlines` is `[]`, `score_history` may be 0–1 entries, and
// `trend` is "insufficient_data". Frontend renders an explicit "not
// enough scan history yet" panel — honest gap, never silently hidden.

export const DriftHeadlineKindSchema = z.enum([
  "tool_added",
  "tool_removed",
  "tool_description_changed",
  "capability_added",
  "dangerous_capability_introduced",
  "score_changed",
]);
export type DriftHeadlineKind = z.infer<typeof DriftHeadlineKindSchema>;

export const DriftSeverityHintSchema = z.enum([
  "neutral",
  "elevated",
  "degrading",
  "improving",
]);
export type DriftSeverityHint = z.infer<typeof DriftSeverityHintSchema>;

export const DriftHeadlineRefSchema = z
  .object({
    tool_name: z.string().nullable().optional(),
    from: z.string().nullable().optional(),
    to: z.string().nullable().optional(),
  })
  .passthrough();
export type DriftHeadlineRef = z.infer<typeof DriftHeadlineRefSchema>;

export const DriftHeadlineSchema = z
  .object({
    kind: DriftHeadlineKindSchema,
    severity_hint: DriftSeverityHintSchema,
    occurred_at: z.string().min(1),
    summary: z.string().min(1).max(200),
    ref: DriftHeadlineRefSchema.optional(),
  })
  .passthrough();
export type DriftHeadline = z.infer<typeof DriftHeadlineSchema>;

export const DriftScorePointSchema = z
  .object({
    scanned_at: z.string().min(1),
    score: z.number().int().min(0).max(100),
  })
  .passthrough();
export type DriftScorePoint = z.infer<typeof DriftScorePointSchema>;

export const DriftTrendSchema = z.enum([
  "neutral",
  "improving",
  "degrading",
  "insufficient_data",
]);
export type DriftTrend = z.infer<typeof DriftTrendSchema>;

export const DriftResponseSchema = z
  .object({
    server_slug: z.string().min(1),
    window_days: z.number().int().min(1).max(365),
    headlines: z.array(DriftHeadlineSchema),
    score_history: z.array(DriftScorePointSchema),
    trend: DriftTrendSchema,
  })
  .passthrough();
export type DriftResponse = z.infer<typeof DriftResponseSchema>;

// ─── API Response Schemas ────────────────────────────────────────────────────

export const EcosystemStatsSchema = z.object({
  total_servers: z.number(),
  total_scanned: z.number(),
  average_score: z.number(),
  category_breakdown: z.record(z.number()),
  severity_breakdown: z.record(z.number()),
  score_distribution: z.array(
    z.object({ range: z.string(), count: z.number() })
  ),
});
export type EcosystemStats = z.infer<typeof EcosystemStatsSchema>;
