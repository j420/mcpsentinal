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
});
export type Score = z.infer<typeof ScoreSchema>;

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
