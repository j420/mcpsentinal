/**
 * Attack Graph Engine — Type Definitions
 *
 * These types model multi-step kill chains that synthesize individual
 * risk-matrix edges (P01-P12) into ordered attack narratives with
 * exploitability scoring and actionable mitigations.
 *
 * Design philosophy:
 *   - Every chain maps to a documented real-world attack or CVE
 *   - Exploitability scoring is transparent (every factor visible)
 *   - Mitigations are ordered by chain-breaking impact
 *   - No LLM — all narrative generation is deterministic
 */
import type {
  Capability,
  CapabilityNode,
  RiskEdge,
  EdgeType,
  RiskMatrixReport,
} from "@mcp-sentinel/risk-matrix";

// Re-export consumed types for convenience
export type { Capability, CapabilityNode, RiskEdge, EdgeType, RiskMatrixReport };

// ── Attack objectives ──────────────────────────────────────────────────────────

/**
 * What the attacker is trying to achieve. Each kill chain template
 * declares exactly one objective. This constrains which role
 * combinations are meaningful.
 */
export type AttackObjective =
  | "data_exfiltration"        // steal sensitive data (SSH keys, credentials, PII)
  | "remote_code_execution"    // execute arbitrary code on user's machine
  | "credential_theft"         // steal OAuth tokens, API keys, auth credentials
  | "persistent_backdoor"      // maintain persistent access across sessions
  | "privilege_escalation";    // escalate from limited to full system access

// ── Attack step roles ──────────────────────────────────────────────────────────

/**
 * Each server in a kill chain plays a specific role. Role assignment
 * is based on the server's capabilities (from CapabilityNode).
 *
 * A server can play at most ONE role per chain instance — this prevents
 * degenerate single-server "chains" that the risk-matrix already covers.
 */
export type AttackRole =
  | "injection_gateway"   // ingests attacker-controlled content (web scraper, email reader)
  | "pivot"               // transforms/relays data between stages
  | "data_source"         // has access to sensitive data (filesystem, credentials, DB)
  | "executor"            // can execute code or commands
  | "exfiltrator"         // can send data externally (network, email, webhook)
  | "config_writer"       // can modify agent/MCP configuration files
  | "memory_writer";      // can write to shared agent memory/vector stores

// ── Attack step ────────────────────────────────────────────────────────────────

export interface AttackStep {
  /** Position in the chain (1-indexed) */
  ordinal: number;
  /** Server playing this role */
  server_id: string;
  server_name: string;
  /** Role this server plays in the chain */
  role: AttackRole;
  /** Capabilities that qualify this server for the role */
  capabilities_used: Capability[];
  /** Specific tool names involved (when identifiable from CapabilityNode) */
  tools_involved: string[];
  /** Risk-matrix edge connecting this step to the next (null for last step) */
  edge_to_next: RiskEdge | null;
  /** Per-step narrative fragment */
  narrative: string;
}

// ── Exploitability score ───────────────────────────────────────────────────────

/**
 * 7-factor weighted exploitability model.
 *
 * Each factor is independently testable with known inputs and outputs.
 * The overall score uses a weighted sum (not noisy-OR — factors are
 * not independent probabilities but correlated risk indicators).
 *
 * Rating thresholds:
 *   >= 0.75 → critical
 *   >= 0.55 → high
 *   >= 0.35 → medium
 *   <  0.35 → low
 */
export interface ExploitabilityScore {
  /** Weighted composite: 0.0-1.0 */
  overall: number;
  /** How likely this attack is to be attempted */
  likelihood: number;
  /** Damage if the attack succeeds */
  impact: number;
  /** How easy the attack is to execute (1.0 = trivial, 0.0 = extremely hard) */
  effort: number;
  /** Human-readable rating */
  rating: "critical" | "high" | "medium" | "low";
  /** Transparent breakdown of all 7 factors */
  factors: ExploitabilityFactor[];
}

export interface ExploitabilityFactor {
  /** Factor identifier */
  factor: string;
  /** Computed factor value (0.0-1.0) */
  value: number;
  /** Contribution weight (all weights sum to 1.0) */
  weight: number;
  /** Human-readable explanation of this factor's contribution */
  description: string;
}

// ── Mitigation ─────────────────────────────────────────────────────────────────

/**
 * Actionable mitigation — ordered by chain-breaking impact.
 *
 * "breaks_chain" mitigations are listed first because removing a single
 * link in the chain neutralizes the entire attack. "reduces_risk"
 * mitigations make the attack harder but don't fully prevent it.
 */
export interface Mitigation {
  /** What action to take */
  action:
    | "remove_server"          // nuclear option: remove the server entirely
    | "add_auth"               // add authentication to the server
    | "restrict_capability"    // limit specific tool capabilities
    | "add_confirmation"       // require human confirmation for dangerous ops
    | "isolate_server";        // move server to a separate config/sandbox
  /** Which server to apply the mitigation to */
  target_server_id: string;
  target_server_name: string;
  /** Human-readable description of the mitigation */
  description: string;
  /** Which chain steps this mitigation affects (1-indexed ordinals) */
  breaks_steps: number[];
  /** Whether this fully breaks the chain or only reduces risk */
  effect: "breaks_chain" | "reduces_risk";
}

// ── Kill chain template ────────────────────────────────────────────────────────

/**
 * Declarative kill chain template — models a documented real-world
 * attack pattern. Templates are NOT generic "find all paths" — each
 * maps to a specific attack with known precedent.
 *
 * The engine matches templates against the server set using:
 *   1. Prerequisite check (required patterns + edge types)
 *   2. Role assignment (capabilities match)
 *   3. Edge verification (risk-matrix edges connect consecutive roles)
 */
export interface KillChainTemplate {
  /** Template identifier: "KC01" through "KC07" */
  id: string;
  /** Human-readable attack name */
  name: string;
  /** What the attacker achieves */
  objective: AttackObjective;
  /** Real-world precedent (CVE, research paper, incident report) */
  precedent: string;
  /** Minimum distinct servers required */
  min_servers: number;
  /** Ordered roles that must be filled */
  roles: KillChainRole[];
  /** Risk-matrix pattern IDs (P01-P12) that must have fired */
  required_patterns: string[];
  /** Edge types that must exist between consecutive role-servers */
  required_edge_types: EdgeType[];
  /** Base likelihood before server-specific adjustments (0.0-1.0) */
  base_likelihood: number;
  /** Base impact before server-specific adjustments (0.0-1.0) */
  base_impact: number;
  /** OWASP MCP Top 10 references */
  owasp: string[];
  /** MITRE ATLAS references */
  mitre: string[];
}

export interface KillChainRole {
  /** Role this position plays */
  role: AttackRole;
  /**
   * Capability requirements: OR-groups of AND-sets.
   *
   * A server matches if it satisfies ANY group (OR), where satisfying
   * a group means having ALL capabilities in that group (AND).
   *
   * Example: [["web-scraping"], ["reads-messages"]]
   *   → server needs web-scraping OR reads-messages
   *
   * Example: [["reads-data", "accesses-filesystem"]]
   *   → server needs BOTH reads-data AND accesses-filesystem
   */
  required_capabilities: Capability[][];
  /** Additional flags for specialized role matching */
  flags?: {
    /** Must be classified as an injection gateway */
    is_injection_gateway?: boolean;
    /** Must be classified as a shared writer */
    is_shared_writer?: boolean;
  };
}

// ── Attack chain (output) ──────────────────────────────────────────────────────

export interface AttackChain {
  /**
   * Deterministic chain identifier: SHA-256 of
   * sorted server_ids + kill_chain_id. Two identical server
   * sets with the same template always produce the same chain_id.
   */
  chain_id: string;
  /** Template that produced this chain */
  kill_chain_id: string;
  kill_chain_name: string;
  /** Ordered attack steps */
  steps: AttackStep[];
  /** Exploitability assessment */
  exploitability: ExploitabilityScore;
  /** Full human-readable attack narrative */
  narrative: string;
  /** Ordered mitigations (chain-breakers first) */
  mitigations: Mitigation[];
  /** Framework references */
  owasp_refs: string[];
  mitre_refs: string[];
  /** Supporting evidence from risk-matrix and single-server analysis */
  evidence: ChainEvidence;
}

export interface ChainEvidence {
  /** Risk-matrix edges that connect the chain steps */
  risk_edges: RiskEdge[];
  /** Pattern IDs (P01-P12) that were prerequisites for this chain */
  pattern_ids: string[];
  /** Single-server findings that strengthen the chain's credibility */
  supporting_findings: string[];
}

// ── Attack graph report (top-level output) ─────────────────────────────────────

export interface AttackGraphReport {
  /** ISO timestamp */
  generated_at: string;
  /** Config ID from risk-matrix (hash of server ID set) */
  config_id: string;
  /** Input server count */
  server_count: number;
  /** All synthesized attack chains, ordered by exploitability (descending) */
  chains: AttackChain[];
  /** Summary statistics */
  chain_count: number;
  critical_chains: number;
  high_chains: number;
  /** Aggregate assessment */
  aggregate_risk: "none" | "low" | "medium" | "high" | "critical";
  /** Human-readable summary */
  summary: string;
}

// ── Engine input ───────────────────────────────────────────────────────────────

/**
 * Input to AttackGraphEngine.analyze() — assembled from risk-matrix
 * output and the capability graph.
 */
export interface AttackGraphInput {
  /** Capability-classified servers */
  nodes: CapabilityNode[];
  /** Risk-matrix edges (P01-P12 output) */
  edges: RiskEdge[];
  /** Pattern IDs that fired in risk-matrix analysis */
  patterns_detected: string[];
  /** Optional: single-server finding rule IDs per server for evidence enrichment */
  server_findings?: Record<string, string[]>;
}
