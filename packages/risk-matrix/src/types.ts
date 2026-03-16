import { z } from "zod";

// ── Capability classification ──────────────────────────────────────────────────

export const CapabilitySchema = z.enum([
  "reads-data",
  "writes-data",
  "executes-code",
  "sends-network",
  "accesses-filesystem",
  "manages-credentials",
  "reads-messages",           // email, slack, github issues — G1 gateway
  "writes-agent-config",      // J1 — cross-agent config poisoning
  "reads-agent-memory",       // H3 — shared agent memory
  "writes-agent-memory",      // H3 — shared agent memory writes
  "web-scraping",             // G1 — ingests untrusted web content
  "code-generation",          // generates code that may be executed
  "database-query",           // parameterized DB queries
  "database-admin",           // DDL, DROP, schema changes
]);
export type Capability = z.infer<typeof CapabilitySchema>;

// ── Graph nodes ────────────────────────────────────────────────────────────────

export interface CapabilityNode {
  server_id: string;
  server_name: string;
  server_slug: string;
  latest_score: number | null;
  capabilities: Capability[];
  /** True if server reads from user-controlled or untrusted external sources */
  is_injection_gateway: boolean;
  /** True if server can write to files/configs/memory readable by other agents */
  is_shared_writer: boolean;
  category: string | null;
}

// ── Graph edges ────────────────────────────────────────────────────────────────

export type EdgeType =
  | "data_flow"           // Server A reads data that Server B writes
  | "credential_chain"    // Server A holds credentials that Server B could abuse
  | "injection_path"      // Untrusted content from A can reach B's execution context
  | "config_poisoning"    // A writes agent configs that B reads
  | "memory_pollution"    // A writes shared memory that B reads
  | "privilege_escalation"// A's low-privilege output enables B's high-privilege action
  | "exfiltration_chain"; // A reads sensitive data, B sends it externally

export interface RiskEdge {
  from_server_id: string;
  to_server_id: string;
  edge_type: EdgeType;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  owasp: string;
  mitre: string;
}

// ── Risk patterns ─────────────────────────────────────────────────────────────

export interface RiskPattern {
  id: string;
  name: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  owasp: string;
  mitre: string;
  required_capabilities: Capability[][];  // Array of [cap_set_A, cap_set_B] pairs
  /**
   * Function that checks if this pattern applies to a pair/set of nodes.
   * Returns a RiskEdge if the pattern matches, null otherwise.
   */
  detect: (nodes: CapabilityNode[]) => RiskEdge[];
}

// ── Matrix output ──────────────────────────────────────────────────────────────

export interface RiskMatrixReport {
  generated_at: string;
  config_id: string;    // hash of the server ID set
  server_count: number;
  edges: RiskEdge[];
  patterns_detected: string[];  // pattern IDs that fired
  aggregate_risk: "none" | "low" | "medium" | "high" | "critical";
  /**
   * Recommended score adjustment: if lethal trifecta is detected across
   * servers, each participating server gets its score capped at 40.
   */
  score_caps: Record<string, number>;
  summary: string;
}
