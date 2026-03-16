import type { RuleFixtureSet } from "../types.js";

const base = {
  server: { id: "test", name: "test-server", description: null, github_url: null },
  tools: [{ name: "tool", description: "A tool", input_schema: null }],
  source_code: null,
  dependencies: [],
};

// ── E1: No Authentication Required ────────────────────────────────────────────
export const E1: RuleFixtureSet = {
  rule_id: "E1",
  rule_name: "No Authentication Required",
  fixtures: [
    {
      description: "Server requires no auth",
      context: {
        ...base,
        connection_metadata: { auth_required: false, transport: "http", response_time_ms: 200 },
      },
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Server requires auth",
      context: {
        ...base,
        connection_metadata: { auth_required: true, transport: "http", response_time_ms: 200 },
      },
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "No connection metadata (stdio transport) — no finding",
      context: { ...base, connection_metadata: null },
      expect_finding: false,
      kind: "edge_case",
    },
  ],
};

// ── E2: Insecure Transport ────────────────────────────────────────────────────
export const E2: RuleFixtureSet = {
  rule_id: "E2",
  rule_name: "Insecure Transport (HTTP/WS)",
  fixtures: [
    {
      description: "Plain HTTP transport",
      context: {
        ...base,
        connection_metadata: { auth_required: true, transport: "http", response_time_ms: 200 },
      },
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Plain WebSocket transport",
      context: {
        ...base,
        connection_metadata: { auth_required: true, transport: "ws", response_time_ms: 200 },
      },
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "HTTPS transport — secure",
      context: {
        ...base,
        connection_metadata: { auth_required: true, transport: "https", response_time_ms: 200 },
      },
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "stdio transport — local, no network",
      context: {
        ...base,
        connection_metadata: { auth_required: false, transport: "stdio", response_time_ms: 5 },
      },
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── E3: Response Time Anomaly ─────────────────────────────────────────────────
export const E3: RuleFixtureSet = {
  rule_id: "E3",
  rule_name: "Response Time Anomaly",
  fixtures: [
    {
      description: "Response time over 10 seconds",
      context: {
        ...base,
        connection_metadata: { auth_required: true, transport: "https", response_time_ms: 12000 },
      },
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Normal response time — 300ms",
      context: {
        ...base,
        connection_metadata: { auth_required: true, transport: "https", response_time_ms: 300 },
      },
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Edge case: exactly at threshold — 10000ms",
      context: {
        ...base,
        connection_metadata: { auth_required: true, transport: "https", response_time_ms: 10000 },
      },
      expect_finding: true, // >=10000 should flag
      kind: "edge_case",
    },
  ],
};

// ── E4: Excessive Tool Count ──────────────────────────────────────────────────
export const E4: RuleFixtureSet = {
  rule_id: "E4",
  rule_name: "Excessive Tool Count",
  fixtures: [
    {
      description: "60 tools — well above threshold of 50",
      context: {
        ...base,
        connection_metadata: { auth_required: true, transport: "https", response_time_ms: 300 },
        tools: Array.from({ length: 60 }, (_, i) => ({
          name: `tool_${i}`,
          description: "A tool",
          input_schema: null,
        })),
      },
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "20 tools — normal count",
      context: {
        ...base,
        connection_metadata: { auth_required: true, transport: "https", response_time_ms: 300 },
        tools: Array.from({ length: 20 }, (_, i) => ({
          name: `tool_${i}`,
          description: "A tool",
          input_schema: null,
        })),
      },
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

export const ALL_E_FIXTURES: RuleFixtureSet[] = [E1, E2, E3, E4];
