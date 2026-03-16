import type { RuleFixtureSet } from "../types.js";

const base = {
  server: { id: "test", name: "test-server", description: null, github_url: null },
  source_code: null,
  dependencies: [],
  connection_metadata: null,
};

function toolCtx(tools: Array<{ name: string; description: string; input_schema: Record<string, unknown> | null }>) {
  return { ...base, tools };
}

// ── F1: Lethal Trifecta ────────────────────────────────────────────────────────
export const F1: RuleFixtureSet = {
  rule_id: "F1",
  rule_name: "Lethal Trifecta — Private Data + Untrusted Content + External Communication",
  fixtures: [
    {
      description: "Server reads DB + scrapes web + sends webhook — complete trifecta",
      context: toolCtx([
        { name: "query_database", description: "Reads records from the internal database", input_schema: null },
        { name: "fetch_webpage", description: "Fetches and returns content from any URL", input_schema: null },
        { name: "send_webhook", description: "Sends HTTP POST to external webhook endpoint", input_schema: null },
      ]),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "F1 — single-server lethal trifecta, score capped at 40",
    },
    {
      description: "Server reads files + ingests emails + sends Slack messages",
      context: toolCtx([
        { name: "read_file", description: "Reads files from the local filesystem", input_schema: null },
        { name: "get_emails", description: "Reads unread emails from inbox", input_schema: null },
        { name: "send_slack_message", description: "Sends a message to Slack", input_schema: null },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: read-only server with no network or untrusted content",
      context: toolCtx([
        { name: "list_files", description: "Lists local project files", input_schema: null },
        { name: "read_file", description: "Reads a local file", input_schema: null },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: notification-only server with no data reading",
      context: toolCtx([
        { name: "send_notification", description: "Sends a push notification", input_schema: null },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Edge: two out of three — missing external comms capability",
      context: toolCtx([
        { name: "read_database", description: "Reads database records", input_schema: null },
        { name: "scrape_url", description: "Fetches arbitrary web content", input_schema: null },
        // No send/webhook/email tool
      ]),
      expect_finding: false,
      kind: "edge_case",
    },
  ],
};

// ── F2: High-Risk Capability Profile ──────────────────────────────────────────
export const F2: RuleFixtureSet = {
  rule_id: "F2",
  rule_name: "High-Risk Capability Profile",
  fixtures: [
    {
      description: "Server executes code and sends network requests",
      context: toolCtx([
        { name: "execute_code", description: "Executes arbitrary code in a sandbox", input_schema: null },
        { name: "http_request", description: "Sends HTTP requests to external services", input_schema: null },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Server has filesystem access and sends network requests",
      context: toolCtx([
        { name: "read_file", description: "Reads files from disk", input_schema: null },
        { name: "write_file", description: "Writes files to disk", input_schema: null },
        { name: "send_request", description: "Sends HTTP request to any URL", input_schema: null },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: read-only with no execution or network capability",
      context: toolCtx([
        { name: "search_docs", description: "Searches documentation", input_schema: null },
        { name: "get_definition", description: "Gets word definition", input_schema: null },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── F3: Data Flow Risk — Source to Sink ────────────────────────────────────────
export const F3: RuleFixtureSet = {
  rule_id: "F3",
  rule_name: "Data Flow Risk — Source to Sink",
  fixtures: [
    {
      description: "Server has read_database + send_email — source to sink data flow",
      context: toolCtx([
        { name: "read_database", description: "Reads records from the database", input_schema: null },
        { name: "send_email", description: "Sends an email message", input_schema: null },
      ]),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "F3 — data source-to-sink enables exfiltration path",
    },
    {
      description: "Server has search_files + upload_to_s3",
      context: toolCtx([
        { name: "search_files", description: "Searches for files matching a pattern", input_schema: null },
        { name: "upload_to_s3", description: "Uploads a file to AWS S3", input_schema: null },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: only read tools, no write/send capability",
      context: toolCtx([
        { name: "list_files", description: "Lists files in directory", input_schema: null },
        { name: "read_file", description: "Reads a file", input_schema: null },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: only send capability, no data reading source",
      context: toolCtx([
        { name: "send_notification", description: "Sends a status notification", input_schema: null },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── F4: MCP Spec Non-Compliance ────────────────────────────────────────────────
export const F4: RuleFixtureSet = {
  rule_id: "F4",
  rule_name: "MCP Spec Non-Compliance",
  fixtures: [
    {
      description: "Server missing required name, version, and protocol version fields",
      context: {
        ...base,
        server: { id: "test", name: "", description: null, github_url: null },
        tools: [{ name: "do_thing", description: null, input_schema: null }],
      },
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Server with all required fields populated — compliant",
      context: {
        ...base,
        server: { id: "test", name: "my-mcp-server", description: "A well-documented server", github_url: "https://github.com/org/repo" },
        tools: [
          {
            name: "read_file",
            description: "Reads a file from the filesystem",
            input_schema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
          },
        ],
      },
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── F5: Official Namespace Squatting ──────────────────────────────────────────
export const F5: RuleFixtureSet = {
  rule_id: "F5",
  rule_name: "Official Namespace Squatting",
  fixtures: [
    {
      description: "Server named '@anthropic-tools/filesystem' by unverified author",
      context: {
        ...base,
        server: { id: "test", name: "@anthropic-tools/filesystem", description: null, github_url: "https://github.com/some-random-user/mcp-fs" },
        tools: [],
      },
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "F5 — namespace squatting for implicit trust exploitation",
    },
    {
      description: "Server named 'mcp-official-github' mimicking official naming",
      context: {
        ...base,
        server: { id: "test", name: "mcp-official-github", description: null, github_url: "https://github.com/unknown/fake-mcp" },
        tools: [],
      },
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Server from official modelcontextprotocol org — legitimate",
      context: {
        ...base,
        server: { id: "test", name: "@modelcontextprotocol/server-filesystem", description: "Official MCP filesystem server", github_url: "https://github.com/modelcontextprotocol/servers" },
        tools: [],
      },
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Server with unique custom namespace — safe",
      context: {
        ...base,
        server: { id: "test", name: "mycompany-file-manager", description: "Company internal file manager", github_url: "https://github.com/mycompany/mcp-files" },
        tools: [],
      },
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── F6: Circular Data Loop ─────────────────────────────────────────────────────
export const F6: RuleFixtureSet = {
  rule_id: "F6",
  rule_name: "Circular Data Loop — Persistent Prompt Injection Storage Risk",
  fixtures: [
    {
      description: "Server has save_note and read_notes — persistent injection loop",
      context: toolCtx([
        { name: "save_note", description: "Saves a note to the notes database", input_schema: null },
        { name: "read_notes", description: "Reads notes from the notes database", input_schema: null },
      ]),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "F6 — attacker poisons stored content once; AI executes on every read",
    },
    {
      description: "Server has write_memory and recall_memory — shared memory injection",
      context: toolCtx([
        { name: "write_memory", description: "Stores data in persistent memory", input_schema: null },
        { name: "recall_memory", description: "Retrieves stored memory entries", input_schema: null },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: only read tools — no write capability to create loop",
      context: toolCtx([
        { name: "read_file", description: "Reads a local file", input_schema: null },
        { name: "list_directory", description: "Lists directory contents", input_schema: null },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: write and read on separate, non-overlapping stores",
      context: toolCtx([
        { name: "write_log", description: "Writes to the audit log (append-only)", input_schema: null },
        { name: "query_database", description: "Reads from the product database", input_schema: null },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── F7: Multi-Step Exfiltration Chain ─────────────────────────────────────────
export const F7: RuleFixtureSet = {
  rule_id: "F7",
  rule_name: "Multi-Step Exfiltration Chain",
  fixtures: [
    {
      description: "Complete chain: read_file + base64_encode + http_request",
      context: toolCtx([
        { name: "read_file", description: "Reads file content from disk", input_schema: null },
        { name: "base64_encode", description: "Encodes data as base64 string", input_schema: null },
        { name: "http_request", description: "Sends HTTP request to any endpoint", input_schema: null },
      ]),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "F7 — no single tool is dangerous; the chain is the threat",
    },
    {
      description: "Chain: query_database + compress_data + send_email",
      context: toolCtx([
        { name: "query_database", description: "Executes SQL queries against the database", input_schema: null },
        { name: "compress_data", description: "Compresses data using gzip", input_schema: null },
        { name: "send_email", description: "Sends email with attachments", input_schema: null },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: only read tools, no transform or exfiltration step",
      context: toolCtx([
        { name: "read_file", description: "Reads a file", input_schema: null },
        { name: "list_directory", description: "Lists directory contents", input_schema: null },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: encode + decode only — no read source or send sink",
      context: toolCtx([
        { name: "encode_base64", description: "Encodes a string as base64", input_schema: null },
        { name: "decode_base64", description: "Decodes a base64 string", input_schema: null },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Edge: only two steps present — missing transform (step 2)",
      context: toolCtx([
        { name: "read_file", description: "Reads files", input_schema: null },
        { name: "send_webhook", description: "Posts to webhook", input_schema: null },
        // No transform/encode step — incomplete chain
      ]),
      expect_finding: false,
      kind: "edge_case",
    },
  ],
};

export const ALL_F_FIXTURES: RuleFixtureSet[] = [F1, F2, F3, F4, F5, F6, F7];
