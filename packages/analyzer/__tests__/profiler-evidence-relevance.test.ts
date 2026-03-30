/**
 * Tests for Phase 1 rebuild: Server Profiler, Evidence Chains, Threat Model, Relevance.
 *
 * These tests verify that:
 * 1. Server profiler correctly infers capabilities from different server types
 * 2. Evidence chains are well-formed and render correctly
 * 3. Threat model selects the right threats for each server profile
 * 4. Rule relevance filtering produces correct scored vs. informational findings
 */
import { describe, it, expect } from "vitest";
import { profileServer, type ServerProfile } from "../src/profiler.js";
import {
  EvidenceChainBuilder,
  renderEvidenceNarrative,
  type EvidenceChain,
} from "../src/evidence.js";
import {
  THREAT_REGISTRY,
  selectThreats,
  getRelevantRuleIds,
  getEvidenceStandard,
} from "../src/threat-model.js";
import {
  annotateFindings,
  scoredFindings,
  unscoredFindings,
  generateProfileReport,
} from "../src/relevance.js";
import type { AnalysisContext } from "../src/engine.js";
import type { TypedFinding } from "../src/rules/base.js";

// ─── Test Fixtures: Realistic MCP Server Contexts ─────────────────────────────

/** A read-only weather API — minimal attack surface */
function weatherServer(): AnalysisContext {
  return {
    server: {
      id: "weather-001",
      name: "weather-mcp",
      description: "Get current weather and forecasts for any location",
      github_url: "https://github.com/example/weather-mcp",
    },
    tools: [
      {
        name: "get_weather",
        description: "Get current weather for a city",
        input_schema: {
          type: "object",
          properties: {
            location: { type: "string", description: "City name" },
            units: { type: "string", enum: ["celsius", "fahrenheit"] },
          },
          required: ["location"],
        },
        annotations: { readOnlyHint: true },
      },
      {
        name: "get_forecast",
        description: "Get 5-day weather forecast",
        input_schema: {
          type: "object",
          properties: {
            location: { type: "string" },
            days: { type: "number" },
          },
        },
        annotations: { readOnlyHint: true },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: {
      auth_required: false,
      transport: "https",
      response_time_ms: 150,
    },
  };
}

/** A filesystem server with shell access — large attack surface */
function filesystemServer(): AnalysisContext {
  return {
    server: {
      id: "fs-001",
      name: "filesystem-mcp",
      description: "Read, write, and execute files on the local filesystem",
      github_url: "https://github.com/example/filesystem-mcp",
    },
    tools: [
      {
        name: "read_file",
        description: "Read the contents of a file from the filesystem",
        input_schema: {
          type: "object",
          properties: {
            path: { type: "string", description: "File path to read" },
          },
          required: ["path"],
        },
        annotations: { readOnlyHint: true },
      },
      {
        name: "write_file",
        description: "Write content to a file on the filesystem",
        input_schema: {
          type: "object",
          properties: {
            path: { type: "string" },
            content: { type: "string" },
          },
          required: ["path", "content"],
        },
        annotations: { destructiveHint: true },
      },
      {
        name: "execute_command",
        description: "Execute a shell command on the host system",
        input_schema: {
          type: "object",
          properties: {
            command: { type: "string", description: "Shell command to execute" },
          },
          required: ["command"],
        },
      },
      {
        name: "send_webhook",
        description: "Send data to a webhook URL via HTTP POST",
        input_schema: {
          type: "object",
          properties: {
            url: { type: "string" },
            payload: { type: "string" },
          },
          required: ["url", "payload"],
        },
      },
    ],
    source_code: `
import { exec } from "child_process";
import fs from "fs";

export async function handleExecute(params) {
  const cmd = params.command;
  return new Promise((resolve) => {
    exec(cmd, (err, stdout) => resolve(stdout));
  });
}
`,
    dependencies: [
      { name: "express", version: "4.18.2", has_known_cve: false, cve_ids: [], last_updated: new Date() },
    ],
    connection_metadata: {
      auth_required: false,
      transport: "http",
      response_time_ms: 50,
    },
  };
}

/** An email reader + Slack bot — indirect injection gateway */
function communicationServer(): AnalysisContext {
  return {
    server: {
      id: "comm-001",
      name: "slack-email-mcp",
      description: "Read emails and send Slack messages",
      github_url: null,
    },
    tools: [
      {
        name: "read_emails",
        description: "Read emails from inbox via IMAP",
        input_schema: {
          type: "object",
          properties: {
            folder: { type: "string" },
            limit: { type: "number" },
          },
        },
      },
      {
        name: "send_slack_message",
        description: "Send a message to a Slack channel",
        input_schema: {
          type: "object",
          properties: {
            channel: { type: "string" },
            message: { type: "string" },
          },
          required: ["channel", "message"],
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}

/** A database server with credential management */
function databaseServer(): AnalysisContext {
  return {
    server: {
      id: "db-001",
      name: "postgres-mcp",
      description: "Execute SQL queries against a PostgreSQL database",
      github_url: "https://github.com/example/postgres-mcp",
    },
    tools: [
      {
        name: "query",
        description: "Execute a SQL query against the database",
        input_schema: {
          type: "object",
          properties: {
            sql: { type: "string", description: "SQL query to execute" },
          },
          required: ["sql"],
        },
      },
      {
        name: "configure_connection",
        description: "Set the database connection credentials",
        input_schema: {
          type: "object",
          properties: {
            host: { type: "string" },
            password: { type: "string" },
            token: { type: "string" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}

// ─── Server Profiler Tests ────────────────────────────────────────────────────

describe("Server Profiler", () => {
  describe("Weather API (minimal attack surface)", () => {
    it("infers reads-public-data from readOnlyHint annotations", () => {
      const profile = profileServer(weatherServer());
      const readPublic = profile.capabilities.find(
        (c) => c.capability === "reads-public-data",
      );
      expect(readPublic).toBeDefined();
      expect(readPublic!.confidence).toBeGreaterThanOrEqual(0.5);
      expect(readPublic!.evidence.some((e) => e.source === "annotation")).toBe(true);
    });

    it("does NOT infer reads-private-data", () => {
      const profile = profileServer(weatherServer());
      const readPrivate = profile.capabilities.find(
        (c) => c.capability === "reads-private-data",
      );
      // Either not present, or low confidence
      if (readPrivate) {
        expect(readPrivate.confidence).toBeLessThan(0.5);
      }
    });

    it("has minimal attack surfaces", () => {
      const profile = profileServer(weatherServer());
      // A read-only weather API should NOT have code-execution, data-exfiltration, etc.
      expect(profile.attack_surfaces).not.toContain("code-execution");
      expect(profile.attack_surfaces).not.toContain("data-exfiltration");
      expect(profile.attack_surfaces).not.toContain("credential-theft");
    });

    it("has zero data flow pairs", () => {
      const profile = profileServer(weatherServer());
      expect(profile.data_flow_pairs).toHaveLength(0);
    });
  });

  describe("Filesystem + Shell server (large attack surface)", () => {
    it("infers executes-code from command parameter", () => {
      const profile = profileServer(filesystemServer());
      const execCode = profile.capabilities.find(
        (c) => c.capability === "executes-code",
      );
      expect(execCode).toBeDefined();
      expect(execCode!.confidence).toBeGreaterThanOrEqual(0.7);
    });

    it("infers reads-private-data from path parameter", () => {
      const profile = profileServer(filesystemServer());
      const readPrivate = profile.capabilities.find(
        (c) => c.capability === "reads-private-data",
      );
      expect(readPrivate).toBeDefined();
      expect(readPrivate!.confidence).toBeGreaterThanOrEqual(0.5);
    });

    it("infers sends-network from url parameter", () => {
      const profile = profileServer(filesystemServer());
      const sendsNet = profile.capabilities.find(
        (c) => c.capability === "sends-network",
      );
      expect(sendsNet).toBeDefined();
    });

    it("infers destructive-ops from destructiveHint", () => {
      const profile = profileServer(filesystemServer());
      const destructive = profile.capabilities.find(
        (c) => c.capability === "destructive-ops",
      );
      expect(destructive).toBeDefined();
      expect(destructive!.confidence).toBeGreaterThanOrEqual(0.9);
    });

    it("has code-execution and data-exfiltration attack surfaces", () => {
      const profile = profileServer(filesystemServer());
      expect(profile.attack_surfaces).toContain("code-execution");
      expect(profile.attack_surfaces).toContain("data-exfiltration");
    });

    it("detects data-read-to-send flow pairs", () => {
      const profile = profileServer(filesystemServer());
      const readToSend = profile.data_flow_pairs.find(
        (p) => p.flow_type === "data-read-to-send",
      );
      expect(readToSend).toBeDefined();
      expect(readToSend!.source_tool).toBe("read_file");
      expect(readToSend!.sink_tool).toBe("send_webhook");
    });

    it("has source code available", () => {
      const profile = profileServer(filesystemServer());
      expect(profile.has_source_code).toBe(true);
    });
  });

  describe("Communication server (injection gateway)", () => {
    it("infers ingests-untrusted from email reading", () => {
      const profile = profileServer(communicationServer());
      const ingests = profile.capabilities.find(
        (c) => c.capability === "ingests-untrusted",
      );
      expect(ingests).toBeDefined();
      expect(ingests!.confidence).toBeGreaterThanOrEqual(0.5);
    });

    it("infers sends-network from Slack messaging", () => {
      const profile = profileServer(communicationServer());
      const sends = profile.capabilities.find(
        (c) => c.capability === "sends-network",
      );
      expect(sends).toBeDefined();
    });

    it("has prompt-injection attack surface", () => {
      const profile = profileServer(communicationServer());
      expect(profile.attack_surfaces).toContain("prompt-injection");
    });
  });

  describe("Database server (credential handling)", () => {
    it("infers manages-credentials from password/token parameters", () => {
      const profile = profileServer(databaseServer());
      const creds = profile.capabilities.find(
        (c) => c.capability === "manages-credentials",
      );
      expect(creds).toBeDefined();
      expect(creds!.confidence).toBeGreaterThanOrEqual(0.7);
    });

    it("infers writes-database from sql parameter", () => {
      const profile = profileServer(databaseServer());
      const writeDb = profile.capabilities.find(
        (c) => c.capability === "writes-database",
      );
      expect(writeDb).toBeDefined();
    });

    it("has credential-theft attack surface", () => {
      const profile = profileServer(databaseServer());
      expect(profile.attack_surfaces).toContain("credential-theft");
    });
  });

  describe("Noisy-OR aggregation", () => {
    it("combines multiple signals into higher confidence", () => {
      // Filesystem server: "path" param (0.70) + "reads files" description (0.55)
      // Noisy-OR: 1 - (0.30 * 0.45) = 0.865
      const profile = profileServer(filesystemServer());
      const readPrivate = profile.capabilities.find(
        (c) => c.capability === "reads-private-data",
      );
      expect(readPrivate).toBeDefined();
      // Multiple signals should produce higher confidence than any single signal
      expect(readPrivate!.evidence.length).toBeGreaterThan(1);
      expect(readPrivate!.confidence).toBeGreaterThan(0.7);
    });
  });
});

// ─── Evidence Chain Tests ─────────────────────────────────────────────────────

describe("Evidence Chains", () => {
  it("builds a complete source→propagation→sink chain", () => {
    const chain = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: 'tool "execute_command", parameter "command"',
        observed: "string type, no constraints",
        rationale: "AI fills this parameter from user prompt — unconstrained string input",
      })
      .propagation({
        propagation_type: "direct-pass",
        location: "src/handlers.ts:42",
        observed: "exec(params.command)",
        rationale: "Parameter passed directly to exec()",
      })
      .sink({
        sink_type: "command-execution",
        location: "src/handlers.ts:42",
        observed: 'exec(cmd, (err, stdout) => resolve(stdout))',
        cve_precedent: "CVE-2025-6514",
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: "tool input_schema",
        detail: "No enum, pattern, or maxLength constraint on command parameter",
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: false,
        location: "src/handlers.ts:40-45",
        detail: "No escapeShell/execFile wrapper — exec() called directly",
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          'User says "list files in /etc" → AI calls execute_command({command: "ls /etc"}) → ' +
          "attacker-controlled prompt could inject: ls /etc; cat /etc/passwd",
      })
      .reference({
        id: "CVE-2025-6514",
        title: "mcp-remote OS Command Injection",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
        relevance: "Same pattern: unconstrained string parameter → exec()",
      })
      .factor("complete source→sink taint path", 0.15, "AST-confirmed data flow from parameter to exec()")
      .factor("no sanitization found", 0.10, "Neither escapeShell nor execFile detected")
      .build();

    expect(chain.links).toHaveLength(6);
    expect(chain.confidence).toBeGreaterThan(0.7);
    expect(chain.threat_reference?.id).toBe("CVE-2025-6514");
  });

  it("renders a human-readable narrative", () => {
    const chain = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: 'tool "query", parameter "sql"',
        observed: "string type, no constraints",
        rationale: "AI fills SQL query from user prompt",
      })
      .sink({
        sink_type: "sql-execution",
        location: "src/db.ts:15",
        observed: "db.query(params.sql)",
      })
      .build();

    const narrative = renderEvidenceNarrative(chain);
    expect(narrative).toContain("SOURCE:");
    expect(narrative).toContain("SINK:");
    expect(narrative).toContain("CONFIDENCE:");
  });

  it("computes higher confidence for complete chains", () => {
    const fullChain = new EvidenceChainBuilder()
      .source({ source_type: "user-parameter", location: "tool A", observed: "x", rationale: "untrusted" })
      .propagation({ propagation_type: "direct-pass", location: "line 5", observed: "exec(x)" })
      .sink({ sink_type: "command-execution", location: "line 5", observed: "exec(x)" })
      .build();

    const partialChain = new EvidenceChainBuilder()
      .sink({ sink_type: "command-execution", location: "line 5", observed: "exec(x)" })
      .build();

    expect(fullChain.confidence).toBeGreaterThan(partialChain.confidence);
  });

  it("mitigations reduce confidence", () => {
    const withoutMit = new EvidenceChainBuilder()
      .source({ source_type: "user-parameter", location: "tool A", observed: "x", rationale: "untrusted" })
      .sink({ sink_type: "command-execution", location: "line 5", observed: "exec(x)" })
      .build();

    const withMit = new EvidenceChainBuilder()
      .source({ source_type: "user-parameter", location: "tool A", observed: "x", rationale: "untrusted" })
      .sink({ sink_type: "command-execution", location: "line 5", observed: "exec(x)" })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: true,
        location: "line 4",
        detail: "escapeShell() applied before exec()",
      })
      .build();

    expect(withMit.confidence).toBeLessThan(withoutMit.confidence);
  });
});

// ─── Threat Model Tests ───────────────────────────────────────────────────────

describe("Threat Model", () => {
  it("every threat has at least one real-world reference", () => {
    for (const threat of THREAT_REGISTRY) {
      expect(threat.references.length).toBeGreaterThanOrEqual(1);
      for (const ref of threat.references) {
        expect(ref.id).toBeTruthy();
        expect(ref.title).toBeTruthy();
        expect(ref.url).toBeTruthy();
      }
    }
  });

  it("every threat has an evidence standard", () => {
    for (const threat of THREAT_REGISTRY) {
      expect(threat.evidence_standard.min_chain_length).toBeGreaterThanOrEqual(1);
      expect(threat.evidence_standard.min_confidence).toBeGreaterThan(0);
      expect(threat.evidence_standard.description).toBeTruthy();
    }
  });

  it("selects code-execution threats for filesystem server", () => {
    const profile = profileServer(filesystemServer());
    const threats = selectThreats(profile);
    const execThreats = threats.filter((t) => t.attack_surface === "code-execution");
    expect(execThreats.length).toBeGreaterThanOrEqual(1);
    expect(execThreats.some((t) => t.rule_ids.includes("C1"))).toBe(true);
  });

  it("does NOT select code-execution threats for weather server", () => {
    const profile = profileServer(weatherServer());
    const threats = selectThreats(profile);
    const execThreats = threats.filter((t) => t.attack_surface === "code-execution");
    expect(execThreats).toHaveLength(0);
  });

  it("selects prompt-injection threats for communication server", () => {
    const profile = profileServer(communicationServer());
    const threats = selectThreats(profile);
    const injectThreats = threats.filter((t) => t.attack_surface === "prompt-injection");
    expect(injectThreats.length).toBeGreaterThanOrEqual(1);
  });

  it("selects credential-theft threats for database server", () => {
    const profile = profileServer(databaseServer());
    const threats = selectThreats(profile);
    const credThreats = threats.filter((t) => t.attack_surface === "credential-theft");
    expect(credThreats.length).toBeGreaterThanOrEqual(1);
  });

  it("returns fewer relevant rules for weather server than filesystem server", () => {
    const weatherRules = getRelevantRuleIds(profileServer(weatherServer()));
    const fsRules = getRelevantRuleIds(profileServer(filesystemServer()));
    expect(weatherRules.size).toBeLessThan(fsRules.size);
  });
});

// ─── Relevance Filtering Tests ────────────────────────────────────────────────

describe("Relevance Filtering", () => {
  // Simulate findings from a weather server scan
  const a1Chain = new EvidenceChainBuilder()
    .source({ source_type: "external-content", location: "tool description", observed: "injection pattern", rationale: "Test fixture" })
    .sink({ sink_type: "code-evaluation", location: "AI client", observed: "injection" })
    .impact({ impact_type: "session-hijack", scope: "connected-services", exploitability: "moderate", scenario: "Test" })
    .verification({ step_type: "inspect-description", instruction: "Review", target: "tool", expected_observation: "Injection" })
    .build();

  const c1Chain = new EvidenceChainBuilder()
    .source({ source_type: "user-parameter", location: "source code", observed: "exec()", rationale: "Test fixture" })
    .sink({ sink_type: "command-execution", location: "line 1", observed: "exec()" })
    .impact({ impact_type: "remote-code-execution", scope: "server-host", exploitability: "trivial", scenario: "Test" })
    .verification({ step_type: "inspect-source", instruction: "Review", target: "source", expected_observation: "exec" })
    .build();

  const weatherFindings: TypedFinding[] = [
    {
      rule_id: "A1", // Description analysis — always relevant
      severity: "high",
      evidence: "Prompt injection pattern found in tool description",
      remediation: "Remove injection patterns",
      owasp_category: "MCP01-prompt-injection",
      mitre_technique: "AML.T0054",
      confidence: 0.85,
      metadata: { evidence_chain: a1Chain },
    },
    {
      rule_id: "C1", // Command injection — NOT relevant for weather server
      severity: "critical",
      evidence: "exec() found in source code",
      remediation: "Use execFile()",
      owasp_category: "MCP03-command-injection",
      mitre_technique: null,
      confidence: 0.60,
      metadata: { evidence_chain: c1Chain },
    },
  ];

  it("marks A1 as relevant for all servers (universal rule)", () => {
    const profile = profileServer(weatherServer());
    const annotated = annotateFindings(weatherFindings, profile);
    const a1 = annotated.find((f) => f.rule_id === "A1");
    expect(a1?.relevant).toBe(true);
  });

  it("marks C1 as NOT relevant for weather server", () => {
    const profile = profileServer(weatherServer());
    const annotated = annotateFindings(weatherFindings, profile);
    const c1 = annotated.find((f) => f.rule_id === "C1");
    expect(c1?.relevant).toBe(false);
  });

  it("marks C1 as relevant for filesystem server", () => {
    const profile = profileServer(filesystemServer());
    const annotated = annotateFindings(weatherFindings, profile);
    const c1 = annotated.find((f) => f.rule_id === "C1");
    expect(c1?.relevant).toBe(true);
  });

  it("scored findings excludes irrelevant rules", () => {
    const profile = profileServer(weatherServer());
    const annotated = annotateFindings(weatherFindings, profile);
    const scored = scoredFindings(annotated);
    expect(scored.some((f) => f.rule_id === "A1")).toBe(true);
    expect(scored.some((f) => f.rule_id === "C1")).toBe(false);
  });

  it("unscored findings includes irrelevant rules", () => {
    const profile = profileServer(weatherServer());
    const annotated = annotateFindings(weatherFindings, profile);
    const unscored = unscoredFindings(annotated);
    expect(unscored.some((f) => f.rule_id === "C1")).toBe(true);
  });
});

// ─── Profile Report Tests ─────────────────────────────────────────────────────

describe("Profile Report", () => {
  it("generates a report for filesystem server", () => {
    const profile = profileServer(filesystemServer());
    const report = generateProfileReport(profile);
    expect(report).toContain("SERVER SECURITY PROFILE");
    expect(report).toContain("CAPABILITIES:");
    expect(report).toContain("ATTACK SURFACES:");
    expect(report).toContain("code-execution");
    expect(report).toContain("DATA FLOW CHAINS:");
    expect(report).toContain("APPLICABLE THREAT MODELS:");
  });

  it("generates a minimal report for weather server", () => {
    const profile = profileServer(weatherServer());
    const report = generateProfileReport(profile);
    expect(report).toContain("SERVER SECURITY PROFILE");
    expect(report).not.toContain("code-execution");
  });

  it("shows NOT APPLICABLE categories for weather server", () => {
    const profile = profileServer(weatherServer());
    const report = generateProfileReport(profile);
    expect(report).toContain("NOT APPLICABLE");
  });
});

// ─── Integration: Full Profile-Aware Analysis Smoke Test ──────────────────────

describe("Profile-Aware Analysis Integration", () => {
  it("generates fewer scored findings for weather server than filesystem server", () => {
    // This is a logical test — weather servers should produce fewer relevant findings
    const weatherProfile = profileServer(weatherServer());
    const fsProfile = profileServer(filesystemServer());

    const weatherRules = getRelevantRuleIds(weatherProfile);
    const fsRules = getRelevantRuleIds(fsProfile);

    // Filesystem server should have significantly more relevant rules
    expect(fsRules.size).toBeGreaterThan(weatherRules.size);
    // Weather server should still have universal rules (A, B, E, I1, I2, I16, G6)
    expect(weatherRules.size).toBeGreaterThan(10);
  });
});
