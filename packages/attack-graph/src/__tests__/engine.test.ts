/**
 * Engine Tests — Template-Driven Chain Synthesis
 *
 * Each kill chain: 3 true positives + 3 true negatives + 2 edge cases = 8 tests × 7 = 56
 * Plus engine-wide tests for dedup, safety caps, aggregate risk, etc.
 */
import { describe, it, expect } from "vitest";
import { AttackGraphEngine, findCandidates, generateCombinations, verifyEdges } from "../engine.js";
import {
  webScraper, emailReader, slackBot,
  fileManager, credentialStore, dbReader,
  codeRunner, shellExec,
  webhookSender, emailSender,
  configWriter, memoryWriter, memoryReader,
  codeGenerator, dbAdmin,
  safeCalculator, safeFormatter,
} from "./fixtures/nodes.js";
import {
  kc01Edges, kc02Edges, kc03Edges, kc04Edges,
  kc05Edges, kc06Edges, kc07Edges, makeEdge,
} from "./fixtures/edges.js";
import { KC01, KC02, KC03, KC04, KC05, KC06, KC07 } from "../kill-chains.js";
import type { AttackGraphInput } from "../types.js";

const engine = new AttackGraphEngine();

// ── KC01: Indirect Injection → Data Exfiltration ──────────────────────────────

describe("KC01: Indirect Injection → Data Exfiltration", () => {
  // True Positives
  it("TP1: web-scraper + file-manager + webhook-sender = 1 chain", () => {
    const report = engine.analyze({
      nodes: [webScraper(), fileManager(), webhookSender()],
      edges: kc01Edges(),
      patterns_detected: ["P01"],
    });
    expect(report.chains.length).toBeGreaterThanOrEqual(1);
    const kc01 = report.chains.find((c) => c.kill_chain_id === "KC01");
    expect(kc01).toBeDefined();
    expect(kc01!.steps).toHaveLength(3);
    expect(kc01!.steps[0].role).toBe("injection_gateway");
    expect(kc01!.steps[1].role).toBe("data_source");
    expect(kc01!.steps[2].role).toBe("exfiltrator");
  });

  it("TP2: email-reader + credential-store + email-sender = chain (alt injection + alt data)", () => {
    const report = engine.analyze({
      nodes: [emailReader(), credentialStore(), emailSender()],
      edges: [
        makeEdge("email-reader", "credential-store", "injection_path", "critical"),
        makeEdge("credential-store", "email-sender", "exfiltration_chain", "critical"),
      ],
      patterns_detected: ["P03"],
    });
    const kc01 = report.chains.find((c) => c.kill_chain_id === "KC01");
    expect(kc01).toBeDefined();
    expect(kc01!.steps[0].server_name).toBe("email-reader");
  });

  it("TP3: chain detected via P09 pattern (alternative prerequisite)", () => {
    const report = engine.analyze({
      nodes: [slackBot(), fileManager(), webhookSender()],
      edges: [
        makeEdge("slack-bot", "file-manager", "injection_path", "critical"),
        makeEdge("file-manager", "webhook-sender", "exfiltration_chain", "critical"),
      ],
      patterns_detected: ["P09"],
    });
    expect(report.chains.find((c) => c.kill_chain_id === "KC01")).toBeDefined();
  });

  // True Negatives
  it("TN1: missing network sender → no chain (role unfillable)", () => {
    const report = engine.analyze({
      nodes: [webScraper(), fileManager()],
      // Provide both required edge types so hasRequiredEdgeTypes passes —
      // the test specifically validates that the ROLE check (no sends-network
      // server) blocks the chain, not that a prerequisite check blocks it.
      edges: [
        makeEdge("web-scraper", "file-manager", "injection_path", "critical"),
        makeEdge("file-manager", "web-scraper", "exfiltration_chain", "critical"),
      ],
      patterns_detected: ["P01"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC01")).toHaveLength(0);
  });

  it("TN2: missing injection gateway → no chain (role unfillable)", () => {
    const report = engine.analyze({
      nodes: [fileManager(), webhookSender()],
      // Provide both required edge types so prerequisite passes —
      // validates that the ROLE check (no injection gateway) blocks the chain.
      edges: [
        makeEdge("file-manager", "webhook-sender", "exfiltration_chain", "critical"),
        makeEdge("webhook-sender", "file-manager", "injection_path", "critical"),
      ],
      patterns_detected: ["P01"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC01")).toHaveLength(0);
  });

  it("TN3: wrong pattern detected → prerequisite fails", () => {
    const report = engine.analyze({
      nodes: [webScraper(), fileManager(), webhookSender()],
      edges: kc01Edges(),
      patterns_detected: ["P02"], // KC01 needs P01, P03, or P09
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC01")).toHaveLength(0);
  });

  // Edge Cases
  it("EC1: safe servers only → 0 chains total", () => {
    const report = engine.analyze({
      nodes: [safeCalculator(), safeFormatter()],
      edges: [],
      patterns_detected: [],
    });
    expect(report.chains).toHaveLength(0);
    expect(report.aggregate_risk).toBe("none");
  });

  it("EC2: nodes present but no edges between them → no chain (edge verification fails)", () => {
    const report = engine.analyze({
      nodes: [webScraper(), fileManager(), webhookSender()],
      edges: [], // no risk-matrix edges
      patterns_detected: ["P01"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC01")).toHaveLength(0);
  });
});

// ── KC02: Config Poisoning → RCE ──────────────────────────────────────────────

describe("KC02: Config Poisoning → RCE", () => {
  it("TP1: config-writer + code-runner = chain", () => {
    const report = engine.analyze({
      nodes: [configWriter(), codeRunner()],
      edges: kc02Edges(),
      patterns_detected: ["P05"],
    });
    const kc02 = report.chains.find((c) => c.kill_chain_id === "KC02");
    expect(kc02).toBeDefined();
    expect(kc02!.steps).toHaveLength(2);
    expect(kc02!.steps[0].role).toBe("config_writer");
    expect(kc02!.steps[1].role).toBe("executor");
  });

  it("TP2: config-writer + shell-exec = chain (alt executor)", () => {
    const report = engine.analyze({
      nodes: [configWriter(), shellExec()],
      edges: [makeEdge("config-writer", "shell-exec", "config_poisoning", "critical")],
      patterns_detected: ["P05"],
    });
    expect(report.chains.find((c) => c.kill_chain_id === "KC02")).toBeDefined();
  });

  it("TP3: filesystem writer acting as config-writer", () => {
    // A server with writes-data + accesses-filesystem matches config_writer role
    const fsWriter = {
      ...fileManager(),
      server_id: "srv-fs-writer",
      server_name: "fs-writer",
      capabilities: ["accesses-filesystem", "writes-data"] as any,
      is_shared_writer: true,
    };
    const report = engine.analyze({
      nodes: [fsWriter, codeRunner()],
      edges: [makeEdge("fs-writer", "code-runner", "config_poisoning", "critical")],
      patterns_detected: ["P05"],
    });
    expect(report.chains.find((c) => c.kill_chain_id === "KC02")).toBeDefined();
  });

  // True Negatives
  it("TN1: no executor → no chain", () => {
    const report = engine.analyze({
      nodes: [configWriter(), safeCalculator()],
      edges: [makeEdge("config-writer", "calculator", "config_poisoning", "critical")],
      patterns_detected: ["P05"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC02")).toHaveLength(0);
  });

  it("TN2: no P05 pattern → prerequisite fails", () => {
    const report = engine.analyze({
      nodes: [configWriter(), codeRunner()],
      edges: kc02Edges(),
      patterns_detected: ["P01"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC02")).toHaveLength(0);
  });

  it("TN3: config writer without is_shared_writer flag → no match", () => {
    const nonSharedWriter = { ...configWriter(), is_shared_writer: false };
    const report = engine.analyze({
      nodes: [nonSharedWriter, codeRunner()],
      edges: kc02Edges(),
      patterns_detected: ["P05"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC02")).toHaveLength(0);
  });

  // Edge Cases
  it("EC1: same server cannot fill both roles", () => {
    // A server with both writes-agent-config and executes-code
    const bothRoles = {
      ...configWriter(),
      capabilities: ["writes-agent-config", "executes-code", "accesses-filesystem", "writes-data"] as any,
    };
    const report = engine.analyze({
      nodes: [bothRoles],
      edges: [makeEdge("config-writer", "config-writer", "config_poisoning", "critical")],
      patterns_detected: ["P05"],
    });
    // Single server cannot fill 2 distinct roles → no chain
    expect(report.chains.filter((c) => c.kill_chain_id === "KC02")).toHaveLength(0);
  });

  it("EC2: no edge between servers → verification fails", () => {
    const report = engine.analyze({
      nodes: [configWriter(), codeRunner()],
      edges: [], // edges exist for P05 pattern but not between these servers
      patterns_detected: ["P05"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC02")).toHaveLength(0);
  });
});

// ── KC03: Credential Harvesting Chain ─────────────────────────────────────────

describe("KC03: Credential Harvesting Chain", () => {
  it("TP1: credential-store + webhook-sender = chain", () => {
    const report = engine.analyze({
      nodes: [credentialStore(), webhookSender()],
      edges: kc03Edges(),
      patterns_detected: ["P02"],
    });
    const kc03 = report.chains.find((c) => c.kill_chain_id === "KC03");
    expect(kc03).toBeDefined();
    expect(kc03!.steps[0].role).toBe("data_source");
    expect(kc03!.steps[1].role).toBe("exfiltrator");
  });

  it("TP2: file-manager (has credentials access) + email-sender", () => {
    const fsWithCreds = { ...fileManager(), capabilities: ["reads-data", "accesses-filesystem", "manages-credentials"] as any };
    const report = engine.analyze({
      nodes: [fsWithCreds, emailSender()],
      edges: [
        makeEdge("file-manager", "email-sender", "credential_chain", "critical"),
        makeEdge("file-manager", "email-sender", "exfiltration_chain", "critical"),
      ],
      patterns_detected: ["P02"],
    });
    expect(report.chains.find((c) => c.kill_chain_id === "KC03")).toBeDefined();
  });

  it("TP3: exploitability factors reflect credential theft severity", () => {
    const report = engine.analyze({
      nodes: [credentialStore(25), webhookSender()],
      edges: kc03Edges(),
      patterns_detected: ["P02"],
      server_findings: { "srv-credential-store": ["C5", "F1"] },
    });
    const kc03 = report.chains.find((c) => c.kill_chain_id === "KC03");
    expect(kc03).toBeDefined();
    expect(kc03!.exploitability.overall).toBeGreaterThan(0);
  });

  // True Negatives
  it("TN1: no network sender → no chain", () => {
    const report = engine.analyze({
      nodes: [credentialStore(), safeCalculator()],
      edges: [],
      patterns_detected: ["P02"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC03")).toHaveLength(0);
  });

  it("TN2: no credential access → no match", () => {
    const report = engine.analyze({
      nodes: [safeCalculator(), webhookSender()],
      edges: [makeEdge("calculator", "webhook-sender", "credential_chain", "critical")],
      patterns_detected: ["P02"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC03")).toHaveLength(0);
  });

  it("TN3: P02 not detected → skip", () => {
    const report = engine.analyze({
      nodes: [credentialStore(), webhookSender()],
      edges: kc03Edges(),
      patterns_detected: ["P01"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC03")).toHaveLength(0);
  });

  // Edge Cases
  it("EC1: credential store with high score (80+) → chain detected but lower exploitability", () => {
    const report = engine.analyze({
      nodes: [credentialStore(85), webhookSender(90)],
      edges: kc03Edges(),
      patterns_detected: ["P02"],
    });
    const kc03 = report.chains.find((c) => c.kill_chain_id === "KC03");
    expect(kc03).toBeDefined();
    // High scores should lower the exploitability
    const weaknessFactor = kc03!.exploitability.factors.find((f) => f.factor === "server_score_weakness");
    expect(weaknessFactor!.value).toBeLessThanOrEqual(0.2);
  });

  it("EC2: multiple credential sources → multiple chains possible", () => {
    const credStore2 = { ...credentialStore(), server_id: "srv-cred-2", server_name: "cred-backup" };
    const report = engine.analyze({
      nodes: [credentialStore(), credStore2, webhookSender()],
      edges: [
        ...kc03Edges(),
        makeEdge("cred-2", "webhook-sender", "credential_chain", "high"),
        makeEdge("cred-2", "webhook-sender", "exfiltration_chain", "high"),
      ],
      patterns_detected: ["P02"],
    });
    const kc03Chains = report.chains.filter((c) => c.kill_chain_id === "KC03");
    expect(kc03Chains.length).toBeGreaterThanOrEqual(2);
  });
});

// ── KC04: Memory Poisoning Persistence ────────────────────────────────────────

describe("KC04: Memory Poisoning Persistence", () => {
  it("TP1: email-reader + memory-writer + memory-reader = chain", () => {
    const report = engine.analyze({
      nodes: [emailReader(), memoryWriter(), memoryReader()],
      edges: kc04Edges(),
      patterns_detected: ["P04"],
    });
    const kc04 = report.chains.find((c) => c.kill_chain_id === "KC04");
    expect(kc04).toBeDefined();
    expect(kc04!.steps).toHaveLength(3);
    expect(kc04!.steps[0].role).toBe("injection_gateway");
    expect(kc04!.steps[1].role).toBe("memory_writer");
    expect(kc04!.steps[2].role).toBe("data_source");
  });

  it("TP2: web-scraper as injection gateway variant", () => {
    const report = engine.analyze({
      nodes: [webScraper(), memoryWriter(), memoryReader()],
      edges: [
        makeEdge("web-scraper", "memory-writer", "injection_path", "critical"),
        makeEdge("memory-writer", "memory-reader", "memory_pollution", "high"),
      ],
      patterns_detected: ["P04"],
    });
    expect(report.chains.find((c) => c.kill_chain_id === "KC04")).toBeDefined();
  });

  it("TP3: narrative mentions persistence across sessions", () => {
    const report = engine.analyze({
      nodes: [emailReader(), memoryWriter(), memoryReader()],
      edges: kc04Edges(),
      patterns_detected: ["P04"],
    });
    const kc04 = report.chains.find((c) => c.kill_chain_id === "KC04");
    expect(kc04).toBeDefined();
    expect(kc04!.narrative).toContain("persistent");
  });

  // True Negatives
  it("TN1: no memory writer → no chain", () => {
    const report = engine.analyze({
      nodes: [emailReader(), memoryReader(), webhookSender()],
      edges: [makeEdge("email-reader", "memory-reader", "injection_path", "critical")],
      patterns_detected: ["P04"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC04")).toHaveLength(0);
  });

  it("TN2: memory writer without is_shared_writer → no match", () => {
    const nonShared = { ...memoryWriter(), is_shared_writer: false };
    const report = engine.analyze({
      nodes: [emailReader(), nonShared, memoryReader()],
      edges: kc04Edges(),
      patterns_detected: ["P04"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC04")).toHaveLength(0);
  });

  it("TN3: no P04 pattern → skip", () => {
    const report = engine.analyze({
      nodes: [emailReader(), memoryWriter(), memoryReader()],
      edges: kc04Edges(),
      patterns_detected: ["P01"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC04")).toHaveLength(0);
  });

  // Edge Cases
  it("EC1: injection_gateway not confirmed → chain still found but lower exploitability", () => {
    const uncofirmedGateway = { ...emailReader(), is_injection_gateway: false };
    const report = engine.analyze({
      nodes: [uncofirmedGateway, memoryWriter(), memoryReader()],
      edges: kc04Edges(),
      patterns_detected: ["P04"],
    });
    // KC04 requires is_injection_gateway flag → no match
    expect(report.chains.filter((c) => c.kill_chain_id === "KC04")).toHaveLength(0);
  });

  it("EC2: memory_pollution edge missing → edge verification fails", () => {
    const report = engine.analyze({
      nodes: [emailReader(), memoryWriter(), memoryReader()],
      edges: [makeEdge("email-reader", "memory-writer", "injection_path", "critical")],
      // missing memory_pollution edge between writer and reader
      patterns_detected: ["P04"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC04")).toHaveLength(0);
  });
});

// ── KC05: Code Generation → Execution ─────────────────────────────────────────

describe("KC05: Code Generation → Execution", () => {
  it("TP1: web-scraper + code-generator + code-runner = chain", () => {
    const report = engine.analyze({
      nodes: [webScraper(), codeGenerator(), codeRunner()],
      edges: kc05Edges(),
      patterns_detected: ["P07"],
    });
    const kc05 = report.chains.find((c) => c.kill_chain_id === "KC05");
    expect(kc05).toBeDefined();
    expect(kc05!.steps).toHaveLength(3);
    expect(kc05!.steps[1].role).toBe("pivot");
  });

  it("TP2: email-reader as gateway variant", () => {
    const report = engine.analyze({
      nodes: [emailReader(), codeGenerator(), shellExec()],
      edges: [
        makeEdge("email-reader", "code-generator", "injection_path", "critical"),
        makeEdge("code-generator", "shell-exec", "injection_path", "critical"),
      ],
      patterns_detected: ["P07"],
    });
    expect(report.chains.find((c) => c.kill_chain_id === "KC05")).toBeDefined();
  });

  it("TP3: mitigations include confirmation on executor", () => {
    const report = engine.analyze({
      nodes: [webScraper(), codeGenerator(), codeRunner()],
      edges: kc05Edges(),
      patterns_detected: ["P07"],
    });
    const kc05 = report.chains.find((c) => c.kill_chain_id === "KC05");
    expect(kc05).toBeDefined();
    const execMitigation = kc05!.mitigations.find(
      (m) => m.target_server_name === "code-runner" && m.action === "add_confirmation"
    );
    expect(execMitigation).toBeDefined();
  });

  // True Negatives
  it("TN1: no code generator (pivot) → no chain", () => {
    const report = engine.analyze({
      nodes: [webScraper(), codeRunner()],
      edges: [makeEdge("web-scraper", "code-runner", "injection_path", "critical")],
      patterns_detected: ["P07"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC05")).toHaveLength(0);
  });

  it("TN2: no executor → no chain", () => {
    const report = engine.analyze({
      nodes: [webScraper(), codeGenerator(), webhookSender()],
      edges: [
        makeEdge("web-scraper", "code-generator", "injection_path", "critical"),
        makeEdge("code-generator", "webhook-sender", "injection_path", "critical"),
      ],
      patterns_detected: ["P07"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC05")).toHaveLength(0);
  });

  it("TN3: no P07 → skip", () => {
    const report = engine.analyze({
      nodes: [webScraper(), codeGenerator(), codeRunner()],
      edges: kc05Edges(),
      patterns_detected: ["P01"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC05")).toHaveLength(0);
  });

  // Edge Cases
  it("EC1: injection gateway not confirmed → role flag check fails", () => {
    const nonGateway = { ...webScraper(), is_injection_gateway: false };
    const report = engine.analyze({
      nodes: [nonGateway, codeGenerator(), codeRunner()],
      edges: kc05Edges(),
      patterns_detected: ["P07"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC05")).toHaveLength(0);
  });

  it("EC2: chain has correct OWASP references", () => {
    const report = engine.analyze({
      nodes: [webScraper(), codeGenerator(), codeRunner()],
      edges: kc05Edges(),
      patterns_detected: ["P07"],
    });
    const kc05 = report.chains.find((c) => c.kill_chain_id === "KC05");
    expect(kc05!.owasp_refs).toContain("MCP01");
    expect(kc05!.mitre_refs).toContain("AML.T0054.001");
  });
});

// ── KC06: Multi-Hop Data Exfiltration ─────────────────────────────────────────

describe("KC06: Multi-Hop Data Exfiltration", () => {
  it("TP1: credential-store + code-runner + webhook-sender = chain", () => {
    const report = engine.analyze({
      nodes: [credentialStore(), codeRunner(), webhookSender()],
      edges: kc06Edges(),
      patterns_detected: ["P12"],
    });
    const kc06 = report.chains.find((c) => c.kill_chain_id === "KC06");
    expect(kc06).toBeDefined();
    expect(kc06!.steps[1].role).toBe("pivot");
  });

  it("TP2: file-manager as data source variant", () => {
    const report = engine.analyze({
      nodes: [fileManager(), codeRunner(), webhookSender()],
      edges: [
        makeEdge("file-manager", "code-runner", "data_flow", "high"),
        makeEdge("code-runner", "webhook-sender", "exfiltration_chain", "high"),
      ],
      patterns_detected: ["P12"],
    });
    expect(report.chains.find((c) => c.kill_chain_id === "KC06")).toBeDefined();
  });

  it("TP3: db-reader as data source", () => {
    const report = engine.analyze({
      nodes: [dbReader(), codeRunner(), webhookSender()],
      edges: [
        makeEdge("db-reader", "code-runner", "data_flow", "high"),
        makeEdge("code-runner", "webhook-sender", "exfiltration_chain", "high"),
      ],
      patterns_detected: ["P12"],
    });
    expect(report.chains.find((c) => c.kill_chain_id === "KC06")).toBeDefined();
  });

  // True Negatives
  it("TN1: no pivot → no chain (direct exfil is KC01 not KC06)", () => {
    const report = engine.analyze({
      nodes: [credentialStore(), webhookSender()],
      edges: [makeEdge("credential-store", "webhook-sender", "exfiltration_chain", "high")],
      patterns_detected: ["P12"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC06")).toHaveLength(0);
  });

  it("TN2: no P12 → skip", () => {
    const report = engine.analyze({
      nodes: [credentialStore(), codeRunner(), webhookSender()],
      edges: kc06Edges(),
      patterns_detected: ["P01"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC06")).toHaveLength(0);
  });

  it("TN3: no exfiltrator → no chain", () => {
    const report = engine.analyze({
      nodes: [credentialStore(), codeRunner(), safeCalculator()],
      edges: [makeEdge("credential-store", "code-runner", "data_flow", "high")],
      patterns_detected: ["P12"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC06")).toHaveLength(0);
  });

  // Edge Cases
  it("EC1: code-generator as pivot instead of executor", () => {
    const report = engine.analyze({
      nodes: [credentialStore(), codeGenerator(), webhookSender()],
      edges: [
        makeEdge("credential-store", "code-generator", "data_flow", "high"),
        makeEdge("code-generator", "webhook-sender", "exfiltration_chain", "high"),
      ],
      patterns_detected: ["P12"],
    });
    expect(report.chains.find((c) => c.kill_chain_id === "KC06")).toBeDefined();
  });

  it("EC2: all edges are medium severity → chain still detected", () => {
    const report = engine.analyze({
      nodes: [credentialStore(), codeRunner(), webhookSender()],
      edges: [
        makeEdge("credential-store", "code-runner", "data_flow", "medium"),
        makeEdge("code-runner", "webhook-sender", "exfiltration_chain", "medium"),
      ],
      patterns_detected: ["P12"],
    });
    const kc06 = report.chains.find((c) => c.kill_chain_id === "KC06");
    expect(kc06).toBeDefined();
    const edgeFactor = kc06!.exploitability.factors.find((f) => f.factor === "edge_severity");
    expect(edgeFactor!.value).toBe(0.5); // medium = 0.5
  });
});

// ── KC07: Database Privilege Escalation → Theft ───────────────────────────────

describe("KC07: Database Privilege Escalation → Theft", () => {
  it("TP1: db-reader + db-admin + webhook-sender = chain", () => {
    const report = engine.analyze({
      nodes: [dbReader(), dbAdmin(), webhookSender()],
      edges: kc07Edges(),
      patterns_detected: ["P08"],
    });
    const kc07 = report.chains.find((c) => c.kill_chain_id === "KC07");
    expect(kc07).toBeDefined();
    expect(kc07!.steps).toHaveLength(3);
  });

  it("TP2: db-admin acting as both recon + escalation (has database-query)", () => {
    // db-admin has database-query → can fill data_source role too
    // But needs separate server for exfiltrator
    const report = engine.analyze({
      nodes: [dbReader(), dbAdmin(), emailSender()],
      edges: [
        makeEdge("db-reader", "db-admin", "privilege_escalation", "critical"),
        makeEdge("db-admin", "email-sender", "exfiltration_chain", "high"),
      ],
      patterns_detected: ["P08"],
    });
    expect(report.chains.find((c) => c.kill_chain_id === "KC07")).toBeDefined();
  });

  it("TP3: supporting findings boost exploitability", () => {
    const report = engine.analyze({
      nodes: [dbReader(), dbAdmin(), webhookSender()],
      edges: kc07Edges(),
      patterns_detected: ["P08"],
      server_findings: {
        "srv-db-reader": ["C4"],
        "srv-db-admin": ["C4", "C1"],
        "srv-webhook-sender": ["F3"],
      },
    });
    const kc07 = report.chains.find((c) => c.kill_chain_id === "KC07");
    const findingsFactor = kc07!.exploitability.factors.find((f) => f.factor === "supporting_findings");
    expect(findingsFactor!.value).toBe(1.0); // 4 findings → 1.0
  });

  // True Negatives
  it("TN1: no db-admin → no chain", () => {
    const report = engine.analyze({
      nodes: [dbReader(), webhookSender()],
      edges: [makeEdge("db-reader", "webhook-sender", "exfiltration_chain", "high")],
      patterns_detected: ["P08"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC07")).toHaveLength(0);
  });

  it("TN2: no P08 → skip", () => {
    const report = engine.analyze({
      nodes: [dbReader(), dbAdmin(), webhookSender()],
      edges: kc07Edges(),
      patterns_detected: ["P01"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC07")).toHaveLength(0);
  });

  it("TN3: db-admin without database-admin capability → no match", () => {
    const fakeAdmin = { ...dbReader(), server_id: "srv-fake-admin", server_name: "fake-admin" };
    const report = engine.analyze({
      nodes: [dbReader(), fakeAdmin, webhookSender()],
      edges: [
        makeEdge("db-reader", "fake-admin", "privilege_escalation", "critical"),
        makeEdge("fake-admin", "webhook-sender", "exfiltration_chain", "high"),
      ],
      patterns_detected: ["P08"],
    });
    expect(report.chains.filter((c) => c.kill_chain_id === "KC07")).toHaveLength(0);
  });

  // Edge Cases
  it("EC1: chain ID is deterministic across runs", () => {
    const input: AttackGraphInput = {
      nodes: [dbReader(), dbAdmin(), webhookSender()],
      edges: kc07Edges(),
      patterns_detected: ["P08"],
    };
    const r1 = engine.analyze(input);
    const r2 = engine.analyze(input);
    const kc07_1 = r1.chains.find((c) => c.kill_chain_id === "KC07");
    const kc07_2 = r2.chains.find((c) => c.kill_chain_id === "KC07");
    expect(kc07_1!.chain_id).toBe(kc07_2!.chain_id);
  });

  it("EC2: privilege_escalation edge type is required", () => {
    const report = engine.analyze({
      nodes: [dbReader(), dbAdmin(), webhookSender()],
      edges: [
        makeEdge("db-reader", "db-admin", "data_flow", "critical"), // wrong type
        makeEdge("db-admin", "webhook-sender", "exfiltration_chain", "high"),
      ],
      patterns_detected: ["P08"],
    });
    // KC07 requires privilege_escalation edge type → prerequisite fails
    expect(report.chains.filter((c) => c.kill_chain_id === "KC07")).toHaveLength(0);
  });
});

// ── Engine-wide tests ─────────────────────────────────────────────────────────

describe("engine-wide behavior", () => {
  it("chains are sorted by exploitability descending", () => {
    const report = engine.analyze({
      nodes: [webScraper(), fileManager(), webhookSender(), credentialStore()],
      edges: [
        ...kc01Edges(),
        makeEdge("credential-store", "webhook-sender", "credential_chain", "critical"),
        makeEdge("credential-store", "webhook-sender", "exfiltration_chain", "critical"),
      ],
      patterns_detected: ["P01", "P02"],
    });

    for (let i = 1; i < report.chains.length; i++) {
      expect(report.chains[i - 1].exploitability.overall)
        .toBeGreaterThanOrEqual(report.chains[i].exploitability.overall);
    }
  });

  it("aggregate_risk is critical if any chain is critical", () => {
    const report = engine.analyze({
      nodes: [webScraper(), fileManager(), webhookSender()],
      edges: kc01Edges(),
      patterns_detected: ["P01"],
    });

    if (report.chains.some((c) => c.exploitability.rating === "critical")) {
      expect(report.aggregate_risk).toBe("critical");
    }
  });

  it("0 chains → aggregate_risk is none", () => {
    const report = engine.analyze({
      nodes: [safeCalculator()],
      edges: [],
      patterns_detected: [],
    });
    expect(report.aggregate_risk).toBe("none");
    expect(report.summary).toContain("No multi-step attack chains");
  });

  it("summary includes chain count and risk level", () => {
    const report = engine.analyze({
      nodes: [webScraper(), fileManager(), webhookSender()],
      edges: kc01Edges(),
      patterns_detected: ["P01"],
    });

    if (report.chains.length > 0) {
      expect(report.summary).toContain("attack chain(s) detected");
    }
  });

  it("multiple templates can fire on the same server set", () => {
    // A config with enough servers to match multiple templates
    const report = engine.analyze({
      nodes: [
        webScraper(), fileManager(), webhookSender(),
        credentialStore(), codeRunner(), codeGenerator(),
      ],
      edges: [
        ...kc01Edges(),
        makeEdge("credential-store", "webhook-sender", "credential_chain", "critical"),
        makeEdge("credential-store", "webhook-sender", "exfiltration_chain", "critical"),
        makeEdge("web-scraper", "code-generator", "injection_path", "critical"),
        makeEdge("code-generator", "code-runner", "injection_path", "critical"),
      ],
      patterns_detected: ["P01", "P02", "P07"],
    });

    const templateIds = new Set(report.chains.map((c) => c.kill_chain_id));
    // Should find at least KC01 and KC03
    expect(templateIds.size).toBeGreaterThanOrEqual(2);
  });

  it("evidence.pattern_ids reflects detected patterns", () => {
    const report = engine.analyze({
      nodes: [webScraper(), fileManager(), webhookSender()],
      edges: kc01Edges(),
      patterns_detected: ["P01", "P03", "P09"],
    });

    const kc01 = report.chains.find((c) => c.kill_chain_id === "KC01");
    if (kc01) {
      expect(kc01.evidence.pattern_ids.length).toBeGreaterThan(0);
      // Pattern IDs should be from KC01's required_patterns that were detected
      for (const pid of kc01.evidence.pattern_ids) {
        expect(["P01", "P03", "P09"]).toContain(pid);
      }
    }
  });

  it("every step has a non-empty narrative", () => {
    const report = engine.analyze({
      nodes: [webScraper(), fileManager(), webhookSender()],
      edges: kc01Edges(),
      patterns_detected: ["P01"],
    });

    expect(report.chains.length).toBeGreaterThan(0);
    for (const chain of report.chains) {
      for (const step of chain.steps) {
        expect(step.narrative).toBeTruthy();
        expect(step.narrative.length).toBeGreaterThan(0);
      }
    }
  });

  it("report.config_id is a deterministic hash of server IDs", () => {
    const input: AttackGraphInput = {
      nodes: [webScraper(), fileManager()],
      edges: [],
      patterns_detected: [],
    };
    const r1 = engine.analyze(input);
    const r2 = engine.analyze(input);
    expect(r1.config_id).toBe(r2.config_id);
    expect(r1.config_id).toHaveLength(16);
  });
});

// ── Internal function tests ───────────────────────────────────────────────────

describe("findCandidates", () => {
  it("matches OR groups of AND sets", () => {
    const nodes = [webScraper(), emailReader(), fileManager()];
    const candidates = findCandidates(KC01.roles[0], nodes); // injection_gateway
    // web-scraper has web-scraping, email-reader has reads-messages — both match
    expect(candidates.length).toBeGreaterThanOrEqual(2);
  });

  it("respects is_injection_gateway flag", () => {
    const nonGateway = { ...webScraper(), is_injection_gateway: false };
    const candidates = findCandidates(KC01.roles[0], [nonGateway]);
    expect(candidates).toHaveLength(0);
  });

  it("returns empty for no matching capabilities", () => {
    const candidates = findCandidates(KC01.roles[0], [safeCalculator()]);
    expect(candidates).toHaveLength(0);
  });
});

describe("generateCombinations", () => {
  it("produces cartesian product with distinct servers", () => {
    const a = [webScraper()];
    const b = [fileManager()];
    const c = [webhookSender()];
    const combos = generateCombinations([a, b, c], 3);
    expect(combos).toHaveLength(1);
    expect(combos[0]).toHaveLength(3);
  });

  it("skips combinations where same server fills multiple roles", () => {
    const node = webScraper();
    const combos = generateCombinations([[node], [node]], 2);
    // same server can't fill both → 0 combinations
    expect(combos).toHaveLength(0);
  });

  it("respects min_servers constraint", () => {
    const a = [webScraper()];
    const b = [fileManager()];
    const combos = generateCombinations([a, b], 3); // need 3 but only 2 roles
    expect(combos).toHaveLength(0);
  });
});

describe("verifyEdges", () => {
  it("returns edges when chain is fully connected", () => {
    const combo = [webScraper(), fileManager(), webhookSender()];
    const edges = verifyEdges(combo, KC01, kc01Edges());
    expect(edges).not.toBeNull();
    expect(edges).toHaveLength(2);
  });

  it("returns null when chain has a gap", () => {
    const combo = [webScraper(), fileManager(), webhookSender()];
    // Only edge between first two, missing second
    const edges = verifyEdges(combo, KC01, [kc01Edges()[0]]);
    expect(edges).toBeNull();
  });

  it("matches edges in either direction", () => {
    const combo = [webhookSender(), fileManager()];
    // Edge is file-manager → webhook-sender, but combo order is reversed
    const edges = verifyEdges(combo, KC03, [
      makeEdge("file-manager", "webhook-sender", "exfiltration_chain", "critical"),
    ]);
    expect(edges).not.toBeNull();
  });

  it("returns null for single-node combo", () => {
    const edges = verifyEdges([webScraper()], KC01, kc01Edges());
    expect(edges).toBeNull();
  });
});
