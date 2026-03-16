/**
 * Cross-server risk patterns.
 *
 * Each pattern describes a dangerous capability combination across
 * two or more servers in the same MCP client configuration.
 *
 * The design principle: no single server may be dangerous in isolation,
 * but the COMBINATION creates an attack path. This is the cross-server
 * lethal trifecta analysis that F1 cannot detect (F1 is single-server only).
 *
 * Pattern catalogue (12 patterns):
 *   P01 — Cross-Config Lethal Trifecta (extends F1 to multi-server)
 *   P02 — Credential Harvesting Chain
 *   P03 — Injection Propagation Path
 *   P04 — Shared Memory Pollution
 *   P05 — Agent Config Poisoning Chain
 *   P06 — Data Read-Exfiltration Chain
 *   P07 — Code Generation + Execution
 *   P08 — Database Privilege Escalation
 *   P09 — Email/Slack Indirect Injection
 *   P10 — Web Scrape + Execute
 *   P11 — Low-Score Server in High-Trust Configuration
 *   P12 — Multi-Hop Exfiltration (3+ server chain)
 */
import type { CapabilityNode, RiskEdge, RiskPattern } from "./types.js";

function has(node: CapabilityNode, ...caps: CapabilityNode["capabilities"]): boolean {
  return caps.every((c) => node.capabilities.includes(c));
}

function hasAny(node: CapabilityNode, ...caps: CapabilityNode["capabilities"]): boolean {
  return caps.some((c) => node.capabilities.includes(c));
}

// ── P01: Cross-Config Lethal Trifecta ─────────────────────────────────────────
const P01: RiskPattern = {
  id: "P01",
  name: "Cross-Config Lethal Trifecta",
  description:
    "Private data reader + untrusted content ingester + external network sender across multiple servers. " +
    "No individual server triggers F1, but the combination is equally dangerous.",
  severity: "critical",
  owasp: "MCP01 + MCP04",
  mitre: "AML.T0054.001 + AML.T0057",
  required_capabilities: [
    ["reads-data", "manages-credentials"],
    ["web-scraping", "reads-messages"],
    ["sends-network"],
  ],
  detect(nodes) {
    const edges: RiskEdge[] = [];
    const privateReaders = nodes.filter(
      (n) => has(n, "reads-data") && hasAny(n, "manages-credentials", "accesses-filesystem")
    );
    const injectionGateways = nodes.filter((n) => n.is_injection_gateway);
    const networkSenders = nodes.filter((n) => has(n, "sends-network"));

    if (privateReaders.length > 0 && injectionGateways.length > 0 && networkSenders.length > 0) {
      const reader = privateReaders[0];
      const gateway = injectionGateways[0];
      const sender = networkSenders[0];

      edges.push({
        from_server_id: gateway.server_id,
        to_server_id: reader.server_id,
        edge_type: "injection_path",
        severity: "critical",
        description: `${gateway.server_name} ingests untrusted content → can inject instructions into ${reader.server_name}'s data access context`,
        owasp: "MCP01",
        mitre: "AML.T0054.001",
      });
      edges.push({
        from_server_id: reader.server_id,
        to_server_id: sender.server_id,
        edge_type: "exfiltration_chain",
        severity: "critical",
        description: `${reader.server_name} accesses sensitive data → ${sender.server_name} can exfiltrate it`,
        owasp: "MCP04",
        mitre: "AML.T0057",
      });
    }
    return edges;
  },
};

// ── P02: Credential Harvesting Chain ──────────────────────────────────────────
const P02: RiskPattern = {
  id: "P02",
  name: "Credential Harvesting Chain",
  description:
    "A credential manager + a network sender in the same config creates a direct credential exfiltration path. " +
    "An attacker who compromises either server or injects instructions into the session can extract all managed credentials.",
  severity: "critical",
  owasp: "MCP04 + MCP05",
  mitre: "AML.T0057",
  required_capabilities: [["manages-credentials"], ["sends-network"]],
  detect(nodes) {
    const edges: RiskEdge[] = [];
    const credServers = nodes.filter((n) => has(n, "manages-credentials"));
    const senderServers = nodes.filter((n) => has(n, "sends-network"));

    for (const cred of credServers) {
      for (const sender of senderServers) {
        if (cred.server_id === sender.server_id) continue;
        edges.push({
          from_server_id: cred.server_id,
          to_server_id: sender.server_id,
          edge_type: "exfiltration_chain",
          severity: "critical",
          description: `${cred.server_name} manages credentials + ${sender.server_name} can send network requests → credential exfiltration path`,
          owasp: "MCP04",
          mitre: "AML.T0057",
        });
      }
    }
    return edges;
  },
};

// ── P03: Injection Propagation Path ───────────────────────────────────────────
const P03: RiskPattern = {
  id: "P03",
  name: "Injection Propagation Path",
  description:
    "A server that ingests untrusted content (web, email, issues) combined with a code executor. " +
    "Injected payload from the gateway can propagate into the executor's context via the shared AI conversation.",
  severity: "critical",
  owasp: "MCP01 + MCP03",
  mitre: "AML.T0054.001",
  required_capabilities: [["web-scraping"], ["executes-code"]],
  detect(nodes) {
    const edges: RiskEdge[] = [];
    const gateways = nodes.filter((n) => n.is_injection_gateway);
    const executors = nodes.filter((n) => has(n, "executes-code"));

    for (const gw of gateways) {
      for (const ex of executors) {
        if (gw.server_id === ex.server_id) continue;
        edges.push({
          from_server_id: gw.server_id,
          to_server_id: ex.server_id,
          edge_type: "injection_path",
          severity: "critical",
          description: `${gw.server_name} ingests untrusted content → injected payload propagates to ${ex.server_name}'s code execution context`,
          owasp: "MCP01",
          mitre: "AML.T0054.001",
        });
      }
    }
    return edges;
  },
};

// ── P04: Shared Memory Pollution ──────────────────────────────────────────────
const P04: RiskPattern = {
  id: "P04",
  name: "Shared Agent Memory Pollution",
  description:
    "A server that writes to shared agent memory (vector stores, scratchpads) combined with a server that reads from it. " +
    "An attacker who poisons the memory store once affects all downstream agents that read from it.",
  severity: "high",
  owasp: "MCP01",
  mitre: "AML.T0059",
  required_capabilities: [["writes-agent-memory"], ["reads-agent-memory"]],
  detect(nodes) {
    const edges: RiskEdge[] = [];
    const writers = nodes.filter((n) => has(n, "writes-agent-memory"));
    const readers = nodes.filter((n) => has(n, "reads-agent-memory"));

    for (const writer of writers) {
      for (const reader of readers) {
        if (writer.server_id === reader.server_id) continue;
        edges.push({
          from_server_id: writer.server_id,
          to_server_id: reader.server_id,
          edge_type: "memory_pollution",
          severity: "high",
          description: `${writer.server_name} writes to shared memory → ${reader.server_name} reads from it → persistent injection vector`,
          owasp: "MCP01",
          mitre: "AML.T0059",
        });
      }
    }
    return edges;
  },
};

// ── P05: Agent Config Poisoning Chain ─────────────────────────────────────────
const P05: RiskPattern = {
  id: "P05",
  name: "Agent Config Poisoning Chain",
  description:
    "A server that can write to agent config files (.claude/, .cursor/, .gemini/, ~/.mcp.json). " +
    "Enables cross-agent RCE: add a malicious MCP server to another agent's config.",
  severity: "critical",
  owasp: "MCP10",
  mitre: "AML.T0060",
  required_capabilities: [["writes-agent-config"]],
  detect(nodes) {
    const edges: RiskEdge[] = [];
    const configWriters = nodes.filter((n) => has(n, "writes-agent-config"));

    for (const writer of configWriters) {
      for (const other of nodes) {
        if (writer.server_id === other.server_id) continue;
        edges.push({
          from_server_id: writer.server_id,
          to_server_id: other.server_id,
          edge_type: "config_poisoning",
          severity: "critical",
          description: `${writer.server_name} can write agent configs → can inject malicious MCP server into any agent's configuration`,
          owasp: "MCP10",
          mitre: "AML.T0060",
        });
        break; // One edge is enough to flag the pattern
      }
    }
    return edges;
  },
};

// ── P06: Data Read-Exfiltration Chain ─────────────────────────────────────────
const P06: RiskPattern = {
  id: "P06",
  name: "Data Read-Exfiltration Chain",
  description:
    "A filesystem reader or database querier combined with a network sender. " +
    "Classic data exfiltration pattern: read sensitive data, send it externally.",
  severity: "high",
  owasp: "MCP04",
  mitre: "AML.T0057",
  required_capabilities: [["accesses-filesystem", "reads-data"], ["sends-network"]],
  detect(nodes) {
    const edges: RiskEdge[] = [];
    const readers = nodes.filter((n) => hasAny(n, "accesses-filesystem", "database-query"));
    const senders = nodes.filter((n) => has(n, "sends-network"));

    for (const reader of readers) {
      for (const sender of senders) {
        if (reader.server_id === sender.server_id) continue;
        edges.push({
          from_server_id: reader.server_id,
          to_server_id: sender.server_id,
          edge_type: "exfiltration_chain",
          severity: "high",
          description: `${reader.server_name} can read sensitive data → ${sender.server_name} can exfiltrate it`,
          owasp: "MCP04",
          mitre: "AML.T0057",
        });
      }
    }
    return edges;
  },
};

// ── P07: Code Generation + Execution ─────────────────────────────────────────
const P07: RiskPattern = {
  id: "P07",
  name: "Code Generation + Execution",
  description:
    "A code-generation server combined with a code-execution server. " +
    "Injected instructions can ask the generator to produce malicious code, which the executor then runs.",
  severity: "critical",
  owasp: "MCP03",
  mitre: "AML.T0054",
  required_capabilities: [["code-generation"], ["executes-code"]],
  detect(nodes) {
    const edges: RiskEdge[] = [];
    const generators = nodes.filter((n) => has(n, "code-generation"));
    const executors = nodes.filter((n) => has(n, "executes-code"));

    for (const gen of generators) {
      for (const ex of executors) {
        if (gen.server_id === ex.server_id) continue;
        edges.push({
          from_server_id: gen.server_id,
          to_server_id: ex.server_id,
          edge_type: "injection_path",
          severity: "critical",
          description: `${gen.server_name} generates code → ${ex.server_name} executes it → injection via code generation`,
          owasp: "MCP03",
          mitre: "AML.T0054",
        });
      }
    }
    return edges;
  },
};

// ── P08: Database Privilege Escalation ───────────────────────────────────────
const P08: RiskPattern = {
  id: "P08",
  name: "Database Privilege Escalation",
  description:
    "A database query server + a database admin server in the same config. " +
    "An attacker can use the query server to discover schema details, then use the admin server to drop/alter tables.",
  severity: "high",
  owasp: "MCP05",
  mitre: "AML.T0054",
  required_capabilities: [["database-query"], ["database-admin"]],
  detect(nodes) {
    const edges: RiskEdge[] = [];
    const queryServers = nodes.filter((n) => has(n, "database-query"));
    const adminServers = nodes.filter((n) => has(n, "database-admin"));

    for (const q of queryServers) {
      for (const a of adminServers) {
        if (q.server_id === a.server_id) continue;
        edges.push({
          from_server_id: q.server_id,
          to_server_id: a.server_id,
          edge_type: "privilege_escalation",
          severity: "high",
          description: `${q.server_name} can query schema → ${a.server_name} can perform destructive DDL operations`,
          owasp: "MCP05",
          mitre: "AML.T0054",
        });
      }
    }
    return edges;
  },
};

// ── P09: Email/Slack Indirect Injection ───────────────────────────────────────
const P09: RiskPattern = {
  id: "P09",
  name: "Email/Slack Indirect Injection",
  description:
    "A message reader + a message sender in the same config. " +
    "Attacker sends a crafted email/Slack message with injection payload → " +
    "AI reads it → executes injected instructions via the sender.",
  severity: "high",
  owasp: "MCP01",
  mitre: "AML.T0054.001",
  required_capabilities: [["reads-messages"], ["sends-network"]],
  detect(nodes) {
    const edges: RiskEdge[] = [];
    const readers = nodes.filter((n) => has(n, "reads-messages"));
    const senders = nodes.filter((n) => has(n, "sends-network"));

    for (const reader of readers) {
      for (const sender of senders) {
        if (reader.server_id === sender.server_id) continue;
        edges.push({
          from_server_id: reader.server_id,
          to_server_id: sender.server_id,
          edge_type: "injection_path",
          severity: "high",
          description: `${reader.server_name} reads messages (injection gateway) → ${sender.server_name} can be used to exfiltrate or send attacker-controlled content`,
          owasp: "MCP01",
          mitre: "AML.T0054.001",
        });
      }
    }
    return edges;
  },
};

// ── P10: Web Scrape + Execute ─────────────────────────────────────────────────
const P10: RiskPattern = {
  id: "P10",
  name: "Web Scrape + Execute",
  description:
    "A web scraper + a code/command executor. The attacker hosts a webpage with an injection payload. " +
    "The AI scrapes it, the injected instructions trigger code execution on the user's machine.",
  severity: "critical",
  owasp: "MCP01 + MCP03",
  mitre: "AML.T0054.001",
  required_capabilities: [["web-scraping"], ["executes-code"]],
  detect(nodes) {
    // Covered by P03 — deduplicate
    return [];
  },
};

// ── P11: Low-Score Server in High-Trust Configuration ────────────────────────
const P11: RiskPattern = {
  id: "P11",
  name: "Low-Score Server in High-Trust Configuration",
  description:
    "A critically-scored server (score < 40) in the same config as servers that have high privileges. " +
    "The weakest link raises risk for all servers that share the same AI session context.",
  severity: "high",
  owasp: "MCP02",
  mitre: "AML.T0054",
  required_capabilities: [],
  detect(nodes) {
    const edges: RiskEdge[] = [];
    const criticalServers = nodes.filter(
      (n) => n.latest_score !== null && n.latest_score < 40
    );
    const highPrivServers = nodes.filter(
      (n) => hasAny(n, "manages-credentials", "executes-code", "database-admin") &&
        !criticalServers.includes(n)
    );

    for (const weak of criticalServers) {
      for (const highPriv of highPrivServers) {
        edges.push({
          from_server_id: weak.server_id,
          to_server_id: highPriv.server_id,
          edge_type: "injection_path",
          severity: "high",
          description: `${weak.server_name} (score ${weak.latest_score}) is critically vulnerable → shared session with ${highPriv.server_name} which has high-privilege capabilities`,
          owasp: "MCP02",
          mitre: "AML.T0054",
        });
      }
    }
    return edges;
  },
};

// ── P12: Multi-Hop Exfiltration ───────────────────────────────────────────────
const P12: RiskPattern = {
  id: "P12",
  name: "Multi-Hop Exfiltration Chain",
  description:
    "Three-server chain: read sensitive data → transform/encode → exfiltrate. " +
    "No individual server triggers F7, but the distributed chain achieves the same goal. " +
    "Extends F7 (single-server multi-step exfiltration) to multi-server configurations.",
  severity: "critical",
  owasp: "MCP04",
  mitre: "AML.T0057",
  required_capabilities: [
    ["accesses-filesystem", "manages-credentials"],
    ["writes-data", "code-generation"],
    ["sends-network"],
  ],
  detect(nodes) {
    const edges: RiskEdge[] = [];
    const sensitiveReaders = nodes.filter(
      (n) => hasAny(n, "manages-credentials", "accesses-filesystem")
    );
    const transformers = nodes.filter(
      (n) => hasAny(n, "writes-data", "code-generation") && !sensitiveReaders.includes(n)
    );
    const senders = nodes.filter(
      (n) => has(n, "sends-network") && !sensitiveReaders.includes(n) && !transformers.includes(n)
    );

    if (sensitiveReaders.length > 0 && transformers.length > 0 && senders.length > 0) {
      const reader = sensitiveReaders[0];
      const transformer = transformers[0];
      const sender = senders[0];

      edges.push({
        from_server_id: reader.server_id,
        to_server_id: transformer.server_id,
        edge_type: "data_flow",
        severity: "critical",
        description: `Multi-hop exfiltration: ${reader.server_name} (read) → ${transformer.server_name} (transform) → ${sender.server_name} (exfiltrate)`,
        owasp: "MCP04",
        mitre: "AML.T0057",
      });
      edges.push({
        from_server_id: transformer.server_id,
        to_server_id: sender.server_id,
        edge_type: "exfiltration_chain",
        severity: "critical",
        description: `Exfiltration hop: ${transformer.server_name} → ${sender.server_name}`,
        owasp: "MCP04",
        mitre: "AML.T0057",
      });
    }
    return edges;
  },
};

export const ALL_PATTERNS: RiskPattern[] = [
  P01, P02, P03, P04, P05, P06, P07, P08, P09, P10, P11, P12,
];
