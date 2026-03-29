/**
 * Test Fixture Nodes — Reusable CapabilityNode factories
 *
 * Each node models a realistic MCP server with capabilities matching
 * what the risk-matrix capability classifier would produce.
 */
import type { CapabilityNode, Capability } from "../../types.js";

let counter = 0;

function makeNode(
  name: string,
  capabilities: Capability[],
  overrides: Partial<CapabilityNode> = {}
): CapabilityNode {
  counter++;
  return {
    server_id: `srv-${name}`,
    server_name: name,
    server_slug: name.toLowerCase().replace(/\s+/g, "-"),
    latest_score: 50,
    capabilities,
    is_injection_gateway: false,
    is_shared_writer: false,
    category: null,
    ...overrides,
  };
}

// ── Injection gateways ─────────────────────────────────────────────────────────

export function webScraper(score = 30): CapabilityNode {
  return makeNode("web-scraper", ["web-scraping", "reads-data"], {
    is_injection_gateway: true,
    latest_score: score,
  });
}

export function emailReader(score = 40): CapabilityNode {
  return makeNode("email-reader", ["reads-messages", "reads-data"], {
    is_injection_gateway: true,
    latest_score: score,
  });
}

export function slackBot(score = 45): CapabilityNode {
  return makeNode("slack-bot", ["reads-messages", "sends-network"], {
    is_injection_gateway: true,
    latest_score: score,
  });
}

// ── Data sources ───────────────────────────────────────────────────────────────

export function fileManager(score = 55): CapabilityNode {
  return makeNode("file-manager", ["reads-data", "writes-data", "accesses-filesystem"], {
    latest_score: score,
  });
}

export function credentialStore(score = 35): CapabilityNode {
  return makeNode("credential-store", ["reads-data", "manages-credentials"], {
    latest_score: score,
  });
}

export function dbReader(score = 60): CapabilityNode {
  return makeNode("db-reader", ["reads-data", "database-query"], {
    latest_score: score,
  });
}

// ── Executors ──────────────────────────────────────────────────────────────────

export function codeRunner(score = 40): CapabilityNode {
  return makeNode("code-runner", ["executes-code"], {
    latest_score: score,
  });
}

export function shellExec(score = 30): CapabilityNode {
  return makeNode("shell-exec", ["executes-code", "accesses-filesystem"], {
    latest_score: score,
  });
}

// ── Network senders (exfiltrators) ─────────────────────────────────────────────

export function webhookSender(score = 50): CapabilityNode {
  return makeNode("webhook-sender", ["sends-network"], {
    latest_score: score,
  });
}

export function emailSender(score = 50): CapabilityNode {
  return makeNode("email-sender", ["sends-network", "reads-messages"], {
    is_injection_gateway: true,
    latest_score: score,
  });
}

// ── Config/memory writers ──────────────────────────────────────────────────────

export function configWriter(score = 35): CapabilityNode {
  return makeNode("config-writer", ["writes-agent-config", "accesses-filesystem", "writes-data"], {
    is_shared_writer: true,
    latest_score: score,
  });
}

export function memoryWriter(score = 45): CapabilityNode {
  return makeNode("memory-writer", ["writes-agent-memory", "writes-data"], {
    is_shared_writer: true,
    latest_score: score,
  });
}

export function memoryReader(score = 55): CapabilityNode {
  return makeNode("memory-reader", ["reads-agent-memory", "reads-data"], {
    latest_score: score,
  });
}

// ── Code generation ────────────────────────────────────────────────────────────

export function codeGenerator(score = 50): CapabilityNode {
  return makeNode("code-generator", ["code-generation"], {
    latest_score: score,
  });
}

// ── Database admin ─────────────────────────────────────────────────────────────

export function dbAdmin(score = 40): CapabilityNode {
  return makeNode("db-admin", ["database-admin", "database-query", "reads-data", "writes-data"], {
    latest_score: score,
  });
}

// ── Safe servers (no dangerous capabilities) ───────────────────────────────────

export function safeCalculator(score = 90): CapabilityNode {
  return makeNode("calculator", ["reads-data"], {
    latest_score: score,
  });
}

export function safeFormatter(score = 85): CapabilityNode {
  return makeNode("formatter", ["reads-data"], {
    latest_score: score,
  });
}
