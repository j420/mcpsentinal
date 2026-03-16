/**
 * Capability graph builder.
 *
 * Takes a set of server records (from the database) and classifies
 * each server's capabilities based on its tools and findings.
 *
 * This is intentionally conservative — when in doubt, we assign the
 * more dangerous capability class. Better to have a false alarm on
 * the risk matrix than to miss a genuine cross-server attack path.
 */
import type { Capability, CapabilityNode } from "./types.js";

interface ServerInput {
  server_id: string;
  server_name: string;
  server_slug: string;
  latest_score: number | null;
  category: string | null;
  tools: Array<{
    name: string;
    description: string | null;
    capability_tags?: string[];
  }>;
}

// ── Tool name / description pattern classifiers ────────────────────────────────

const CAPABILITY_PATTERNS: Array<{
  capability: Capability;
  toolNamePatterns: RegExp[];
  descriptionPatterns: RegExp[];
}> = [
  {
    capability: "executes-code",
    toolNamePatterns: [/exec|run|eval|shell|bash|python|js|script|spawn|execute/i],
    descriptionPatterns: [/execut|run\s+code|shell|command/i],
  },
  {
    capability: "sends-network",
    toolNamePatterns: [/send|post|http|fetch|request|webhook|email|slack|notify|push/i],
    descriptionPatterns: [/sends?\s+(to|request|http|email)|post\s+(to|request)|http\s+request/i],
  },
  {
    capability: "accesses-filesystem",
    toolNamePatterns: [/read_file|write_file|list_file|delete_file|mkdir|fs_|file_/i],
    descriptionPatterns: [/file\s+system|filesystem|read\s+file|write\s+file|directory/i],
  },
  {
    capability: "reads-data",
    toolNamePatterns: [/read|get|fetch|list|search|query|select|find/i],
    descriptionPatterns: [/reads?|fetches?|retrieves?|returns?/i],
  },
  {
    capability: "writes-data",
    toolNamePatterns: [/write|create|update|insert|put|patch|upsert|save|store/i],
    descriptionPatterns: [/writes?|creates?|updates?|inserts?|stores?|saves?/i],
  },
  {
    capability: "manages-credentials",
    toolNamePatterns: [/auth|login|token|credential|secret|key|password|oauth/i],
    descriptionPatterns: [/credential|secret|token|api.key|password|authenticate/i],
  },
  {
    capability: "reads-messages",
    toolNamePatterns: [/read_email|read_slack|read_message|read_issue|get_inbox|list_email/i],
    descriptionPatterns: [/reads?\s+(email|message|slack|issue|notification)/i],
  },
  {
    capability: "web-scraping",
    toolNamePatterns: [/scrape|crawl|browse|webpage|fetch_url|get_page|web_search/i],
    descriptionPatterns: [/scrapes?|crawls?|webpage|web\s+content|fetches?\s+(any\s+)?url/i],
  },
  {
    capability: "writes-agent-config",
    toolNamePatterns: [/write_config|update_config|set_config|modify_setting/i],
    descriptionPatterns: [/\.(claude|cursor|gemini|mcp)\s*(\/|\.json)|agent\s+config/i],
  },
  {
    capability: "reads-agent-memory",
    toolNamePatterns: [/read_memory|get_memory|recall|remember|vector_search/i],
    descriptionPatterns: [/reads?\s+(agent\s+)?memory|vector\s+store|semantic\s+search|recall/i],
  },
  {
    capability: "writes-agent-memory",
    toolNamePatterns: [/write_memory|store_memory|save_memory|upsert_memory|add_memory/i],
    descriptionPatterns: [/writes?\s+(to\s+)?(agent\s+)?memory|stores?\s+(in\s+)?vector/i],
  },
  {
    capability: "code-generation",
    toolNamePatterns: [/generate_code|write_code|scaffold|create_function|codegen/i],
    descriptionPatterns: [/generates?\s+code|writes?\s+code|scaffold/i],
  },
  {
    capability: "database-admin",
    toolNamePatterns: [/drop_table|create_table|alter_table|migrate|truncate|drop_/i],
    descriptionPatterns: [/drops?\s+table|creates?\s+table|alter\s+table|truncate|ddl/i],
  },
  {
    capability: "database-query",
    toolNamePatterns: [/query|select|execute_sql|run_query|db_query/i],
    descriptionPatterns: [/sql\s+query|database\s+query|executes?\s+a\s+(sql|query)/i],
  },
];

/**
 * Classify a server into capability nodes based on its tools.
 */
export function buildCapabilityNode(server: ServerInput): CapabilityNode {
  const capabilities = new Set<Capability>();

  for (const tool of server.tools) {
    // Use capability_tags if available (already computed by the analyzer)
    if (tool.capability_tags) {
      for (const tag of tool.capability_tags) {
        if (CAPABILITY_PATTERNS.some((p) => p.capability === tag)) {
          capabilities.add(tag as Capability);
        }
      }
    }

    // Augment with name/description pattern matching
    for (const { capability, toolNamePatterns, descriptionPatterns } of CAPABILITY_PATTERNS) {
      if (toolNamePatterns.some((p) => p.test(tool.name))) {
        capabilities.add(capability);
      }
      if (tool.description && descriptionPatterns.some((p) => p.test(tool.description!))) {
        capabilities.add(capability);
      }
    }
  }

  const capList = Array.from(capabilities);

  return {
    server_id: server.server_id,
    server_name: server.server_name,
    server_slug: server.server_slug,
    latest_score: server.latest_score,
    capabilities: capList,
    is_injection_gateway:
      capList.includes("web-scraping") ||
      capList.includes("reads-messages") ||
      capList.includes("accesses-filesystem"),
    is_shared_writer:
      capList.includes("writes-agent-memory") ||
      capList.includes("writes-agent-config") ||
      (capList.includes("writes-data") && capList.includes("reads-agent-memory")),
    category: server.category,
  };
}

export function buildCapabilityGraph(servers: ServerInput[]): CapabilityNode[] {
  return servers.map(buildCapabilityNode);
}
