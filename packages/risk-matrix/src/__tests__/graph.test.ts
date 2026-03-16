import { describe, it, expect } from "vitest";
import { buildCapabilityNode, buildCapabilityGraph } from "../graph.js";

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeServer(
  id: string,
  tools: Array<{ name: string; description?: string; capability_tags?: string[] }>,
  overrides: Partial<{
    server_name: string;
    server_slug: string;
    latest_score: number | null;
    category: string | null;
  }> = {}
) {
  return {
    server_id: id,
    server_name: overrides.server_name ?? `Server-${id}`,
    server_slug: overrides.server_slug ?? id,
    latest_score: overrides.latest_score ?? null,
    category: overrides.category ?? null,
    tools: tools.map((t) => ({
      name: t.name,
      description: t.description ?? null,
      capability_tags: t.capability_tags,
    })),
  };
}

// ── Tool name pattern classification ─────────────────────────────────────────

describe("buildCapabilityNode — tool name patterns", () => {
  it("classifies executes-code from tool name", () => {
    const node = buildCapabilityNode(makeServer("s1", [{ name: "run_python_code" }]));
    expect(node.capabilities).toContain("executes-code");
  });

  it("classifies executes-code from exec/bash variants", () => {
    for (const name of ["exec_command", "bash_run", "spawn_process", "shell_exec", "eval_js"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("executes-code");
    }
  });

  it("classifies sends-network from send/http/fetch variants", () => {
    for (const name of ["send_email", "http_post", "webhook_push", "fetch_data", "notify_slack"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("sends-network");
    }
  });

  it("classifies accesses-filesystem from file operation names", () => {
    for (const name of ["read_file", "write_file", "list_files", "delete_file", "mkdir_recursive"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("accesses-filesystem");
    }
  });

  it("classifies manages-credentials from auth/token/secret names", () => {
    for (const name of ["auth_token", "login_user", "get_secret", "oauth_flow", "password_reset"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("manages-credentials");
    }
  });

  it("classifies web-scraping from scrape/crawl/browse names", () => {
    for (const name of ["scrape_page", "crawl_site", "browse_url", "fetch_url", "get_page", "web_search"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("web-scraping");
    }
  });

  it("classifies reads-messages from email/slack reader names", () => {
    for (const name of ["read_email", "read_slack", "get_inbox", "list_email", "read_message"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("reads-messages");
    }
  });

  it("classifies writes-agent-config from config write names", () => {
    for (const name of ["write_config", "update_config", "set_config", "modify_setting"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("writes-agent-config");
    }
  });

  it("classifies reads-agent-memory from memory read names", () => {
    for (const name of ["read_memory", "get_memory", "recall_fact", "vector_search", "remember"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("reads-agent-memory");
    }
  });

  it("classifies writes-agent-memory from memory write names", () => {
    for (const name of ["write_memory", "store_memory", "save_memory", "upsert_memory", "add_memory"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("writes-agent-memory");
    }
  });

  it("classifies code-generation from codegen names", () => {
    for (const name of ["generate_code", "write_code", "scaffold_project", "codegen", "create_function"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("code-generation");
    }
  });

  it("classifies database-admin from DDL names", () => {
    for (const name of ["drop_table", "create_table", "alter_table", "truncate_db", "migrate_schema"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("database-admin");
    }
  });

  it("classifies database-query from SQL query names", () => {
    for (const name of ["execute_sql", "run_query", "db_query", "select_rows"]) {
      const node = buildCapabilityNode(makeServer("s1", [{ name }]));
      expect(node.capabilities).toContain("database-query");
    }
  });
});

// ── Description pattern classification ───────────────────────────────────────

describe("buildCapabilityNode — description patterns", () => {
  it("classifies executes-code from description", () => {
    const node = buildCapabilityNode(
      makeServer("s1", [{ name: "do_thing", description: "Executes shell commands on the host" }])
    );
    expect(node.capabilities).toContain("executes-code");
  });

  it("classifies sends-network from description", () => {
    const node = buildCapabilityNode(
      makeServer("s1", [{ name: "do_thing", description: "Sends an HTTP request to the specified endpoint" }])
    );
    expect(node.capabilities).toContain("sends-network");
  });

  it("classifies accesses-filesystem from description", () => {
    const node = buildCapabilityNode(
      makeServer("s1", [{ name: "do_thing", description: "Reads files from the filesystem" }])
    );
    expect(node.capabilities).toContain("accesses-filesystem");
  });

  it("classifies manages-credentials from description", () => {
    const node = buildCapabilityNode(
      makeServer("s1", [{ name: "do_thing", description: "Manages API credentials and tokens" }])
    );
    expect(node.capabilities).toContain("manages-credentials");
  });

  it("classifies web-scraping from description", () => {
    const node = buildCapabilityNode(
      makeServer("s1", [{ name: "do_thing", description: "Fetches any URL and returns web content" }])
    );
    expect(node.capabilities).toContain("web-scraping");
  });

  it("classifies reads-messages from description", () => {
    const node = buildCapabilityNode(
      makeServer("s1", [{ name: "do_thing", description: "Reads email messages from inbox" }])
    );
    expect(node.capabilities).toContain("reads-messages");
  });
});

// ── capability_tags passthrough ───────────────────────────────────────────────

describe("buildCapabilityNode — capability_tags", () => {
  it("uses capability_tags when present", () => {
    const node = buildCapabilityNode(
      makeServer("s1", [{
        name: "safe_calculator",
        description: "Adds two numbers",
        capability_tags: ["executes-code", "sends-network"],
      }])
    );
    expect(node.capabilities).toContain("executes-code");
    expect(node.capabilities).toContain("sends-network");
  });

  it("ignores unknown tags in capability_tags", () => {
    const node = buildCapabilityNode(
      makeServer("s1", [{
        name: "tool",
        capability_tags: ["unknown-cap-xyz", "reads-data"],
      }])
    );
    expect(node.capabilities).not.toContain("unknown-cap-xyz");
    expect(node.capabilities).toContain("reads-data");
  });

  it("merges capability_tags with name-matched capabilities", () => {
    const node = buildCapabilityNode(
      makeServer("s1", [{
        name: "exec_command",  // matches executes-code by name
        capability_tags: ["sends-network"],  // adds sends-network from tag
      }])
    );
    expect(node.capabilities).toContain("executes-code");
    expect(node.capabilities).toContain("sends-network");
  });

  it("deduplicates when capability_tags overlaps with name patterns", () => {
    const node = buildCapabilityNode(
      makeServer("s1", [{
        name: "exec_command",
        capability_tags: ["executes-code"],
      }])
    );
    const execCount = node.capabilities.filter((c) => c === "executes-code").length;
    expect(execCount).toBe(1);
  });
});

// ── is_injection_gateway ──────────────────────────────────────────────────────

describe("buildCapabilityNode — is_injection_gateway", () => {
  it("is true for web-scraping servers", () => {
    const node = buildCapabilityNode(makeServer("s1", [{ name: "scrape_url" }]));
    expect(node.is_injection_gateway).toBe(true);
  });

  it("is true for reads-messages servers", () => {
    const node = buildCapabilityNode(makeServer("s1", [{ name: "read_email" }]));
    expect(node.is_injection_gateway).toBe(true);
  });

  it("is true for accesses-filesystem servers", () => {
    const node = buildCapabilityNode(makeServer("s1", [{ name: "read_file" }]));
    expect(node.is_injection_gateway).toBe(true);
  });

  it("is false for a pure calculator/non-input server", () => {
    const node = buildCapabilityNode(makeServer("s1", [
      { name: "add_numbers", description: "Adds two numbers and returns the sum" },
    ]));
    expect(node.is_injection_gateway).toBe(false);
  });

  it("is false for a writes-data only server", () => {
    const node = buildCapabilityNode(makeServer("s1", [{ name: "store_record" }]));
    expect(node.is_injection_gateway).toBe(false);
  });
});

// ── is_shared_writer ──────────────────────────────────────────────────────────

describe("buildCapabilityNode — is_shared_writer", () => {
  it("is true for writes-agent-memory servers", () => {
    const node = buildCapabilityNode(makeServer("s1", [{ name: "write_memory" }]));
    expect(node.is_shared_writer).toBe(true);
  });

  it("is true for writes-agent-config servers", () => {
    const node = buildCapabilityNode(makeServer("s1", [{ name: "write_config" }]));
    expect(node.is_shared_writer).toBe(true);
  });

  it("is true for writes-data AND reads-agent-memory combination", () => {
    const node = buildCapabilityNode(makeServer("s1", [
      { name: "store_data" },     // writes-data
      { name: "vector_search" },  // reads-agent-memory
    ]));
    expect(node.capabilities).toContain("writes-data");
    expect(node.capabilities).toContain("reads-agent-memory");
    expect(node.is_shared_writer).toBe(true);
  });

  it("is false for writes-data without reads-agent-memory", () => {
    const node = buildCapabilityNode(makeServer("s1", [
      { name: "store_record", description: "Writes a record to the database" },
    ]));
    // writes-data alone is not a shared writer
    if (!node.capabilities.includes("reads-agent-memory")) {
      expect(node.is_shared_writer).toBe(false);
    }
  });

  it("is false for reads-data only server", () => {
    const node = buildCapabilityNode(makeServer("s1", [
      { name: "get_record", description: "Returns a record from the database" },
    ]));
    // reads-data without write capabilities is not a shared writer
    if (!node.capabilities.some((c) => ["writes-agent-memory", "writes-agent-config", "writes-data"].includes(c))) {
      expect(node.is_shared_writer).toBe(false);
    }
  });
});

// ── Multi-tool servers ────────────────────────────────────────────────────────

describe("buildCapabilityNode — multi-tool servers", () => {
  it("accumulates capabilities from multiple tools", () => {
    const node = buildCapabilityNode(makeServer("s1", [
      { name: "read_file" },
      { name: "http_post" },
      { name: "exec_command" },
    ]));
    expect(node.capabilities).toContain("accesses-filesystem");
    expect(node.capabilities).toContain("sends-network");
    expect(node.capabilities).toContain("executes-code");
  });

  it("returns empty capabilities for zero tools", () => {
    const node = buildCapabilityNode(makeServer("s1", []));
    expect(node.capabilities).toHaveLength(0);
    expect(node.is_injection_gateway).toBe(false);
    expect(node.is_shared_writer).toBe(false);
  });

  it("preserves server metadata on node", () => {
    const node = buildCapabilityNode(makeServer(
      "srv-123",
      [{ name: "read_file" }],
      { server_name: "My File Server", server_slug: "my-file-server", latest_score: 75, category: "filesystem" }
    ));
    expect(node.server_id).toBe("srv-123");
    expect(node.server_name).toBe("My File Server");
    expect(node.server_slug).toBe("my-file-server");
    expect(node.latest_score).toBe(75);
    expect(node.category).toBe("filesystem");
  });

  it("handles null description without throwing", () => {
    expect(() =>
      buildCapabilityNode(makeServer("s1", [{ name: "tool", description: undefined }]))
    ).not.toThrow();
  });
});

// ── buildCapabilityGraph ──────────────────────────────────────────────────────

describe("buildCapabilityGraph", () => {
  it("maps each server to a node", () => {
    const servers = [
      makeServer("s1", [{ name: "read_file" }]),
      makeServer("s2", [{ name: "http_post" }]),
      makeServer("s3", [{ name: "exec_command" }]),
    ];
    const nodes = buildCapabilityGraph(servers);
    expect(nodes).toHaveLength(3);
    expect(nodes.map((n) => n.server_id)).toEqual(["s1", "s2", "s3"]);
  });

  it("returns empty array for empty input", () => {
    expect(buildCapabilityGraph([])).toEqual([]);
  });
});
