/**
 * ad-hoc-scanner tests — the shared ephemeral scan core.
 *
 * MCPConnector is mocked so the suite is hermetic (no live network). The
 * real rule engine is loaded from the rules/ directory — that exercises
 * the genuine analyze → score path.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

const enumerateMock = vi.fn();

vi.mock("@mcp-sentinel/connector", () => ({
  MCPConnector: class {
    enumerate = enumerateMock;
  },
}));

// Mock the SSRF guard's DNS-resolving `assertSafe` so the suite is hermetic:
// literal blocked IPs still throw (classifyAddress is real), but DNS names
// resolve without a real lookup. The real `assertSafe` is covered by
// url-guard.test.ts.
vi.mock("./url-guard.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-guard.js")>();
  return {
    ...actual,
    assertSafe: vi.fn(async (raw: string) => {
      const url = actual.parseAndValidate(raw);
      const host = url.hostname.replace(/^\[/, "").replace(/\]$/, "");
      const reason = actual.classifyAddress(host);
      if (reason) throw new actual.UrlGuardError(`Blocked (${reason}): ${host}`, reason);
      return url;
    }),
  };
});

import { runAdHocScan, AdHocScanError } from "./ad-hoc-scanner.js";
import { UrlGuardError } from "./url-guard.js";

function successfulEnumeration(tools: Array<{ name: string; description: string }> = []) {
  return {
    server_id: "ad-hoc-scan",
    tools: tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: { type: "object", properties: {} },
      output_schema: null,
      annotations: null,
    })),
    connection_success: true,
    connection_error: null,
    response_time_ms: 42,
    server_version: "1.0.0",
    server_instructions: null,
    resources: [],
    prompts: [],
    roots: [],
    declared_capabilities: { tools: true },
  };
}

beforeEach(() => {
  enumerateMock.mockReset();
});

describe("runAdHocScan — url input", () => {
  it("scans a live server and returns a shaped result", async () => {
    enumerateMock.mockResolvedValue(
      successfulEnumeration([{ name: "read_file", description: "Reads a file." }]),
    );
    const result = await runAdHocScan({ kind: "url", url: "https://example.com/mcp" });

    expect(result.input_type).toBe("url");
    expect(result.servers).toHaveLength(1);
    expect(result.servers[0].connection_success).toBe(true);
    expect(result.servers[0].endpoint).toContain("example.com");
    expect(result.servers[0].score.total_score).toBeGreaterThanOrEqual(0);
    expect(result.servers[0].score.total_score).toBeLessThanOrEqual(100);
    expect(result.servers[0].coverage.confidence_band).toBeDefined();
  });

  it("rejects an SSRF-blocked URL before connecting", async () => {
    await expect(
      runAdHocScan({ kind: "url", url: "http://169.254.169.254/latest/" }),
    ).rejects.toThrow(UrlGuardError);
    expect(enumerateMock).not.toHaveBeenCalled();
  });

  it("throws AdHocScanError when the server cannot be reached", async () => {
    enumerateMock.mockResolvedValue({
      server_id: "ad-hoc-scan",
      tools: [],
      connection_success: false,
      connection_error: "Connection timeout after 30000ms",
      response_time_ms: 30000,
      server_version: null,
      server_instructions: null,
      resources: [],
      prompts: [],
      roots: [],
      declared_capabilities: null,
    });
    await expect(
      runAdHocScan({ kind: "url", url: "https://offline.example.com/mcp" }),
    ).rejects.toMatchObject({ reason: "connection-failed" });
  });
});

describe("runAdHocScan — config input", () => {
  it("rejects malformed JSON", async () => {
    await expect(
      runAdHocScan({ kind: "config", config: "{ not json" }),
    ).rejects.toMatchObject({ reason: "bad-config-json" });
  });

  it("rejects a config with no server entries", async () => {
    await expect(
      runAdHocScan({ kind: "config", config: '{"mcpServers":{}}' }),
    ).rejects.toMatchObject({ reason: "empty-config" });
  });

  it("reports stdio entries as unscannable and scans remote ones", async () => {
    enumerateMock.mockResolvedValue(successfulEnumeration());
    const config = JSON.stringify({
      mcpServers: {
        "local-fs": { command: "npx", args: ["-y", "fs-server"] },
        remote: { url: "https://remote.example.com/mcp" },
      },
    });
    const result = await runAdHocScan({ kind: "config", config });

    expect(result.input_type).toBe("config");
    expect(result.unscannable_stdio).toHaveLength(1);
    expect(result.unscannable_stdio[0].name).toBe("local-fs");
    expect(result.servers).toHaveLength(1);
    expect(result.servers[0].connection_success).toBe(true);
  });

  it("rejects a config with only stdio servers", async () => {
    const config = JSON.stringify({
      mcpServers: { "local-fs": { command: "npx" } },
    });
    await expect(
      runAdHocScan({ kind: "config", config }),
    ).rejects.toMatchObject({ reason: "no-remote-servers" });
  });

  it("supports the alternate `servers` config shape", async () => {
    enumerateMock.mockResolvedValue(successfulEnumeration());
    const config = JSON.stringify({
      servers: { remote: { url: "https://remote.example.com/mcp" } },
    });
    const result = await runAdHocScan({ kind: "config", config });
    expect(result.servers).toHaveLength(1);
  });
});

describe("runAdHocScan — source input", () => {
  it("throws AdHocScanError for an unresolvable reference", async () => {
    await expect(
      runAdHocScan({ kind: "source", ref: "pypi:this-package-does-not-exist-xyzzy-99999" }),
    ).rejects.toBeInstanceOf(AdHocScanError);
  });
});
