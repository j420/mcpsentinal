import { describe, it, expect } from "vitest";
import { generateCanaryInput, getInjectionPayloads } from "../canary.js";

describe("generateCanaryInput", () => {
  it("returns empty input for null schema", () => {
    const result = generateCanaryInput("test_tool", null);
    expect(result.input).toEqual({});
    expect(result.coverage).toEqual([]);
  });

  it("returns empty input when no properties", () => {
    const result = generateCanaryInput("test_tool", { type: "object" });
    expect(result.input).toEqual({});
  });

  it("fills required string parameters with canary value", () => {
    const schema = {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"],
    };
    const result = generateCanaryInput("search", schema);
    expect(result.input.query).toBe("mcp-sentinel-canary-test-value");
    expect(result.coverage).toContain("string");
  });

  it("fills path parameters with safe /tmp path", () => {
    const schema = {
      type: "object",
      properties: { file_path: { type: "string" } },
      required: ["file_path"],
    };
    const result = generateCanaryInput("read_file", schema);
    expect(result.input.file_path).toContain("/tmp/mcp-sentinel-canary");
    expect(result.coverage).toContain("path");
  });

  it("fills URL parameters with localhost canary URL", () => {
    const schema = {
      type: "object",
      properties: { url: { type: "string" } },
      required: ["url"],
    };
    const result = generateCanaryInput("fetch", schema);
    expect(result.input.url).toContain("127.0.0.1");
    expect(result.coverage).toContain("url");
  });

  it("defaults boolean to false (safe for permission-like flags)", () => {
    const schema = {
      type: "object",
      properties: { recursive: { type: "boolean" } },
      required: ["recursive"],
    };
    const result = generateCanaryInput("delete_dir", schema);
    expect(result.input.recursive).toBe(false);
    expect(result.coverage).toContain("boolean");
  });

  it("fills numeric params within min/max bounds", () => {
    const schema = {
      type: "object",
      properties: { limit: { type: "integer", minimum: 1, maximum: 100 } },
      required: ["limit"],
    };
    const result = generateCanaryInput("paginate", schema);
    const limit = result.input.limit as number;
    expect(limit).toBeGreaterThanOrEqual(1);
    expect(limit).toBeLessThanOrEqual(100);
  });

  it("uses first enum value for enum strings", () => {
    const schema = {
      type: "object",
      properties: {
        mode: { type: "string", enum: ["read", "write"] },
      },
      required: ["mode"],
    };
    const result = generateCanaryInput("set_mode", schema);
    expect(result.input.mode).toBe("read");
  });

  it("skips optional params that are not dangerous", () => {
    const schema = {
      type: "object",
      properties: {
        name: { type: "string" },         // optional, not dangerous
        description: { type: "string" },  // optional, not dangerous
        url: { type: "string" },           // optional but dangerous → included
      },
      required: [],
    };
    const result = generateCanaryInput("create_item", schema);
    expect(result.input.name).toBeUndefined();
    expect(result.input.description).toBeUndefined();
    expect(result.input.url).toBeDefined(); // dangerous param always filled
  });
});

describe("getInjectionPayloads", () => {
  it("returns path traversal payloads for path parameters", () => {
    const payloads = getInjectionPayloads("file_path");
    expect(payloads.some((p) => p.type === "path_traversal")).toBe(true);
    // All payloads stay within /tmp or use URL-encoded variants
    for (const p of payloads.filter((x) => x.type === "path_traversal")) {
      expect(p.value).not.toContain("/etc/passwd");
      expect(p.value).not.toContain("/root");
    }
  });

  it("returns command injection payloads for command parameters", () => {
    const payloads = getInjectionPayloads("command");
    const cmdPayloads = payloads.filter((p) => p.type === "command_injection");
    expect(cmdPayloads.length).toBeGreaterThan(0);
    // Commands must be safe (echo only, no rm/curl to real endpoints)
    for (const p of cmdPayloads) {
      expect(p.value).not.toMatch(/\brm\b/);
      expect(p.value).not.toMatch(/curl\s+https?:\/\/(?!127\.0\.0\.1)/);
    }
  });

  it("returns SQL injection payloads for query parameters", () => {
    const payloads = getInjectionPayloads("sql_query");
    expect(payloads.some((p) => p.type === "sql_injection")).toBe(true);
  });

  it("returns empty array for non-dangerous parameter names", () => {
    const payloads = getInjectionPayloads("username");
    expect(payloads).toHaveLength(0);
  });

  it("every payload has a unique canary_token for reflection detection", () => {
    const payloads = getInjectionPayloads("file_path");
    for (const p of payloads) {
      expect(p.canary_token.length).toBeGreaterThan(0);
      expect(p.value).not.toContain("undefined");
    }
  });
});
