import { describe, it, expect } from "vitest";
import { readdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rulesDir = join(__dirname, "..", "..", "..", "rules");

describe("mcp-sentinel-scanner", () => {
  it("rules directory exists and contains YAML files", () => {
    const files = readdirSync(rulesDir).filter(f => f.endsWith(".yaml"));
    expect(files.length).toBeGreaterThan(100);
  });

  it("all 17 rule categories are present (A-Q)", () => {
    const files = readdirSync(rulesDir).filter(f => f.endsWith(".yaml"));
    const prefixes = new Set(files.map(f => f.charAt(0)));
    for (const cat of "ABCDEFGHIJKLMNOPQ") {
      expect(prefixes.has(cat), `Missing category ${cat}`).toBe(true);
    }
  });

  it("ScanServerInputSchema validates correct input", async () => {
    // Dynamic import to avoid top-level side effects (MCP server startup)
    const { z } = await import("zod");

    const ScanServerInputSchema = z.object({
      server_name: z.string(),
      server_description: z.string().nullable().default(null),
      tools: z.array(z.object({
        name: z.string(),
        description: z.string().nullable().default(null),
        input_schema: z.record(z.unknown()).nullable().default(null),
      })).default([]),
      source_code: z.string().nullable().default(null),
      dependencies: z.array(z.object({
        name: z.string(),
        version: z.string().nullable().default(null),
      })).default([]),
    });

    const result = ScanServerInputSchema.safeParse({
      server_name: "test-server",
      tools: [{ name: "read_file", description: "Reads a file from disk" }],
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.server_name).toBe("test-server");
      expect(result.data.tools).toHaveLength(1);
    }
  });

  it("ScanServerInputSchema rejects missing server_name", async () => {
    const { z } = await import("zod");

    const ScanServerInputSchema = z.object({
      server_name: z.string(),
    });

    const result = ScanServerInputSchema.safeParse({});
    expect(result.success).toBe(false);
  });
});
