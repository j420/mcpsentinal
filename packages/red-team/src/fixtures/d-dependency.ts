import type { RuleFixtureSet } from "../types.js";

const base = {
  server: { id: "test", name: "test-server", description: null, github_url: null },
  tools: [],
  source_code: null,
  connection_metadata: null,
};

function depsCtx(dependencies: Array<{ name: string; version: string | null; has_known_cve: boolean; cve_ids: string[]; last_updated: Date | null }>) {
  return { ...base, dependencies };
}

const NOW = new Date();
const OLD_DATE = new Date("2021-01-01");

// ── D1: Known CVEs in Dependencies ────────────────────────────────────────────
export const D1: RuleFixtureSet = {
  rule_id: "D1",
  rule_name: "Known CVEs in Dependencies",
  fixtures: [
    {
      description: "Dependency with known CVE",
      context: depsCtx([
        {
          name: "lodash",
          version: "4.17.15",
          has_known_cve: true,
          cve_ids: ["CVE-2021-23337"],
          last_updated: NOW,
        },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Multiple CVEs in dependency",
      context: depsCtx([
        {
          name: "node-forge",
          version: "0.10.0",
          has_known_cve: true,
          cve_ids: ["CVE-2022-0122", "CVE-2022-24771"],
          last_updated: NOW,
        },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Clean dependency — no CVEs",
      context: depsCtx([
        {
          name: "zod",
          version: "3.23.0",
          has_known_cve: false,
          cve_ids: [],
          last_updated: NOW,
        },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Empty dependencies — no findings",
      context: depsCtx([]),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── D2: Abandoned Dependencies ────────────────────────────────────────────────
export const D2: RuleFixtureSet = {
  rule_id: "D2",
  rule_name: "Abandoned Dependencies",
  fixtures: [
    {
      description: "Dependency not updated in over 3 years",
      context: depsCtx([
        {
          name: "request",
          version: "2.88.2",
          has_known_cve: false,
          cve_ids: [],
          last_updated: new Date("2019-03-15"),
        },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Dependency updated last month",
      context: depsCtx([
        {
          name: "axios",
          version: "1.7.0",
          has_known_cve: false,
          cve_ids: [],
          last_updated: new Date(NOW.getTime() - 30 * 24 * 60 * 60 * 1000),
        },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Dependency with no last_updated data",
      context: depsCtx([
        {
          name: "some-mystery-package",
          version: "1.0.0",
          has_known_cve: false,
          cve_ids: [],
          last_updated: null,
        },
      ]),
      expect_finding: false, // null = unknown, not abandoned
      kind: "edge_case",
    },
  ],
};

// ── D5: Known Malicious Packages ──────────────────────────────────────────────
export const D5: RuleFixtureSet = {
  rule_id: "D5",
  rule_name: "Known Malicious Packages",
  fixtures: [
    {
      description: "MCP ecosystem typosquat: @mcp/sdk (not @modelcontextprotocol/sdk)",
      context: depsCtx([
        {
          name: "@mcp/sdk",
          version: "1.0.0",
          has_known_cve: false,
          cve_ids: [],
          last_updated: NOW,
        },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Known malicious: event-stream (2018 supply chain attack)",
      context: depsCtx([
        {
          name: "event-stream",
          version: "3.3.6",
          has_known_cve: true,
          cve_ids: ["CVE-2018-16484"],
          last_updated: OLD_DATE,
        },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Known malicious: colors (protestware v1.4.44+1.4.2)",
      context: depsCtx([
        {
          name: "colors",
          version: "1.4.44",
          has_known_cve: true,
          cve_ids: ["CVE-2022-21803"],
          last_updated: OLD_DATE,
        },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Legitimate package: @modelcontextprotocol/sdk",
      context: depsCtx([
        {
          name: "@modelcontextprotocol/sdk",
          version: "1.0.4",
          has_known_cve: false,
          cve_ids: [],
          last_updated: NOW,
        },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Legitimate popular package: express",
      context: depsCtx([
        {
          name: "express",
          version: "4.21.0",
          has_known_cve: false,
          cve_ids: [],
          last_updated: NOW,
        },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── D7: Dependency Confusion Attack Risk ──────────────────────────────────────
export const D7: RuleFixtureSet = {
  rule_id: "D7",
  rule_name: "Dependency Confusion Attack Risk",
  fixtures: [
    {
      description: "Suspiciously high version number — attacker trick",
      context: depsCtx([
        {
          name: "my-internal-package",
          version: "9999.0.0",
          has_known_cve: false,
          cve_ids: [],
          last_updated: NOW,
        },
      ]),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "Alex Birsan 2021 dependency confusion",
    },
    {
      description: "Scoped internal package with high version",
      context: depsCtx([
        {
          name: "@mycompany/internal-lib",
          version: "1000.0.0",
          has_known_cve: false,
          cve_ids: [],
          last_updated: NOW,
        },
      ]),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Normal version number — not suspicious",
      context: depsCtx([
        {
          name: "@mycompany/internal-lib",
          version: "1.5.3",
          has_known_cve: false,
          cve_ids: [],
          last_updated: NOW,
        },
      ]),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Edge case: version 100.0.0 — moderate suspicion, below threshold",
      context: depsCtx([
        {
          name: "some-package",
          version: "100.0.0",
          has_known_cve: false,
          cve_ids: [],
          last_updated: NOW,
        },
      ]),
      expect_finding: false, // threshold is typically 999+
      kind: "edge_case",
    },
  ],
};

export const ALL_D_FIXTURES: RuleFixtureSet[] = [D1, D2, D5, D7];
