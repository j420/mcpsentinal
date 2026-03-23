/**
 * DependencyAnalyzer — Package analysis for D1–D7
 *
 * Replaces composite switch-case checks with structured dependency analysis:
 * - CVE database lookup (D1)
 * - Abandonment detection via last-update timestamps (D2)
 * - Multi-algorithm typosquatting (D3)
 * - Excessive dependencies (D4)
 * - Known malicious packages (D5)
 * - Weak cryptography (D6)
 * - Dependency confusion via version anomaly (D7)
 */

import type { AnalysisContext } from "../engine.js";
import type { Severity, OwaspCategory } from "@mcp-sentinel/database";
import { computeSimilarity, normalizeName } from "../rules/analyzers/similarity.js";
import { normalizeConfusables } from "../rules/analyzers/unicode.js";

export interface DependencyFinding {
  rule_id: string;
  severity: Severity;
  evidence: string;
  remediation: string;
  owasp_category: OwaspCategory | null;
  mitre_technique: string | null;
  confidence: number;
  metadata?: Record<string, unknown>;
}

// ── Known malicious packages (confirmed supply chain attacks) ──

const MALICIOUS_PACKAGES = new Set([
  "event-stream", "flatmap-stream", "colors", "faker",
  "ua-parser-js", "coa", "rc", "node-ipc",
  "@mcp/sdk", "mcp-sdk", "fastmcp-sdk", "mcp-server-sdk",
  "cross-env.js", "crossenv", "mongose", "babelcli",
  "d3.js", "jquery.js", "mariadb", "mysqljs",
  "node-fabric", "node-opencv", "node-opensl", "node-openssl",
  "nodecaffe", "nodefabric", "nodemailer-js", "noderequest",
  "nodesass", "nodesqlite", "sqlikinode", "tkinter",
]);

// ── Weak crypto dependencies ──

const WEAK_CRYPTO: Array<{ name: string; maxSafeVersion?: string; reason: string }> = [
  { name: "md5", reason: "MD5 is cryptographically broken (collision attacks)" },
  { name: "sha1", reason: "SHA-1 is deprecated (SHAttered attack, 2017)" },
  { name: "node-forge", maxSafeVersion: "1.3.0", reason: "Known vulnerabilities below v1.3.0" },
  { name: "jsonwebtoken", maxSafeVersion: "8.5.1", reason: "Algorithm confusion below v8.5.1" },
  { name: "bcrypt-nodejs", reason: "Abandoned — use bcrypt or argon2 instead" },
  { name: "crypto-js", maxSafeVersion: "4.2.0", reason: "PBKDF2 weakness below v4.2.0" },
  { name: "pycrypto", reason: "Abandoned — use pycryptodome instead" },
];

// ── Known legitimate packages for typosquat comparison ──

const KNOWN_PACKAGES = [
  "@modelcontextprotocol/sdk", "fastmcp", "mcp-framework",
  "express", "fastify", "next", "react", "vue", "angular",
  "lodash", "axios", "zod", "prisma", "drizzle-orm",
  "typescript", "eslint", "prettier", "vitest", "jest",
  "webpack", "vite", "esbuild", "pnpm",
  "flask", "django", "fastapi", "pydantic", "requests",
  "openai", "anthropic", "langchain",
];

export class DependencyAnalyzer {
  analyze(context: AnalysisContext): DependencyFinding[] {
    const findings: DependencyFinding[] = [];
    if (!context.dependencies || context.dependencies.length === 0) return findings;

    for (const dep of context.dependencies) {
      // D1: Known CVEs
      if (dep.has_known_cve && dep.cve_ids && dep.cve_ids.length > 0) {
        findings.push({
          rule_id: "D1", severity: "high",
          evidence: `[Dependency] "${dep.name}@${dep.version}" has ${dep.cve_ids.length} known CVE(s): ${dep.cve_ids.join(", ")}.`,
          remediation: `Update "${dep.name}" to the latest patched version or replace with an alternative.`,
          owasp_category: "MCP08-dependency-vuln", mitre_technique: null,
          confidence: 0.95,
        });
      }

      // D2: Abandoned (>12 months since last update)
      if (dep.last_updated) {
        const lastUpdate = new Date(dep.last_updated);
        const monthsAgo = (Date.now() - lastUpdate.getTime()) / (1000 * 60 * 60 * 24 * 30);
        if (monthsAgo > 12) {
          findings.push({
            rule_id: "D2", severity: "medium",
            evidence: `[Dependency] "${dep.name}@${dep.version}" last updated ${Math.floor(monthsAgo)} months ago. Likely abandoned.`,
            remediation: `Evaluate if "${dep.name}" is still maintained. Consider alternatives.`,
            owasp_category: "MCP08-dependency-vuln", mitre_technique: null,
            confidence: 0.7,
          });
        }
      }

      // D3: Typosquatting via multi-algorithm similarity
      findings.push(...this.checkTyposquatting({ name: dep.name, version: dep.version || "" }));

      // D5: Known malicious packages
      if (MALICIOUS_PACKAGES.has(dep.name)) {
        findings.push({
          rule_id: "D5", severity: "critical",
          evidence: `[Dependency] "${dep.name}" is a KNOWN MALICIOUS package (confirmed supply chain attack).`,
          remediation: `Remove "${dep.name}" immediately. This package has been used in documented supply chain attacks.`,
          owasp_category: "MCP10-supply-chain", mitre_technique: "AML.T0054",
          confidence: 0.99,
        });
      }

      // D5 addendum: homoglyph check against malicious packages
      const normalizedDep = normalizeConfusables(dep.name);
      if (normalizedDep !== dep.name && MALICIOUS_PACKAGES.has(normalizedDep)) {
        findings.push({
          rule_id: "D5", severity: "critical",
          evidence: `[Dependency] "${dep.name}" uses Unicode confusables to impersonate malicious package "${normalizedDep}".`,
          remediation: `Remove "${dep.name}" immediately.`,
          owasp_category: "MCP10-supply-chain", mitre_technique: "AML.T0054",
          confidence: 0.99,
        });
      }

      // D6: Weak cryptography
      for (const weak of WEAK_CRYPTO) {
        if (dep.name === weak.name) {
          if (!weak.maxSafeVersion || this.versionLessThan(dep.version || "0.0.0", weak.maxSafeVersion)) {
            findings.push({
              rule_id: "D6", severity: "high",
              evidence: `[Dependency] "${dep.name}@${dep.version}" — ${weak.reason}.`,
              remediation: weak.maxSafeVersion
                ? `Update "${dep.name}" to ≥${weak.maxSafeVersion} or replace.`
                : `Replace "${dep.name}" with a modern alternative.`,
              owasp_category: "MCP07-insecure-config", mitre_technique: null,
              confidence: 0.9,
            });
          }
        }
      }

      // D7: Dependency confusion — suspiciously high version numbers
      const depVersion = dep.version || "";
      const major = parseInt(depVersion.split(".")[0], 10);
      if (major >= 99 && dep.name.includes("/")) {
        findings.push({
          rule_id: "D7", severity: "high",
          evidence: `[Dependency] "${dep.name}@${dep.version}" — scoped package with suspiciously high major version (${major}). ` +
            `This is a known dependency confusion attack pattern (Alex Birsan, 2021).`,
          remediation: "Verify this is the intended package. Check npm/PyPI for the author and publish date.",
          owasp_category: "MCP10-supply-chain", mitre_technique: null,
          confidence: 0.8,
        });
      }
    }

    // D4: Excessive dependency count
    if (context.dependencies.length > 50) {
      findings.push({
        rule_id: "D4", severity: "low",
        evidence: `[Dependency] ${context.dependencies.length} direct dependencies (threshold: 50). Large dependency trees increase supply chain risk.`,
        remediation: "Audit dependencies. Remove unused packages. Prefer standard library functions.",
        owasp_category: "MCP08-dependency-vuln", mitre_technique: null,
        confidence: 0.9,
      });
    }

    return findings;
  }

  private checkTyposquatting(dep: { name: string; version: string }): DependencyFinding[] {
    const findings: DependencyFinding[] = [];
    if (KNOWN_PACKAGES.includes(dep.name)) return findings;

    let bestMatch: { known: string; score: number; attackClass: string } | null = null;

    for (const known of KNOWN_PACKAGES) {
      if (dep.name === known) continue;
      const normDep = normalizeName(dep.name);
      const normKnown = normalizeName(known);
      if (Math.abs(normDep.length - normKnown.length) > 3) continue;

      const result = computeSimilarity(dep.name, known);
      if (result.score >= 0.75 && (!bestMatch || result.score > bestMatch.score)) {
        bestMatch = { known, score: result.score, attackClass: result.attack_class };
      }
    }

    // Also check homoglyph impersonation
    const normalized = normalizeConfusables(dep.name);
    if (normalized !== dep.name) {
      for (const known of KNOWN_PACKAGES) {
        if (normalized === known || normalizeName(normalized) === normalizeName(known)) {
          findings.push({
            rule_id: "D3", severity: "critical",
            evidence: `[Dependency] "${dep.name}" uses Unicode confusables to impersonate "${known}". Normalized: "${normalized}".`,
            remediation: `Replace with the legitimate package "${known}".`,
            owasp_category: "MCP10-supply-chain", mitre_technique: "AML.T0054",
            confidence: 0.99,
          });
          return findings;
        }
      }
    }

    if (bestMatch) {
      findings.push({
        rule_id: "D3",
        severity: bestMatch.score >= 0.85 ? "critical" : "high",
        evidence:
          `[Dependency] "${dep.name}" is ${(bestMatch.score * 100).toFixed(1)}% similar to "${bestMatch.known}" — ` +
          `possible typosquat (attack class: ${bestMatch.attackClass}).`,
        remediation: `Verify "${dep.name}" is the intended package, not a typosquat of "${bestMatch.known}".`,
        owasp_category: "MCP10-supply-chain", mitre_technique: "AML.T0054",
        confidence: bestMatch.score * 0.9,
        metadata: { engine: "dependency_analyzer", target: bestMatch.known, score: bestMatch.score },
      });
    }

    return findings;
  }

  private versionLessThan(version: string, threshold: string): boolean {
    const v = version.split(".").map(Number);
    const t = threshold.split(".").map(Number);
    for (let i = 0; i < Math.max(v.length, t.length); i++) {
      const a = v[i] || 0;
      const b = t[i] || 0;
      if (a < b) return true;
      if (a > b) return false;
    }
    return false;
  }
}
