/**
 * Dependency & Behavioral Detector — D1, D2, D4, D5, D6, D7, E1-E4
 *
 * D1: Known CVEs in dependencies (OSV lookup via dependency list)
 * D2: Abandoned dependencies (>12 months since update)
 * D4: Excessive dependency count
 * D5: Known malicious packages
 * D6: Weak cryptography dependencies
 * D7: Dependency confusion attack risk
 * E1: No authentication required
 * E2: Insecure transport (HTTP/WS)
 * E3: Response time anomaly
 * E4: Excessive tool count
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { damerauLevenshtein } from "../analyzers/similarity.js";

// ─── D1: Known CVEs ───────────────────────────────────────────────────────

registerTypedRule({
  id: "D1", name: "Known CVEs in Dependencies",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    for (const dep of ctx.dependencies) {
      if (dep.has_known_cve && dep.cve_ids && dep.cve_ids.length > 0) {
        findings.push({
          rule_id: "D1", severity: "high",
          evidence: `Dependency "${dep.name}@${dep.version}" has known CVE(s): [${dep.cve_ids.join(", ")}].`,
          remediation: `Update "${dep.name}" to a patched version. Check ${dep.cve_ids[0]} for details.`,
          owasp_category: "MCP08-dependency-vuln", mitre_technique: null,
          confidence: 0.95, metadata: { dep_name: dep.name, version: dep.version, cves: dep.cve_ids },
        });
      }
    }
    return findings;
  },
});

// ─── D2: Abandoned Dependencies ───────────────────────────────────────────

registerTypedRule({
  id: "D2", name: "Abandoned Dependencies",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    const now = Date.now();
    const TWELVE_MONTHS = 365 * 24 * 60 * 60 * 1000;

    for (const dep of ctx.dependencies) {
      if (dep.last_updated) {
        const lastUpdate = new Date(dep.last_updated).getTime();
        const age = now - lastUpdate;
        if (age > TWELVE_MONTHS) {
          const months = Math.floor(age / (30 * 24 * 60 * 60 * 1000));
          findings.push({
            rule_id: "D2", severity: "medium",
            evidence: `Dependency "${dep.name}@${dep.version}" last updated ${months} months ago.`,
            remediation: "Replace abandoned dependencies with actively maintained alternatives.",
            owasp_category: "MCP08-dependency-vuln", mitre_technique: null,
            confidence: Math.min(0.85, 0.50 + months / 60),
            metadata: { dep_name: dep.name, months_since_update: months },
          });
        }
      }
    }
    return findings;
  },
});

// ─── D4: Excessive Dependency Count ───────────────────────────────────────

registerTypedRule({
  id: "D4", name: "Excessive Dependency Count",
  analyze(ctx) {
    if (ctx.dependencies.length > 50) {
      return [{
        rule_id: "D4", severity: "low",
        evidence: `${ctx.dependencies.length} direct dependencies (threshold: 50). Large dependency trees increase attack surface.`,
        remediation: "Audit dependencies. Remove unused ones. Consider lighter alternatives.",
        owasp_category: "MCP08-dependency-vuln", mitre_technique: null,
        confidence: 0.70, metadata: { count: ctx.dependencies.length },
      }];
    }
    return [];
  },
});

// ─── D5: Known Malicious Packages ─────────────────────────────────────────

const MALICIOUS_PACKAGES = new Set([
  // npm confirmed malicious
  "event-stream", "flatmap-stream", "ua-parser-js-malicious",
  "colors-malicious", "faker-malicious",
  // MCP-ecosystem typosquats
  "@mcp/sdk", "mcp-sdk", "fastmcp-sdk", "mcp-server-sdk",
  "modelcontextprotocol", "model-context-protocol",
  // Common typosquats
  "crossenv", "cross-env.js", "d3.js", "gruntcli", "http-proxy.js",
  "jquery.js", "mariadb", "mongose", "mssql.js", "mssql-node",
  "node-hierarchypdf", "node-openssl", "nodecaffe", "nodefabric",
  "nodemailer-js", "noderequest", "nodesass", "nodesqlite",
  "node-tkinter", "opencv.js", "openssl.js", "proxy.js",
  "shadowsock", "smb", "sqlite.js", "sqliter", "sqlserver",
  "tkinter", "gruntcli", "cofeescript", "coffescript",
  "babelcli", "jquey", "discordi.js", "discord.jss",
]);

registerTypedRule({
  id: "D5", name: "Known Malicious Packages",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    for (const dep of ctx.dependencies) {
      if (MALICIOUS_PACKAGES.has(dep.name)) {
        findings.push({
          rule_id: "D5", severity: "critical",
          evidence: `Dependency "${dep.name}" is a known malicious package.`,
          remediation: `Remove "${dep.name}" immediately. This package is confirmed malicious or a known typosquat.`,
          owasp_category: "MCP08-dependency-vuln", mitre_technique: "AML.T0054",
          confidence: 0.99, metadata: { dep_name: dep.name },
        });
      }
    }
    return findings;
  },
});

// ─── D6: Weak Cryptography Dependencies ───────────────────────────────────

const WEAK_CRYPTO: Array<{ name: string; maxSafe?: string; desc: string }> = [
  { name: "md5", desc: "MD5 is broken — use SHA-256+" },
  { name: "sha1", desc: "SHA-1 is deprecated — use SHA-256+" },
  { name: "crypto-js", maxSafe: "4.2.0", desc: "crypto-js <4.2.0 has known vulnerabilities" },
  { name: "node-forge", maxSafe: "1.3.0", desc: "node-forge <1.3.0 has known vulnerabilities" },
  { name: "bcrypt-nodejs", desc: "bcrypt-nodejs is abandoned — use bcrypt or bcryptjs" },
  { name: "pycrypto", desc: "pycrypto is abandoned — use pycryptodome" },
];

registerTypedRule({
  id: "D6", name: "Weak Cryptography Dependencies",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    for (const dep of ctx.dependencies) {
      for (const weak of WEAK_CRYPTO) {
        if (dep.name === weak.name) {
          findings.push({
            rule_id: "D6", severity: "high",
            evidence: `Dependency "${dep.name}@${dep.version}": ${weak.desc}.`,
            remediation: weak.maxSafe
              ? `Update "${dep.name}" to >=${weak.maxSafe} or replace with a modern alternative.`
              : `Replace "${dep.name}" with a modern, maintained cryptography library.`,
            owasp_category: "MCP07-insecure-config", mitre_technique: null,
            confidence: 0.88, metadata: { dep_name: dep.name },
          });
        }
      }
    }
    return findings;
  },
});

// ─── D7: Dependency Confusion Attack Risk ─────────────────────────────────

registerTypedRule({
  id: "D7", name: "Dependency Confusion Attack Risk",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    for (const dep of ctx.dependencies) {
      // Scoped packages with suspiciously high versions (attacker trick)
      if (dep.name.startsWith("@") && dep.version) {
        const major = parseInt(dep.version.split(".")[0], 10);
        if (major >= 99) {
          findings.push({
            rule_id: "D7", severity: "high",
            evidence: `Scoped package "${dep.name}@${dep.version}" has suspiciously high version (${major}.x). Dependency confusion indicator.`,
            remediation: "Verify the package is from the expected scope. High version numbers are used in dependency confusion attacks.",
            owasp_category: "MCP08-dependency-vuln", mitre_technique: "AML.T0054",
            confidence: 0.85, metadata: { dep_name: dep.name, major_version: major },
          });
        }
      }
    }
    return findings;
  },
});

// ─── E1: No Authentication Required ──────────────────────────────────────

registerTypedRule({
  id: "E1", name: "No Authentication Required",
  analyze(ctx) {
    if (ctx.connection_metadata && !ctx.connection_metadata.auth_required) {
      return [{
        rule_id: "E1", severity: "medium",
        evidence: "Server does not require authentication. Any client can connect and use tools.",
        remediation: "Add authentication (API key, OAuth, mTLS). Even localhost servers should require auth (DNS rebinding).",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.90, metadata: { analysis_type: "behavioral" },
      }];
    }
    return [];
  },
});

// ─── E2: Insecure Transport ──────────────────────────────────────────────

registerTypedRule({
  id: "E2", name: "Insecure Transport",
  analyze(ctx) {
    if (ctx.connection_metadata) {
      const transport = ctx.connection_metadata.transport.toLowerCase();
      if (transport === "http" || transport === "ws") {
        return [{
          rule_id: "E2", severity: "high",
          evidence: `Server uses insecure transport: ${transport}. Data transmitted in plaintext.`,
          remediation: "Use HTTPS or WSS. All MCP connections should be encrypted in transit.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.95, metadata: { transport },
        }];
      }
    }
    return [];
  },
});

// ─── E3: Response Time Anomaly ───────────────────────────────────────────

registerTypedRule({
  id: "E3", name: "Response Time Anomaly",
  analyze(ctx) {
    if (ctx.connection_metadata && ctx.connection_metadata.response_time_ms > 10000) {
      return [{
        rule_id: "E3", severity: "low",
        evidence: `Server response time: ${ctx.connection_metadata.response_time_ms}ms (threshold: 10s). May indicate crypto-mining or processing abuse.`,
        remediation: "Investigate slow response. May indicate resource abuse, infinite loops, or network issues.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.60, metadata: { response_time_ms: ctx.connection_metadata.response_time_ms },
      }];
    }
    return [];
  },
});

// ─── E4: Excessive Tool Count ────────────────────────────────────────────

registerTypedRule({
  id: "E4", name: "Excessive Tool Count",
  analyze(ctx) {
    if (ctx.tools.length > 50) {
      return [{
        rule_id: "E4", severity: "medium",
        evidence: `Server exposes ${ctx.tools.length} tools (threshold: 50). Large tool sets increase attack surface and enable consent fatigue.`,
        remediation: "Reduce tool count. Split into focused servers. Each server should do one thing well.",
        owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
        confidence: 0.75, metadata: { tool_count: ctx.tools.length },
      }];
    }
    return [];
  },
});
