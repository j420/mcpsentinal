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
import { EvidenceChainBuilder } from "../../evidence.js";

// ─── D1: Known CVEs ───────────────────────────────────────────────────────

registerTypedRule({
  id: "D1", name: "Known CVEs in Dependencies",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    for (const dep of ctx.dependencies) {
      if (dep.has_known_cve && dep.cve_ids && dep.cve_ids.length > 0) {
        const cveList = dep.cve_ids.join(", ");
        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `package dependency: ${dep.name}@${dep.version}`,
            observed: `Dependency "${dep.name}@${dep.version}" included in project`,
            rationale: "Third-party package dependency with known vulnerabilities introduces untrusted code paths",
          })
          .sink({
            sink_type: "code-evaluation",
            location: `${dep.name}@${dep.version}`,
            observed: `Vulnerable code paths in ${dep.name}: ${cveList}`,
            cve_precedent: dep.cve_ids[0],
          })
          .mitigation({
            mitigation_type: "input-validation",
            present: false,
            location: `${dep.name}@${dep.version}`,
            detail: "No patched version in use — vulnerable version still installed",
          })
          .impact({
            impact_type: "remote-code-execution",
            scope: "server-host",
            exploitability: "moderate",
            scenario: `Attacker exploits known vulnerability ${dep.cve_ids[0]} in ${dep.name}@${dep.version} to compromise the MCP server host`,
          })
          .factor("cve_confirmed", 0.20, `CVE(s) confirmed in vulnerability databases: ${cveList}`)
          .reference({
            id: dep.cve_ids[0],
            title: `Known vulnerability in ${dep.name}`,
            url: `https://nvd.nist.gov/vuln/detail/${dep.cve_ids[0]}`,
            relevance: `${dep.name}@${dep.version} is affected by this CVE — update to patched version`,
          })
          .verification({
            step_type: "check-dependency",
            instruction: `Verify that ${dep.name}@${dep.version} is affected by ${cveList}. Cross-reference the installed version against the affected version ranges listed in the NVD or OSV advisory.`,
            target: `${dep.name}@${dep.version}`,
            expected_observation: `CVE entries exist in OSV/NVD databases for this package version`,
          })
          .verification({
            step_type: "check-dependency",
            instruction: `Check whether a patched version of "${dep.name}" exists that resolves ${cveList}. Review the advisory for the recommended minimum safe version.`,
            target: `${dep.name} release history`,
            expected_observation: `A newer version of ${dep.name} is available that is not affected by the listed CVEs`,
          })
          .build();

        findings.push({
          rule_id: "D1", severity: "high",
          evidence: `Dependency "${dep.name}@${dep.version}" has known CVE(s): [${cveList}].`,
          remediation: `Update "${dep.name}" to a patched version. Check ${dep.cve_ids[0]} for details.`,
          owasp_category: "MCP08-dependency-vuln", mitre_technique: null,
          confidence: 0.95, metadata: { dep_name: dep.name, version: dep.version, cves: dep.cve_ids, evidence_chain: chain },
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
          const chain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `package dependency: ${dep.name}@${dep.version}`,
              observed: `Last updated ${months} months ago (${dep.last_updated})`,
              rationale: "Unmaintained dependency receives no security patches — known and future vulnerabilities go unaddressed",
            })
            .sink({
              sink_type: "config-modification",
              location: `${dep.name}@${dep.version}`,
              observed: `Dependency "${dep.name}" has not received updates for ${months} months — potential unpatched vulnerabilities in code paths`,
            })
            .mitigation({
              mitigation_type: "input-validation",
              present: false,
              location: `${dep.name}@${dep.version}`,
              detail: "No active maintainer to patch security issues — dependency is effectively abandoned",
            })
            .impact({
              impact_type: "privilege-escalation",
              scope: "server-host",
              exploitability: "complex",
              scenario: `Unpatched vulnerability in abandoned dependency "${dep.name}" allows attacker to escalate privileges. No maintainer exists to release a security fix, leaving the server permanently exposed to any future CVE discovered in this package.`,
            })
            .factor("age_severity", months > 36 ? 0.15 : 0.05, `Package abandoned for ${months} months — ${months > 36 ? "high" : "moderate"} risk of unpatched vulnerabilities`)
            .verification({
              step_type: "check-dependency",
              instruction: `Check the last publish date of "${dep.name}" on its package registry (npm, PyPI, etc.). Verify the date against the 12-month abandonment threshold.`,
              target: `${dep.name}@${dep.version}`,
              expected_observation: `Last publish date is more than 12 months ago (${months} months)`,
            })
            .verification({
              step_type: "check-dependency",
              instruction: `Search for actively maintained alternatives to "${dep.name}" that provide equivalent functionality. Check the package's GitHub repository for open security issues or CVEs filed since the last release.`,
              target: `${dep.name} GitHub repository / alternatives`,
              expected_observation: `Repository shows no recent commits, open security issues without patches, or has been archived by the maintainer`,
            })
            .build();

          findings.push({
            rule_id: "D2", severity: "medium",
            evidence: `Dependency "${dep.name}@${dep.version}" last updated ${months} months ago.`,
            remediation: "Replace abandoned dependencies with actively maintained alternatives.",
            owasp_category: "MCP08-dependency-vuln", mitre_technique: null,
            confidence: Math.min(0.85, 0.50 + months / 60),
            metadata: { dep_name: dep.name, months_since_update: months, evidence_chain: chain },
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
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "external-content",
          location: "package manifest (package.json / requirements.txt)",
          observed: `${ctx.dependencies.length} direct dependencies declared`,
          rationale: "Each dependency is an external content source that expands the attack surface",
        })
        .sink({
          sink_type: "config-modification",
          location: "package manifest",
          observed: `${ctx.dependencies.length} direct dependencies — each one is a potential entry point for supply chain compromise`,
        })
        .mitigation({
          mitigation_type: "input-validation",
          present: false,
          location: "package manifest",
          detail: "No dependency minimization strategy — all dependencies included without auditing necessity",
        })
        .impact({
          impact_type: "privilege-escalation",
          scope: "server-host",
          exploitability: "complex",
          scenario: `With ${ctx.dependencies.length} dependencies, the probability of at least one containing a vulnerability or being compromised increases significantly. Each transitive dependency tree compounds the risk, creating dozens of potential entry points for privilege escalation via supply chain attacks.`,
        })
        .factor("count_severity", ctx.dependencies.length > 100 ? 0.10 : 0.05, `${ctx.dependencies.length} dependencies — ${ctx.dependencies.length > 100 ? "very large" : "large"} attack surface`)
        .verification({
          step_type: "check-dependency",
          instruction: `Count the direct dependencies in the package manifest (package.json or requirements.txt). Verify that the count exceeds the 50-dependency threshold.`,
          target: "package.json / requirements.txt",
          expected_observation: `${ctx.dependencies.length} direct dependencies listed (threshold: 50)`,
        })
        .verification({
          step_type: "check-dependency",
          instruction: `Audit the dependency list for unused or redundant packages that could be removed. Run a dependency analysis tool (e.g., depcheck for npm, pip-extra-reqs for Python) to identify unnecessary dependencies.`,
          target: "project dependency tree",
          expected_observation: `Multiple dependencies are unused or have overlapping functionality that could be consolidated`,
        })
        .build();

      return [{
        rule_id: "D4", severity: "low",
        evidence: `${ctx.dependencies.length} direct dependencies (threshold: 50). Large dependency trees increase attack surface.`,
        remediation: "Audit dependencies. Remove unused ones. Consider lighter alternatives.",
        owasp_category: "MCP08-dependency-vuln", mitre_technique: null,
        confidence: 0.70, metadata: { count: ctx.dependencies.length, evidence_chain: chain },
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
        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `package dependency: ${dep.name}`,
            observed: `Known malicious package "${dep.name}" found in dependency list`,
            rationale: "This package is confirmed malicious or a known typosquat targeting legitimate packages",
          })
          .sink({
            sink_type: "command-execution",
            location: `${dep.name} install/postinstall hooks`,
            observed: `Malicious package "${dep.name}" executes arbitrary code during installation or at runtime`,
          })
          .mitigation({
            mitigation_type: "input-validation",
            present: false,
            location: "package manifest",
            detail: "No protection against malicious package — it is directly listed as a dependency",
          })
          .impact({
            impact_type: "remote-code-execution",
            scope: "server-host",
            exploitability: "trivial",
            scenario: `Malicious package "${dep.name}" executes attacker-controlled code in the build environment during npm install / pip install, potentially exfiltrating credentials or installing backdoors`,
          })
          .factor("confirmed_malicious", 0.25, `"${dep.name}" is listed in known malicious package databases`)
          .reference({
            id: "MALICIOUS-PKG-DB",
            title: `Known malicious package: ${dep.name}`,
            url: "https://github.com/nickvdyck/malicious-packages",
            relevance: `"${dep.name}" is a confirmed malicious package or typosquat — must be removed immediately`,
          })
          .verification({
            step_type: "check-dependency",
            instruction: `Cross-reference "${dep.name}" against malicious package databases (npm advisories, Snyk, Socket.dev)`,
            target: dep.name,
            expected_observation: `"${dep.name}" appears in malicious package lists or is a known typosquat`,
          })
          .build();

        findings.push({
          rule_id: "D5", severity: "critical",
          evidence: `Dependency "${dep.name}" is a known malicious package.`,
          remediation: `Remove "${dep.name}" immediately. This package is confirmed malicious or a known typosquat.`,
          owasp_category: "MCP08-dependency-vuln", mitre_technique: "AML.T0054",
          confidence: 0.99, metadata: { dep_name: dep.name, evidence_chain: chain },
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
          const chain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `package dependency: ${dep.name}@${dep.version}`,
              observed: `Weak cryptography library "${dep.name}@${dep.version}" in dependency list`,
              rationale: "This cryptographic library uses broken or deprecated algorithms that can be exploited to recover protected data",
            })
            .sink({
              sink_type: "credential-exposure",
              location: `${dep.name} cryptographic operations`,
              observed: `${weak.desc} — cryptographic operations using this library do not provide adequate protection`,
            })
            .mitigation({
              mitigation_type: "input-validation",
              present: false,
              location: `${dep.name}@${dep.version}`,
              detail: weak.maxSafe
                ? `Version ${dep.version} is below safe version ${weak.maxSafe}`
                : "No safe version exists — library must be replaced entirely",
            })
            .impact({
              impact_type: "credential-theft",
              scope: "user-data",
              exploitability: "moderate",
              scenario: `Data protected by ${dep.name} can be recovered by attackers using known cryptographic attacks — hashed passwords cracked, encrypted data decrypted, signatures forged`,
            })
            .factor("weak_crypto_confirmed", 0.10, `${dep.name} uses cryptographic primitives known to be broken or deprecated`)
            .reference({
              id: "CWE-327",
              title: "Use of a Broken or Risky Cryptographic Algorithm",
              url: "https://cwe.mitre.org/data/definitions/327.html",
              relevance: `${dep.name} relies on cryptographic algorithms that are known to be weak (CWE-327)`,
            })
            .verification({
              step_type: "check-dependency",
              instruction: `Verify the installed version of "${dep.name}" and check if a safe alternative exists`,
              target: `${dep.name}@${dep.version}`,
              expected_observation: weak.maxSafe
                ? `Version is below ${weak.maxSafe} — update required`
                : `Library is fundamentally broken/abandoned — replacement required`,
            })
            .build();

          findings.push({
            rule_id: "D6", severity: "high",
            evidence: `Dependency "${dep.name}@${dep.version}": ${weak.desc}.`,
            remediation: weak.maxSafe
              ? `Update "${dep.name}" to >=${weak.maxSafe} or replace with a modern alternative.`
              : `Replace "${dep.name}" with a modern, maintained cryptography library.`,
            owasp_category: "MCP07-insecure-config", mitre_technique: null,
            confidence: 0.88, metadata: { dep_name: dep.name, evidence_chain: chain },
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
          const chain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `package dependency: ${dep.name}@${dep.version}`,
              observed: `Scoped package "${dep.name}" with major version ${major} (suspiciously high)`,
              rationale: "Dependency confusion attacks use artificially high version numbers to trick package managers into installing attacker-controlled packages from public registries instead of private ones",
            })
            .sink({
              sink_type: "command-execution",
              location: `${dep.name}@${dep.version} install hooks`,
              observed: `If this is a confusion attack, the package executes attacker code during installation`,
            })
            .mitigation({
              mitigation_type: "input-validation",
              present: false,
              location: "package manager configuration",
              detail: "No registry pinning or scope restriction detected to prevent public registry substitution",
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "server-host",
              exploitability: "moderate",
              scenario: `Attacker publishes "${dep.name}@${dep.version}" on the public registry with a higher version than the legitimate private package — package manager installs the attacker's version, executing malicious install hooks in the build environment`,
            })
            .factor("high_version_indicator", 0.10, `Major version ${major} is a strong indicator of dependency confusion attack technique`)
            .reference({
              id: "BIRSAN-2021",
              title: "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies",
              url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
              year: 2021,
              relevance: `Same attack technique: high version number on scoped package "${dep.name}" to win version resolution against private registries`,
            })
            .verification({
              step_type: "check-dependency",
              instruction: `Verify that "${dep.name}@${dep.version}" is the legitimate package from the expected private registry, not a public registry substitution`,
              target: `${dep.name}@${dep.version}`,
              expected_observation: `Package has an unusually high major version (${major}) — check if this is the intended private package or a public registry impostor`,
            })
            .build();

          findings.push({
            rule_id: "D7", severity: "high",
            evidence: `Scoped package "${dep.name}@${dep.version}" has suspiciously high version (${major}.x). Dependency confusion indicator.`,
            remediation: "Verify the package is from the expected scope. High version numbers are used in dependency confusion attacks.",
            owasp_category: "MCP08-dependency-vuln", mitre_technique: "AML.T0054",
            confidence: 0.85, metadata: { dep_name: dep.name, major_version: major, evidence_chain: chain },
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
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "environment",
          location: "server network configuration",
          observed: "Server accepts connections without authentication",
          rationale: "Unauthenticated MCP server allows any client to connect and invoke tools — no identity verification",
        })
        .sink({
          sink_type: "privilege-grant",
          location: "MCP server endpoint",
          observed: "Full tool access granted to any connecting client without credentials",
        })
        .mitigation({
          mitigation_type: "auth-check",
          present: false,
          location: "server connection handler",
          detail: "No authentication mechanism detected — API key, OAuth, or mTLS required",
        })
        .impact({
          impact_type: "privilege-escalation",
          scope: "server-host",
          exploitability: "trivial",
          scenario: "Any network-reachable client can connect to the MCP server and invoke all exposed tools without authentication — DNS rebinding attacks can reach even localhost servers",
        })
        .factor("no_auth_confirmed", 0.15, "Connection metadata confirms no authentication is required")
        .verification({
          step_type: "check-config",
          instruction: "Attempt to connect to the MCP server without providing any credentials",
          target: "MCP server endpoint",
          expected_observation: "Server accepts the connection and responds to initialize + tools/list without authentication",
        })
        .build();

      return [{
        rule_id: "E1", severity: "medium",
        evidence: "Server does not require authentication. Any client can connect and use tools.",
        remediation: "Add authentication (API key, OAuth, mTLS). Even localhost servers should require auth (DNS rebinding).",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.90, metadata: { analysis_type: "behavioral", evidence_chain: chain },
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
        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "environment",
            location: "server transport configuration",
            observed: `Transport protocol: ${transport} (unencrypted)`,
            rationale: "Unencrypted transport exposes all data in transit — tool invocations, parameters, responses, and any credentials are visible to network observers",
          })
          .sink({
            sink_type: "credential-exposure",
            location: `${transport}:// transport layer`,
            observed: `All MCP protocol messages transmitted in plaintext over ${transport}`,
          })
          .mitigation({
            mitigation_type: "auth-check",
            present: false,
            location: "transport configuration",
            detail: `No TLS encryption — using ${transport} instead of ${transport === "http" ? "https" : "wss"}`,
          })
          .impact({
            impact_type: "credential-theft",
            scope: "user-data",
            exploitability: "moderate",
            scenario: `Network attacker (MITM, rogue WiFi, compromised router) intercepts ${transport} traffic to steal credentials, API keys, and sensitive data passed through MCP tool invocations`,
          })
          .factor("plaintext_transport", 0.15, `${transport} transport confirmed — no encryption in transit`)
          .reference({
            id: "CWE-319",
            title: "Cleartext Transmission of Sensitive Information",
            url: "https://cwe.mitre.org/data/definitions/319.html",
            relevance: `MCP server uses ${transport} transport, transmitting all protocol messages including potential credentials in cleartext (CWE-319)`,
          })
          .verification({
            step_type: "check-config",
            instruction: `Verify the server transport protocol and confirm TLS is not configured`,
            target: "MCP server connection endpoint",
            expected_observation: `Server listens on ${transport}:// (not ${transport === "http" ? "https" : "wss"}://) — data transmitted in plaintext`,
          })
          .build();

        return [{
          rule_id: "E2", severity: "high",
          evidence: `Server uses insecure transport: ${transport}. Data transmitted in plaintext.`,
          remediation: "Use HTTPS or WSS. All MCP connections should be encrypted in transit.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.95, metadata: { transport, evidence_chain: chain },
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
      const responseTime = ctx.connection_metadata.response_time_ms;
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "environment",
          location: "server response timing",
          observed: `Response time: ${responseTime}ms (threshold: 10,000ms)`,
          rationale: "Abnormally slow response times may indicate resource abuse (crypto-mining), infinite loops, or intentional delay attacks",
        })
        .impact({
          impact_type: "denial-of-service",
          scope: "server-host",
          exploitability: "complex",
          scenario: `Server takes ${responseTime}ms to respond — may indicate crypto-mining siphoning CPU, infinite loop consuming resources, or intentional slowdown to degrade client performance`,
        })
        .factor("response_time_anomaly", 0.05, `Response time ${responseTime}ms exceeds 10s threshold — anomalous but not conclusive`)
        .verification({
          step_type: "test-input",
          instruction: `Measure the server response time for initialize + tools/list across multiple attempts`,
          target: "MCP server endpoint",
          expected_observation: `Response time consistently exceeds 10 seconds (observed: ${responseTime}ms)`,
        })
        .build();

      return [{
        rule_id: "E3", severity: "low",
        evidence: `Server response time: ${responseTime}ms (threshold: 10s). May indicate crypto-mining or processing abuse.`,
        remediation: "Investigate slow response. May indicate resource abuse, infinite loops, or network issues.",
        owasp_category: "MCP07-insecure-config", mitre_technique: null,
        confidence: 0.60, metadata: { response_time_ms: responseTime, evidence_chain: chain },
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
      const toolCount = ctx.tools.length;
      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "environment",
          location: "MCP server tools/list response",
          observed: `Server exposes ${toolCount} tools (threshold: 50)`,
          rationale: "Excessive tool count creates consent fatigue — users stop carefully reviewing tool approvals after the first dozen, allowing dangerous tools to slip through",
        })
        .impact({
          impact_type: "privilege-escalation",
          scope: "ai-client",
          exploitability: "moderate",
          scenario: `With ${toolCount} tools, users experience consent fatigue and auto-approve tool invocations. An attacker hides 1-2 dangerous tools among ${toolCount - 2} benign ones — 84.2% success rate for tool poisoning with auto-approve (Invariant Labs)`,
        })
        .factor("tool_count_severity", toolCount > 100 ? 0.10 : 0.05, `${toolCount} tools — ${toolCount > 100 ? "extreme" : "excessive"} consent fatigue risk`)
        .reference({
          id: "INVARIANT-LABS-2025",
          title: "Consent Fatigue in MCP Tool Approval",
          relevance: `84.2% tool poisoning success rate with auto-approve enabled — ${toolCount} tools greatly increases the risk of users enabling auto-approve`,
        })
        .verification({
          step_type: "inspect-schema",
          instruction: `Count the tools returned by the server's tools/list endpoint`,
          target: "MCP server tools/list response",
          expected_observation: `${toolCount} tools returned (threshold: 50)`,
        })
        .build();

      return [{
        rule_id: "E4", severity: "medium",
        evidence: `Server exposes ${toolCount} tools (threshold: 50). Large tool sets increase attack surface and enable consent fatigue.`,
        remediation: "Reduce tool count. Split into focused servers. Each server should do one thing well.",
        owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
        confidence: 0.75, metadata: { tool_count: toolCount, evidence_chain: chain },
      }];
    }
    return [];
  },
});
