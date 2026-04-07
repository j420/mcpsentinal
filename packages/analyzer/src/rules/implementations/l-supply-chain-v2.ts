/**
 * L8, L10, L15 — Supply Chain rules migrated to TypedRuleV2
 *
 * L8:  Version Rollback Attack (structural config parsing)
 * L10: Registry Metadata Spoofing (structural JSON parsing)
 * L15: Update Notification Spoofing (AST structural)
 */

import ts from "typescript";
import type { AnalysisContext } from "../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../base.js";
import { EvidenceChainBuilder } from "../../evidence.js";

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }

// ═══════════════════════════════════════════════════════════════════════════════
// L8 — Version Rollback Attack
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Detects dependency version overrides/pins to known-vulnerable old versions.
 *
 * Phase 1: Structural JSON parsing — detect overrides/resolutions in package.json
 * Phase 2: AST analysis — detect install commands pinning old versions
 * Phase 3: Cross-check — is the overridden package MCP/security-critical?
 */

/** Old/vulnerable version patterns */
const OLD_VERSION_PATTERNS = [
  /["'](?:0\.\d+\.\d+|1\.0\.\d+)["']/,  // 0.x.x or 1.0.x
  /["'](?:<=?\s*\d|<\d)/,                  // <= or < constraints
];

/** MCP-critical package names */
const MCP_CRITICAL_PACKAGES = /(?:mcp|modelcontextprotocol|fastmcp|server-sdk|client-sdk|anthropic|openai)/i;

/** Override/resolution property names */
const OVERRIDE_PROPS = /^(?:overrides|resolutions|pnpm\.overrides)$/;

class L8Rule implements TypedRuleV2 {
  readonly id = "L8";
  readonly name = "Version Rollback Attack";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    // Phase 1: Try to parse as JSON (package.json)
    try {
      const parsed = JSON.parse(source);
      for (const key of ["overrides", "resolutions", "pnpm"]) {
        const section = key === "pnpm" ? parsed.pnpm?.overrides : parsed[key];
        if (!section || typeof section !== "object") continue;

        for (const [pkg, version] of Object.entries(section)) {
          const ver = String(version);
          if (OLD_VERSION_PATTERNS.some(p => p.test(`"${ver}"`))) {
            const isCritical = MCP_CRITICAL_PACKAGES.test(pkg);
            findings.push(this.buildFinding(
              pkg, ver, key, isCritical, "json-override",
            ));
          }
        }
      }
    } catch {
      // Not JSON — continue to AST analysis
    }

    // Phase 2: AST — detect install commands with old version pins
    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
          const text = node.text;
          // npm install pkg@0.x or pip install pkg==0.x
          const installMatch = text.match(/(?:npm\s+install|pip\s+install|pnpm\s+add|yarn\s+add)\s+([\w@/-]+)(?:@|==)(0\.\d+|1\.0\.\d+)/i);
          if (installMatch) {
            const pkg = installMatch[1];
            const ver = installMatch[2];
            const isCritical = MCP_CRITICAL_PACKAGES.test(pkg);
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;

            findings.push(this.buildFindingFromCode(pkg, ver, line, isCritical));
          }
        }
        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }

    return findings;
  }

  private buildFinding(
    pkg: string, version: string, sectionName: string,
    isCritical: boolean, method: string,
  ): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `${sectionName}.${pkg}`,
        observed: `${pkg}: "${version}" in ${sectionName}`,
        rationale:
          `Package "${pkg}" is overridden to version "${version}" in ${sectionName} section. ` +
          `Old versions may contain known vulnerabilities that have been patched in newer releases. ` +
          (isCritical ? `This is an MCP-critical package — rollback is especially dangerous.` :
            `Verify this version is intentional and doesn't introduce known CVEs.`),
      })
      .sink({
        sink_type: "code-evaluation",
        location: `${sectionName} section`,
        observed: `Version rollback to ${version} — may restore known vulnerabilities`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: isCritical ? "moderate" : "complex",
        scenario:
          `Version rollback forces installation of an older dependency version. ` +
          `If the old version has known CVEs, this restores exploitable vulnerabilities. ` +
          `Supply chain attackers use overrides to force vulnerable versions that enable RCE or data theft.`,
      })
      .factor("version_rollback", 0.10, `Override to version "${version}" detected via ${method}`)
      .factor(isCritical ? "mcp_critical_package" : "general_package",
        isCritical ? 0.08 : 0.03,
        isCritical ? `MCP-critical package "${pkg}" — high-impact rollback` : `General package "${pkg}"`)
      .reference({
        id: "CoSAI-MCP-T6",
        title: "CoSAI MCP Security — T6: Supply Chain Integrity",
        relevance: "Dependency overrides to old versions bypass supply chain integrity.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Check ${sectionName} section for "${pkg}". Verify version "${version}" is intentional and CVE-free.`,
        target: `source_code:${sectionName}`,
        expected_observation: `Version rollback: ${pkg}@${version}`,
      });

    return {
      rule_id: "L8",
      severity: isCritical ? "critical" : "high",
      owasp_category: "MCP10-supply-chain",
      mitre_technique: "AML.T0017",
      remediation: "Don't override dependencies to old versions. Use automated updates (Dependabot, Renovate). Pin to latest secure version.",
      chain: builder.build(),
    };
  }

  private buildFindingFromCode(
    pkg: string, version: string, line: number, isCritical: boolean,
  ): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: `Install command pins "${pkg}" to old version "${version}"`,
        rationale: `Install command at line ${line} pins package "${pkg}" to version "${version}".`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: `line ${line}`,
        observed: `Version pin to ${version} in install command`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: isCritical ? "moderate" : "complex",
        scenario: `Old version pin in install command may restore known vulnerabilities.`,
      })
      .factor("version_pin_in_code", 0.10, `Old version pin at line ${line}`)
      .reference({
        id: "OWASP-ASI04",
        title: "OWASP Agentic Top 10 — ASI04: Agentic Supply Chain",
        relevance: "Old version pins weaken supply chain integrity.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Check line ${line} for install command. Verify version pin is intentional.`,
        target: `source_code:${line}`,
        expected_observation: `Old version pin: ${pkg}@${version}`,
      });

    return {
      rule_id: "L8",
      severity: isCritical ? "critical" : "high",
      owasp_category: "MCP10-supply-chain",
      mitre_technique: "AML.T0017",
      remediation: "Don't pin to old versions. Use latest secure version.",
      chain: builder.build(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// L10 — Registry Metadata Spoofing
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Detects false vendor attribution in package metadata.
 *
 * Phase 1: JSON structural — check author/publisher/organization fields
 * Phase 2: AST — check string literals claiming vendor affiliation
 */

const PROTECTED_VENDORS = [
  "anthropic", "openai", "google", "microsoft", "aws", "amazon",
  "github", "stripe", "cloudflare", "meta", "facebook", "apple",
];

const VENDOR_REGEX = new RegExp(`\\b(?:${PROTECTED_VENDORS.join("|")})\\b`, "i");

/** Metadata fields that indicate authorship */
const AUTHOR_FIELDS = /^(?:author|publisher|organization|maintainer|vendor|company)$/i;

class L10Rule implements TypedRuleV2 {
  readonly id = "L10";
  readonly name = "Registry Metadata Spoofing";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    // Phase 1: JSON structural parsing
    try {
      const parsed = JSON.parse(source);
      this.checkJsonMetadata(parsed, findings);
    } catch {
      // Not JSON — continue to AST
    }

    // Phase 2: AST — property assignments with vendor names
    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        if (ts.isPropertyAssignment(node)) {
          const propName = node.name.getText(sf);
          if (AUTHOR_FIELDS.test(propName)) {
            if (ts.isStringLiteral(node.initializer)) {
              const value = node.initializer.text;
              if (VENDOR_REGEX.test(value)) {
                const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                findings.push(this.buildFinding(propName, value, line));
              }
            }
          }
        }
        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }

    return findings;
  }

  private checkJsonMetadata(obj: Record<string, unknown>, findings: RuleResult[]): void {
    for (const [key, value] of Object.entries(obj)) {
      if (AUTHOR_FIELDS.test(key)) {
        const valStr = typeof value === "string" ? value
          : (typeof value === "object" && value !== null && "name" in value)
            ? String((value as Record<string, unknown>).name) : null;

        if (valStr && VENDOR_REGEX.test(valStr)) {
          findings.push(this.buildFinding(key, valStr, 0));
        }
      }
    }
  }

  private buildFinding(field: string, value: string, line: number): RuleResult {
    const matchedVendor = PROTECTED_VENDORS.find(v =>
      new RegExp(`\\b${v}\\b`, "i").test(value),
    ) || "unknown";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: line > 0 ? `line ${line}` : `"${field}" field`,
        observed: `${field}: "${value}"`,
        rationale:
          `Package metadata field "${field}" claims affiliation with "${matchedVendor}". ` +
          `If this package is not actually published by ${matchedVendor}, this is metadata spoofing ` +
          `designed to gain trust from developers and AI clients.`,
      })
      .sink({
        sink_type: "config-modification",
        location: line > 0 ? `line ${line}` : "package metadata",
        observed: `False vendor attribution: "${field}" = "${value}"`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "connected-services",
        exploitability: "moderate",
        scenario:
          `False vendor attribution causes developers and AI clients to trust this package. ` +
          `Registry UI displays the spoofed vendor name, increasing installation probability. ` +
          `Combined with typosquatting (D3), this enables supply chain attacks.`,
      })
      .factor("vendor_impersonation", 0.12,
        `Protected vendor "${matchedVendor}" claimed in "${field}" field`)
      .reference({
        id: "CoSAI-MCP-T6",
        title: "CoSAI MCP Security — T6: Supply Chain Integrity",
        relevance: "Package metadata must accurately reflect authorship.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Verify "${field}" field. Is this package actually from ${matchedVendor}?`,
        target: line > 0 ? `source_code:${line}` : `source_code:metadata`,
        expected_observation: `Vendor impersonation: ${field}="${value}"`,
      });

    return {
      rule_id: "L10",
      severity: "high",
      owasp_category: "MCP10-supply-chain",
      mitre_technique: "AML.T0017",
      remediation: "Don't impersonate official vendors in package metadata. Use accurate author/publisher fields.",
      chain: builder.build(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// L15 — Update Notification Spoofing
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Detects fake update notifications with install commands in source code.
 *
 * Uses AST to find string literals containing update notification patterns
 * paired with install commands, distinguishing from legitimate update checks.
 */

/** Update notification language patterns */
const UPDATE_NOTIFICATION_PATTERNS = [
  { regex: /(?:update|upgrade)\s+(?:available|required|needed|recommended)/i, desc: "update notification", weight: 0.60 },
  { regex: /(?:new\s+version|newer\s+version|latest\s+version)\s+(?:available|released)/i, desc: "version announcement", weight: 0.55 },
  { regex: /(?:please|must|should)\s+(?:update|upgrade|install)/i, desc: "update imperative", weight: 0.50 },
];

/** Install command patterns — amplify threat when combined with notification */
const INSTALL_COMMAND_PATTERNS = [
  { regex: /(?:npm\s+install|npx|pip\s+install|pnpm\s+add|yarn\s+add|brew\s+install)\s+\S+/i, desc: "install command" },
  { regex: /(?:curl|wget)\s+\S+.*\|\s*(?:bash|sh)/i, desc: "pipe-to-shell install" },
];

/** Legitimate update check patterns (mitigations) */
const LEGITIMATE_UPDATE_PATTERNS = [
  /\b(?:npm\s+outdated|npm\s+update|dependabot|renovate|greenkeeper)\b/i,
  /\b(?:semver|compareVersions|versionCheck)\b/i,
  /\b(?:checkForUpdates|updateNotifier|update-notifier)\b/i,
];

class L15Rule implements TypedRuleV2 {
  readonly id = "L15";
  readonly name = "Update Notification Spoofing";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ||
            ts.isTemplateExpression(node)) {
          const text = ts.isTemplateExpression(node) ? node.getText(sf) : (node as ts.StringLiteral).text;

          // Check for update notification + install command in same string
          const notifMatch = UPDATE_NOTIFICATION_PATTERNS.find(p => p.regex.test(text));
          const installMatch = INSTALL_COMMAND_PATTERNS.find(p => p.regex.test(text));

          if (notifMatch && installMatch) {
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            const lineText = source.split("\n")[line - 1]?.trim() || "";

            if (!lineText.startsWith("//") && !lineText.startsWith("*")) {
              // Check for legitimate update checking in enclosing scope
              const funcText = this.getEnclosingFunctionText(node, sf);
              const isLegitimate = LEGITIMATE_UPDATE_PATTERNS.some(p => p.test(funcText));

              if (!isLegitimate) {
                findings.push(this.buildFinding(
                  text, notifMatch.desc, installMatch.desc, line, lineText,
                ));
              }
            }
          }
        }
        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }

    return findings;
  }

  private getEnclosingFunctionText(node: ts.Node, sf: ts.SourceFile): string {
    let current: ts.Node | undefined = node.parent;
    while (current) {
      if (ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current) ||
          ts.isArrowFunction(current) || ts.isMethodDeclaration(current)) {
        return current.getText(sf);
      }
      current = current.parent;
    }
    return "";
  }

  private buildFinding(
    text: string, notifDesc: string, installDesc: string,
    line: number, lineText: string,
  ): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: lineText.slice(0, 150),
        rationale:
          `String at line ${line} combines ${notifDesc} language with an ${installDesc}. ` +
          `This pattern is characteristic of fake update notifications that trick users into ` +
          `installing malicious packages.`,
      })
      .sink({
        sink_type: "command-execution",
        location: `line ${line}`,
        observed: `${installDesc} embedded in ${notifDesc}`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `Fake update notification displays an install command for a malicious package. ` +
          `Users or automated systems may execute the command, installing attacker-controlled code. ` +
          `This is a social engineering supply chain attack.`,
      })
      .factor("update_notification", 0.10, `${notifDesc} language detected`)
      .factor("install_command", 0.10, `${installDesc} embedded in notification`)
      .reference({
        id: "OWASP-ASI04",
        title: "OWASP Agentic Top 10 — ASI04: Agentic Supply Chain",
        relevance: "Fake update notifications are a supply chain social engineering vector.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Check line ${line} for fake update notification. Verify the install command points to a legitimate package.`,
        target: `source_code:${line}`,
        expected_observation: `Fake update with install command`,
      });

    return {
      rule_id: "L15",
      severity: "high",
      owasp_category: "MCP10-supply-chain",
      mitre_technique: "AML.T0017",
      remediation: "Don't display fake update notifications. Updates should come from official package managers (npm, pip, etc.).",
      chain: builder.build(),
    };
  }
}

// Register all rules
registerTypedRuleV2(new L8Rule());
registerTypedRuleV2(new L10Rule());
registerTypedRuleV2(new L15Rule());
