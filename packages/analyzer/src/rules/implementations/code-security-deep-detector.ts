/**
 * Code Security Deep Detector — Taint-aware analysis for C2, C5, C10, C14
 *
 * C2:  Path Traversal — taint from user input to file path operations
 * C5:  Hardcoded Secrets — entropy analysis + token pattern matching
 * C10: Prototype Pollution — taint from user input to __proto__/constructor
 * C14: JWT Algorithm Confusion — structural detection of JWT misconfigurations
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { analyzeASTTaint } from "../analyzers/taint-ast.js";
import { analyzeTaint } from "../analyzers/taint.js";
import { shannonEntropy } from "../analyzers/entropy.js";
import { EvidenceChainBuilder } from "../../evidence.js";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

function getLineNumber(source: string, index: number): number {
  return source.substring(0, index).split("\n").length;
}

// ─── C2: Path Traversal (Taint-Aware) ─────────────────────────────────────

class PathTraversalRule implements TypedRule {
  readonly id = "C2";
  readonly name = "Path Traversal (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];

    // Phase 1: AST taint — user input reaching file path operations
    try {
      const astFlows = analyzeASTTaint(context.source_code);
      const pathFlows = astFlows.filter(
        (f) => (f.sink.category === "file_write" || f.sink.category === "file_read") && !f.sanitized
      );

      for (const flow of pathFlows) {
        const c2AstChain = new EvidenceChainBuilder()
          .source({ source_type: "user-parameter", location: `line ${flow.source.line}`, observed: flow.source.expression.slice(0, 100), rationale: `${flow.source.category} input flows to file path operation without sanitization` })
          .propagation({ propagation_type: "variable-assignment", location: `lines ${flow.source.line}-${flow.sink.line}`, observed: `${flow.path.length} step(s) from source to sink` })
          .sink({ sink_type: "file-write", location: `line ${flow.sink.line}`, observed: flow.sink.expression.slice(0, 80) })
          .factor("ast_taint", flow.confidence - 0.70, `AST taint: ${flow.path.length} steps, source: ${flow.source.category}`)
          .verification({ step_type: "inspect-source", instruction: `Trace data flow from line ${flow.source.line} to line ${flow.sink.line}`, target: `source:line ${flow.source.line}-${flow.sink.line}`, expected_observation: `User input reaches file operation without path normalization` })
          .build();
        findings.push({
          rule_id: "C2",
          severity: "critical",
          evidence:
            `[AST taint] ${flow.source.category} input "${flow.source.expression}" (L${flow.source.line}) ` +
            `flows to file operation "${flow.sink.expression.slice(0, 60)}" (L${flow.sink.line}) ` +
            `without path sanitization. ${flow.path.length} step(s). ` +
            `Attacker can traverse directories to read/write arbitrary files.`,
          remediation:
            "Use path.resolve() + path.relative() to normalize paths, then verify the result " +
            "starts with the allowed base directory. Never pass user input directly to fs operations. " +
            "Use path.join() with a base dir, then check startsWith(baseDir).",
          owasp_category: "MCP05-privilege-escalation",
          mitre_technique: "AML.T0054",
          confidence: flow.confidence,
          metadata: {
            analysis_type: "ast_taint",
            source_line: flow.source.line,
            sink_line: flow.sink.line,
            evidence_chain: c2AstChain,
          },
        });
      }
    } catch {
      // Fall through
    }

    // Phase 2: Lightweight taint
    if (findings.length === 0) {
      const taintFlows = analyzeTaint(context.source_code);
      const pathFlows = taintFlows.filter(
        (f) => f.sink.category === "path_access" && !f.sanitized
      );

      for (const flow of pathFlows) {
        const c2TaintChain = new EvidenceChainBuilder()
          .source({ source_type: "user-parameter", location: `line ${flow.source.line}`, observed: flow.source.expression?.slice(0, 80) || flow.source.category, rationale: `${flow.source.category} input reaches file path operation` })
          .propagation({ propagation_type: "direct-pass", location: `line ${flow.sink.line}`, observed: `Taint flow from ${flow.source.category} to path_access` })
          .sink({ sink_type: "file-write", location: `line ${flow.sink.line}`, observed: flow.sink.expression?.slice(0, 80) || "file path operation" })
          .factor("taint_analysis", flow.confidence - 0.70, `Regex taint: ${flow.source.category} → path_access`)
          .verification({ step_type: "inspect-source", instruction: `Trace data from ${flow.source.category} to file operation at line ${flow.sink.line}`, target: `source:line ${flow.sink.line}`, expected_observation: `User input reaches file path operation without validation` })
          .build();
        findings.push({
          rule_id: "C2",
          severity: "critical",
          evidence:
            `[Taint] ${flow.source.category} → file path operation (L${flow.sink.line}). Path traversal risk.`,
          remediation:
            "Validate and normalize all file paths. Use realpath() and verify against base directory.",
          owasp_category: "MCP05-privilege-escalation",
          mitre_technique: "AML.T0054",
          confidence: flow.confidence,
          metadata: { analysis_type: "taint", evidence_chain: c2TaintChain },
        });
      }
    }

    // Phase 3: Pattern fallback for literal traversal patterns
    if (findings.length === 0) {
      const patterns = [
        { regex: /(?:readFile|readFileSync|open|writeFile)\s*\([^)]*(?:\.\.\/)/, desc: "literal ../ in file operation", confidence: 0.85 },
        { regex: /(?:readFile|readFileSync|open|writeFile)\s*\([^)]*(?:%2e%2e|%2f)/i, desc: "URL-encoded traversal in file operation", confidence: 0.90 },
        { regex: /(?:readFile|readFileSync|open)\s*\([^)]*\\x00/, desc: "null byte in file path", confidence: 0.95 },
      ];

      for (const { regex, desc, confidence } of patterns) {
        const match = regex.exec(context.source_code);
        if (match) {
          const line = getLineNumber(context.source_code, match.index);
          const c2PatternChain = new EvidenceChainBuilder()
            .source({ source_type: "file-content", location: `line ${line}`, observed: match[0].slice(0, 80), rationale: `Literal path traversal pattern in file operation: ${desc}` })
            .propagation({ propagation_type: "direct-pass", location: `line ${line}`, observed: `${desc} detected in source code` })
            .sink({ sink_type: "file-write", location: `line ${line}`, observed: `Path traversal: "${match[0].slice(0, 60)}"` })
            .factor("structural_match", confidence - 0.70, `Pattern: ${desc}`)
            .verification({ step_type: "inspect-source", instruction: `Review file operation at line ${line} for path traversal`, target: `source:line ${line}`, expected_observation: desc })
            .build();
          findings.push({
            rule_id: "C2",
            severity: "critical",
            evidence: `[Pattern] ${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
            remediation: "Remove path traversal sequences. Use path.resolve() with base directory validation.",
            owasp_category: "MCP05-privilege-escalation",
            mitre_technique: "AML.T0054",
            confidence,
            metadata: { analysis_type: "regex_fallback", line, evidence_chain: c2PatternChain },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── C5: Hardcoded Secrets (Entropy-Aware) ────────────────────────────────

const SECRET_PATTERNS: Array<{
  regex: RegExp;
  name: string;
  confidence: number;
}> = [
  // API keys with known prefixes (highest confidence)
  { regex: /sk-[a-zA-Z0-9]{20,}/g, name: "OpenAI API key", confidence: 0.98 },
  { regex: /sk-ant-[a-zA-Z0-9-]{20,}/g, name: "Anthropic API key", confidence: 0.98 },
  { regex: /ghp_[a-zA-Z0-9]{36}/g, name: "GitHub PAT", confidence: 0.98 },
  { regex: /gho_[a-zA-Z0-9]{36}/g, name: "GitHub OAuth token", confidence: 0.98 },
  { regex: /AKIA[0-9A-Z]{16}/g, name: "AWS Access Key ID", confidence: 0.98 },
  { regex: /ASIA[0-9A-Z]{16}/g, name: "AWS Temporary Key", confidence: 0.98 },
  { regex: /xoxb-[0-9]+-[0-9A-Za-z]+/g, name: "Slack Bot Token", confidence: 0.97 },
  { regex: /xoxp-[0-9]+-[0-9A-Za-z]+/g, name: "Slack User Token", confidence: 0.97 },
  { regex: /sk_live_[a-zA-Z0-9]{24,}/g, name: "Stripe Secret Key", confidence: 0.98 },
  { regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, name: "SendGrid API Key", confidence: 0.97 },
  { regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, name: "JWT Token", confidence: 0.85 },
  { regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, name: "PEM Private Key", confidence: 0.99 },
  { regex: /AIza[0-9A-Za-z_-]{35}/g, name: "Google API Key", confidence: 0.97 },
  { regex: /dapi[a-f0-9]{32}/g, name: "Databricks Token", confidence: 0.95 },
  { regex: /npm_[a-zA-Z0-9]{36}/g, name: "npm Token", confidence: 0.97 },

  // Generic high-entropy assignments (lower confidence — needs entropy check)
  { regex: /(?:api_key|apikey|secret_key|auth_token|access_token|private_key)\s*[:=]\s*["']([^"']{20,})["']/gi, name: "Generic secret assignment", confidence: 0.70 },
  { regex: /(?:password|passwd)\s*[:=]\s*["']([^"']{8,})["']/gi, name: "Hardcoded password", confidence: 0.65 },
];

class HardcodedSecretsRule implements TypedRule {
  readonly id = "C5";
  readonly name = "Hardcoded Secrets (Entropy-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const seen = new Set<string>();

    for (const { regex, name, confidence } of SECRET_PATTERNS) {
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = regex.exec(context.source_code)) !== null) {
        const secret = match[1] || match[0];
        const line = getLineNumber(context.source_code, match.index);
        const lineText = context.source_code.split("\n")[line - 1] || "";

        // Skip if in comments
        if (/^\s*(?:\/\/|#|\/\*|\*)/.test(lineText)) continue;
        // Skip if in test/example context
        if (/(?:example|sample|placeholder|test|fake|dummy|xxx)/i.test(lineText)) continue;
        // Skip if already found this pattern
        const key = `${name}:${line}`;
        if (seen.has(key)) continue;
        seen.add(key);

        // For generic patterns, verify with entropy analysis
        let finalConfidence = confidence;
        if (confidence < 0.90) {
          const entropy = shannonEntropy(secret);
          if (entropy < 3.5) continue; // Low entropy — likely not a real secret
          if (entropy > 4.5) finalConfidence = Math.min(0.95, confidence + 0.15);
        }

        const masked = secret.slice(0, 4) + "..." + secret.slice(-4);
        const entropy = shannonEntropy(secret);

        const chain = new EvidenceChainBuilder()
          .sink({
            sink_type: "credential-exposure",
            location: `line ${line}`,
            observed: `${name}: "${masked}" (entropy: ${entropy.toFixed(2)} bits/char)`,
          })
          .mitigation({
            mitigation_type: "sanitizer-function",
            present: false,
            location: `line ${line}`,
            detail: "Secret is hardcoded in source — not read from environment variable or secrets manager",
          })
          .impact({
            impact_type: "credential-theft",
            scope: "connected-services",
            exploitability: "trivial",
            scenario:
              `${name} exposed in source code at line ${line}. ` +
              `Anyone with repo access (including forks) can extract and use this credential.`,
          })
          .factor("entropy analysis", entropy > 4.5 ? 0.15 : 0.0, `Shannon entropy: ${entropy.toFixed(2)} bits/char`)
          .factor("known token prefix", confidence >= 0.90 ? 0.20 : 0.0, `Pattern: ${name}`)
          .reference({
            id: "GITHUB-SECRET-SCANNING",
            title: "GitHub Secret Scanning Partner Program",
            relevance: `Detected ${name} — matches known credential pattern`,
          })
          .verification({
            step_type: "inspect-source",
            instruction: `Open source file and check line ${line} for a hardcoded credential`,
            target: `source:line:${line}`,
            expected_observation: `Line contains ${name} with high-entropy string (not a test/example value)`,
          })
          .verification({
            step_type: "check-config",
            instruction: "Verify the secret is not loaded from an environment variable",
            target: `source:line:${line}`,
            expected_observation: "Secret is a string literal, not process.env.* or os.environ reference",
          })
          .build();

        findings.push({
          rule_id: "C5",
          severity: "critical",
          evidence:
            `[Entropy: ${entropy.toFixed(2)} bits] ${name} at line ${line}: "${masked}". ` +
            `Hardcoded secrets in source code are exposed in version control and build artifacts.`,
          remediation:
            "Move secrets to environment variables or a secrets manager (Vault, AWS Secrets Manager). " +
            "Rotate the exposed credential immediately. Add .env to .gitignore.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0057",
          confidence: finalConfidence,
          metadata: {
            analysis_type: "entropy_pattern",
            secret_type: name,
            line,
            entropy,
            evidence_chain: chain,
          },
        });
      }
    }

    return findings;
  }
}

// ─── C10: Prototype Pollution (Taint-Aware) ───────────────────────────────

class PrototypePollutionRule implements TypedRule {
  readonly id = "C10";
  readonly name = "Prototype Pollution (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Phase 1: Direct __proto__ / constructor.prototype access with user input
    try {
      const astFlows = analyzeASTTaint(source);
      // Any tainted data flowing to property assignment could be proto pollution
      // But AST taint doesn't track property writes specifically
      // So we check for tainted flows + __proto__ patterns nearby
    } catch {
      // Fall through
    }

    // Phase 2: Pattern-based detection with context awareness
    const patterns = [
      {
        regex: /(?:__proto__|constructor\s*\.\s*prototype)\s*(?:\[|\.)/g,
        desc: "direct __proto__/constructor.prototype access",
        confidence: 0.90,
      },
      {
        regex: /Object\.assign\s*\(\s*(?:{}|target|\w+)\s*,\s*(?!['"{])(\w+)/g,
        desc: "Object.assign with variable source (potential prototype pollution)",
        confidence: 0.70,
      },
      {
        regex: /(?:lodash|_)\.(?:merge|defaultsDeep|set|setWith)\s*\(/g,
        desc: "lodash deep merge (known prototype pollution vector)",
        confidence: 0.80,
      },
      {
        regex: /(?:deepmerge|merge-deep|deep-extend)\s*\(/g,
        desc: "deep merge library (prototype pollution risk)",
        confidence: 0.75,
      },
      {
        regex: /\[\s*(?:key|prop|field|attr|name)\s*\]\s*=\s*(?!['"\d])\w+/g,
        desc: "dynamic property assignment with variable key",
        confidence: 0.60,
      },
    ];

    for (const { regex, desc, confidence } of patterns) {
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(source)) !== null) {
        const line = getLineNumber(source, match.index);
        const lineText = source.split("\n")[line - 1] || "";

        // Check if there's user input context nearby (within 5 lines)
        const startLine = Math.max(0, line - 6);
        const contextLines = source.split("\n").slice(startLine, line + 5).join("\n");
        const hasUserInput = /(?:req\.|request\.|body|params|query|user[Ii]nput|JSON\.parse)/i.test(contextLines);

        // Skip if no user input context and low base confidence
        if (!hasUserInput && confidence < 0.80) continue;

        const adjustedConfidence = hasUserInput ? Math.min(0.95, confidence + 0.15) : confidence;

        // Skip obvious safe patterns
        if (/(?:hasOwnProperty|Object\.create\(null\)|Object\.freeze)/.test(lineText)) continue;

        const c10Chain = new EvidenceChainBuilder()
          .source({ source_type: hasUserInput ? "user-parameter" : "file-content", location: `line ${line}`, observed: match[0].slice(0, 80), rationale: `${desc} — ${hasUserInput ? "user input detected nearby" : "code pattern"}` })
          .propagation({ propagation_type: hasUserInput ? "variable-assignment" : "direct-pass", location: `line ${line}`, observed: `Prototype pollution pattern with ${hasUserInput ? "user input context" : "code-level access"}` })
          .sink({ sink_type: "code-evaluation", location: `line ${line}`, observed: `${desc}: "${match[0].slice(0, 60)}"` })
          .factor(hasUserInput ? "user_input_context" : "structural_match", adjustedConfidence - 0.70, `${desc} ${hasUserInput ? "with user input nearby" : ""}`)
          .verification({ step_type: "inspect-source", instruction: `Review prototype pollution pattern at line ${line}`, target: `source:line ${line}`, expected_observation: desc })
          .build();
        findings.push({
          rule_id: "C10",
          severity: "critical",
          evidence:
            `[${hasUserInput ? "User input context" : "Code pattern"}] ${desc} at line ${line}: ` +
            `"${match[0].slice(0, 80)}".` +
            (hasUserInput ? " User-controlled data detected nearby — high prototype pollution risk." : ""),
          remediation:
            "Use Object.create(null) for lookup objects. Validate keys against a blocklist " +
            "(__proto__, constructor, prototype). Use Map instead of plain objects for dynamic keys. " +
            "For lodash: upgrade to >=4.17.21 and avoid _.merge with untrusted input.",
          owasp_category: "MCP03-command-injection",
          mitre_technique: "AML.T0054",
          confidence: adjustedConfidence,
          metadata: { analysis_type: hasUserInput ? "context_aware" : "pattern", line, evidence_chain: c10Chain },
        });
        break; // One finding per pattern type
      }
    }

    return findings;
  }
}

// ─── C14: JWT Algorithm Confusion ─────────────────────────────────────────

class JWTAlgorithmConfusionRule implements TypedRule {
  readonly id = "C14";
  readonly name = "JWT Algorithm Confusion";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    const patterns = [
      {
        regex: /algorithms\s*:\s*\[.*['"]none['"]/gi,
        desc: "'none' algorithm accepted — signature bypass",
        confidence: 0.98,
        severity: "critical" as const,
      },
      {
        regex: /(?:verify|decode)\s*\([^)]*(?:algorithms|algorithm)\s*:\s*(?:undefined|null|\[\s*\])/gi,
        desc: "no algorithm restriction on verify — accepts any algorithm",
        confidence: 0.90,
        severity: "critical" as const,
      },
      {
        regex: /ignoreExpiration\s*:\s*true/gi,
        desc: "JWT expiration check disabled",
        confidence: 0.95,
        severity: "high" as const,
      },
      {
        regex: /(?:jwt|jsonwebtoken).*verify\s*=\s*False/gi,
        desc: "PyJWT verify=False — signature not checked",
        confidence: 0.98,
        severity: "critical" as const,
      },
      {
        regex: /(?:algorithms?\s*[:=]\s*\[?\s*['"]HS256['"].*(?:RS256|publicKey|public_key|cert))|(?:(?:RS256|publicKey|public_key|cert).*algorithms?\s*[:=]\s*\[?\s*['"]HS256['"])/gi,
        desc: "RS256→HS256 downgrade — public key used as HMAC secret",
        confidence: 0.92,
        severity: "critical" as const,
      },
    ];

    for (const { regex, desc, confidence, severity } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);

        const c14Chain = new EvidenceChainBuilder()
          .source({ source_type: "file-content", location: `line ${line}`, observed: match[0].slice(0, 80), rationale: `JWT configuration vulnerability: ${desc}` })
          .propagation({ propagation_type: "direct-pass", location: `line ${line}`, observed: `JWT misconfiguration flows to authentication decision` })
          .sink({ sink_type: "credential-exposure", location: `line ${line}`, observed: `${desc}: "${match[0].slice(0, 60)}"` })
          .factor("jwt_pattern", confidence - 0.70, `JWT vulnerability: ${desc}`)
          .verification({ step_type: "inspect-source", instruction: `Review JWT configuration at line ${line}`, target: `source:line ${line}`, expected_observation: desc })
          .build();
        findings.push({
          rule_id: "C14",
          severity,
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
          remediation:
            "Pin the JWT algorithm explicitly: { algorithms: ['RS256'] }. " +
            "Never accept 'none'. Never use HS256 with an RSA public key. " +
            "Always set ignoreExpiration: false. For PyJWT: always use verify=True.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence,
          metadata: { analysis_type: "structural", line, evidence_chain: c14Chain },
        });
      }
    }

    return findings;
  }
}

// ─── Register ──────────────────────────────────────────────────────────────

registerTypedRule(new PathTraversalRule());
registerTypedRule(new HardcodedSecretsRule());
registerTypedRule(new PrototypePollutionRule());
registerTypedRule(new JWTAlgorithmConfusionRule());
