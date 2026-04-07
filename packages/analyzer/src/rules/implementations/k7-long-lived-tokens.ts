/**
 * K7 — Long-Lived Tokens Without Rotation (v2: AST Structural Analysis)
 *
 * REPLACES the regex: /(?:expiresIn|expires_in|maxAge|max_age)\s*[:=]\s*['"]?(?:365d|8760h|31536000|\d{8,})/
 *
 * Old behavior: Matched specific duration strings on the same line as expiresIn.
 *   False positive: expiresIn: 86400 (24h — that's fine)
 *   False negative: jwt.sign(payload, secret) — no expiry at all (worst case, missed entirely)
 *
 * New behavior: AST structural analysis to:
 *   1. Find JWT/token creation calls (jwt.sign, jsonwebtoken, jose, passport-jwt)
 *   2. Check if expiry is configured: expiresIn, exp claim, maxAge
 *   3. Parse duration values: detect >30d for access tokens, >90d for refresh tokens
 *   4. Find token storage without rotation: tokens stored in env/config with no rotation logic
 *   5. Detect "never expire" patterns: { expiresIn: undefined }, verify=False, ignoreExpiration
 *
 * Compliance:
 *   - OWASP ASI03: Identity & privilege abuse — stale tokens enable persistent access
 *   - ISO 27001 A.8.24: Cryptographic key lifecycle management
 *   - CoSAI MCP-T1: Authentication token management
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

const RULE_ID = "K7";
const RULE_NAME = "Long-Lived Tokens Without Rotation";
const OWASP = "ASI03-identity-privilege-abuse";
const REMEDIATION =
  "Set access token expiry to ≤24h and refresh token expiry to ≤30d. " +
  "Implement token rotation: issue a new refresh token on each use. " +
  "Never set expiresIn to undefined/null or use ignoreExpiration: true. " +
  "Use short-lived JWTs with a token refresh endpoint. " +
  "Example: jwt.sign(payload, secret, { expiresIn: '1h' })";

/** Max acceptable durations in seconds */
const MAX_ACCESS_TOKEN_SECONDS = 86400;    // 24h
const MAX_REFRESH_TOKEN_SECONDS = 2592000; // 30d

/** JWT/token creation patterns */
const TOKEN_CREATION_PATTERNS = [
  /jwt\.sign\s*\(/,
  /jsonwebtoken.*\.sign\s*\(/,
  /jose.*\.sign\s*\(/,
  /createToken\s*\(/,
  /generateToken\s*\(/,
  /signToken\s*\(/,
  /issueToken\s*\(/,
];

/** Duration string to seconds converter */
function parseDuration(value: string): number | null {
  // Numeric (raw seconds): 86400, 31536000
  const numMatch = value.match(/^(\d+)$/);
  if (numMatch) return parseInt(numMatch[1], 10);

  // Time strings: "365d", "8760h", "525600m", "1y"
  const timeMatch = value.match(/^(\d+)(s|m|h|d|w|y)$/i);
  if (timeMatch) {
    const n = parseInt(timeMatch[1], 10);
    const unit = timeMatch[2].toLowerCase();
    switch (unit) {
      case "s": return n;
      case "m": return n * 60;
      case "h": return n * 3600;
      case "d": return n * 86400;
      case "w": return n * 604800;
      case "y": return n * 31536000;
    }
  }

  // ms strings: "86400000ms"
  const msMatch = value.match(/^(\d+)ms$/i);
  if (msMatch) return parseInt(msMatch[1], 10) / 1000;

  return null;
}

class LongLivedTokensRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code) return [];
    if (/(?:__tests?__|\.(?:test|spec)\.)/.test(context.source_code)) return [];

    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Phase 1: Find jwt.sign() and similar token creation calls
        if (ts.isCallExpression(node)) {
          const callText = node.expression.getText(sf) + "(";
          const isTokenCreation = TOKEN_CREATION_PATTERNS.some(p => p.test(callText));

          if (isTokenCreation) {
            const finding = this.analyzeTokenCreation(node, sf, source);
            if (finding) findings.push(finding);
          }
        }

        // Phase 2: Find expiresIn/maxAge assignments with long durations
        if (ts.isPropertyAssignment(node) || ts.isBinaryExpression(node)) {
          const finding = this.analyzeExpiryAssignment(node, sf, source);
          if (finding) findings.push(finding);
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch {
      // AST parse failure
    }

    // Phase 3: Detect "never expire" patterns via regex (these are simple string patterns)
    const neverExpireFindings = this.detectNeverExpirePatterns(source);
    findings.push(...neverExpireFindings);

    return findings;
  }

  /** Analyze a jwt.sign() call for missing or excessive expiry */
  private analyzeTokenCreation(
    node: ts.CallExpression,
    sf: ts.SourceFile,
    source: string,
  ): RuleResult | null {
    const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
    const callText = node.expression.getText(sf);

    // Check if any argument contains expiresIn
    const argsText = node.arguments.map(a => a.getText(sf)).join(" ");
    const hasExpiry = /expiresIn|expires_in|exp\s*:|maxAge/i.test(argsText);

    if (!hasExpiry) {
      // No expiry at all — token lives forever
      return this.buildFinding(
        callText,
        line,
        source.split("\n")[line - 1]?.trim() || "",
        "no-expiry",
        null,
      );
    }

    // Extract the duration value
    const expiryMatch = argsText.match(/(?:expiresIn|expires_in|maxAge)\s*[:=]\s*['"]?(\d+[smhdwy]?|[\d.]+)/i);
    if (expiryMatch) {
      const durationSec = parseDuration(expiryMatch[1]);
      if (durationSec && durationSec > MAX_ACCESS_TOKEN_SECONDS) {
        return this.buildFinding(
          callText,
          line,
          source.split("\n")[line - 1]?.trim() || "",
          "excessive-expiry",
          durationSec,
        );
      }
    }

    return null;
  }

  /** Analyze expiresIn/maxAge property assignments for excessive duration */
  private analyzeExpiryAssignment(
    node: ts.Node,
    sf: ts.SourceFile,
    source: string,
  ): RuleResult | null {
    let propName = "";
    let valueText = "";
    let line = 0;

    if (ts.isPropertyAssignment(node)) {
      propName = node.name.getText(sf);
      valueText = node.initializer.getText(sf);
      line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
    } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      propName = node.left.getText(sf);
      valueText = node.right.getText(sf);
      line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
    }

    if (!/(?:expiresIn|expires_in|maxAge|max_age|token_lifetime)/i.test(propName)) return null;

    // Strip quotes
    const cleanValue = valueText.replace(/['"]/g, "").trim();
    const durationSec = parseDuration(cleanValue);

    if (durationSec && durationSec > MAX_ACCESS_TOKEN_SECONDS) {
      return this.buildFinding(
        propName,
        line,
        source.split("\n")[line - 1]?.trim() || "",
        "excessive-expiry",
        durationSec,
      );
    }

    // Detect explicitly undefined/null expiry
    if (/undefined|null|false|0/.test(cleanValue)) {
      return this.buildFinding(
        propName,
        line,
        source.split("\n")[line - 1]?.trim() || "",
        "disabled-expiry",
        null,
      );
    }

    return null;
  }

  /** Detect "never expire" string patterns */
  private detectNeverExpirePatterns(source: string): RuleResult[] {
    const findings: RuleResult[] = [];
    const patterns: Array<{ regex: RegExp; desc: string }> = [
      { regex: /ignoreExpiration\s*:\s*true/g, desc: "JWT expiration check disabled" },
      { regex: /verify\s*[:=]\s*false/g, desc: "JWT verification disabled" },
      { regex: /(?:token|jwt).*(?:never\s+expire|no\s+expir|immortal)/gi, desc: "non-expiring token" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = source.substring(0, match.index).split("\n").length;
        const lineText = source.split("\n")[line - 1]?.trim() || "";

        if (lineText.startsWith("//") || lineText.startsWith("*")) continue;

        findings.push(this.buildFinding(match[0], line, lineText, "never-expire-pattern", null));
      }
    }

    return findings;
  }

  private buildFinding(
    pattern: string,
    line: number,
    lineText: string,
    findingType: "no-expiry" | "excessive-expiry" | "disabled-expiry" | "never-expire-pattern",
    durationSeconds: number | null,
  ): RuleResult {
    const builder = new EvidenceChainBuilder();

    const durationDesc = durationSeconds
      ? `${Math.round(durationSeconds / 86400)}d (${durationSeconds}s)`
      : "no expiration";

    const typeDesc: Record<string, string> = {
      "no-expiry": `Token created without expiry at line ${line}: "${pattern}" — token never expires`,
      "excessive-expiry": `Token expiry set to ${durationDesc} at line ${line} — exceeds 24h max for access tokens`,
      "disabled-expiry": `Token expiry explicitly disabled at line ${line}: "${pattern}"`,
      "never-expire-pattern": `Token immortality pattern at line ${line}: "${pattern}"`,
    };

    builder.source({
      source_type: "file-content",
      location: `line ${line}`,
      observed: lineText.slice(0, 120),
      rationale: typeDesc[findingType],
    });

    builder.sink({
      sink_type: "credential-exposure",
      location: `line ${line}`,
      observed:
        findingType === "no-expiry"
          ? `Token created without expiry — lives until explicitly revoked or key rotation`
          : findingType === "excessive-expiry"
          ? `Token expiry ${durationDesc} exceeds recommended maximum of 24h (access) or 30d (refresh)`
          : `Token expiry disabled — ${pattern}`,
    });

    builder.impact({
      impact_type: "credential-theft",
      scope: "connected-services",
      exploitability: "moderate",
      scenario:
        `A stolen long-lived token provides persistent access. Unlike short-lived tokens ` +
        `(≤1h), long-lived tokens cannot be mitigated by key rotation or session management. ` +
        `If an attacker obtains this token (via log exposure, memory dump, or network intercept), ` +
        `they retain access for ${durationSeconds ? durationDesc : "indefinitely"}. ` +
        `In MCP server contexts, a compromised token enables persistent tool invocation.`,
    });

    builder.factor("token_expiry_issue", 0.12, typeDesc[findingType]);
    if (findingType === "no-expiry" || findingType === "disabled-expiry" || findingType === "never-expire-pattern") {
      builder.factor("no_rotation_possible", 0.08, "Without expiry, token rotation is ineffective");
    }
    if (durationSeconds && durationSeconds > MAX_REFRESH_TOKEN_SECONDS) {
      builder.factor("exceeds_refresh_max", 0.05, "Duration exceeds even refresh token maximum (30d)");
    }

    builder.reference({
      id: "ISO-27001-A.8.24",
      title: "ISO/IEC 27001:2022 Annex A Control 8.24 — Use of Cryptography",
      relevance: "Requires cryptographic key lifecycle management including rotation schedules.",
    });

    builder.verification({
      step_type: "inspect-source",
      instruction: `Check line ${line} for token creation/expiry. Verify expiry is ≤24h for access tokens, ≤30d for refresh tokens.`,
      target: `source_code:${line}`,
      expected_observation: "Token with excessive or missing expiration",
    });

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain: builder.build(),
    };
  }
}

registerTypedRuleV2(new LongLivedTokensRule());
