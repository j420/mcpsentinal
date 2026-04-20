/**
 * C1 — Command Injection (Taint-Aware), Rule Standard v2.
 *
 * Orchestrator. Loads the charter's contract from `CHARTER.md` (parsed by the
 * charter-traceability guard) and turns the deterministic facts gathered by
 * `gather.ts` into RuleResult[] with v2-compliant EvidenceChains:
 *
 *   - every link carries a structured Location (not prose);
 *   - every VerificationStep.target is a Location produced in verification.ts;
 *   - AST-confirmed unsanitised flows are critical; sanitised flows drop to
 *     informational (per CHARTER lethal edge case #2 — sanitiser identity
 *     bypass must remain visible to a reviewer);
 *   - regex-fallback findings degrade to severity "high" and carry a negative
 *     `regex_fallback_only` factor so the scorer can distinguish them;
 *   - confidence is capped at 0.95 per CHARTER — the 0.05 gap is reserved for
 *     runtime controls (argv normalisers, seccomp, MCP gateway whitelists)
 *     the static analyser cannot observe.
 *
 * No regex literals. No string-literal arrays > 5. Detection patterns live in
 * `./data/*.ts`, which the no-static-patterns guard explicitly skips.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import {
  EvidenceChainBuilder,
  type EvidenceChain,
  type SourceLink,
  type SinkLink,
  type MitigationLink,
} from "../../../evidence.js";
import type { Location } from "../../location.js";
import {
  gatherC1,
  type ASTFinding,
  type ASTPathStep,
  type RegexFinding,
} from "./gather.js";
import {
  stepInspectSource,
  stepInspectSink,
  stepTracePath,
  stepInspectSanitizer,
  stepInspectRegexMatch,
} from "./verification.js";

// ─── Constants — charter-controlled ───────────────────────────────────────

const RULE_ID = "C1";
const RULE_NAME = "Command Injection (Taint-Aware)";
const OWASP = "MCP03-command-injection" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.95;

/**
 * Canonical remediation. MUST contain the word "execFile" and the word
 * "allowlist" — `c1-evidence-chains.test.ts` asserts both substrings on
 * every critical finding.
 */
const REMEDIATION =
  "Replace exec() / execSync() with execFile() and pass arguments as an " +
  "array, never as a single concatenated string. Validate every element of " +
  "that array against an allowlist (enum constraint, Zod schema, or a " +
  "hand-maintained whitelist of permitted commands) before it reaches any " +
  "shell surface. For Python, call subprocess.run([...], shell=False). For " +
  "dynamic command selection, map a user-supplied key to a hardcoded argv " +
  "array rather than interpolating user data into a shell string.";

/**
 * Shorter remediation for sanitised flows (severity informational). Still
 * contains "execFile" and "allowlist" because the test suite checks the
 * remediation on every finding reported as critical — sanitised findings
 * are not critical, so this variant is for narrative completeness only.
 */
const SANITIZED_REMEDIATION =
  "A sanitiser was detected on the taint path; nonetheless, prefer execFile " +
  "over exec and constrain inputs via an allowlist. Audit the sanitiser's " +
  "body to confirm it actually escapes shell metacharacters (see CHARTER " +
  "edge case #2 — sanitizer-identity bypass).";

// ─── Rule class ───────────────────────────────────────────────────────────

class CommandInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC1(context);
    if (gathered.mode === "absent" || gathered.mode === "test-file") return [];

    const out: RuleResult[] = [];

    if (gathered.mode === "ast") {
      for (const ast of gathered.astFindings) {
        out.push(this.buildASTFinding(ast));
      }
      return out;
    }

    // mode === "regex"
    for (const regex of gathered.regexFindings) {
      out.push(this.buildRegexFinding(regex));
    }
    return out;
  }

  // ─── AST-confirmed flows ────────────────────────────────────────────

  private buildASTFinding(ast: ASTFinding): RuleResult {
    const sourceType = mapSourceType(ast.sourceCategory);
    const sinkType: SinkLink["sink_type"] =
      ast.sinkCategory === "vm_escape" ? "code-evaluation" : "command-execution";
    const exploitability = ast.path.length === 0 ? "trivial" : "moderate";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: sourceType,
        location: ast.sourceLocation,
        observed: ast.sourceExpression,
        rationale:
          `Untrusted ${ast.sourceCategory} source — the expression reads from an ` +
          `external input surface (HTTP body/query/params, process.argv, process.env, ` +
          `or MCP tool parameter) and therefore carries attacker-controlled content ` +
          `until a sanitiser proves otherwise.`,
      });

    for (const step of ast.path) {
      builder.propagation({
        propagation_type: mapPropagationType(step),
        location: step.location,
        observed: step.expression,
      });
    }

    builder
      .sink({
        sink_type: sinkType,
        location: ast.sinkLocation,
        observed: ast.sinkExpression,
        cve_precedent: "CVE-2025-6514",
      })
      .mitigation(buildMitigation(ast))
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability,
        scenario:
          `Attacker crafts a payload in the ${ast.sourceCategory} source and, ` +
          `because nothing on the ${ast.path.length}-hop path either validates ` +
          `against an allowlist or quotes for POSIX shell, the payload reaches ` +
          `the ${sinkType === "code-evaluation" ? "dynamic-evaluation" : "shell"} ` +
          `sink and executes on the MCP server host — full RCE equivalent to ` +
          `CVE-2025-6514's in-the-wild exploitation of mcp-remote.`,
      })
      .factor(
        "ast_confirmed",
        0.15,
        `AST taint analyser traced data flow from source to sink with ` +
          `${ast.path.length} intermediate hop(s) — this is the strongest ` +
          `static proof the rule can produce.`,
      )
      .factor(
        "interprocedural_hops",
        ast.path.length === 0 ? 0.05 : ast.path.length >= 3 ? -0.05 : 0.02,
        ast.path.length === 0
          ? `Direct source→sink flow (zero hops) — the source expression is the ` +
            `sink's first argument on the same call.`
          : ast.path.length >= 3
          ? `${ast.path.length}-hop path — each additional hop introduces a small ` +
            `chance the taint was broken by an unrecognised transform, so the ` +
            `factor is slightly negative.`
          : `${ast.path.length}-hop path — short enough that every step is ` +
            `independently verifiable.`,
      );

    // Sanitiser-present-but-identity-unknown (CHARTER edge case #2).
    if (ast.sanitized && !ast.sanitizerIsCharterKnown) {
      builder.factor(
        "unverified_sanitizer_identity",
        0.1,
        `Sanitiser "${ast.sanitizerName ?? "<anonymous>"}" is not on the ` +
          `CHARTER list of audited shell escapers — a reviewer must audit its ` +
          `body before accepting the informational severity (edge case #2).`,
      );
    }

    builder
      .reference({
        id: "CVE-2025-6514",
        title: "mcp-remote OS command injection (CVSS 9.6, June 2025)",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
        relevance:
          "Same user-parameter→exec pattern — canonical MCP C1 precedent.",
      })
      .verification(stepInspectSource(ast))
      .verification(stepInspectSink(ast))
      .verification(stepTracePath(ast));

    if (ast.sanitized) {
      builder.verification(stepInspectSanitizer(ast));
    }

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: ast.sanitized ? "informational" : "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: ast.sanitized ? SANITIZED_REMEDIATION : REMEDIATION,
      chain,
    };
  }

  // ─── Regex-fallback findings ────────────────────────────────────────

  private buildRegexFinding(regex: RegexFinding): RuleResult {
    const sinkType: SinkLink["sink_type"] =
      regex.sink.sinkType === "code-evaluation" ? "code-evaluation" : "command-execution";

    const chain = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: regex.location,
        observed: regex.matchText,
        rationale:
          `Regex fallback engaged because AST taint analysis could not confirm a ` +
          `source→sink flow in this file (typical causes: the source lives in a ` +
          `different file, the file did not parse, or the source is an MCP tool ` +
          `parameter pattern the AST taint analyser does not yet recognise). The ` +
          `matched pattern (${regex.sink.description}) is a known-dangerous ` +
          `construct whose argument is typically attacker-controlled.`,
      })
      .sink({
        sink_type: sinkType,
        location: regex.location,
        observed: regex.sink.description,
        cve_precedent: "CVE-2025-68143",
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: regex.location,
        detail:
          `No sanitiser could be located via regex fallback — AST taint analysis ` +
          `is required to prove a sanitiser lies on the path, and that analysis ` +
          `did not fire for this file.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `If the argument reaching ${regex.sink.description} is attacker-controlled, ` +
          `${regex.sink.impactFragment}, leading to arbitrary command execution on ` +
          `the MCP server host. Manual review required because the AST taint ` +
          `analyser could not confirm the flow automatically.`,
      })
      .factor(
        "regex_fallback_only",
        -0.15,
        `AST taint analysis was not able to confirm a source→sink flow in this ` +
          `file. The regex fallback matched ${regex.sink.description}, which is a ` +
          `known-dangerous structural pattern, but the finding lacks the same ` +
          `provenance a full taint proof would carry.`,
      )
      .reference({
        id: "CVE-2025-68143",
        title: "Anthropic mcp-server-git argument injection chain",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-68143",
        relevance:
          "Argument-injection pattern detected via structural regex fallback when " +
          "AST taint could not confirm the flow.",
      })
      .verification(stepInspectRegexMatch(regex))
      .build();

    const capped = capConfidence(chain, CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain: capped,
    };
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/**
 * Map the taint analyser's source `category` string to the v2 evidence
 * source_type taxonomy. Defaults to "user-parameter" — the MCP-native case
 * where an AI-filled tool argument is the untrusted source.
 */
function mapSourceType(category: string): SourceLink["source_type"] {
  if (category === "environment") return "environment";
  // http_body | http_query | http_params all collapse to "user-parameter" —
  // per CHARTER, user-parameter is the safe default for MCP contexts where
  // the untrusted input is an AI-filled tool argument or equivalent external
  // surface. "external-content" is reserved for scraped or fetched content
  // that is NOT directly parameterised by the caller.
  return "user-parameter";
}

/**
 * Map an ASTFlowStep's `type` into the v2 evidence propagation taxonomy.
 * Not all step types have a 1:1 mapping — the rationale is recorded in
 * CHARTER.md (evidence_contract.minimum_chain).
 */
function mapPropagationType(step: ASTPathStep): "variable-assignment" | "template-literal" | "function-call" | "direct-pass" {
  switch (step.type) {
    case "assignment":
    case "destructure":
      return "variable-assignment";
    case "template_embed":
      return "template-literal";
    case "return_value":
    case "callback_arg":
    case "parameter_binding":
      return "function-call";
    default:
      return "direct-pass";
  }
}

/**
 * Build the mitigation link for an AST finding. When a sanitiser is on the
 * path, the charter requires present=true (even if the sanitiser identity
 * is unknown); otherwise the link records an absent input-validation check
 * so the evidence chain always includes a mitigation.
 */
function buildMitigation(ast: ASTFinding): Omit<MitigationLink, "type"> {
  if (ast.sanitized) {
    const name = ast.sanitizerName ?? "<anonymous>";
    return {
      mitigation_type: "sanitizer-function",
      present: true,
      location: ast.sinkLocation,
      detail: ast.sanitizerIsCharterKnown
        ? `Sanitiser "${name}" is on the CHARTER-recognised list of audited ` +
          `shell escapers — its contract is to quote shell metacharacters before ` +
          `the value reaches the sink.`
        : `Sanitiser "${name}" was found on the taint path but is NOT on the ` +
          `CHARTER list of audited shell escapers — a reviewer must audit its ` +
          `body to confirm it actually sanitises (CHARTER edge case #2).`,
    };
  }
  return {
    mitigation_type: "input-validation",
    present: false,
    location: ast.sinkLocation,
    detail:
      `No sanitiser found on the taint path between source and sink — the ` +
      `source value reaches the sink unfiltered.`,
  };
}

/**
 * Clamp `chain.confidence` to `cap`, recording the reason in
 * `confidence_factors` so the cap is auditable (not a magic number).
 * Mutates the chain — the builder's output is owned by the rule.
 */
function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `C1 charter caps AST-confirmed in-file taint at ${cap}; the 0.05 gap is ` +
      `reserved for runtime controls (argv normalisers, seccomp, MCP gateway ` +
      `whitelists) the static analyser cannot observe.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new CommandInjectionRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { CommandInjectionRule };
