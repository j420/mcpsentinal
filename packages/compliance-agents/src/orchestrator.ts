/**
 * ComplianceOrchestrator — runs the 4-step pipeline for one or more
 * frameworks against an AnalysisContext, deduplicates rules in combined
 * mode, and demultiplexes findings into per-framework reports.
 *
 * Pipeline (per rule per framework that the rule satisfies):
 *   1. rule.gatherEvidence(context)              ← deterministic
 *   2. generator.generate({ rule, bundle, framework, ... })   ← LLM
 *   3. executor.execute(test)                    ← LLM
 *   4. rule.judge(bundle, raw)                   ← deterministic firewall
 *
 * Rules whose gather phase already detected a violation still go through
 * the LLM steps so the runtime tests are recorded in the audit log; the
 * judge() will trivially confirm them.
 */

import type { AnalysisContext } from "@mcp-sentinel/analyzer";
import { EvidenceChainBuilder } from "@mcp-sentinel/analyzer";
import { computeFrameworkComplianceScore } from "@mcp-sentinel/scorer";
import { randomUUID } from "node:crypto";

import "./rules/index.js"; // side-effect: register all rules
import { rulesForFrameworks } from "./rules/registry.js";
import { getFrameworkAgent } from "./frameworks/index.js";
import { TestGenerator } from "./tests/generator.js";
import { TestExecutor } from "./tests/executor.js";
import { applyLLMCap } from "./llm/confidence.js";
import type { LLMClient } from "./llm/client.js";
import type { LLMAuditLog } from "./llm/audit-log.js";
import {
  ALL_FRAMEWORKS,
  type CategoryResult,
  type ComplianceFinding,
  type ComplianceReport,
  type ComplianceScanRequest,
  type ComplianceScanResult,
  type FrameworkId,
} from "./types.js";
import type { ComplianceRule } from "./rules/base-rule.js";

export interface OrchestratorDeps {
  llm: LLMClient;
  audit: LLMAuditLog;
  model?: string;
}

export class ComplianceOrchestrator {
  private readonly generator: TestGenerator;
  private readonly executor: TestExecutor;

  constructor(private readonly deps: OrchestratorDeps) {
    this.generator = new TestGenerator(deps.llm, deps.model);
    this.executor = new TestExecutor(deps.llm, deps.model);
  }

  async scan(
    context: AnalysisContext,
    request: ComplianceScanRequest,
  ): Promise<ComplianceScanResult> {
    const start = Date.now();
    const scanId = randomUUID();
    const frameworks: FrameworkId[] =
      request.frameworks === "all" ? [...ALL_FRAMEWORKS] : [...request.frameworks];

    const rules = rulesForFrameworks(frameworks);
    const maxTests = request.max_tests_per_rule ?? 5;

    // Each rule runs once. Findings are bucketed per framework via the
    // rule's `applies_to` array.
    const findingsByFramework = new Map<FrameworkId, ComplianceFinding[]>();
    for (const fw of frameworks) findingsByFramework.set(fw, []);

    const allFindings: ComplianceFinding[] = [];

    for (const rule of rules) {
      const bundle = rule.gatherEvidence(context);

      // Synthesize tests once per (rule, framework) pair, biased to the
      // first framework the rule satisfies in the requested set so the
      // generator's framework_control_text matches the audit log.
      const primaryFramework = frameworks.find((f) => rule.appliesToFramework(f));
      if (!primaryFramework) continue;

      const controlText = describeFrameworkControlText(rule, primaryFramework);
      let tests;
      try {
        tests = await this.generator.generate({
          rule,
          bundle,
          framework: primaryFramework,
          framework_control_text: controlText,
          scan_id: scanId,
          max_tests: maxTests,
        });
      } catch (err) {
        // Generator failure should never crash the whole scan.
        // Record nothing for this rule and continue.
        continue;
      }

      for (const test of tests) {
        let raw;
        try {
          raw = await this.executor.execute({
            rule,
            bundle,
            test,
            framework: primaryFramework,
            framework_control_text: controlText,
            scan_id: scanId,
          });
        } catch (err) {
          continue;
        }

        const judged = rule.judge(bundle, raw);
        if (!judged.judge_confirmed) continue;

        const finding = buildFinding({
          rule,
          context,
          bundle,
          test,
          judged,
        });

        allFindings.push(finding);
        // Demultiplex into every requested framework the rule satisfies.
        for (const fw of frameworks) {
          if (rule.appliesToFramework(fw)) {
            findingsByFramework.get(fw)!.push(finding);
          }
        }
      }
    }

    const reports: ComplianceReport[] = frameworks.map((fw) =>
      buildReport({
        framework: fw,
        serverId: context.server.id,
        findings: findingsByFramework.get(fw) ?? [],
        rulesRun: rules.filter((r) => r.appliesToFramework(fw)),
        auditCount: this.deps.audit.count(),
        cachedCount: this.deps.audit.cachedCount(),
      }),
    );

    return {
      scan_id: scanId,
      server_id: context.server.id,
      reports,
      combined_findings: allFindings,
      duration_ms: Date.now() - start,
      llm_calls_made: this.deps.audit.count() - this.deps.audit.cachedCount(),
      cached_runs: this.deps.audit.cachedCount(),
    };
  }
}

function describeFrameworkControlText(
  rule: ComplianceRule,
  framework: FrameworkId,
): string {
  const controls = rule.controlsForFramework(framework);
  if (controls.length === 0) return framework;
  return controls.map((c) => `${c.category} (${c.control})`).join("; ");
}

function buildFinding(args: {
  rule: ComplianceRule;
  context: AnalysisContext;
  bundle: ReturnType<ComplianceRule["gatherEvidence"]>;
  test: import("./types.js").ComplianceTest;
  judged: import("./types.js").JudgedTestResult;
}): ComplianceFinding {
  const builder = new EvidenceChainBuilder()
    .source({
      source_type: "external-content",
      location: `bundle:${args.bundle.bundle_id}`,
      observed: args.bundle.summary,
      rationale: `Evidence bundle gathered deterministically by ${args.rule.metadata.id}`,
    })
    .sink({
      sink_type: "config-modification",
      location: args.judged.evidence_path_used,
      observed: args.judged.rationale,
    })
    .impact({
      impact_type: "config-poisoning",
      scope: "ai-client",
      exploitability: "moderate",
      scenario: args.test.scenario,
    })
    .factor(
      "judge-confirmed",
      0.05,
      `Deterministic judge confirmed the LLM verdict: ${args.judged.judge_rationale}`,
    );

  const builtChain = builder.build();
  const chain = applyLLMCap(builtChain, args.judged);

  return {
    server_id: args.context.server.id,
    rule_id: args.rule.metadata.id,
    applies_to: args.rule.metadata.applies_to,
    severity: args.rule.metadata.severity,
    chain,
    test: args.test,
    judge_result: args.judged,
    remediation: args.rule.metadata.remediation,
    confidence: chain.confidence,
    created_at: new Date(),
  };
}

function buildReport(args: {
  framework: FrameworkId;
  serverId: string;
  findings: ComplianceFinding[];
  rulesRun: ComplianceRule[];
  auditCount: number;
  cachedCount: number;
}): ComplianceReport {
  const agent = getFrameworkAgent(args.framework);
  const categories = agent.categories();

  const categoryResults: CategoryResult[] = categories.map((cat) => {
    const findings = args.findings.filter((f) =>
      f.applies_to.some(
        (m) => m.framework === args.framework && m.control === cat.control,
      ),
    );
    const ruleIdsInCategory = new Set(cat.rule_ids);
    const rulesClean = args.rulesRun
      .filter((r) => ruleIdsInCategory.has(r.metadata.id))
      .filter((r) => !findings.some((f) => f.rule_id === r.metadata.id))
      .map((r) => r.metadata.id);

    let status: CategoryResult["status"];
    if (cat.rule_ids.length === 0) {
      status = "insufficient-evidence";
    } else if (findings.length === 0) {
      status = "compliant";
    } else if (findings.length < cat.rule_ids.length) {
      status = "partial";
    } else {
      status = "non-compliant";
    }

    return {
      category: cat,
      status,
      findings,
      rules_clean: rulesClean,
      rules_skipped: [],
    };
  });

  const overallStatus = computeOverallStatus(categoryResults);
  const complianceScore = computeComplianceScore(categoryResults);

  return {
    framework: args.framework,
    framework_metadata: agent.metadata,
    server_id: args.serverId,
    generated_at: new Date(),
    category_results: categoryResults,
    overall_status: overallStatus,
    compliance_score: complianceScore,
    findings_count: args.findings.length,
    llm_calls_made: args.auditCount - args.cachedCount,
    cached_runs: args.cachedCount,
  };
}

function computeOverallStatus(
  categories: CategoryResult[],
): ComplianceReport["overall_status"] {
  const statuses = categories.map((c) => c.status);
  if (statuses.every((s) => s === "compliant")) return "compliant";
  if (statuses.some((s) => s === "non-compliant")) return "non-compliant";
  if (statuses.some((s) => s === "partial")) return "partial";
  return "insufficient-evidence";
}

function computeComplianceScore(categories: CategoryResult[]): number {
  if (categories.length === 0) return 0;
  // Delegate to packages/scorer so the per-framework compliance score uses
  // the same severity weights as the deterministic scorer (single source of
  // truth: scoring-algorithm.md).
  const findings = categories.flatMap((c) => c.findings);
  return computeFrameworkComplianceScore(findings);
}
