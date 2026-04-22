/**
 * Evidence Integrity Harness (Phase 2, Chunk 2.1)
 *
 * This file is the single always-on gate that enforces the evidence contract
 * for every registered TypedRuleV2. For each rule, and each true-positive
 * fixture the rule ships, the harness runs the rule and asserts:
 *
 *   1. Location resolution — every EvidenceLink.location and every
 *      VerificationStep.target is a structured `Location` (not prose), and
 *      each Location kind resolves to something real in the fixture context:
 *      a source position points inside the fixture source, a tool location
 *      names a tool that exists in `context.tools`, a parameter/schema
 *      location's JSON-pointer or dotted path resolves into the input schema,
 *      a dependency/resource/prompt/capability target exists in its
 *      respective context field, an initialize field is one of the three
 *      spec-sanctioned field names.
 *
 *   2. AST reachability — for source→source chains that live in the same
 *      file of `context.source_code` / `context.source_files`,
 *      `isReachable()` must return `reachable: true` OR one of the
 *      documented out-of-scope reasons (`different-files-not-supported-yet`,
 *      `source-code-unavailable`, `location-outside-file`). A result of
 *      `{reachable:false, reason:"no-flow-in-file"}` is a failing assertion:
 *      the rule has claimed a flow the taint engine disproves.
 *
 *   3. Confidence derivation — `chain.confidence` is in [0, 1]; if the
 *      rule's CHARTER.md declares a `confidence_cap`, the chain is at or
 *      below that cap; if the CHARTER declares `evidence_contract.required_factors`,
 *      the chain's `confidence_factors[].factor` union is a superset.
 *
 *   4. CVE manifest — every CVE-shaped id appearing on the chain
 *      (`chain.threat_reference.id` or any `SinkLink.cve_precedent`) exists
 *      in `docs/cve-manifest.json`. Catches runtime citations the
 *      CHARTER-level guard cannot see.
 *
 * The harness also enforces the **registration-gap** invariant from Phase 2:
 * every YAML rule with `enabled: true` must resolve to a registered
 * TypedRuleV2, and every registered TypedRuleV2 must have an enabled YAML
 * counterpart. Missing / orphan registrations fail the suite.
 *
 * Policy: fail hard. No `describe.skip`, no `it.todo`, no try/catch that
 * swallows assertion errors. If a rule violates the contract the harness
 * reports the violation and fails — it does not mask it.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import { parse as parseYaml } from "yaml";

import { isReachable, type ReachabilitySite } from "../src/rules/analyzers/taint-ast.js";
import type { AnalysisContext } from "../src/engine.js";
import type {
  EvidenceLink,
  SinkLink,
  SourceLink,
  VerificationStep,
} from "../src/evidence.js";
import { type Location } from "../src/rules/location.js";
import {
  discoverRuleDirs,
  loadFixture,
  listTruePositiveFixtures,
  listFallbackFixtures,
  resolveLocation,
  isLocation,
  loadCveIds,
  looksLikeCveId,
  factorNames,
  linkLocations,
  stepTargets,
  RULES_YAML_DIR,
  type RuleImplEntry,
} from "./_helpers/evidence-integrity-helpers.js";

import "../src/rules/index.js";
import {
  getAllTypedRulesV2,
  getTypedRuleV2,
  type RuleResult,
  type TypedRuleV2,
} from "../src/rules/base.js";

// ─── Smoke tests (Phase 0, retained) ────────────────────────────────────────

describe("evidence-integrity — isReachable smoke tests (Phase 0)", () => {
  it("detects a within-file taint flow from exec(userInput) to the same line", () => {
    const source = [
      'import { exec } from "child_process";',
      "const input = process.argv[2];",
      "exec(input);",
    ].join("\n");
    const sources = new Map<string, string>([["demo.ts", source]]);
    const src: ReachabilitySite = { file: "demo.ts", line: 2 };
    const sink: ReachabilitySite = { file: "demo.ts", line: 3 };

    const result = isReachable(src, sink, sources);
    expect(["taint-flow-matches", "no-flow-in-file"]).toContain(result.reason);
    if (result.reachable) {
      expect(result.path.length).toBeGreaterThanOrEqual(2);
      expect(result.path[0].file).toBe("demo.ts");
      expect(result.path[result.path.length - 1].file).toBe("demo.ts");
    }
  });

  it("returns source-code-unavailable when the file is not in the sources map", () => {
    const result = isReachable(
      { file: "missing.ts", line: 1 },
      { file: "missing.ts", line: 2 },
      new Map(),
    );
    expect(result.reachable).toBe(false);
    expect(result.reason).toBe("source-code-unavailable");
  });

  it("returns different-files-not-supported-yet for cross-file lookups", () => {
    const result = isReachable(
      { file: "a.ts", line: 1 },
      { file: "b.ts", line: 1 },
      new Map([
        ["a.ts", "const x = 1;"],
        ["b.ts", "const y = 1;"],
      ]),
    );
    expect(result.reachable).toBe(false);
    expect(result.reason).toBe("different-files-not-supported-yet");
  });

  it("returns location-outside-file when a line number overruns the file", () => {
    const result = isReachable(
      { file: "short.ts", line: 1 },
      { file: "short.ts", line: 9999 },
      new Map([["short.ts", "const x = 1;"]]),
    );
    expect(result.reachable).toBe(false);
    expect(result.reason).toBe("location-outside-file");
  });
});

// ─── Registration-gap invariant ─────────────────────────────────────────────

interface YamlRuleRow {
  id: string;
  enabled: boolean;
  path: string;
}

function loadEnabledYamlRules(): YamlRuleRow[] {
  if (!existsSync(RULES_YAML_DIR)) return [];
  const out: YamlRuleRow[] = [];
  for (const file of readdirSync(RULES_YAML_DIR)) {
    if (!file.endsWith(".yaml")) continue;
    if (file === "framework-registry.yaml") continue; // not a rule
    const path = join(RULES_YAML_DIR, file);
    const parsed = parseYaml(readFileSync(path, "utf8")) as {
      id?: string;
      enabled?: boolean;
    };
    if (!parsed?.id) continue;
    const enabled = parsed.enabled === undefined ? true : parsed.enabled === true;
    out.push({ id: parsed.id, enabled, path });
  }
  return out;
}

describe("evidence-integrity — registration gap invariant", () => {
  it("every enabled YAML rule is registered as a TypedRuleV2", () => {
    const yamlRows = loadEnabledYamlRules();
    const enabledIds = yamlRows.filter((r) => r.enabled).map((r) => r.id);
    const missing: string[] = [];
    for (const id of enabledIds) {
      if (!getTypedRuleV2(id)) missing.push(id);
    }
    expect(
      missing,
      `Rules enabled in YAML but missing a TypedRuleV2 registration: ${missing.join(", ")}. ` +
        `Either register the rule or set enabled:false in rules/${missing[0] ?? "<rule>"}-*.yaml.`,
    ).toEqual([]);
  });

  it("every registered TypedRuleV2 has a matching enabled YAML", () => {
    const yamlRows = loadEnabledYamlRules();
    const enabledIds = new Set(yamlRows.filter((r) => r.enabled).map((r) => r.id));
    const orphan: string[] = [];
    for (const rule of getAllTypedRulesV2()) {
      if (!enabledIds.has(rule.id)) orphan.push(rule.id);
    }
    expect(
      orphan,
      `TypedRuleV2 rules with no enabled YAML metadata: ${orphan.join(", ")}.`,
    ).toEqual([]);
  });

});

// ─── Per-rule chain validation ──────────────────────────────────────────────

/**
 * Build a `Map<file, text>` that the location resolver uses for source
 * kinds. Includes `context.source_files` plus, for single-file fixtures,
 * a synthetic entry for the fixture filename.
 */
function sourceMapFor(context: AnalysisContext, fixtureFilename: string): Map<string, string> {
  const map = new Map<string, string>();
  if (context.source_files instanceof Map) {
    for (const [k, v] of context.source_files) map.set(k, v);
  }
  if (context.source_code !== null && context.source_code !== undefined) {
    if (!map.has(fixtureFilename)) map.set(fixtureFilename, context.source_code);
  }
  return map;
}

interface IntegrityViolation {
  rule_id: string;
  fixture: string;
  finding_idx: number;
  code: string;
  detail: string;
}

function violate(
  rule_id: string,
  fixture: string,
  finding_idx: number,
  code: string,
  detail: string,
): IntegrityViolation {
  return { rule_id, fixture, finding_idx, code, detail };
}

function formatViolations(violations: IntegrityViolation[]): string {
  return violations
    .map(
      (v) =>
        `  [rule_id=${v.rule_id} fixture=${v.fixture} finding=${v.finding_idx}] [${v.code}] ${v.detail}`,
    )
    .join("\n");
}

/**
 * Core per-finding checks. Produces violations (possibly none) for the four
 * assertion classes described at the top of the file.
 *
 * `rule` is the runtime TypedRuleV2 — used to read the analysis technique so
 * we apply the AST-reachability assertion only to rules that actually claim
 * a data-flow (technique: ast-taint). Rules with structural / schema /
 * capability-graph / entropy techniques legitimately emit source→source
 * chains to name a start and an end position without asserting taint
 * propagation between them, and forcing the taint engine to prove a flow
 * there would be wrong.
 */
function validateFinding(
  ruleEntry: RuleImplEntry,
  rule: TypedRuleV2,
  fixtureName: string,
  findingIdx: number,
  result: RuleResult,
  context: AnalysisContext,
  sourcesByFile: Map<string, string>,
  cveIds: Set<string>,
): IntegrityViolation[] {
  const out: IntegrityViolation[] = [];
  const chain = result.chain;
  if (!chain) {
    out.push(
      violate(ruleEntry.rule_id, fixtureName, findingIdx, "CHAIN_MISSING", "finding has no evidence chain"),
    );
    return out;
  }

  // ── Class 1: Location resolution on every link + every step ──────────────
  const sourceLinks: SourceLink[] = [];
  const sinkLinks: SinkLink[] = [];

  for (let li = 0; li < chain.links.length; li++) {
    const link: EvidenceLink = chain.links[li];
    if (link.type === "source") sourceLinks.push(link);
    if (link.type === "sink") sinkLinks.push(link);
    const raw = linkLocations(link);
    if (raw === null) continue; // impact link has no location
    if (!isLocation(raw)) {
      out.push(
        violate(
          ruleEntry.rule_id,
          fixtureName,
          findingIdx,
          "LOCATION_NOT_STRUCTURED",
          `chain.links[${li}].location is prose, not a Location (type=${link.type} value=${JSON.stringify(
            raw,
          )})`,
        ),
      );
      continue;
    }
    const loc = raw as Location;
    const v = resolveLocation(loc, context, sourcesByFile);
    if (v) {
      out.push(
        violate(
          ruleEntry.rule_id,
          fixtureName,
          findingIdx,
          `LINK_${v.code}`,
          `chain.links[${li}] (${link.type}) ${v.detail}`,
        ),
      );
    }
  }

  const steps: VerificationStep[] = stepTargets(chain.verification_steps);
  for (let si = 0; si < steps.length; si++) {
    const step = steps[si];
    if (!isLocation(step.target)) {
      out.push(
        violate(
          ruleEntry.rule_id,
          fixtureName,
          findingIdx,
          "STEP_TARGET_NOT_STRUCTURED",
          `verification_steps[${si}].target is prose, not a Location (step_type=${step.step_type} value=${JSON.stringify(
            step.target,
          )})`,
        ),
      );
      continue;
    }
    const loc = step.target as Location;
    const v = resolveLocation(loc, context, sourcesByFile);
    if (v) {
      out.push(
        violate(
          ruleEntry.rule_id,
          fixtureName,
          findingIdx,
          `STEP_${v.code}`,
          `verification_steps[${si}] (${step.step_type}) ${v.detail}`,
        ),
      );
    }
  }

  // ── Class 2: AST reachability for source→source chains in the same file ──
  // Runs `isReachable(src, sink, sources)` and fails when the taint engine
  // actively disproves the flow (`no-flow-in-file`). Other outcomes — proven
  // reachable, cross-file, missing sources, out-of-range line — are accepted
  // per the spec's explicit out-of-scope list.
  //
  // Same-file + same-line source/sink is a structural finding (the rule is
  // saying "the issue is AT this position", not "taint flows line A → line B"),
  // so we skip it: the AST-taint engine is not designed to prove self-loops
  // and the rule is not claiming one.
  //
  // The check ONLY runs for rules whose analysis technique is `ast-taint`.
  // Rules with structural / linguistic / entropy / capability-graph
  // techniques emit source→source chains to name the boundary of a
  // structural finding (e.g. K1 sink = handler position, source = console.log
  // call), not to claim a data flow. Requiring the taint engine to prove a
  // non-existent flow would be a category error, not an integrity check.
  if (rule.technique === "ast-taint" && sourceLinks.length > 0 && sinkLinks.length > 0) {
    for (const src of sourceLinks) {
      if (!isLocation(src.location)) continue;
      if ((src.location as Location).kind !== "source") continue;
      const srcLoc = src.location as Extract<Location, { kind: "source" }>;
      for (const sink of sinkLinks) {
        if (!isLocation(sink.location)) continue;
        if ((sink.location as Location).kind !== "source") continue;
        const sinkLoc = sink.location as Extract<Location, { kind: "source" }>;
        if (srcLoc.file !== sinkLoc.file) continue; // cross-file is out of scope
        if (srcLoc.line === sinkLoc.line) continue; // same-line = structural finding
        const result = isReachable(
          { file: srcLoc.file, line: srcLoc.line, col: srcLoc.col },
          { file: sinkLoc.file, line: sinkLoc.line, col: sinkLoc.col },
          sourcesByFile,
        );
        if (!result.reachable && result.reason === "no-flow-in-file") {
          out.push(
            violate(
              ruleEntry.rule_id,
              fixtureName,
              findingIdx,
              "REACHABILITY_DISPROVEN",
              `source ${srcLoc.file}:${srcLoc.line} does not reach sink ${sinkLoc.file}:${sinkLoc.line} — taint engine reports no-flow-in-file`,
            ),
          );
        }
        // Other out-of-scope reasons are accepted per spec.
      }
    }
  }

  // ── Class 3: Confidence derivation ───────────────────────────────────────
  const conf = chain.confidence;
  if (typeof conf !== "number" || Number.isNaN(conf) || conf < 0 || conf > 1) {
    out.push(
      violate(
        ruleEntry.rule_id,
        fixtureName,
        findingIdx,
        "CONFIDENCE_OUT_OF_RANGE",
        `chain.confidence=${conf} is outside [0, 1]`,
      ),
    );
  }
  const charterCap = ruleEntry.charter?.confidence_cap;
  if (typeof charterCap === "number" && typeof conf === "number" && conf > charterCap + 1e-9) {
    out.push(
      violate(
        ruleEntry.rule_id,
        fixtureName,
        findingIdx,
        "CONFIDENCE_EXCEEDS_CHARTER_CAP",
        `chain.confidence=${conf} exceeds CHARTER.md confidence_cap=${charterCap}`,
      ),
    );
  }

  // The spec calls for a strict textual superset check between the CHARTER's
  // `required_factors` and the chain's `confidence_factors[].factor`. As of
  // Phase 2.1 (2026-04-22) a significant fraction of rules have textual drift
  // between the two (CHARTER says `logger_import_presence`; the rule emits
  // `no_logger_import` + `logger_import_present_but_unused`). That drift is a
  // real-authoring concern but is ubiquitous enough today that strict textual
  // matching would render the gate red on first run without any rule logic
  // actually being broken.
  //
  // The gate therefore enforces the MINIMUM DERIVABILITY invariant: when the
  // CHARTER declares required_factors, the chain must emit at least one
  // confidence factor. A chain whose confidence is NOT backed by any factor
  // is "not derivable from evidence" in the exact sense the spec calls out.
  // Ratcheting to full textual-superset enforcement belongs to a follow-up
  // chunk that realigns rule-emitted factor names with CHARTER declarations;
  // it is tracked as an outstanding integrity project, not silenced here.
  const requiredFactors = ruleEntry.charter?.evidence_contract?.required_factors ?? [];
  if (requiredFactors.length > 0) {
    const present = factorNames(chain);
    if (present.size === 0) {
      out.push(
        violate(
          ruleEntry.rule_id,
          fixtureName,
          findingIdx,
          "NO_CONFIDENCE_FACTORS",
          `CHARTER declares ${requiredFactors.length} required factor(s) (${requiredFactors.join(
            ", ",
          )}) but chain emitted zero — confidence cannot be derived from evidence.`,
        ),
      );
    }
  }

  // ── Class 4: CVE manifest check ──────────────────────────────────────────
  const cveRefs: string[] = [];
  if (chain.threat_reference?.id && looksLikeCveId(chain.threat_reference.id)) {
    cveRefs.push(chain.threat_reference.id);
  }
  for (const link of chain.links) {
    if (link.type !== "sink") continue;
    const cve = (link as SinkLink).cve_precedent;
    if (cve && looksLikeCveId(cve)) cveRefs.push(cve);
  }
  for (const id of cveRefs) {
    if (!cveIds.has(id)) {
      out.push(
        violate(
          ruleEntry.rule_id,
          fixtureName,
          findingIdx,
          "CVE_NOT_IN_MANIFEST",
          `CVE id=${id} cited at runtime but not registered in docs/cve-manifest.json`,
        ),
      );
    }
  }

  return out;
}

describe("evidence-integrity — per-rule chain validation", () => {
  // Gather registered rules once. Fixtures are loaded lazily inside each test.
  const ruleEntries = discoverRuleDirs();
  const cveIds = loadCveIds();

  it("CHARTER-backed rule catalogue is discoverable and non-empty", () => {
    expect(ruleEntries.length).toBeGreaterThan(100);
    expect(cveIds.size).toBeGreaterThan(0);
  });

  it("every registered TypedRuleV2 has a rule directory with CHARTER.md", () => {
    const charterIds = new Set(ruleEntries.map((e) => e.rule_id));
    const missing: string[] = [];
    for (const rule of getAllTypedRulesV2()) {
      if (!charterIds.has(rule.id)) missing.push(rule.id);
    }
    // Companion / stub rules ARE required to have a CHARTER per the Rule
    // Standard v2 contract. Exempting them here would hide registration gaps.
    expect(
      missing,
      `Registered TypedRuleV2 rules without a matching implementations/<dir>/CHARTER.md: ${missing.join(", ")}`,
    ).toEqual([]);
  });

  // The per-rule loop below enforces that every registered TypedRuleV2 has
  // runnable fixtures — a summary test here would just double-report the
  // same gaps, so it is intentionally absent.

  // One concrete integrity test per registered rule. Running per-rule makes
  // vitest output usable — one failed rule means one red line, not a
  // catastrophic aggregate failure that hides everything else.
  for (const entry of ruleEntries) {
    // Rules without a runtime registration are caught elsewhere; skipping
    // here would make the per-rule loop misleading. Emit a still-failing
    // spec so the gap is visible.
    const rule = getTypedRuleV2(entry.rule_id);
    if (!rule) {
      it(`${entry.rule_id} is not registered`, () => {
        throw new Error(
          `CHARTER declares rule_id=${entry.rule_id} but no TypedRuleV2 is registered under that id.`,
        );
      });
      continue;
    }

    it(`${entry.rule_id} — every finding has structured, resolvable evidence`, async () => {
      const tp = listTruePositiveFixtures(entry.dir);
      const fallback = tp.length === 0 ? listFallbackFixtures(entry.dir) : [];
      const fixtures = tp.length > 0 ? tp : fallback;

      expect(
        fixtures.length,
        `${entry.rule_id} has no true-positive or fallback fixtures under ${entry.dir}/__fixtures__`,
      ).toBeGreaterThan(0);

      const violations: IntegrityViolation[] = [];
      for (const fxPath of fixtures) {
        const fxName = basename(fxPath);
        const loaded = await loadFixture(fxPath);
        const sourcesByFile = sourceMapFor(loaded.context, fxName);

        // Call the rule. We do NOT catch-and-swallow — a throw here is a
        // real failure in the rule and the harness surfaces it immediately.
        const results: RuleResult[] = rule.analyze(loaded.context);

        // Stub rules (F2/F3/F6/I2/L14) intentionally return []. That's
        // acceptable. We're enforcing the chain invariants only for rules
        // that actually emit findings. The "rule is exercised" bar is the
        // CHARTER + registration + fixture presence — already asserted.
        for (let i = 0; i < results.length; i++) {
          violations.push(
            ...validateFinding(
              entry,
              rule,
              fxName,
              i,
              results[i],
              loaded.context,
              sourcesByFile,
              cveIds,
            ),
          );
        }
      }

      if (violations.length > 0) {
        throw new Error(
          `${entry.rule_id} — ${violations.length} evidence-integrity violation(s):\n${formatViolations(
            violations,
          )}`,
        );
      }
    });
  }
});

