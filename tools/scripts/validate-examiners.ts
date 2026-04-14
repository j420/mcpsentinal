#!/usr/bin/env tsx
/**
 * Examiner Thoroughness Discipline Validator (Phase 7.5)
 *
 * Enforces the 9-point thoroughness discipline on every migrated Examiner.
 * Legacy v1 rules listed in packages/analyzer/rule-migration-status.json are
 * skipped — they will be gated individually as they migrate.
 *
 * Gates (from agent_docs plan compiled-drifting-raven.md §Phase 1.5):
 *   1. Research citation              hypothesis.threat_reference.primary present + shape-valid
 *   2. Primary-source uniqueness      no two Examiners share the same primary source
 *   3. Edge-case manifest             ≥5 variants, each with a locator that exists in a red-team fixture
 *   4. Adversarial mutations          ≥3 adversarial mutations, each declaring a bypass technique
 *   5. Negative controls              ≥3 known-safe patterns, each with a locator
 *   6. CVE replay                     every CVE-backed Examiner has a fixture in cve-replays.ts
 *   7. Cross-rule interactions        every interacts_with target resolves to a real rule ID
 *   8. Calibrated confidence          AST scan rejects bare numeric literals on
 *                                     property names /confidence|weight|threshold|score/
 *                                     unless wrapped in TrustedConstant(value, reason)
 *   9. Red-team corpus replay         enforced in a separate CI job (pnpm test --filter=red-team)
 *
 * Exit code 0: all gates passed
 * Exit code 1: one or more gates failed (precise errors printed)
 *
 * Usage:
 *   pnpm tsx tools/scripts/validate-examiners.ts
 *   pnpm tsx tools/scripts/validate-examiners.ts --verbose
 */

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import ts from "typescript";

const ROOT = resolve(import.meta.dirname ?? __dirname, "../..");
const ANALYZER = join(ROOT, "packages/analyzer");
const EXAMINERS_DIR = join(ANALYZER, "src/rules/examiners");
const MIGRATION_STATUS = join(ANALYZER, "rule-migration-status.json");

const verbose = process.argv.includes("--verbose");

interface MigrationStatus {
  migrated: Array<{ rule_id: string; examiner_path: string; cve_backed: boolean }>;
  legacy: string[];
  retired: string[];
}

interface GateFailure {
  rule_id: string;
  gate: string;
  message: string;
}

function loadMigrationStatus(): MigrationStatus {
  const raw = readFileSync(MIGRATION_STATUS, "utf-8");
  return JSON.parse(raw) as MigrationStatus;
}

async function loadExaminerRegistry() {
  // Side-effect import registers all Examiners + legacy rules
  await import(join(ANALYZER, "src/rules/index.js"));
  const base = await import(join(ANALYZER, "src/rules/base.js"));
  const examinerMod = await import(join(ANALYZER, "src/rules/examiner.js"));

  const allV2 = base.getAllTypedRulesV2() as unknown[];
  const examiners: InstanceType<typeof examinerMod.Examiner>[] = [];
  for (const rule of allV2) {
    if (rule instanceof examinerMod.Examiner) {
      examiners.push(rule as InstanceType<typeof examinerMod.Examiner>);
    }
  }
  return { examiners, Examiner: examinerMod.Examiner };
}

async function loadFixtureLocators() {
  // ALL_FIXTURES + ALL_CVE_REPLAY_FIXTURES exported from the red-team package.
  // We resolve from its source so the validator works without a prior build.
  const redTeam = await import(join(ROOT, "packages/red-team/src/fixtures/index.js"));
  const cveReplays = await import(join(ROOT, "packages/red-team/src/fixtures/cve-replays.js"));
  type Fixture = { description: string };
  type FixtureSet = { rule_id: string; fixtures: Fixture[] };

  const byCategory = new Map<string, Set<string>>();

  function ingest(prefix: string, sets: FixtureSet[]) {
    const bucket = byCategory.get(prefix) ?? new Map<string, Set<string>>();
    for (const fs of sets) {
      const key = `${prefix}:${fs.rule_id}`;
      const existing = bucket.get(key) ?? new Set<string>();
      for (const f of fs.fixtures) existing.add(f.description);
      bucket.set(key, existing);
    }
    // Flatten bucket into byCategory with the combined key
    for (const [k, v] of bucket.entries()) byCategory.set(k, v);
  }

  // We need to map each fixture file to its "prefix" used by Examiners.
  // The convention: "<fixture-file-stem>:<rule-id>:<description-substring>".
  // We load the individual per-category exports by doing a directory walk.
  const fixturesDir = join(ROOT, "packages/red-team/src/fixtures");
  const files = readdirSync(fixturesDir).filter((f) => f.endsWith(".ts") && f !== "index.ts");
  for (const file of files) {
    const stem = file.replace(/\.ts$/, "");
    const mod = await import(join(fixturesDir, file.replace(/\.ts$/, ".js")));
    const sets = Object.values(mod).filter(
      (v): v is FixtureSet =>
        typeof v === "object" &&
        v !== null &&
        "rule_id" in (v as Record<string, unknown>) &&
        "fixtures" in (v as Record<string, unknown>),
    );
    // Handle aggregate arrays like ALL_C_FIXTURES
    const arrays = Object.values(mod).filter(
      (v): v is FixtureSet[] => Array.isArray(v) && v.every((x) => x && "rule_id" in x && "fixtures" in x),
    );
    const merged: FixtureSet[] = [...sets];
    for (const arr of arrays) merged.push(...arr);

    ingest(stem, merged);
  }

  // Minor compat: also allow "cve-replays" prefix to match the stem.
  void redTeam;
  void cveReplays;

  return byCategory;
}

/**
 * Check a fixture locator of the form "<prefix>:<rule-id>:<description-substring>"
 * against the discovered fixture set. Returns true iff at least one fixture in
 * the matching set has a description containing the substring.
 */
function fixtureExists(locator: string, byCategory: Map<string, Set<string>>): boolean {
  // Locator grammar:
  //   "<prefix>:<description-substring>"                 — when prefix is unique like cve-replays
  //   "<prefix>:<rule-id>:<description-substring>"       — the normal case
  const parts = locator.split(":");
  if (parts.length < 2) return false;

  // Try "prefix:rule-id" key first
  if (parts.length >= 3) {
    const key = `${parts[0]}:${parts[1]}`;
    const substring = parts.slice(2).join(":");
    const set = byCategory.get(key);
    if (set) {
      for (const desc of set) {
        if (desc.includes(substring)) return true;
      }
    }
  }

  // Fall back to searching every set under the given prefix
  const prefix = parts[0];
  const substring = parts.slice(1).join(":");
  for (const [key, set] of byCategory.entries()) {
    if (!key.startsWith(`${prefix}:`)) continue;
    for (const desc of set) {
      if (desc.includes(substring)) return true;
    }
  }
  return false;
}

// ── Gate 8: hardcoded-confidence AST scan ────────────────────────────────────

const SUSPECT_PROP = /^(confidence|weight|threshold|score)$/i;

function scanForHardcodedConfidence(filePath: string): GateFailure[] {
  const failures: GateFailure[] = [];
  const source = readFileSync(filePath, "utf-8");
  const sf = ts.createSourceFile(filePath, source, ts.ScriptTarget.ESNext, true);
  const rel = relative(ROOT, filePath);

  function visit(node: ts.Node) {
    if (
      ts.isPropertyAssignment(node) &&
      ts.isIdentifier(node.name) &&
      SUSPECT_PROP.test(node.name.text)
    ) {
      const init = node.initializer;
      // Accept: TrustedConstant(x, "reason")
      if (
        ts.isCallExpression(init) &&
        ts.isIdentifier(init.expression) &&
        init.expression.text === "TrustedConstant"
      ) {
        /* ok */
      } else if (
        ts.isNumericLiteral(init) ||
        (ts.isPrefixUnaryExpression(init) && ts.isNumericLiteral(init.operand))
      ) {
        const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
        failures.push({
          rule_id: rel,
          gate: "8-calibrated-confidence",
          message: `${rel}:${line + 1}:${character + 1} — property "${node.name.text}" uses a bare numeric literal. Wrap in TrustedConstant(value, "justification ≥10 chars") or derive from baselines/z-score.`,
        });
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(sf);
  return failures;
}

function walkTsFiles(dir: string): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) out.push(...walkTsFiles(full));
    else if (entry.endsWith(".ts") && !entry.endsWith(".d.ts")) out.push(full);
  }
  return out;
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const status = loadMigrationStatus();
  const { examiners, Examiner: _Ex } = await loadExaminerRegistry();
  const fixtureIndex = await loadFixtureLocators();

  const failures: GateFailure[] = [];
  const pass = (msg: string) => { if (verbose) console.log(`  ✓ ${msg}`); };
  const fail = (f: GateFailure) => { failures.push(f); console.log(`  ✗ [${f.gate}] ${f.rule_id}: ${f.message}`); };

  // Migrated rule IDs the validator must cover
  const migratedIds = new Set(status.migrated.map((m) => m.rule_id));
  const seenExaminerIds = new Set<string>();

  // Track primary citations for gate #2 (uniqueness)
  const citationOwners = new Map<string, string>();

  console.log(`\n▶ Validating ${examiners.length} Examiner(s) against the 9-point discipline\n`);

  for (const ex of examiners) {
    seenExaminerIds.add(ex.id);
    console.log(`— ${ex.id} (${ex.name})`);

    // Gate 1: research citation
    const primary = ex.hypothesis?.threat_reference?.primary;
    if (!primary || !primary.kind || !primary.id) {
      fail({ rule_id: ex.id, gate: "1-research-citation", message: "hypothesis.threat_reference.primary missing or incomplete" });
    } else {
      pass(`gate 1: primary citation ${primary.kind}:${primary.id}`);
    }

    // Gate 2: primary-source uniqueness
    if (primary?.id) {
      const citationKey = `${primary.kind}:${primary.id}`;
      const existing = citationOwners.get(citationKey);
      if (existing && existing !== ex.id) {
        fail({
          rule_id: ex.id,
          gate: "2-primary-unique",
          message: `Primary citation ${citationKey} is already owned by ${existing}. Each Examiner must own a distinct primary source.`,
        });
      } else {
        citationOwners.set(citationKey, ex.id);
        pass("gate 2: primary citation unique");
      }
    }

    // Gate 3: edge-case manifest
    const variants = ex.edge_cases?.variants ?? [];
    if (variants.length < 5) {
      fail({
        rule_id: ex.id,
        gate: "3-edge-case-manifest",
        message: `Declared ${variants.length} variants; need ≥5 concrete edge-case variants with fixtures`,
      });
    } else {
      pass(`gate 3: ${variants.length} variants declared`);
    }
    for (const v of variants) {
      if (!fixtureExists(v.fixture, fixtureIndex)) {
        fail({
          rule_id: ex.id,
          gate: "3-edge-case-manifest",
          message: `Variant ${v.id} references missing fixture locator "${v.fixture}"`,
        });
      }
    }

    // Gate 4: adversarial mutations
    const adv = ex.edge_cases?.adversarial_mutations ?? [];
    if (adv.length < 3) {
      fail({
        rule_id: ex.id,
        gate: "4-adversarial-mutations",
        message: `Declared ${adv.length} adversarial mutations; need ≥3 (e.g. unicode-homoglyph, encoding-base64, alias-rename)`,
      });
    } else {
      pass(`gate 4: ${adv.length} adversarial mutations declared`);
    }
    for (const m of adv) {
      if (!m.bypass) {
        fail({ rule_id: ex.id, gate: "4-adversarial-mutations", message: `Mutation ${m.id} missing bypass technique tag` });
      }
      if (!fixtureExists(m.fixture, fixtureIndex)) {
        fail({ rule_id: ex.id, gate: "4-adversarial-mutations", message: `Mutation ${m.id} references missing fixture "${m.fixture}"` });
      }
    }

    // Gate 5: negative controls
    const neg = ex.edge_cases?.known_safe_patterns ?? [];
    if (neg.length < 3) {
      fail({
        rule_id: ex.id,
        gate: "5-negative-controls",
        message: `Declared ${neg.length} known-safe patterns; need ≥3 commonly-confused-but-legitimate patterns`,
      });
    } else {
      pass(`gate 5: ${neg.length} negative controls declared`);
    }
    for (const n of neg) {
      if (!fixtureExists(n.fixture, fixtureIndex)) {
        fail({ rule_id: ex.id, gate: "5-negative-controls", message: `Pattern ${n.id} references missing fixture "${n.fixture}"` });
      }
    }

    // Gate 6: CVE replay — required when primary citation is a CVE
    if (primary?.kind === "CVE") {
      const replays = ex.edge_cases?.cve_replays ?? [];
      const match = replays.find((r) => r.cve === primary.id);
      if (!match) {
        fail({
          rule_id: ex.id,
          gate: "6-cve-replay",
          message: `Primary citation is ${primary.id} but no matching cve_replays[] entry found`,
        });
      } else if (!fixtureExists(match.fixture, fixtureIndex)) {
        fail({
          rule_id: ex.id,
          gate: "6-cve-replay",
          message: `CVE replay fixture "${match.fixture}" does not exist in the red-team corpus`,
        });
      } else if (match.expected_confidence_min < 0.9) {
        fail({
          rule_id: ex.id,
          gate: "6-cve-replay",
          message: `CVE replay expected_confidence_min=${match.expected_confidence_min} below required 0.9`,
        });
      } else {
        pass(`gate 6: CVE replay ${match.cve} wired and ≥0.9`);
      }
    }

    // Gate 7: cross-rule interactions resolve to real rule IDs
    const interactions = ex.edge_cases?.interacts_with ?? [];
    const allRuleIds = new Set<string>([
      ...status.migrated.map((m) => m.rule_id),
      ...status.legacy,
      ...status.retired,
    ]);
    for (const i of interactions) {
      if (!allRuleIds.has(i.rule_id)) {
        fail({
          rule_id: ex.id,
          gate: "7-cross-rule",
          message: `Declared interaction with unknown rule_id "${i.rule_id}" (not in migration ledger)`,
        });
      }
    }
    if (interactions.length > 0) pass(`gate 7: ${interactions.length} interactions resolved`);
  }

  // Gate 8: AST scan across every Examiner file
  console.log(`\n— Gate 8: scanning ${EXAMINERS_DIR} for hardcoded confidence literals`);
  for (const file of walkTsFiles(EXAMINERS_DIR)) {
    const gate8Failures = scanForHardcodedConfidence(file);
    for (const f of gate8Failures) failures.push(f) && console.log(`  ✗ [${f.gate}] ${f.message}`);
    if (gate8Failures.length === 0 && verbose) console.log(`  ✓ ${relative(ROOT, file)}`);
  }

  // Consistency: every rule in migration ledger should register an Examiner instance
  for (const id of migratedIds) {
    if (!seenExaminerIds.has(id)) {
      fail({
        rule_id: id,
        gate: "0-registration",
        message: `rule-migration-status.json lists ${id} as migrated but no Examiner instance is registered`,
      });
    }
  }

  console.log("");
  if (failures.length > 0) {
    console.log(`\n✗ ${failures.length} gate violation(s) across ${new Set(failures.map((f) => f.rule_id)).size} Examiner(s). Build fails.`);
    process.exit(1);
  }
  console.log(`\n✓ All ${examiners.length} Examiner(s) pass the 9-point thoroughness discipline.`);
}

main().catch((err) => {
  console.error("validate-examiners crashed:", err);
  process.exit(2);
});
