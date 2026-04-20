/**
 * Charter Traceability Guard (Analyzer Mirror)
 *
 * Phase 0, Chunk 0.4. Analyzer counterpart to the compliance-agents
 * `charter-traceability.test.ts`. Enforces the dual-persona authoring
 * protocol described in `docs/standards/rule-standard-v2.md`:
 *
 *   Every v2 rule lives in its own directory under
 *   `packages/analyzer/src/rules/implementations/<rule>/` and contains both
 *   a `CHARTER.md` (Senior MCP Threat Researcher persona) and an
 *   `index.ts` (Senior MCP Security Engineer persona). This test parses
 *   each charter and verifies it agrees with the sibling implementation
 *   on the same identifying facts the compliance-agents guard checks,
 *   PLUS the v2-specific contract:
 *
 *     - rule_id matches the implementation's TypedRule.id
 *     - interface_version: "v2"
 *     - severity matches the rule's YAML metadata
 *     - threat_refs has ≥1 entry; every cve entry exists in docs/cve-manifest.json
 *     - lethal_edge_cases has ≥3 entries
 *     - edge_case_strategies has ≥1 entry
 *     - evidence_contract.minimum_chain.{source,sink}: true
 *
 * Zero charters today is expected — Phase 1 creates them one per rule.
 * The guard is warn-only in Phase 0 (console.warn instead of throw);
 * set ANALYZER_CHARTER_GUARD_STRICT=true to enforce early.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
const REPO_ROOT = resolve(PACKAGE_ROOT, "..", "..");
const IMPL_ROOT = join(PACKAGE_ROOT, "src", "rules", "implementations");
const RULES_YAML_DIR = join(REPO_ROOT, "rules");
const CVE_MANIFEST = join(REPO_ROOT, "docs", "cve-manifest.json");
const STRICT = process.env.ANALYZER_CHARTER_GUARD_STRICT === "true";

interface ThreatRef {
  kind?: string;
  id?: string;
  url?: string;
  summary?: string;
}

interface EvidenceContract {
  minimum_chain?: {
    source?: boolean;
    propagation?: boolean;
    sink?: boolean;
    mitigation?: boolean;
    impact?: boolean;
  };
  required_factors?: string[];
  location_kinds?: string[];
}

interface CharterFrontmatter {
  rule_id?: string;
  interface_version?: string;
  severity?: string;
  threat_refs?: ThreatRef[];
  lethal_edge_cases?: string[];
  edge_case_strategies?: string[];
  evidence_contract?: EvidenceContract;
  obsolescence?: { retire_when?: string };
}

interface CveManifest {
  version: number;
  entries: Array<{ id: string }>;
}

// ─── Charter discovery ─────────────────────────────────────────────────────

function findCharters(root: string): string[] {
  if (!existsSync(root)) return [];
  const out: string[] = [];
  for (const name of readdirSync(root)) {
    const full = join(root, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      const charter = join(full, "CHARTER.md");
      if (existsSync(charter)) out.push(charter);
    }
  }
  return out;
}

// ─── Frontmatter parsing ───────────────────────────────────────────────────

function parseFrontmatter(markdown: string): CharterFrontmatter | null {
  // Expected shape:
  //   ---
  //   <yaml>
  //   ---
  //   <markdown body>
  const lines = markdown.split("\n");
  if (lines[0]?.trim() !== "---") return null;
  const end = lines.findIndex((l, i) => i > 0 && l.trim() === "---");
  if (end < 0) return null;
  const yamlText = lines.slice(1, end).join("\n");
  try {
    return parseYaml(yamlText) as CharterFrontmatter;
  } catch {
    return null;
  }
}

// ─── Implementation probing ────────────────────────────────────────────────

/**
 * Find the rule id declared inside <ruleDir>/index.ts. Supports:
 *   - `const RULE_ID = "K1";` + `readonly id = RULE_ID;`
 *   - `readonly id = "K1";`  / `id: "K1"` property declarations
 */
function findImplRuleId(ruleDir: string): string | null {
  const indexPath = join(ruleDir, "index.ts");
  if (!existsSync(indexPath)) return null;
  const text = readFileSync(indexPath, "utf8");

  // Line scan — the no-static-patterns guard prevents regex cheating, but we
  // need a light pattern match here to extract known property shapes.
  const lines = text.split("\n");
  const constStrings = new Map<string, string>();
  for (const line of lines) {
    const trimmed = line.trim();
    // const RULE_ID = "K1";
    const constMatch = trimmed.match(/^(?:export\s+)?const\s+([A-Z_][A-Z0-9_]*)\s*=\s*"([^"]+)"/);
    if (constMatch) constStrings.set(constMatch[1], constMatch[2]);
  }
  for (const line of lines) {
    const trimmed = line.trim();
    // readonly id = "K1";   id: "K1"   public readonly id: string = "K1";
    const litMatch = trimmed.match(/\bid\s*[:=]\s*"([A-Q]\d+)"/);
    if (litMatch) return litMatch[1];
    // readonly id = RULE_ID;
    const refMatch = trimmed.match(/\bid\s*[:=]\s*([A-Z_][A-Z0-9_]*)\b/);
    if (refMatch && constStrings.has(refMatch[1])) {
      return constStrings.get(refMatch[1]) ?? null;
    }
  }
  return null;
}

// ─── YAML metadata → severity ──────────────────────────────────────────────

function loadYamlSeverity(ruleId: string): string | null {
  if (!existsSync(RULES_YAML_DIR)) return null;
  for (const name of readdirSync(RULES_YAML_DIR)) {
    if (!name.startsWith(`${ruleId}-`)) continue;
    try {
      const parsed = parseYaml(readFileSync(join(RULES_YAML_DIR, name), "utf8")) as {
        id?: string;
        severity?: string;
      };
      if (parsed?.id === ruleId) return parsed.severity ?? null;
    } catch {
      // Ignore — the YAML validator owns structural checks.
    }
  }
  return null;
}

// ─── CVE manifest ──────────────────────────────────────────────────────────

function loadCveIds(): Set<string> {
  if (!existsSync(CVE_MANIFEST)) return new Set();
  try {
    const parsed = JSON.parse(readFileSync(CVE_MANIFEST, "utf8")) as CveManifest;
    return new Set(parsed.entries.map((e) => e.id));
  } catch {
    return new Set();
  }
}

// ─── Validation ────────────────────────────────────────────────────────────

interface CharterViolation {
  charter: string;
  code: string;
  detail: string;
}

function validateCharter(
  charterPath: string,
  cveIds: Set<string>,
): CharterViolation[] {
  const violations: CharterViolation[] = [];
  const rel = relative(REPO_ROOT, charterPath);
  const body = readFileSync(charterPath, "utf8");
  const fm = parseFrontmatter(body);

  if (!fm) {
    violations.push({
      charter: rel,
      code: "MISSING_FRONTMATTER",
      detail: "CHARTER.md has no YAML frontmatter delimited by --- blocks",
    });
    return violations;
  }

  // 1. rule_id must agree with implementation.
  const implId = findImplRuleId(dirname(charterPath));
  if (!fm.rule_id) {
    violations.push({ charter: rel, code: "NO_RULE_ID", detail: "frontmatter.rule_id missing" });
  } else if (!implId) {
    violations.push({
      charter: rel,
      code: "NO_IMPL_ID",
      detail: `sibling index.ts has no recognisable rule id (expected ${fm.rule_id})`,
    });
  } else if (implId !== fm.rule_id) {
    violations.push({
      charter: rel,
      code: "ID_MISMATCH",
      detail: `charter.rule_id=${fm.rule_id}, implementation id=${implId}`,
    });
  }

  // 2. interface_version must be v2.
  if (fm.interface_version !== "v2") {
    violations.push({
      charter: rel,
      code: "INTERFACE_VERSION",
      detail: `interface_version must be "v2", got ${JSON.stringify(fm.interface_version)}`,
    });
  }

  // 3. severity must match YAML metadata.
  if (fm.rule_id) {
    const yamlSeverity = loadYamlSeverity(fm.rule_id);
    if (yamlSeverity && fm.severity && yamlSeverity !== fm.severity) {
      violations.push({
        charter: rel,
        code: "SEVERITY_DRIFT",
        detail: `charter.severity=${fm.severity}, rules/${fm.rule_id}-*.yaml severity=${yamlSeverity}`,
      });
    }
  }

  // 4. threat_refs — ≥1 entry; every cve kind exists in cve-manifest.
  if (!fm.threat_refs || fm.threat_refs.length < 1) {
    violations.push({
      charter: rel,
      code: "NO_THREAT_REFS",
      detail: "threat_refs must have at least one entry",
    });
  } else {
    for (const ref of fm.threat_refs) {
      if (ref.kind === "cve") {
        if (!ref.id) {
          violations.push({
            charter: rel,
            code: "CVE_NO_ID",
            detail: "threat_refs entry kind=cve missing id",
          });
        } else if (!cveIds.has(ref.id)) {
          violations.push({
            charter: rel,
            code: "CVE_NOT_IN_MANIFEST",
            detail: `${ref.id} is not registered in docs/cve-manifest.json — add it in the same PR`,
          });
        }
      } else if (ref.kind && ref.kind !== "cve") {
        if (!ref.url || !ref.summary || ref.summary.length < 40) {
          violations.push({
            charter: rel,
            code: "NON_CVE_REF_INCOMPLETE",
            detail: `non-cve threat_ref needs both a url and a summary ≥ 40 chars`,
          });
        }
      }
    }
  }

  // 5. lethal_edge_cases — ≥3 entries.
  if (!fm.lethal_edge_cases || fm.lethal_edge_cases.length < 3) {
    violations.push({
      charter: rel,
      code: "LETHAL_EDGES",
      detail: `lethal_edge_cases must have ≥3 entries, got ${fm.lethal_edge_cases?.length ?? 0}`,
    });
  }

  // 6. edge_case_strategies — ≥1 entry.
  if (!fm.edge_case_strategies || fm.edge_case_strategies.length < 1) {
    violations.push({
      charter: rel,
      code: "STRATEGIES",
      detail: "edge_case_strategies must have ≥1 entry",
    });
  }

  // 7. evidence_contract.minimum_chain.{source,sink} must be true.
  const min = fm.evidence_contract?.minimum_chain ?? {};
  if (min.source !== true || min.sink !== true) {
    violations.push({
      charter: rel,
      code: "EVIDENCE_CONTRACT",
      detail: `evidence_contract.minimum_chain must require source:true and sink:true (got source=${min.source}, sink=${min.sink})`,
    });
  }

  return violations;
}

// ─── Tests ────────────────────────────────────────────────────────────────

describe("charter-traceability guard (analyzer, warn-only in Phase 0)", () => {
  it("cve-manifest exists and parses", () => {
    expect(existsSync(CVE_MANIFEST)).toBe(true);
    const cveIds = loadCveIds();
    expect(cveIds.size).toBeGreaterThan(0);
  });

  it("every CHARTER.md passes the v2 contract", () => {
    const charters = findCharters(IMPL_ROOT);
    if (charters.length === 0) {
      console.info(
        "charter-traceability: zero CHARTER.md files found under packages/analyzer/src/rules/implementations/. " +
          "This is expected during Phase 0 — charters are created in Phase 1 chunks 1.1–1.27.",
      );
      return;
    }

    const cveIds = loadCveIds();
    const allViolations: CharterViolation[] = [];
    for (const charter of charters) {
      allViolations.push(...validateCharter(charter, cveIds));
    }

    if (allViolations.length === 0) return;

    const lines = allViolations.map((v) => `  ${v.charter} [${v.code}] ${v.detail}`);
    const msg = `charter-traceability: ${allViolations.length} violation(s) across ${charters.length} charter(s):\n${lines.join("\n")}`;

    if (STRICT) {
      throw new Error(msg);
    } else {
      console.warn(`[warn-only — ANALYZER_CHARTER_GUARD_STRICT=true to enforce]\n${msg}`);
    }
  });
});
