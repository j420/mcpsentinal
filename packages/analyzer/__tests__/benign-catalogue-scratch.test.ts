/**
 * Scratch test for iterating on the benign catalogue. NOT part of the
 * committed corpus — kept during development only and deleted before
 * commit. Prints ALL findings (not just critical/high) so I can see
 * whether allowed_findings needs declaring.
 */
import { describe, it, expect } from "vitest";
import { getAllTypedRules } from "../src/rules/base.js";
import "../src/rules/index.js";
import { benignCatalogue } from "./__fixtures__/benign/index.js";
import type { BenignFixture } from "./__fixtures__/benign/index.js";

interface FindingRow {
  fixture_id: string;
  rule_id: string;
  severity: string;
  evidence: string;
}

function scanAll(fx: BenignFixture): FindingRow[] {
  const out: FindingRow[] = [];
  for (const rule of getAllTypedRules()) {
    try {
      const findings = rule.analyze(fx.context);
      for (const f of findings) {
        out.push({
          fixture_id: fx.id,
          rule_id: f.rule_id,
          severity: f.severity,
          evidence: f.evidence.slice(0, 120),
        });
      }
    } catch {
      // tolerate rule errors
    }
  }
  return out;
}

describe("benign catalogue — scratch findings dump", () => {
  it("prints findings per fixture", () => {
    const allRows: FindingRow[] = [];
    for (const fx of benignCatalogue) {
      const rows = scanAll(fx);
      allRows.push(...rows);
    }
    const bySev: Record<string, FindingRow[]> = {};
    for (const r of allRows) {
      (bySev[r.severity] ??= []).push(r);
    }
    for (const sev of ["critical", "high", "medium", "low", "informational"]) {
      const rows = bySev[sev] ?? [];
      // eslint-disable-next-line no-console
      console.log(`\n=== ${sev.toUpperCase()} (${rows.length}) ===`);
      for (const r of rows.slice(0, 40)) {
        // eslint-disable-next-line no-console
        console.log(`  [${r.rule_id}] ${r.fixture_id} — ${r.evidence}`);
      }
      if (rows.length > 40) {
        // eslint-disable-next-line no-console
        console.log(`  ... and ${rows.length - 40} more`);
      }
    }
    expect(bySev.critical ?? []).toEqual([]);
    expect(bySev.high ?? []).toEqual([]);
  });
});
