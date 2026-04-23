/**
 * CHARTER.md frontmatter writer.
 *
 * Reads `docs/mutations/latest.json` and updates every rule's CHARTER.md
 * frontmatter with two new keys, appended as the LAST two frontmatter
 * entries before the closing `---`:
 *
 *   mutations_survived:
 *     - <mutation-id>
 *     - ...
 *   mutations_acknowledged_blind:
 *     - <mutation-id>
 *     - ...
 *
 * Not-applicable and error outcomes are deliberately excluded from the
 * CHARTER — those are debugging signals, not detection claims. The CHARTER
 * records ONLY what the rule did and did not catch.
 *
 * Idempotent: running the writer a second time replaces the prior two keys
 * in place (not appending duplicates). The writer never touches the prose
 * body below the frontmatter.
 *
 * Invoked by:
 *   pnpm --filter=@mcp-sentinel/red-team exec tsx \
 *     src/mutation/charter-writer.ts --report=docs/mutations/latest.json
 */

import { existsSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import type { MutationId, MutationReport, PerRuleSummary } from "./types.js";

const MARKER_SURVIVED = "mutations_survived:";
const MARKER_BLIND = "mutations_acknowledged_blind:";

interface CharterLocation {
  absPath: string;
  frontmatterEndLine: number; // zero-indexed line number of the closing `---`
  lines: string[];
}

export function locateCharter(absPath: string): CharterLocation | null {
  if (!existsSync(absPath)) return null;
  const text = readFileSync(absPath, "utf8");
  const lines = text.split(/\r?\n/);
  if (lines[0] !== "---") return null;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i] === "---") {
      return { absPath, frontmatterEndLine: i, lines };
    }
  }
  return null;
}

/**
 * Decide whether a line is a list-entry continuation under a YAML key. We
 * accept lines whose first non-whitespace character is `-` (list entry),
 * `#` (comment), or that contain a trailing inline-comment after the entry
 * text. No regex — a left-to-right character walk keeps this in line with
 * the project's no-static-patterns convention.
 */
function isListEntryLine(line: string): boolean {
  let i = 0;
  while (i < line.length && (line[i] === " " || line[i] === "\t")) i++;
  if (i >= line.length) return false;
  return line[i] === "-" || line[i] === "#";
}

/**
 * A line with a top-level YAML key (non-indented, contains `:`). Used to
 * stop the list-continuation scan when the prior block ends at a new key.
 */
function isTopLevelKeyLine(line: string): boolean {
  if (line.length === 0) return false;
  if (line[0] === " " || line[0] === "\t" || line[0] === "-") return false;
  return line.includes(":");
}

/**
 * Remove any previously-inserted mutations_survived / mutations_acknowledged_blind
 * blocks from the frontmatter. Returns the line array with those blocks
 * stripped. A "block" here is the marker line plus all subsequent list-entry
 * lines up to the first line that is either a top-level key, the closing
 * `---`, or a blank line that's followed by a top-level key.
 *
 * Also supports the inline form `mutations_survived: []` which is one line.
 */
function stripPriorMutationBlocks(loc: CharterLocation): CharterLocation {
  const out: string[] = [];
  let i = 0;
  const closeIdx = loc.frontmatterEndLine;
  while (i < loc.lines.length) {
    const line = loc.lines[i];
    // Only strip blocks before the closing `---`.
    if (i >= closeIdx) {
      out.push(line);
      i++;
      continue;
    }
    const isMarker = line.startsWith(MARKER_SURVIVED) || line.startsWith(MARKER_BLIND);
    if (!isMarker) {
      out.push(line);
      i++;
      continue;
    }
    // Inline-empty form: `mutations_survived: []`
    if (line.includes("[]")) {
      i++;
      continue;
    }
    // Block form: marker line then list entries.
    i++;
    while (i < closeIdx && (isListEntryLine(loc.lines[i]) || loc.lines[i].trim() === "")) {
      // Stop if we hit a blank line followed by a top-level key — that blank
      // line belongs to the next block's separator, not ours.
      if (loc.lines[i].trim() === "") {
        const next = loc.lines[i + 1] ?? "";
        if (isTopLevelKeyLine(next) || next === "---") {
          break;
        }
      }
      i++;
    }
  }
  const newEnd = out.findIndex((l, idx) => idx > 0 && l === "---");
  return { absPath: loc.absPath, frontmatterEndLine: newEnd === -1 ? closeIdx : newEnd, lines: out };
}

function renderBlock(marker: string, ids: MutationId[]): string[] {
  if (ids.length === 0) {
    // Emit an empty-list form that's still valid YAML and still reviewable
    // ("we ran the audit and the list was empty" vs. "we skipped this rule").
    return [`${marker} []`];
  }
  const out: string[] = [marker];
  for (const id of ids) out.push(`  - ${id}`);
  return out;
}

/**
 * Write the mutation frontmatter block into a CHARTER. Returns true if the
 * file was modified, false if it was already up to date.
 */
export function writeCharterMutations(
  absPath: string,
  summary: PerRuleSummary,
): { modified: boolean; absPath: string } {
  const loc = locateCharter(absPath);
  if (!loc) return { modified: false, absPath };

  const stripped = stripPriorMutationBlocks(loc);
  const survivedBlock = renderBlock(MARKER_SURVIVED, summary.survived);
  const blindBlock = renderBlock(MARKER_BLIND, summary.acknowledged_blind);

  const insertAt = stripped.frontmatterEndLine;
  const before = stripped.lines.slice(0, insertAt);
  const after = stripped.lines.slice(insertAt);

  // Ensure there's a single blank line separator before the mutation blocks
  // to keep the frontmatter readable.
  let sep: string[] = [];
  if (before.length === 0 || before[before.length - 1].trim() !== "") {
    sep = [""];
  }

  const next = [
    ...before,
    ...sep,
    ...survivedBlock,
    ...blindBlock,
    ...after,
  ].join("\n");

  const prev = loc.lines.join("\n");
  if (prev === next) return { modified: false, absPath };
  writeFileSync(absPath, next, "utf8");
  return { modified: true, absPath };
}

/**
 * Walk the implementations directory, match each rule-dir to a PerRuleSummary
 * entry, and update the CHARTER. Returns counts of (modified, unchanged,
 * missing-charter, missing-summary) for logging.
 */
export function sweepAllCharters(
  implementationsDir: string,
  report: MutationReport,
): { modified: number; unchanged: number; missingCharter: number; missingSummary: number } {
  const byId = new Map<string, PerRuleSummary>();
  for (const s of report.per_rule_summary) byId.set(s.rule_id, s);

  let modified = 0;
  let unchanged = 0;
  let missingCharter = 0;
  let missingSummary = 0;

  const entries = readdirSync(implementationsDir, { withFileTypes: true });
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    if (e.name === "_shared") continue;
    const match = e.name.match(/^([a-z]\d+)-/);
    if (!match) continue;
    const id = match[1].toUpperCase();
    const charterPath = join(implementationsDir, e.name, "CHARTER.md");
    if (!existsSync(charterPath)) {
      missingCharter += 1;
      continue;
    }
    const summary = byId.get(id);
    if (!summary) {
      missingSummary += 1;
      continue;
    }
    const res = writeCharterMutations(charterPath, summary);
    if (res.modified) modified += 1;
    else unchanged += 1;
  }

  return { modified, unchanged, missingCharter, missingSummary };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let reportPath = "";
  let implDir = "";
  for (const arg of args) {
    if (arg.startsWith("--report=")) reportPath = arg.slice("--report=".length);
    else if (arg.startsWith("--implementations=")) implDir = arg.slice("--implementations=".length);
  }
  if (!reportPath) {
    // Default relative to the NEAREST ancestor containing both packages/ and
    // tsconfig.base.json. Inside a worktree the source-file location is at
    // .claude/worktrees/<id>/packages/red-team/src/mutation/, so walking up
    // from this file finds the worktree-local packages/ first; falling back
    // to the outer repo only if no such local marker exists.
    let dir = dirname(new URL(import.meta.url).pathname);
    for (let i = 0; i < 20; i++) {
      if (existsSync(join(dir, "packages")) && existsSync(join(dir, "tsconfig.base.json"))) {
        reportPath = join(dir, "docs", "mutations", "latest.json");
        if (!implDir) implDir = join(dir, "packages", "analyzer", "src", "rules", "implementations");
        break;
      }
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  if (!reportPath || !existsSync(reportPath)) {
    process.stderr.write(`charter-writer: report not found at ${reportPath}\n`);
    process.exit(2);
  }
  if (!implDir) {
    process.stderr.write(`charter-writer: implementations dir not found\n`);
    process.exit(2);
  }
  const report = JSON.parse(readFileSync(reportPath, "utf8")) as MutationReport;
  const stats = sweepAllCharters(implDir, report);
  process.stderr.write(
    `charter-writer: modified=${stats.modified} unchanged=${stats.unchanged} missingCharter=${stats.missingCharter} missingSummary=${stats.missingSummary}\n`,
  );
}

// ESM direct-execution detection without relying on import.meta.main (not
// available in tsx's Node target). We check if the resolved process.argv[1]
// ends with this file's URL path.
const runDirect = process.argv[1] && new URL(import.meta.url).pathname === process.argv[1];
if (runDirect) {
  main().catch((err) => {
    process.stderr.write(`charter-writer: fatal: ${err instanceof Error ? err.stack : String(err)}\n`);
    process.exit(1);
  });
}
