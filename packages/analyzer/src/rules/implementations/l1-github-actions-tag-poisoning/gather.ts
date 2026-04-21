/**
 * L1 — GitHub Actions Tag Poisoning: deterministic fact gatherer.
 *
 * Parses `.github/workflows/*.yml` via the `yaml` npm package and walks
 * `jobs.<id>.steps[i].uses` + `.run` entries. Every fact carries a
 * `config`-kind Location whose `json_pointer` points at the exact
 * offending key.
 *
 * No regex literals. No string-literal arrays > 5 in this file — the
 * classification vocabularies live under `./data/actions-registry.ts`.
 */

import { parse as parseYaml } from "yaml";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  classifyRef,
  splitUses,
  FIRST_PARTY_ACTION_OWNERS,
  DOWNLOAD_PRIMITIVES,
  RUN_STEP_DANGER_TOKENS,
  type RefFamily,
} from "./data/actions-registry.js";

// ─── Fact types ────────────────────────────────────────────────────────────

export type L1Family =
  | "mutable-tag-branch"
  | "mutable-tag-major"
  | "semver-partial"
  | "expression-interpolated"
  | "pipe-to-shell-in-run";

/** One detected issue inside a workflow file. */
export interface L1Fact {
  /** Config-kind Location pointing at the offending `uses:` or `run:` key. */
  location: Location;
  /** Attack family that matched. */
  family: L1Family;
  /** Human description from the family classifier. */
  description: string;
  /** Owner/repo/ref (uses family) or null (run family). */
  usesRef: { owner: string; repo: string; ref: string } | null;
  /** The offending run-step body (truncated) or uses value. */
  observed: string;
  /** Workflow file path — used for narration but Location is authoritative. */
  file: string;
  /** Whether the Action owner is `actions` or `github` (first-party). */
  firstParty: boolean;
  /** Whether a Harden-Runner step is present anywhere in the same workflow. */
  hardenRunnerPresent: boolean;
}

export interface L1GatherResult {
  mode: "absent" | "facts";
  facts: L1Fact[];
}

// ─── Top-level gather ──────────────────────────────────────────────────────

export function gatherL1(context: AnalysisContext): L1GatherResult {
  const workflowFiles = collectWorkflowFiles(context);
  if (workflowFiles.size === 0) return { mode: "absent", facts: [] };

  const facts: L1Fact[] = [];
  for (const [file, text] of workflowFiles) {
    facts.push(...scanWorkflowFile(file, text));
  }
  return { mode: facts.length > 0 ? "facts" : "absent", facts };
}

/**
 * Find files that look like GitHub Actions workflows. Two strategies:
 *   1. source_files map — prefer when available; filter by path.
 *   2. concatenated source_code — fall back to "does this parse as a
 *      GitHub Actions workflow YAML?" check. We use the presence of a
 *      top-level `jobs` or `on` key after YAML parsing as the signal.
 */
function collectWorkflowFiles(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (isLikelyWorkflowPath(path) || looksLikeWorkflow(text)) {
        out.set(path, text);
      }
    }
    return out;
  }
  if (context.source_code && looksLikeWorkflow(context.source_code)) {
    out.set(".github/workflows/<concatenated>.yml", context.source_code);
  }
  return out;
}

function isLikelyWorkflowPath(path: string): boolean {
  // Path contains `.github/workflows/` AND ends with `.yml` or `.yaml`.
  const hasDir = path.includes(".github/workflows/");
  const isYaml = path.endsWith(".yml") || path.endsWith(".yaml");
  return hasDir && isYaml;
}

function looksLikeWorkflow(text: string): boolean {
  let parsed: unknown;
  try {
    parsed = parseYaml(text);
  } catch {
    return false;
  }
  if (typeof parsed !== "object" || parsed === null) return false;
  const obj = parsed as Record<string, unknown>;
  // A workflow document has a `jobs` key that is itself an object.
  if (typeof obj.jobs !== "object" || obj.jobs === null) return false;
  return true;
}

// ─── Scan one workflow ─────────────────────────────────────────────────────

interface Workflow {
  jobs?: Record<string, WorkflowJob | undefined>;
}

interface WorkflowJob {
  steps?: Array<WorkflowStep | undefined>;
  uses?: string; // for reusable-workflow callers
}

interface WorkflowStep {
  uses?: string;
  run?: string;
  name?: string;
}

function scanWorkflowFile(file: string, text: string): L1Fact[] {
  let parsed: unknown;
  try {
    parsed = parseYaml(text);
  } catch {
    return [];
  }
  if (typeof parsed !== "object" || parsed === null) return [];
  const wf = parsed as Workflow;
  const jobs = wf.jobs ?? {};
  if (typeof jobs !== "object") return [];

  const hardenRunnerPresent = workflowHasHardenRunner(wf);

  const out: L1Fact[] = [];
  for (const [jobId, job] of Object.entries(jobs)) {
    if (!job) continue;
    // Reusable workflow call at the job level: `<job>.uses`.
    if (typeof job.uses === "string") {
      const fact = classifyUses(
        file,
        `/jobs/${escapePointer(jobId)}/uses`,
        job.uses,
        hardenRunnerPresent,
      );
      if (fact) out.push(fact);
    }
    const steps = Array.isArray(job.steps) ? job.steps : [];
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      if (!step) continue;
      if (typeof step.uses === "string") {
        const fact = classifyUses(
          file,
          `/jobs/${escapePointer(jobId)}/steps/${i}/uses`,
          step.uses,
          hardenRunnerPresent,
        );
        if (fact) out.push(fact);
      }
      if (typeof step.run === "string") {
        const runFact = classifyRunBody(
          file,
          `/jobs/${escapePointer(jobId)}/steps/${i}/run`,
          step.run,
          hardenRunnerPresent,
        );
        if (runFact) out.push(runFact);
      }
    }
  }
  return out;
}

function workflowHasHardenRunner(wf: Workflow): boolean {
  const jobs = wf.jobs ?? {};
  for (const job of Object.values(jobs)) {
    if (!job) continue;
    const steps = Array.isArray(job.steps) ? job.steps : [];
    for (const step of steps) {
      if (!step) continue;
      if (typeof step.uses === "string" && step.uses.includes("step-security/harden-runner")) {
        return true;
      }
    }
  }
  return false;
}

function classifyUses(
  file: string,
  pointer: string,
  value: string,
  hardenRunnerPresent: boolean,
): L1Fact | null {
  const parts = splitUses(value);
  if (!parts) return null; // malformed — skip silently
  const family: RefFamily | null = classifyRef(parts.ref);
  if (family === null) return null; // SHA-pinned → safe
  const firstParty = FIRST_PARTY_ACTION_OWNERS.has(parts.owner);
  return {
    location: {
      kind: "config",
      file,
      json_pointer: pointer,
    },
    family: family.family,
    description: family.description,
    usesRef: parts,
    observed: value,
    file,
    firstParty,
    hardenRunnerPresent,
  };
}

function classifyRunBody(
  file: string,
  pointer: string,
  body: string,
  hardenRunnerPresent: boolean,
): L1Fact | null {
  let hasDownload = false;
  let matchedDanger: string | null = null;

  for (const token of DOWNLOAD_PRIMITIVES) {
    if (body.includes(token)) {
      hasDownload = true;
      break;
    }
  }
  if (!hasDownload) return null;
  for (const token of RUN_STEP_DANGER_TOKENS) {
    if (body.includes(token)) {
      matchedDanger = token;
      break;
    }
  }
  if (!matchedDanger) return null;

  return {
    location: {
      kind: "config",
      file,
      json_pointer: pointer,
    },
    family: "pipe-to-shell-in-run",
    description:
      "step's `run:` body downloads remote content and pipes it to a shell interpreter — the canonical CVE-2025-30066 termination",
    usesRef: null,
    observed: body.slice(0, 240),
    file,
    firstParty: false,
    hardenRunnerPresent,
  };
}

/** RFC 6901 escape for `/` and `~` inside a JSON pointer segment. */
function escapePointer(segment: string): string {
  return segment.split("~").join("~0").split("/").join("~1");
}
