/**
 * C1 verification-step builders — every step's `target` is a structured
 * Location (v2 standard §4). An auditor reading the chain should be able
 * to open each target, look at the observation text, and confirm or
 * refute the step without re-running the scanner.
 *
 * Step catalogue (one builder per CHARTER.md evidence-contract verb):
 *
 *   stepInspectSource      — open the AST source node (req.body.x, argv[n]).
 *   stepInspectSink        — open the exec/eval/spawn call site.
 *   stepTracePath          — enumerate the propagation hops between them.
 *   stepInspectSanitizer   — open the sanitiser call on the path (only when
 *                            sanitised=true; CHARTER edge case #2 requires
 *                            the sanitiser be visible to a reviewer rather
 *                            than silently trusted).
 *   stepInspectRegexMatch  — when we degraded to regex fallback, jump to
 *                            the matched line so the reviewer can decide
 *                            whether taint is plausible in-context.
 *
 * No regex literals. No string-literal arrays > 5. Every step is concrete —
 * CHARTER.md forbids prose like "check the flow"; the instruction must name
 * a file, a line, and what the reviewer will observe.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { ASTFinding, ASTPathStep, RegexFinding } from "./gather.js";

/**
 * Step 1 — open the untrusted-source AST node.
 *
 * A reviewer disputing the finding starts here: if the "source" is
 * actually a hardcoded literal, the chain collapses.
 */
export function stepInspectSource(astFinding: ASTFinding): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file and confirm the expression at this position really is an ` +
      `untrusted ${astFinding.sourceCategory} source (HTTP body/query/params, ` +
      `process.argv, process.env, MCP tool parameter). If the node is a ` +
      `hardcoded literal or a trusted constant, the taint chain does not hold.`,
    target: astFinding.sourceLocation,
    expected_observation:
      `The expression \`${truncate(astFinding.sourceExpression, 120)}\` is read ` +
      `from an external input surface categorised by the taint analyser as ` +
      `${astFinding.sourceCategory}.`,
  };
}

/**
 * Step 2 — open the command-execution / code-evaluation sink.
 *
 * This is the target of the CVE precedent cited on the chain
 * (CVE-2025-6514 for `exec`, CVE-2017-5941 for `eval`/`vm.run*`).
 */
export function stepInspectSink(astFinding: ASTFinding): VerificationStep {
  const sinkVerb =
    astFinding.sinkCategory === "vm_escape"
      ? "dynamic code evaluation"
      : "shell / subprocess execution";
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file and confirm the call at this position is ${sinkVerb} ` +
      `receiving the value produced by the source above. Safe argv-form ` +
      `equivalents (execFile with an array, spawn with shell=false, ` +
      `subprocess.run([...], shell=False)) are NOT sinks and would have ` +
      `caused the taint analyser to skip the call — their presence here ` +
      `would be a scanner bug.`,
    target: astFinding.sinkLocation,
    expected_observation:
      `A ${sinkVerb} call of the form \`${truncate(astFinding.sinkExpression, 120)}\` ` +
      `whose argument derives from the source at the previous step.`,
  };
}

/**
 * Step 3 — enumerate every propagation hop the taint analyser walked.
 *
 * The trace-flow step is special: its target is the first hop, but the
 * `expected_observation` lists every hop so an auditor can corroborate
 * the path without re-running the analyser. Multi-hop flows list each
 * hop's file:line on its own line for clean diff-style reading.
 */
export function stepTracePath(astFinding: ASTFinding): VerificationStep {
  const steps = astFinding.path;
  const firstTarget: Location =
    steps.length > 0 ? steps[0].location : astFinding.sinkLocation;
  const observation =
    steps.length === 0
      ? `Direct source→sink flow (zero propagation hops). The source and ` +
        `the sink are the same argument of the same call — CHARTER.md ` +
        `exploitability = "trivial".`
      : `Walk the following ${steps.length} hop(s) in order and confirm each ` +
        `is an assignment, destructure, return, parameter bind, or template ` +
        `embed that carries the tainted value forward: ` +
        steps.map(renderHop).join(" → ");
  return {
    step_type: "trace-flow",
    instruction:
      `Follow the propagation chain the AST taint analyser reported. Each ` +
      `hop must be a real data-flow step (not an unrelated line that happens ` +
      `to mention the variable name). A broken hop invalidates the chain.`,
    target: firstTarget,
    expected_observation: observation,
  };
}

/**
 * Step 4 — inspect the sanitiser on the path.
 *
 * Emitted only when `sanitized=true`. CHARTER.md lethal edge case #2
 * (sanitizer-identity bypass) requires the sanitiser definition itself
 * be surfaced to a reviewer — a function named `escapeShell` that
 * returns its argument unchanged must be caught here, not at scan time.
 */
export function stepInspectSanitizer(astFinding: ASTFinding): VerificationStep {
  const name = astFinding.sanitizerName ?? "<anonymous>";
  const charterKnown = astFinding.sanitizerIsCharterKnown;
  const instruction = charterKnown
    ? `The sanitiser \`${name}\` is on the CHARTER-recognised list of real ` +
      `shell escapers (POSIX quoting contract). Confirm the binding resolves ` +
      `to the library function and not a locally-shadowed identifier — an ` +
      `override that imports \`${name}\` but re-exports a no-op still gets ` +
      `picked up by name alone.`
    : `The sanitiser \`${name}\` is NOT on the CHARTER list of audited shell ` +
      `escapers. Open its definition and confirm it actually escapes shell ` +
      `metacharacters (backslash, semicolon, ampersand, pipe, dollar sign, ` +
      `backtick, glob chars, newline, tab). If it only calls toString() or ` +
      `JSON.stringify() it is NOT a sanitiser and the finding should be ` +
      `re-escalated from informational to critical per CHARTER edge case #2.`;
  return {
    step_type: "inspect-source",
    instruction,
    target: astFinding.sinkLocation,
    expected_observation: charterKnown
      ? `\`${name}\` is imported from a CHARTER-audited module and invoked ` +
        `on the tainted value before it reaches the sink.`
      : `\`${name}\` is a project-local helper whose body a reviewer MUST ` +
        `audit before accepting the informational severity.`,
  };
}

/**
 * Step 5 — open the line that matched a regex-fallback sink.
 *
 * Used when AST taint produced zero command flows and the scanner fell
 * back to the FALLBACK_SINKS registry. A reviewer must confirm taint
 * plausibility by hand — CHARTER "regex-fallback-degradation" strategy.
 */
export function stepInspectRegexMatch(regexFinding: RegexFinding): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `The AST taint analyser could not confirm a flow (typically because the ` +
      `source and sink live in different files, or the file did not parse). ` +
      `Open this line and decide by hand whether the matched pattern ` +
      `(${regexFinding.sink.description}) receives an untrusted value. ` +
      `If the argument is a hardcoded string literal, dismiss as a false ` +
      `positive; if the argument is a variable sourced from external input, ` +
      `the finding should be re-raised at critical severity.`,
    target: regexFinding.location,
    expected_observation:
      `Line text: \`${truncate(regexFinding.lineText, 160)}\`. Matched token: ` +
      `\`${truncate(regexFinding.matchText, 80)}\`. Sink category: ` +
      `${regexFinding.sink.sinkType}.`,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function renderHop(step: ASTPathStep): string {
  const loc = step.location;
  const pos = loc.kind === "source" ? `${loc.file}:${loc.line}` : "<non-source>";
  return `${step.type}@${pos} (${truncate(step.expression, 60)})`;
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}
