/**
 * C1 regex-fallback sink lexicon.
 *
 * Loaded at module scope by gather.ts. Every entry is the "what we scan for
 * when AST taint analysis could not confirm a source→sink flow". The guard
 * hides regex literals from the no-static-patterns check by storing them
 * in `data/` (a directory the guard explicitly skips — see
 * __tests__/no-static-patterns.test.ts line 66).
 *
 * The entries are a Record, not an array, to stay structurally consistent
 * with the K1 reference pattern (data is a registry, keys mean something).
 *
 * Severity for every fallback match is "high" (not critical) per CHARTER.md
 * strategy `regex-fallback-degradation` — an AST-unconfirmed match is less
 * trustworthy than an AST-confirmed source→sink taint flow and must carry
 * the negative `regex_only` factor to signal that gap.
 */

export interface FallbackSink {
  /** Short identifier used in evidence narratives. */
  id: string;
  /** Compiled pattern. */
  pattern: RegExp;
  /** Human-readable description for SinkLink.observed. */
  description: string;
  /**
   * Base confidence before global `regex_only` adjustment is applied. The
   * regex fallback path in index.ts always subtracts 0.15 for `regex_only`,
   * so the effective floor is (baseConfidence − 0.15).
   */
  baseConfidence: number;
  /**
   * Which sink category the finding should carry. Matches SinkLink.sink_type.
   */
  sinkType: "command-execution" | "code-evaluation";
  /** A short narrative fragment used in the impact scenario text. */
  impactFragment: string;
}

/**
 * Seven canonical fallback patterns — the intersection of:
 *   1. patterns the AST taint analyser is known to miss, and
 *   2. patterns with real CVE precedent documented in the charter.
 *
 * Adding a pattern: append a new property here, then run
 * `pnpm test c1-evidence-chains` to verify the fallback tests pass.
 */
export const FALLBACK_SINKS: Record<string, FallbackSink> = {
  templateLiteralInExec: {
    id: "template-literal-in-exec",
    pattern: /exec(?:Sync)?\s*\(`[^`]*\$\{/g,
    description: "template literal in exec()",
    baseConfidence: 0.8,
    sinkType: "command-execution",
    impactFragment: "a template literal substitutes a variable directly into the shell command",
  },
  variableInExec: {
    id: "variable-in-exec",
    pattern: /exec(?:Sync)?\s*\(\s*(?!['"`])(\w+)/g,
    description: "variable passed to exec()",
    baseConfidence: 0.6,
    sinkType: "command-execution",
    impactFragment: "a non-literal identifier is the first argument to exec()",
  },
  spawnShellTrue: {
    id: "spawn-shell-true",
    pattern: /spawn(?:Sync)?\s*\([^)]*shell\s*:\s*true/g,
    description: "spawnSync with shell: true",
    baseConfidence: 0.75,
    sinkType: "command-execution",
    impactFragment: "spawn/spawnSync is invoked with shell:true, which pipes the argv through /bin/sh -c",
  },
  vmRunInContext: {
    id: "vm-run-in-context",
    pattern: /vm\.run(?:InNewContext|InThisContext|InContext)\s*\(/g,
    description: "vm.runInNewContext with potential user input",
    baseConfidence: 0.65,
    sinkType: "code-evaluation",
    impactFragment: "vm.run* executes an arbitrary string as JavaScript in a sandbox with documented escape primitives",
  },
  subprocessShellTrue: {
    id: "subprocess-shell-true",
    pattern: /subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True/g,
    description: "subprocess with shell=True",
    baseConfidence: 0.7,
    sinkType: "command-execution",
    impactFragment: "Python subprocess is invoked with shell=True, enabling shell interpolation on the argv",
  },
  osSystemVariable: {
    id: "os-system-variable",
    pattern: /os\.system\s*\(\s*(?!['"`])(\w+)/g,
    description: "variable passed to os.system()",
    baseConfidence: 0.65,
    sinkType: "command-execution",
    impactFragment: "os.system receives a non-literal argument and forwards it to /bin/sh",
  },
  shelljsExec: {
    id: "shelljs-exec",
    pattern: /shell\.exec\s*\(/g,
    description: "shelljs exec()",
    baseConfidence: 0.6,
    sinkType: "command-execution",
    impactFragment: "shelljs.exec is a convenience wrapper around child_process.exec and inherits the same argv-string vulnerability",
  },
};
