/**
 * J2 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import {
  stepInspectTaintSource,
  stepInspectTaintSink,
  stepTraceTaintPath,
  stepInspectTaintSanitiser,
} from "../_shared/taint-rule-kit/index.js";
import type { J2Fact } from "./gather.js";

export function stepInspectGitSource(fact: J2Fact): VerificationStep {
  return stepInspectTaintSource(fact);
}

export function stepInspectGitSink(fact: J2Fact): VerificationStep {
  const detail = fact.dangerousFlag
    ? `a git invocation whose arguments include the dangerous flag \`${fact.dangerousFlag}\` — this is the CVE-2025-68145 primitive`
    : fact.sensitivePath
      ? `a git invocation that touches the sensitive path \`${fact.sensitivePath}\` — this is the CVE-2025-68144 primitive`
      : `a git invocation (exec / spawn / subprocess with argv[0] == "git") whose arguments are tainted`;
  return stepInspectTaintSink(fact, detail);
}

export function stepTraceGitPath(fact: J2Fact): VerificationStep {
  return stepTraceTaintPath(fact);
}

export function stepInspectGitSanitiser(fact: J2Fact): VerificationStep | null {
  return stepInspectTaintSanitiser(fact);
}
