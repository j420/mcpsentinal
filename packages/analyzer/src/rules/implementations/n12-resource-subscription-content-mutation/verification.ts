import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { UpdateSite } from "./gather.js";

export function buildEmitInspectionStep(site: UpdateSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open line ${site.line} and confirm ${site.emit_label} emits the ` +
      `mutated resource content to subscribed clients.`,
    target: site.location as Location,
    expected_observation: `Line reads: "${site.line_text}".`,
  };
}

export function buildIntegrityCheckStep(site: UpdateSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Within ±6 lines, search for hash / sha256 / checksum / hmac / ` +
      `verify / signature. If absent, the subscribed client receives ` +
      `mutated content without any integrity evidence.`,
    target: site.location as Location,
    expected_observation:
      site.integrity_present
        ? `Integrity fragment "${site.integrity_label}" found ${site.integrity_distance} ` +
          `line(s) away — confirm coverage.`
        : `No integrity fragment in window — subscribers can't detect ` +
          `the content swap.`,
  };
}

export function buildTOCTOUTraceStep(site: UpdateSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Walk the TOCTOU: at subscribe-time the client agreed to read a ` +
      `specific resource. At update-time, the resource content has changed. ` +
      `Without an integrity binding, the client cannot tell whether the ` +
      `"same" resource now holds different content.`,
    target: site.location as Location,
    expected_observation:
      `Agent ingests mutated content under the trust granted to the ` +
      `original resource — trust boundary is silently invalidated.`,
  };
}
