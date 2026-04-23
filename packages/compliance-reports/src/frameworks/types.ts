import type { Severity } from "@mcp-sentinel/database";
import type { FrameworkId } from "../types.js";

/**
 * Static description of one control within a compliance framework. The
 * registry is intentionally typed (not dynamically loaded from YAML)
 * because (a) regulators need stable, reviewable definitions that
 * version-control diffs cleanly, and (b) unit tests verify
 * `assessor_rule_ids` against real YAML rule files in `rules/`.
 */
export interface FrameworkControl {
  control_id: string;
  control_name: string;
  /** ≤500 char paraphrase or quote of the control text. */
  control_description: string;
  source_url: string;
  /**
   * Rule ids that ASSESS this control. Multiple rules may map to one
   * control. Empty array + `// NO ASSESSOR RULE` comment means the
   * control is uncovered and will render as `not_applicable` — an
   * honest gap, not a silent omission.
   */
  assessor_rule_ids: string[];
  /**
   * When any assessor rule fires at or above this severity, the control
   * defaults to `unmet`. Lower-severity findings map to `partial`.
   */
  unmet_threshold: Severity;
}

export interface Framework {
  id: FrameworkId;
  name: string;
  version: string;
  /** ISO date (YYYY-MM-DD) that this registry entry was last reviewed. */
  last_updated: string;
  source_url: string;
  controls: FrameworkControl[];
}
