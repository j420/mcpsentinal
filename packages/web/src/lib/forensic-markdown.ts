/**
 * forensic-markdown.ts — Build a copy-pasteable audit pack from a
 * deep-dive finding.
 *
 * The output is a single markdown document an auditor can paste straight
 * into their compliance package, ticket system, or shared notes. It is
 * deliberately verbose: the goal is for the artefact to stand on its
 * own — a regulator reading just the markdown should be able to verify
 * the finding without re-opening the registry.
 *
 * Pure function. No DOM, no fetch, no async. Same inputs → byte-equal
 * output, byte-equal hash. The drawer's "Copy verification as markdown"
 * button calls this and pipes the result into navigator.clipboard.
 */

import type {
  DeepDiveFinding,
  DeepDiveProvenance,
  DeepDiveRule,
} from "./deep-dive";

export interface BuildAuditPackInput {
  serverSlug: string;
  serverName: string;
  rule: DeepDiveRule;
  finding: DeepDiveFinding;
  provenance: DeepDiveProvenance | undefined;
  /** API origin used for receipt + canonical URL building. */
  apiOrigin: string;
}

/** Try to lift a string field off the evidence chain JSON without
 *  asserting the chain's full shape. Returns null on missing/non-string. */
function pluckString(
  obj: Record<string, unknown> | null | undefined,
  key: string,
): string | null {
  if (!obj) return null;
  const v = obj[key];
  return typeof v === "string" && v.length > 0 ? v : null;
}

/** Try to lift an array of structured "verification step" entries off
 *  the evidence chain. Each step's `instruction` becomes one checklist
 *  bullet. Defensive — any non-string instruction is dropped. */
function pluckVerificationSteps(
  chain: Record<string, unknown> | null | undefined,
): string[] {
  if (!chain) return [];
  const raw = chain["verification_steps"];
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const step of raw) {
    if (!step || typeof step !== "object") continue;
    const s = step as Record<string, unknown>;
    const instruction =
      typeof s["instruction"] === "string" ? s["instruction"] : null;
    if (instruction && instruction.length > 0) out.push(instruction);
  }
  return out;
}

/** Try to lift `confidence_factors[]` off the evidence chain so we can
 *  render the confidence ledger inside the audit pack. Each factor is
 *  `{ factor, adjustment, rationale }`. Defensive on every read. */
function pluckConfidenceFactors(
  chain: Record<string, unknown> | null | undefined,
): Array<{ factor: string; adjustment: number; rationale: string }> {
  if (!chain) return [];
  const raw = chain["confidence_factors"];
  if (!Array.isArray(raw)) return [];
  const out: Array<{ factor: string; adjustment: number; rationale: string }> = [];
  for (const f of raw) {
    if (!f || typeof f !== "object") continue;
    const r = f as Record<string, unknown>;
    const factor = typeof r["factor"] === "string" ? r["factor"] : "";
    const adjustment =
      typeof r["adjustment"] === "number" ? r["adjustment"] : null;
    const rationale =
      typeof r["rationale"] === "string" ? r["rationale"] : "";
    if (factor && adjustment !== null) {
      out.push({ factor, adjustment, rationale });
    }
  }
  return out;
}

function fmtSeverity(sev: string): string {
  return sev.charAt(0).toUpperCase() + sev.slice(1);
}

function fmtConfidence(c: number): string {
  if (typeof c !== "number" || !Number.isFinite(c)) return "—";
  return `${Math.round(c * 100)}%`;
}

/** Build the audit-pack markdown. */
export function buildAuditPackMarkdown(input: BuildAuditPackInput): string {
  const { serverSlug, serverName, rule, finding, provenance, apiOrigin } =
    input;
  const chain = (finding.evidence_chain ?? null) as
    | Record<string, unknown>
    | null;

  const lines: string[] = [];

  // ── Header ───────────────────────────────────────────────────────
  lines.push(`# Finding ${rule.rule_id} — ${rule.name}`);
  lines.push("");
  lines.push(`**Server:** ${serverName} (\`${serverSlug}\`)`);
  lines.push(`**Severity:** ${fmtSeverity(finding.severity)}`);
  lines.push(`**Confidence:** ${fmtConfidence(finding.confidence)}`);
  if (rule.owasp) lines.push(`**OWASP:** ${rule.owasp}`);
  if (rule.mitre) lines.push(`**MITRE ATLAS:** ${rule.mitre}`);
  lines.push(`**Finding ID:** \`${finding.id}\``);
  lines.push("");

  // ── Evidence (prose) ─────────────────────────────────────────────
  lines.push("## Evidence");
  lines.push("");
  lines.push(finding.evidence);
  lines.push("");

  // ── Why this matters ─────────────────────────────────────────────
  const impactScenario =
    pluckString(chain, "impact_scenario") ??
    pluckString(chain, "impact") ??
    null;
  if (impactScenario) {
    lines.push("## Why this matters");
    lines.push("");
    lines.push(impactScenario);
    lines.push("");
  }

  // ── How to verify (the actionable checklist) ─────────────────────
  const steps = pluckVerificationSteps(chain);
  lines.push("## How to verify");
  lines.push("");
  if (steps.length > 0) {
    for (const step of steps) {
      lines.push(`- [ ] ${step}`);
    }
  } else {
    // Honest fallback when the engine didn't emit structured steps —
    // give the auditor at least the location + sink to inspect.
    lines.push(
      `- [ ] Locate the evidence in source: ${finding.evidence}`,
    );
    lines.push(
      `- [ ] Confirm the sink is reachable from user-controllable input`,
    );
    lines.push(`- [ ] Confirm no upstream sanitiser exists`);
  }
  lines.push("");

  // ── Confidence ledger ────────────────────────────────────────────
  const factors = pluckConfidenceFactors(chain);
  if (factors.length > 0) {
    lines.push("## Confidence ledger");
    lines.push("");
    lines.push("| Factor | Adjustment | Rationale |");
    lines.push("|---|---:|---|");
    for (const f of factors) {
      const sign = f.adjustment >= 0 ? "+" : "";
      lines.push(
        `| ${f.factor.replace(/_/g, " ")} | ${sign}${f.adjustment.toFixed(2)} | ${f.rationale.replace(/\|/g, "\\|")} |`,
      );
    }
    lines.push(`| **Final** | **${fmtConfidence(finding.confidence)}** | |`);
    lines.push("");
  }

  // ── Remediation ──────────────────────────────────────────────────
  if (finding.remediation) {
    lines.push("## Remediation");
    lines.push("");
    lines.push(finding.remediation);
    lines.push("");
  } else if (rule.remediation) {
    lines.push("## Remediation (rule-level)");
    lines.push("");
    lines.push(rule.remediation);
    lines.push("");
  }

  // ── CVE replay validation (if present) ───────────────────────────
  if (rule.validated_by_cve && rule.validated_by_cve.length > 0) {
    lines.push("## CVE replay validation");
    lines.push("");
    lines.push("This rule has been validated against the following replays:");
    lines.push("");
    for (const v of rule.validated_by_cve) {
      const cvss =
        typeof v.cvss_v3 === "number" && Number.isFinite(v.cvss_v3)
          ? ` · CVSS ${v.cvss_v3.toFixed(1)}`
          : "";
      lines.push(
        `- [${v.id}](${v.source_url}) — ${v.title} (disclosed ${v.disclosed}${cvss})`,
      );
    }
    lines.push("");
  }

  // ── Framework cross-walk ─────────────────────────────────────────
  if (rule.framework_controls && rule.framework_controls.length > 0) {
    lines.push("## Framework cross-walk");
    lines.push("");
    for (const fc of rule.framework_controls) {
      lines.push(`- ${fc.framework_id}: **${fc.control_id}** — ${fc.control_title}`);
    }
    lines.push("");
  }

  // ── Provenance + signed receipt ──────────────────────────────────
  lines.push("## Provenance & attestation");
  lines.push("");
  if (provenance) {
    if (provenance.scan_id) lines.push(`- **Scan:** \`${provenance.scan_id}\``);
    if (provenance.scan_completed_at)
      lines.push(`- **Completed:** ${provenance.scan_completed_at}`);
    if (provenance.rules_version)
      lines.push(`- **Rules version:** \`${provenance.rules_version}\``);
    lines.push(`- **Sentinel:** \`${provenance.sentinel_version}\``);
    lines.push(`- **Signing key id:** \`${provenance.signing_key_id}\``);
    lines.push(`- **Algorithm:** HMAC-SHA256 (RFC 8785 canonicalisation)`);
  } else {
    lines.push(
      "_Provenance metadata not on file for this scan._",
    );
  }
  lines.push("");
  lines.push(
    `**Signed receipt:** ${apiOrigin}/api/v1/findings/${encodeURIComponent(finding.id)}/receipt`,
  );
  lines.push("");
  lines.push(
    "Verify offline by recomputing the HMAC over the canonicalised receipt JSON. The signing key id above identifies the secret to use.",
  );
  lines.push("");

  // ── Footer ──────────────────────────────────────────────────────
  lines.push("---");
  lines.push("");
  lines.push(
    `_Generated from MCP Sentinel Deep Dive · ${apiOrigin.replace(/^https?:\/\//, "")}_`,
  );

  return lines.join("\n");
}
