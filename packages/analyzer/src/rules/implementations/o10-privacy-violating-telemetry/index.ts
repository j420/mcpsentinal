/**
 * O10 — Privacy-Violating Telemetry (Rule Standard v2).
 *
 * Detects (telemetry surface enumeration) × (network-send) within
 * the same enclosing function. Cross-references the shared
 * data-exfil-sink catalogue for env-var bulk reads that compound
 * the surveillance payload.
 *
 * Honest-refusal gate: skips when no network-send primitive is
 * present anywhere in source.
 *
 * Confidence cap: 0.80 per CHARTER. Strong structural signal;
 * legitimate opt-in telemetry exists and a consent-check demotion
 * preserves reviewer headroom.
 *
 * Zero regex literals; all vocabulary in data/telemetry-surfaces.ts.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherO10, type TelemetrySite } from "./gather.js";
import {
  stepInspectSurfaceEnumeration,
  stepInspectNetworkSink,
  stepCheckConsentGate,
} from "./verification.js";

const RULE_ID = "O10";
const RULE_NAME = "Privacy-Violating Telemetry";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Minimise telemetry to what is strictly necessary for the tool's declared " +
  "purpose. Never collect OS / architecture / hostname / username / network " +
  "interface / installed-software / device-identifier surfaces without an " +
  "explicit, per-run, user-approved opt-in. Remove tracking pixels and " +
  "analytics beacons from tool responses. If telemetry is truly needed, " +
  "gate transmission on a consent predicate checked on every emit path, " +
  "document the collected fields in the server's manifest, and aggregate " +
  "before sending (no per-user identifiers). Comply with GDPR Art. 5(1)(c) " +
  "(data minimisation) and EU AI Act Art. 52 (transparency).";

const STRATEGY_SURFACE = "surface-enumeration-vocabulary";
const STRATEGY_SHARED = "exfil-sink-cross-reference";
const STRATEGY_PIXEL = "telemetry-endpoint-or-tracking-pixel";
const STRATEGY_CONSENT = "consent-check-demotion";
const STRATEGY_HONEST_REFUSAL = "honest-refusal-no-network-egress";

const FACTOR_ENUMERATION = "surface_enumeration_observed";
const FACTOR_TRANSMISSION = "transmission_off_box_observed";
const FACTOR_CROSS_SINK = "shared_exfil_sink_cross_reference";
const FACTOR_CONSENT_DEMOTE = "consent_check_demotes";
const FACTOR_PIXEL = "tracking_pixel_in_response";

class O10Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  readonly edgeCaseStrategies = [
    STRATEGY_SURFACE,
    STRATEGY_SHARED,
    STRATEGY_PIXEL,
    STRATEGY_CONSENT,
    STRATEGY_HONEST_REFUSAL,
  ] as const;

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherO10(context);
    if (!gathered.hasNetworkPrimitive) return [];

    // Deduplicate by enclosing-function location — one finding per function.
    const findings: RuleResult[] = [];
    const seen = new Set<string>();
    for (const site of gathered.sites) {
      const key = siteKey(site);
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(this.buildFinding(site));
    }
    return findings.slice(0, 10);
  }

  private buildFinding(site: TelemetrySite): RuleResult {
    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain: this.buildChain(site),
    };
  }

  private buildChain(site: TelemetrySite): EvidenceChain {
    const surfaceCount = site.surfaces.length;
    const surfaceKinds = Array.from(new Set(site.surfaces.map((s) => s.kind)));
    const primarySurface = site.surfaces[0];
    const sourceLocation =
      primarySurface?.location ?? site.networkSink.location;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: sourceLocation,
        observed:
          `${surfaceCount} telemetry surface read(s): ${surfaceKinds.join(", ")} ` +
          `(tokens: ${site.surfaces.slice(0, 5).map((s) => s.token).join(", ")})`,
        rationale:
          `The enclosing function enumerates host-identity surfaces ` +
          `(${surfaceKinds.join(" / ")}) that go beyond the tool's stated ` +
          `functionality. Aggregated over time, the payload identifies the ` +
          `user, machine, and environment the tool runs in — behavioural ` +
          `profiling at surface level (Lakera Q4 2025).`,
      })
      .propagation({
        propagation_type: "function-call",
        location: site.networkSink.location,
        observed:
          `Enumerated surfaces flow to network-send primitive ` +
          `"${site.networkSink.token}" in the same enclosing function. ` +
          (site.envBulk
            ? `A shared env-var exfil sink (process.env-adjacent) is also ` +
              `present in scope — credentials compound the payload.`
            : `No env-var exfil in scope; payload is surface-enumeration only.`),
      })
      .sink({
        sink_type: "network-send",
        location: site.networkSink.location,
        observed:
          site.pixelHint
            ? `Transmission via tracking-pixel URL fragment ` +
              `"${site.pixelHint.token}" in response body.`
            : `Transmission via ${site.networkSink.token}(...) call.`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "user-data",
        exploitability: "trivial",
        scenario:
          `Every invocation of this tool lifts the box's identity fingerprint ` +
          `off the user's machine. Breached.Company's 2026 report attributes ` +
          `77% of corporate AI-tool data leaks to exactly this class of ` +
          `unbounded telemetry. GitGuardian's Secrets Sprawl 2026 reports ` +
          `AI-service-adjacent secret leaks up 81% YoY.`,
      })
      .factor(
        FACTOR_ENUMERATION,
        Math.min(0.04 + Math.min(surfaceCount, 5) * 0.02, 0.12),
        `${surfaceCount} surface enumeration(s) (${surfaceKinds.join(", ")}) ` +
          `observed in the enclosing function ` +
          `(${STRATEGY_SURFACE}).`,
      )
      .factor(
        FACTOR_TRANSMISSION,
        0.10,
        `Network-send primitive "${site.networkSink.token}" present in the ` +
          `same enclosing function; transmission off-box is structurally ` +
          `proven.`,
      )
      .factor(
        FACTOR_CROSS_SINK,
        site.envBulk ? 0.05 : 0.0,
        site.envBulk
          ? `Shared exfil-sink cross-reference (${STRATEGY_SHARED}): env-var ` +
            `bulk tokens also present — the payload compounds credential ` +
            `harvesting.`
          : `No env-var bulk cross-reference; payload is surface-only.`,
      )
      .factor(
        FACTOR_PIXEL,
        site.pixelHint ? 0.04 : 0.0,
        site.pixelHint
          ? `Tracking-pixel / analytics host hint "${site.pixelHint.token}" ` +
            `(${STRATEGY_PIXEL}) in the enclosing scope — confirms ` +
            `transmission is telemetry-shaped.`
          : `No tracking-pixel hint observed; transmission is direct-POST shape.`,
      )
      .factor(
        FACTOR_CONSENT_DEMOTE,
        site.consentFlag ? -0.18 : 0.03,
        site.consentFlag
          ? `Consent identifier "${site.consentFlag}" observed in an ` +
            `enclosing predicate (${STRATEGY_CONSENT}). Finding is demoted; ` +
            `reviewer must verify the predicate is honoured on every emit ` +
            `path.`
          : `No consent predicate in scope — transmission is unconditional.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML-T0057",
        title: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
        url: "https://atlas.mitre.org/techniques/AML.T0057",
        relevance:
          "Behavioural / surface-enumeration telemetry is the highest-" +
          "volume background leakage primitive documented under T0057 for " +
          "agentic tooling.",
      })
      .verification(stepInspectSurfaceEnumeration(site))
      .verification(stepInspectNetworkSink(site))
      .verification(stepCheckConsentGate(site));

    return capConfidence(builder.build(), CONFIDENCE_CAP);
  }
}

function siteKey(site: TelemetrySite): string {
  const loc = site.enclosingFunctionLocation;
  if (loc && loc.kind === "source") return `${loc.file}:${loc.line}`;
  const sink = site.networkSink.location;
  return sink.kind === "source" ? `${sink.file}:${sink.line}` : "module";
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `O10 charter caps confidence at ${cap}. Legitimate opt-in telemetry ` +
      `exists and the consent-check demotion handles the common case; the ` +
      `cap preserves reviewer headroom for non-identifying aggregated metrics.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new O10Rule());

export { O10Rule };
