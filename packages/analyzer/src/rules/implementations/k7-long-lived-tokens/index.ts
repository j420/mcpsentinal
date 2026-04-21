/**
 * K7 — Long-Lived Tokens Without Rotation (v2)
 *
 * Orchestrator. Deduplicates overlapping finding surfaces: when a
 * token-creation call AND an expiry-assignment both point at the same
 * options object, only the more specific token-creation finding is
 * emitted.
 *
 * Zero regex. No string-literal arrays > 5.
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
import { gatherK7, type K7Site } from "./gather.js";
import {
  stepInspectSite,
  stepConfirmDuration,
  stepCheckRotation,
} from "./verification.js";

const RULE_ID = "K7";
const RULE_NAME = "Long-Lived Tokens Without Rotation";
const OWASP = "MCP06-excessive-permissions" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.9;

const REMEDIATION =
  "Bound token lifetimes: access tokens ≤24h, refresh tokens ≤30d. Never " +
  "ship code that sets expiresIn to 0/null/undefined or uses ignoreExpiration: " +
  "true. Pair long-lived refresh tokens with a ROTATION endpoint that issues " +
  "a fresh refresh token on every use and invalidates the predecessor. ISO " +
  "27001 A.8.24 requires cryptographic key lifecycle management; OWASP ASI03 " +
  "and CoSAI MCP-T1 flag persistent tokens as the primary enabler of lateral " +
  "attacker persistence. Example: `jwt.sign(payload, secret, { expiresIn: '1h' })`.";

const REF_ISO_A824 = {
  id: "ISO-27001-A.8.24",
  title: "ISO/IEC 27001:2022 Annex A Control 8.24 — Use of Cryptography",
  url: "https://www.iso.org/standard/82875.html",
  relevance:
    "A.8.24 requires cryptographic key lifecycle management including rotation " +
    "schedules. A JWT issued without an expiry (or with an expiry exceeding " +
    "the rotation policy) defeats the control.",
} as const;

class LongLivedTokensRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK7(context);
    const findings: RuleResult[] = [];
    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      const deduped = dedupe(file.sites);
      for (const site of deduped) {
        findings.push(this.buildFinding(site));
      }
    }
    return findings;
  }

  private buildFinding(site: K7Site): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          site.kind === "token-creation"
            ? `${site.callerLabel}(...) call with ${describeFindingKind(site)}. ` +
              `Under ISO 27001 A.8.24 and OAuth 2.1 BCP, this is a key-lifecycle ` +
              `violation — the token's effective lifetime is outside the policy band.`
            : `Expiry property \`${site.propertyName}\` with ${describeFindingKind(site)}. ` +
              `The property directly configures token lifetime; its effective value ` +
              `sets the attacker persistence window.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: site.location,
        observed: describeFindingKind(site),
      })
      .mitigation({
        mitigation_type: "rate-limit",
        present: false,
        location: site.location,
        detail:
          `No structural indicator of a rotation endpoint colocated with this call. ` +
          `The static analyzer cannot follow runtime wiring; stepCheckRotation ` +
          `lists what to inspect.`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "connected-services",
        exploitability: "moderate",
        scenario:
          `A long-lived (or never-expiring) token remains valid for the entire ` +
          `${site.durationSeconds ? humanDuration(site.durationSeconds) : "unbounded"} ` +
          `window. A single credential leakage (log exposure, memory dump, ` +
          `phished session) grants the attacker that full window of persistent ` +
          `access. When the token carries MCP tool-call authority, every tool ` +
          `invocation in that window is attacker-controlled.`,
      });

    const factor = buildFactor(site);
    builder.factor(factor.factor, factor.adjustment, factor.rationale);
    if (site.isRefreshToken) {
      builder.factor(
        "refresh_class_threshold",
        -0.03,
        `Classifier inferred refresh-token context — threshold is 30 days, not 24 hours, ` +
          `so the finding is relative to the looser refresh-class ceiling.`,
      );
    }
    if (site.findingKind === "disabled-expiry" || site.findingKind === "no-expiry") {
      builder.factor(
        "no_rotation_possible",
        0.07,
        `Without an expiry, rotation has no enforcement anchor — even a perfect ` +
          `rotation endpoint cannot invalidate a token with no \`exp\` claim.`,
      );
    }

    builder.reference(REF_ISO_A824);
    builder.verification(stepInspectSite(site));
    builder.verification(stepConfirmDuration(site));
    builder.verification(stepCheckRotation(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

// ─── Dedup ─────────────────────────────────────────────────────────────────

function dedupe(sites: K7Site[]): K7Site[] {
  // Sort so token-creation sites come first at any given line — they carry
  // more narrative than a bare expiry-assignment.
  const byLineKind = [...sites].sort((a, b) => {
    const la = a.location.kind === "source" ? a.location.line : 0;
    const lb = b.location.kind === "source" ? b.location.line : 0;
    if (la !== lb) return la - lb;
    return a.kind === "token-creation" ? -1 : 1;
  });
  const seen = new Set<number>();
  const out: K7Site[] = [];
  for (const site of byLineKind) {
    const line = site.location.kind === "source" ? site.location.line : 0;
    // Suppress an `expiry-assignment` on a line that ALREADY has a
    // `token-creation` finding (same options object).
    if (site.kind === "expiry-assignment") {
      if (seen.has(line) || anyCreationNearby(byLineKind, line)) continue;
    }
    seen.add(line);
    out.push(site);
  }
  return out;
}

function anyCreationNearby(sites: K7Site[], line: number): boolean {
  // A token-creation call spans multiple lines (args object). If any
  // token-creation site's line is within 10 lines BEFORE this expiry
  // assignment, treat the expiry as its dependent.
  for (const s of sites) {
    if (s.kind !== "token-creation") continue;
    const sLine = s.location.kind === "source" ? s.location.line : 0;
    if (sLine <= line && line - sLine <= 10) return true;
  }
  return false;
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function describeFindingKind(site: K7Site): string {
  switch (site.findingKind) {
    case "no-expiry":
      return "no expiry configured (token never expires unless explicitly revoked)";
    case "disabled-expiry":
      return "expiry explicitly disabled (zero / null / undefined / ignoreExpiration:true)";
    case "excessive-expiry":
      return `excessive access-token lifetime: ${humanDuration(site.durationSeconds ?? 0)} (> 24h policy)`;
    case "excessive-expiry-refresh":
      return `excessive refresh-token lifetime: ${humanDuration(site.durationSeconds ?? 0)} (> 30d policy)`;
  }
}

function humanDuration(seconds: number): string {
  if (seconds === 0) return "0 seconds";
  if (seconds >= 31536000) return `${(seconds / 31536000).toFixed(1)} years`;
  if (seconds >= 86400) return `${Math.round(seconds / 86400)} days`;
  if (seconds >= 3600) return `${Math.round(seconds / 3600)} hours`;
  return `${seconds} seconds`;
}

function buildFactor(site: K7Site): { factor: string; adjustment: number; rationale: string } {
  switch (site.findingKind) {
    case "no-expiry":
      return {
        factor: "no_expiry_on_token_call",
        adjustment: 0.15,
        rationale: "Token-creation call carries no expiry at all — immortal token class.",
      };
    case "disabled-expiry":
      return {
        factor: "explicitly_disabled_expiry",
        adjustment: 0.14,
        rationale:
          "Expiry is present but explicitly disabled (ignoreExpiration:true, value 0/null/undefined).",
      };
    case "excessive-expiry":
      return {
        factor: "excessive_access_token_lifetime",
        adjustment: 0.10,
        rationale:
          `Access-class lifetime ${humanDuration(site.durationSeconds ?? 0)} exceeds ` +
          `the 24h policy ceiling.`,
      };
    case "excessive-expiry-refresh":
      return {
        factor: "excessive_refresh_token_lifetime",
        adjustment: 0.08,
        rationale:
          `Refresh-class lifetime ${humanDuration(site.durationSeconds ?? 0)} exceeds ` +
          `the 30d policy ceiling.`,
      };
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K7 charter caps confidence at ${cap} — runtime wrappers may inject ` +
      `shorter lifetimes (middleware, HSM-enforced limits). Static analysis ` +
      `cannot prove the absence of those wrappers.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new LongLivedTokensRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { LongLivedTokensRule };
