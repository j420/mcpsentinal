/**
 * L5 — Package Manifest Confusion (Rule Standard v2).
 *
 * Orchestrator. Consumes structural facts from gather.ts and emits one
 * RuleResult per L5 primitive. Certain primitives (bin-system-shadow,
 * bin-hidden-target, exports-divergence) additionally emit an L14
 * companion finding — the L14 entry in its own directory is a
 * stub TypedRuleV2 whose analyze() returns [] because this rule is
 * the source of truth for both IDs. This matches the wave-2 companion
 * pattern (I1→I2, F1→F2/F3/F6).
 *
 * Zero regex. Confidence cap 0.85 per CHARTER §"Why confidence is
 * capped at 0.85".
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
import { gatherL5, type L5Context, type L5Primitive, type L5PrimitiveKind } from "./gather.js";
import {
  stepCheckProvenance,
  stepInspectManifestContext,
  stepInspectPrimitive,
} from "./verification.js";

const RULE_ID = "L5";
const RULE_NAME = "Package Manifest Confusion";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0017" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Verify publisher integrity end-to-end. (1) Run `npm publish --provenance` " +
  "so the tarball carries a Sigstore attestation; set publishConfig.provenance: " +
  "true so the flag is implicit. (2) Audit every script under scripts.{prepublish, " +
  "prepublishOnly, prepack, prepare} and remove any sed/jq/node -e/mv/perl " +
  "command that touches package.json — the only safe operations there are build " +
  "tools (tsc, esbuild, rollup, webpack, vite, babel, swc). (3) Rename bin " +
  "entries that shadow system commands (git, node, npm, curl, ssh, sudo, …) and " +
  "never point a bin target at a dot-prefixed or __-prefixed file. (4) Remove " +
  "`exports[\"./package.json\"]: null` — downstream audit tools need to read the " +
  "installed manifest. (5) For dual CJS/ESM builds, keep import and require " +
  "branches functionally equivalent — divergent payloads are the exports-map " +
  "abuse pattern documented by Socket.dev (2025).";

// L14 remediation is the subset that talks to the entry-point primitives only.
const L14_REMEDIATION =
  "Ensure every entry-point field (main, module, exports, bin) points at the " +
  "same logical code path. Never declare a bin entry whose name shadows a " +
  "system command, whose target filename starts with `.` or `__`, or whose " +
  "conditional-export branches serve different logical modules.";

function classifyPrimitive(kind: L5PrimitiveKind): {
  sinkType: "code-evaluation" | "command-execution" | "config-modification";
  impactType: "remote-code-execution" | "config-poisoning";
  impactScope: "server-host" | "connected-services";
  severity: "critical" | "high";
  exploitability: "trivial" | "moderate";
} {
  switch (kind) {
    case "prepublish-manifest-mutation":
      return {
        sinkType: "config-modification",
        impactType: "config-poisoning",
        impactScope: "connected-services",
        severity: "high",
        exploitability: "moderate",
      };
    case "bin-system-shadow":
      return {
        sinkType: "command-execution",
        impactType: "remote-code-execution",
        impactScope: "server-host",
        severity: "high",
        exploitability: "moderate",
      };
    case "bin-hidden-target":
      return {
        sinkType: "command-execution",
        impactType: "remote-code-execution",
        impactScope: "server-host",
        severity: "high",
        exploitability: "moderate",
      };
    case "exports-divergence":
      return {
        sinkType: "code-evaluation",
        impactType: "remote-code-execution",
        impactScope: "connected-services",
        severity: "critical",
        exploitability: "moderate",
      };
    case "exports-package-json-block":
      return {
        sinkType: "config-modification",
        impactType: "config-poisoning",
        impactScope: "connected-services",
        severity: "high",
        exploitability: "moderate",
      };
  }
}

function impactScenario(kind: L5PrimitiveKind, ctx: L5Context): string {
  switch (kind) {
    case "prepublish-manifest-mutation":
      return (
        "The prepublish (or prepublishOnly / prepack / prepare) script runs on " +
        "the publisher's machine between `git push` and tarball upload. When it " +
        "rewrites package.json, the manifest that appears on npmjs.com (which " +
        "reviewers inspect) diverges from the manifest inside the installed " +
        "tarball (which consumers actually run). Darcy Clarke's July 2023 " +
        "disclosure documented this gap as still unpatched; JFrog's 2024 " +
        "follow-up confirmed 800+ live examples. The divergence can conceal " +
        "dependency injection, bin-field swaps, or scripts.postinstall additions."
      );
    case "bin-system-shadow":
      return (
        "After installation — particularly `npm install -g` or any package that " +
        "is linked into a shared node_modules/.bin — this bin entry is symlinked " +
        "onto the PATH ahead of the real system command. Every invocation of the " +
        "shadowed command (by developers at the terminal, by CI scripts, by " +
        "Makefiles, by downstream tooling that shells out) runs the package's " +
        "code with the caller's full privileges. Historical npm hijacking " +
        "incidents (2024-2025) used precisely this primitive."
      );
    case "bin-hidden-target":
      return (
        "The bin entry executes a file whose name starts with `.` or `__`, so " +
        "directory listings and tarball extractions hide it from reviewers by " +
        "default. The visible package appears to contain only the declared " +
        "source; the actual code path that runs when the bin command is invoked " +
        "is the hidden file, making post-install auditing unreliable."
      );
    case "exports-divergence":
      return (
        "Node's conditional exports map serves different files to ESM and CJS " +
        "consumers. Divergent paths with a payload-shaped filename in one branch " +
        "let a publisher ship clean code to reviewers (who examine the import " +
        "path via vitest/esbuild) and backdoored code to consumers (whose " +
        "bundler resolves to require). Socket.dev's 2025 research documented " +
        "live examples of this dual-format supply-chain attack."
      );
    case "exports-package-json-block":
      return (
        "`exports[\"./package.json\"]: null` blocks audit tooling (socket-cli, " +
        "dependency-cruiser, npm outdated) from reading the installed manifest. " +
        "Any other manifest-confusion primitive in the same manifest — " +
        "prepublish mutation, bin hijack, conditional-export payload — can no " +
        "longer be cross-checked against the source-of-truth file after install." +
        (ctx.hasProvenanceField
          ? " Sigstore provenance is present but only binds build source to " +
            "tarball; it does not restore post-install audit access."
          : "")
      );
  }
}

class ManifestConfusionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherL5(context);
    if (gathered.isTestFile) return [];

    const out: RuleResult[] = [];
    for (const ctx of gathered.contexts) {
      for (const primitive of ctx.primitives) {
        out.push(this.buildFinding(RULE_ID, "high", primitive, ctx));
        if (primitive.emitL14Companion) {
          out.push(this.buildFinding("L14", "high", primitive, ctx));
        }
      }
    }
    return out;
  }

  private buildFinding(
    ruleId: string,
    _requested: "high" | "critical",
    primitive: L5Primitive,
    ctx: L5Context,
  ): RuleResult {
    const c = classifyPrimitive(primitive.kind);
    const isL14 = ruleId === "L14";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: ctx.manifestLocation,
        observed: ctx.fromPackageJsonFile
          ? `package.json manifest`
          : `manifest literal at this position`,
        rationale: isL14
          ? `The package manifest declares an entry-point field (bin or exports) ` +
            `whose target mismatches the apparent declaration. L14 isolates the ` +
            `entry-point-mismatch subset of L5's manifest confusion attacks; the ` +
            `finding is emitted here so reviewers searching under "entry-point " +
            "mismatch" see the same primitive L5 flagged.`
          : `The package manifest declares a primitive (${primitive.kind}) that ` +
            `enables divergence between the registry-served manifest and the ` +
            `tarball-installed manifest. Darcy Clarke (July 2023) and JFrog ` +
            `(2024) documented that npm serves these two views independently ` +
            `with no cryptographic binding — CWE-345.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: primitive.location,
        observed:
          primitive.kind === "prepublish-manifest-mutation"
            ? `npm lifecycle: prepublish → pack → publish — mutation runs before tarball creation`
            : primitive.kind === "bin-system-shadow" || primitive.kind === "bin-hidden-target"
              ? `npm install → bin symlink creation → PATH precedence`
              : primitive.kind === "exports-divergence"
                ? `Node.js module resolution → conditional exports → CJS vs ESM consumer split`
                : `Audit-tool resolution → exports["./package.json"] → blocked`,
      })
      .sink({
        sink_type: c.sinkType,
        location: primitive.location,
        observed: primitive.observed,
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: ctx.hasProvenanceField,
        location: ctx.manifestLocation,
        detail: ctx.hasProvenanceField
          ? `publishConfig.provenance: true is set. Sigstore attestation binds ` +
            `the build source to the tarball — it mitigates opaque tarball swaps ` +
            `but does not bind the registry manifest view to the tarball manifest.`
          : `No publishConfig.provenance field; npm serves the registry and ` +
            `tarball manifests without cryptographic binding (CWE-345).`,
      })
      .impact({
        impact_type: c.impactType,
        scope: c.impactScope,
        exploitability: c.exploitability,
        scenario: impactScenario(primitive.kind, ctx),
      })
      .factor(
        "manifest_shape_confirmed",
        0.08,
        ctx.fromPackageJsonFile
          ? `Fact observed in an actual package.json file — manifest shape is certain.`
          : `Fact observed in an object-literal whose shape matches a package manifest.`,
      )
      .factor(
        "primitive_classified",
        0.12,
        `Primitive identified: ${primitive.kind} — ${primitive.detail}`,
      )
      .factor(
        ctx.hasProvenanceField ? "provenance_present" : "publisher_integrity_gap",
        ctx.hasProvenanceField ? -0.1 : 0.08,
        ctx.hasProvenanceField
          ? `publishConfig.provenance: true — partial mitigation via Sigstore.`
          : `No publisher integrity attestation — the primitive lands unchecked.`,
      )
      .reference({
        id: "Clarke-npm-Manifest-Confusion-2023",
        title: "Darcy Clarke: npm Manifest Confusion (July 2023, still unpatched)",
        url: "https://blog.vlt.sh/blog/the-massive-hole-in-the-npm-ecosystem",
        year: 2023,
        relevance:
          `The disclosure describes npm's structural gap between registry and ` +
          `tarball manifests. Every L5 primitive is an instance of the class ` +
          `Clarke documented. CWE-345 (Insufficient Verification of Data ` +
          `Authenticity) is the formal framing.`,
      })
      .verification(stepInspectManifestContext(ctx))
      .verification(stepInspectPrimitive(primitive))
      .verification(stepCheckProvenance(ctx));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: ruleId,
      severity: isL14 ? "high" : c.severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: isL14 ? L14_REMEDIATION : REMEDIATION,
      chain,
    };
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `L5 charter caps confidence at ${cap}. A prepublish may legitimately stamp ` +
      `version metadata into package.json; a bin named "git" may be intentionally ` +
      `shadowing git locally; a conditional export divergence may be a benign ` +
      `dual-format build. Static analysis cannot always distinguish these from ` +
      `the malicious primitive without runtime provenance.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ManifestConfusionRule());

export { ManifestConfusionRule };
