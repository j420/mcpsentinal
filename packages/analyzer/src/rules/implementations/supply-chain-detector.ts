/**
 * Supply Chain Integrity Detector — MIGRATED (Phase 1, Chunk 1.11).
 *
 * All four rules previously housed in this file (L5, L12, L14, K10) were
 * migrated to Rule Standard v2 in Phase 1 Chunk 1.11 and now live in
 * their own directories:
 *
 *   L5  → packages/analyzer/src/rules/implementations/l5-manifest-confusion/
 *   L12 → packages/analyzer/src/rules/implementations/l12-build-artifact-tampering/
 *   L14 → packages/analyzer/src/rules/implementations/l14-hidden-entry-point-mismatch/
 *   K10 → packages/analyzer/src/rules/implementations/k10-package-registry-substitution/
 *
 * L14 remains a stub TypedRuleV2 (companion to L5). The L5 rule emits
 * L14 findings during its manifest scan — see the L14 CHARTER.md for
 * the companion-rule rationale.
 *
 * This file is an empty tombstone. The orchestrator removes the
 * `import "./implementations/supply-chain-detector.js";` line from
 * `packages/analyzer/src/rules/index.ts` and deletes this file in the
 * cleanup commit for Chunk 1.11 (per
 * docs/sub-agent-orchestration.md §"Orchestrator cleanup commit").
 */

export {};
