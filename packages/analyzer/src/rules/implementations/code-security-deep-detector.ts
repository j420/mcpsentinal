/**
 * Code Security Deep Detector — MIGRATION IN PROGRESS (Phase 1, Chunk 1.18)
 *
 * The four rules previously implemented here (C2, C5, C10, C14) have been
 * migrated to individual Rule Standard v2 rule directories:
 *
 *   - c2-path-traversal/
 *   - c5-hardcoded-secrets/
 *   - c10-prototype-pollution/
 *   - c14-jwt-algorithm-confusion/
 *
 * This file is retained temporarily so `packages/analyzer/src/rules/index.ts`
 * continues to build during the migration. The orchestrator cleanup commit
 * deletes this file and replaces its import line with four new imports,
 * one per migrated rule.
 */

export {};
