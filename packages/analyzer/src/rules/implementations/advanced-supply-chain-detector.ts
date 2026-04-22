/**
 * Advanced Supply Chain Detector — FULLY MIGRATED (Phase 1 chunks 1.9 and 1.10).
 *
 * All eight rules that once lived in this file have been migrated to per-
 * rule Rule Standard v2 directories. This file is retained as a tombstone
 * so the import statement in `rules/index.ts` remains valid; the
 * orchestrator cleanup commit will drop the import and delete this file
 * outright.
 *
 * Migrations:
 *
 *   Phase 1, Chunk 1.9:
 *     L1  → implementations/l1-github-actions-tag-poisoning/
 *     L2  → implementations/l2-malicious-build-plugin/
 *     L6  → implementations/l6-config-symlink-attack/
 *     L13 → implementations/l13-build-credential-file-theft/
 *
 *   Phase 1, Chunk 1.10:
 *     L7  → implementations/l7-transitive-mcp-delegation/
 *     K3  → implementations/k3-audit-log-tampering/
 *     K5  → implementations/k5-auto-approve-bypass/
 *     K8  → implementations/k8-cross-boundary-credential-sharing/
 */

export {};
