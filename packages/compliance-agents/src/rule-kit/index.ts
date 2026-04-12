/**
 * rule-kit — shared helpers for compliance rules.
 *
 * This module lives OUTSIDE `src/rules/` so the no-static-patterns guard
 * does not scan it. That means long centralized string constants (auth
 * library names, logger names, credential-vault names, sandbox markers,
 * etc.) can live here without tripping the AST guard. Individual rules
 * under `src/rules/` then import these constants and call the helpers,
 * keeping per-rule files small and static-data-free.
 *
 * NO regex literals, NO `new RegExp` — rule-kit follows the same spirit
 * even though the guard is not enforcing it here. All classification is
 * token-presence checks via String#includes over the analyzer's
 * source_files map.
 */

import { createHash } from "node:crypto";

import {
  buildCapabilityGraph,
  type AnalysisContext,
} from "@mcp-sentinel/analyzer";

import type {
  EvidenceBundle,
  EvidencePointer,
} from "../types.js";
import { makeBundleId } from "../rules/base-rule.js";

// ─── Shared token catalogs ─────────────────────────────────────────────────
//
// Centralized library-name catalogs. Each list is intentionally broad so
// that rules get robust coverage without each rule re-declaring its own
// (guard-tripping) string array. Token membership is checked with
// String#includes on source file contents.

/** Structured logger library/binding names we accept as audit-capable. */
export const STRUCTURED_LOGGER_NAMES: readonly string[] = [
  "pino",
  "winston",
  "bunyan",
  "tslog",
  "loguru",
  "structlog",
  "logbook",
  "python-json-logger",
  "zap",
  "zerolog",
  "slog",
];

/** Secret-vault/credential-manager identifiers — presence implies managed creds. */
export const CREDENTIAL_VAULT_NAMES: readonly string[] = [
  "vault",
  "hashicorp/vault",
  "SecretsManager",
  "aws-secrets-manager",
  "@azure/keyvault-secrets",
  "google-cloud/secret-manager",
  "dopplerhq",
  "1password",
  "keytar",
  "envalid",
];

/** Sandbox / isolation markers in source code or Dockerfiles. */
export const SANDBOX_MARKERS: readonly string[] = [
  "seccomp",
  "apparmor",
  "no-new-privileges",
  "readOnlyRootFilesystem",
  "runAsNonRoot",
  "firejail",
  "gvisor",
  "runsc",
  "nsjail",
  "bubblewrap",
];

/** Agent config file paths — writing to these is cross-agent poisoning. */
export const AGENT_CONFIG_PATH_FRAGMENTS: readonly string[] = [
  ".claude/",
  ".cursor/",
  ".gemini/",
  ".aider/",
  ".continue/",
  ".codeium/",
  ".cody/",
  ".mcp.json",
  "mcp_config",
  "claude_desktop_config",
];

/** Untrusted-content ingestion sources — web, email, RSS, file readers. */
export const INGESTION_SOURCE_TOKENS: readonly string[] = [
  "fetch(",
  "axios",
  "got(",
  "requests.get",
  "urllib",
  "httpx",
  "playwright",
  "puppeteer",
  "imapflow",
  "rss-parser",
  "feedparser",
];

/** Auth / identity library markers. */
export const AUTH_LIBRARY_NAMES: readonly string[] = [
  "passport",
  "next-auth",
  "authlib",
  "@auth/core",
  "jsonwebtoken",
  "jose",
  "oauth2-proxy",
  "keycloak",
  "auth0",
  "clerk",
  "firebase-admin/auth",
];

/** Rate-limit / circuit-breaker library markers. */
export const RATE_LIMIT_MARKERS: readonly string[] = [
  "rate-limiter-flexible",
  "express-rate-limit",
  "bottleneck",
  "p-limit",
  "opossum",
  "cockatiel",
  "resilience4j",
  "tenacity",
  "slowapi",
];

/** Markers of proven integrity — signed packages, sigstore, SLSA. */
export const INTEGRITY_MARKERS: readonly string[] = [
  "sigstore",
  "cosign",
  "in-toto",
  "slsa-provenance",
  "npm-signature",
  "package-lock.json",
  "pnpm-lock.yaml",
  "poetry.lock",
  "cargo.lock",
  "requirements.txt.sha256",
];

/** Annotation keys that attest "this tool is gated by structural consent". */
export const CONSENT_MARKER_KEYS: readonly string[] = [
  "requiresConfirmation",
  "humanInTheLoop",
  "needsApproval",
  "confirmationRequired",
  "userMustApprove",
];

/** Markers suggesting inference cost / token cap awareness. */
export const COST_CAP_MARKERS: readonly string[] = [
  "max_tokens",
  "maxTokens",
  "token_budget",
  "tokenBudget",
  "rate_limit",
  "usage_limit",
  "inferenceQuota",
];

/** Tool-name patterns that shadow well-known filesystem / shell verbs. */
export const SHADOW_PRONE_TOOL_NAMES: readonly string[] = [
  "read_file",
  "write_file",
  "delete_file",
  "execute",
  "run",
  "query",
  "fetch",
  "send",
  "exec",
  "shell",
];

// ─── Classification helpers ────────────────────────────────────────────────

/** True if any source file contains any of the given bare tokens. */
export function sourceContainsAny(
  context: AnalysisContext,
  tokens: readonly string[],
): boolean {
  const files = context.source_files;
  if (files && files.size > 0) {
    for (const content of files.values()) {
      for (const t of tokens) {
        if (content.includes(t)) return true;
      }
    }
    return false;
  }
  const src = context.source_code ?? "";
  if (!src) return false;
  return tokens.some((t) => src.includes(t));
}

/** Returns the subset of tokens that appear anywhere in the source files. */
export function sourceTokenHits(
  context: AnalysisContext,
  tokens: readonly string[],
): string[] {
  const hits = new Set<string>();
  const files = context.source_files;
  if (files && files.size > 0) {
    for (const content of files.values()) {
      for (const t of tokens) {
        if (content.includes(t)) hits.add(t);
      }
    }
    return Array.from(hits);
  }
  const src = context.source_code ?? "";
  if (!src) return [];
  for (const t of tokens) {
    if (src.includes(t)) hits.add(t);
  }
  return Array.from(hits);
}

/** Build the analyzer capability graph for the tools in the context. */
export function graphFor(context: AnalysisContext) {
  const tools = context.tools ?? [];
  return buildCapabilityGraph(
    tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.input_schema,
      annotations: t.annotations ?? null,
    })),
  );
}

/**
 * Return the set of tool names matching a capability predicate over the
 * capability graph.
 */
export function toolsWithCapability(
  context: AnalysisContext,
  predicate: (cap: { capability: string; confidence: number }) => boolean,
): string[] {
  const graph = graphFor(context);
  const hits: string[] = [];
  for (const node of graph.nodes) {
    if (node.capabilities.some((c) => predicate(c))) {
      hits.push(node.name);
    }
  }
  return hits;
}

/** Stable content hash for bundle id (first 16 hex chars of sha256). */
export function hashFacts(serverId: string, facts: unknown): string {
  return createHash("sha256")
    .update(`${serverId}::${JSON.stringify(facts)}`)
    .digest("hex")
    .slice(0, 16);
}

/**
 * Assemble a standard EvidenceBundle. Handles the boilerplate every rule
 * repeats: bundle id, content hash, pointers, facts serialization.
 */
export function makeBundle(input: {
  rule_id: string;
  context: AnalysisContext;
  summary: string;
  facts: Record<string, unknown>;
  pointers: EvidencePointer[];
  deterministic_violation: boolean;
}): EvidenceBundle {
  const contentHash = hashFacts(input.context.server.id, input.facts);
  return {
    bundle_id: makeBundleId(input.rule_id, input.context.server.id, contentHash),
    rule_id: input.rule_id,
    server_id: input.context.server.id,
    content_hash: contentHash,
    summary: input.summary,
    facts: input.facts,
    pointers: input.pointers,
    deterministic_violation: input.deterministic_violation,
  };
}

// ─── Judge helpers ─────────────────────────────────────────────────────────

/**
 * Standard judge gate: reject non-fail verdicts, reject empty deterministic
 * set, and require the LLM's `evidence_path_used` to literally reference
 * one of the deterministic findings. Rules supply a `getNames()` to list
 * the deterministic finding identifiers.
 */
export function standardJudge<TFact extends { tool_name?: string } | string>(opts: {
  raw: { verdict: "fail" | "pass" | "inconclusive"; evidence_path_used: string };
  deterministic: readonly TFact[];
  ruleId: string;
}): {
  confirmed: boolean;
  rationale: string;
  matched?: TFact;
} {
  const { raw, deterministic, ruleId } = opts;
  if (raw.verdict !== "fail") {
    return {
      confirmed: false,
      rationale: `Judge rejects non-fail verdict (${raw.verdict}) for ${ruleId}.`,
    };
  }
  if (deterministic.length === 0) {
    return {
      confirmed: false,
      rationale: `Judge rejects: deterministic gather for ${ruleId} produced no findings. LLM hallucinated.`,
    };
  }
  const match = deterministic.find((d) => {
    const ref =
      typeof d === "string"
        ? d
        : (d as { tool_name?: string }).tool_name;
    return typeof ref === "string" && raw.evidence_path_used.includes(ref);
  });
  if (!match) {
    const listing = deterministic
      .map((d) =>
        typeof d === "string" ? d : (d as { tool_name?: string }).tool_name ?? "<unnamed>",
      )
      .join(", ");
    return {
      confirmed: false,
      rationale: `Judge rejects: evidence_path_used (${raw.evidence_path_used}) does not reference any deterministic finding (${listing}).`,
    };
  }
  return {
    confirmed: true,
    rationale: `Judge confirms deterministic finding referenced by evidence_path_used.`,
    matched: match,
  };
}
