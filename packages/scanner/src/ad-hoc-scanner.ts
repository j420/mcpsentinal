/**
 * P21 — Public Scan Surface Engineer
 * ad-hoc-scanner.ts — the shared, DB-free ephemeral scan core.
 *
 * Composes the three stateless cores — MCPConnector.enumerate,
 * AnalysisEngine.analyzeWithProfile, computeScore — into a single
 * `runAdHocScan()` entry point that scans an MCP server from one of three
 * inputs: a live URL, a pasted MCP client config, or a GitHub/npm/PyPI
 * source reference.
 *
 * This module does NOT touch the database. Callers (the CLI, the API job
 * runner) own persistence. The API job runner additionally registers the
 * result in the public registry — see packages/api/src/scan-job-runner.ts.
 *
 * SAFETY (ADR-007): only initialize + tools/list are ever called. Every
 * live URL is passed through `assertSafe()` (SSRF guard) before any socket
 * opens. There is no dynamic tool invocation here.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import pino from "pino";
import {
  AnalysisEngine,
  loadRules,
  getRulesVersion,
} from "@mcp-sentinel/analyzer";
import type {
  AnalysisContext,
  ProfiledAnalysisResult,
} from "@mcp-sentinel/analyzer";

/** Analysis coverage as produced by `analyzeWithProfile()`. */
type AnalysisCoverage = ProfiledAnalysisResult["coverage"];
import { MCPConnector } from "@mcp-sentinel/connector";
import { computeScore } from "@mcp-sentinel/scorer";
import type { ScoreResult } from "@mcp-sentinel/scorer";
import { SourceFetcher } from "./fetcher.js";
import { DependencyAuditor } from "./auditor.js";
import { assertSafe, parseAndValidate } from "./url-guard.js";

const logger = pino({ name: "scanner:ad-hoc" }, process.stderr);

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const DEFAULT_RULES_DIR = path.resolve(__dirname, "../../../rules");

const CONNECT_TIMEOUT_MS = 30_000;
/** Hard ceiling on servers scanned from one config — prevents abuse. */
const MAX_CONFIG_SERVERS = 20;

// ─── Input / output contract ─────────────────────────────────────────────────

export type AdHocScanInput =
  | { kind: "url"; url: string }
  | { kind: "config"; config: string }
  | { kind: "source"; ref: string };

/** One finding, flattened for transport + persistence. */
export interface AdHocFinding {
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  evidence: string;
  remediation: string;
  owasp_category: string | null;
  mitre_technique: string | null;
  confidence: number;
  evidence_chain: unknown | null;
}

/** Server capability profile summary — surfaced for CLI output + the web UI. */
export interface ScannedServerProfile {
  attack_surfaces: string[];
  capabilities: Array<{ capability: string; confidence: number }>;
  threats: string[];
  /** Total findings before relevance filtering. */
  raw_findings: number;
  /** Findings filtered out as irrelevant / not meeting the evidence standard. */
  filtered_findings: number;
}

/** The result of scanning one MCP server. */
export interface ScannedServer {
  name: string;
  endpoint: string | null;
  github_url: string | null;
  npm_package: string | null;
  pypi_package: string | null;
  connection_success: boolean;
  connection_error: string | null;
  /** MCP initialize serverInfo.version, when a live connection was made. */
  server_version: string | null;
  tool_count: number;
  tools: Array<{
    name: string;
    description: string | null;
    input_schema: Record<string, unknown> | null;
  }>;
  score: ScoreResult;
  findings: AdHocFinding[];
  coverage: AnalysisCoverage;
  profile: ScannedServerProfile;
}

export interface AdHocScanResult {
  input_type: AdHocScanInput["kind"];
  rules_version: string;
  servers: ScannedServer[];
  /** stdio config entries that cannot be scanned server-side. */
  unscannable_stdio: Array<{ name: string; reason: string }>;
  /** Non-fatal per-server problems (e.g. one config entry failed). */
  warnings: string[];
}

/** Thrown for input-level failures that make the whole scan unrunnable. */
export class AdHocScanError extends Error {
  constructor(
    message: string,
    public readonly reason: string,
  ) {
    super(message);
    this.name = "AdHocScanError";
  }
}

/**
 * Turn a raw MCP connection error into a clear, user-facing failure.
 *
 * Auth-required servers — the common case for hosted enterprise MCP servers
 * (Supabase, Notion, Linear, …) — get an explicit explanation instead of a
 * raw transport error: the public scanner connects anonymously and cannot
 * scan a server that demands an OAuth token or API key.
 */
function describeConnectionFailure(
  label: string,
  rawError: string | null,
): { message: string; reason: string } {
  const err = rawError ?? "unknown error";
  const looksLikeAuth =
    /unauthorized|invalid[_ ]token|missing.{0,30}token|access token|\b401\b|\b403\b|forbidden/i.test(
      err,
    );
  if (looksLikeAuth) {
    return {
      reason: "auth-required",
      message:
        `${label} requires authentication. The public scanner connects ` +
        `anonymously (initialize + tools/list only, with no credentials) and ` +
        `cannot scan MCP servers that require an OAuth token or API key.`,
    };
  }
  return {
    reason: "connection-failed",
    message: `Could not connect to the MCP server at ${label}: ${err}`,
  };
}

// ─── Engine (lazily loaded + cached) ─────────────────────────────────────────

interface ScanEngine {
  engine: AnalysisEngine;
  ruleCategories: Record<string, string>;
  ruleEngineV2: Record<string, boolean>;
  rulesVersion: string;
}

let cachedEngine: ScanEngine | null = null;

/**
 * Build (or return the cached) analysis engine. Rule loading is filesystem
 * work; doing it once per process keeps each ad-hoc scan fast.
 */
export function getScanEngine(rulesDir: string = DEFAULT_RULES_DIR): ScanEngine {
  if (cachedEngine) return cachedEngine;
  const rules = loadRules(rulesDir);
  if (rules.length === 0) {
    throw new AdHocScanError(
      `No detection rules found in ${rulesDir}`,
      "no-rules",
    );
  }
  const ruleCategories: Record<string, string> = {};
  const ruleEngineV2: Record<string, boolean> = {};
  for (const rule of rules) {
    ruleCategories[rule.id] = rule.category;
    if (rule.engine_v2) ruleEngineV2[rule.id] = true;
  }
  cachedEngine = {
    engine: new AnalysisEngine(rules),
    ruleCategories,
    ruleEngineV2,
    rulesVersion: getRulesVersion(rules),
  };
  return cachedEngine;
}

// ─── Public entry point ──────────────────────────────────────────────────────

/**
 * Run an ad-hoc scan. Throws `AdHocScanError` / `UrlGuardError` on
 * input-level failures (bad URL, bad config JSON, SSRF rejection,
 * unresolvable source ref, nothing scannable). A server that simply could
 * not be reached is reported as a `ScannedServer` with
 * `connection_success: false`, not thrown.
 */
export async function runAdHocScan(
  input: AdHocScanInput,
  rulesDir?: string,
): Promise<AdHocScanResult> {
  const scanEngine = getScanEngine(rulesDir);

  switch (input.kind) {
    case "url":
      return scanUrlInput(input.url, scanEngine);
    case "config":
      return scanConfigInput(input.config, scanEngine);
    case "source":
      return scanSourceInput(input.ref, scanEngine);
  }
}

/**
 * Scan one live MCP endpoint and return a `ScannedServer`.
 *
 * This is the lower-level shared core: it does NOT apply the SSRF guard.
 * Callers exposed to untrusted input (the public `/api/v1/scan` path) MUST
 * call `assertSafe()` first — `runAdHocScan` does. The CLI uses this
 * function directly because scanning `localhost` is a legitimate
 * local-developer workflow, not an SSRF risk.
 */
export async function scanEndpoint(
  endpoint: string,
  displayName?: string,
  rulesDir?: string,
): Promise<ScannedServer> {
  return scanLiveEndpoint(endpoint, getScanEngine(rulesDir), displayName);
}

// ─── URL input ───────────────────────────────────────────────────────────────

async function scanUrlInput(
  rawUrl: string,
  scanEngine: ScanEngine,
): Promise<AdHocScanResult> {
  // assertSafe throws UrlGuardError on a malformed URL or a blocked address.
  const url = await assertSafe(rawUrl);
  const scanned = await scanLiveEndpoint(url.toString(), scanEngine);

  if (!scanned.connection_success) {
    const { message, reason } = describeConnectionFailure(
      url.hostname,
      scanned.connection_error,
    );
    throw new AdHocScanError(message, reason);
  }

  return {
    input_type: "url",
    rules_version: scanEngine.rulesVersion,
    servers: [scanned],
    unscannable_stdio: [],
    warnings: [],
  };
}

// ─── Config input ────────────────────────────────────────────────────────────

interface ParsedConfigEntry {
  name: string;
  url?: string;
  command?: string;
}

/**
 * Parse a pasted MCP client config. Supports `{ mcpServers: {} }` and the
 * alternate `{ servers: {} }` shape. Throws on malformed JSON or a config
 * with no server entries.
 */
function parseConfig(raw: string): ParsedConfigEntry[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AdHocScanError("Config is not valid JSON", "bad-config-json");
  }
  if (parsed === null || typeof parsed !== "object") {
    throw new AdHocScanError("Config must be a JSON object", "bad-config-shape");
  }
  const obj = parsed as Record<string, unknown>;
  const serverMap =
    (obj.mcpServers as Record<string, unknown> | undefined) ??
    (obj.servers as Record<string, unknown> | undefined);
  if (!serverMap || typeof serverMap !== "object") {
    throw new AdHocScanError(
      "Config has no `mcpServers` (or `servers`) object",
      "bad-config-shape",
    );
  }
  const entries: ParsedConfigEntry[] = [];
  for (const [name, value] of Object.entries(serverMap)) {
    if (value === null || typeof value !== "object") continue;
    const entry = value as Record<string, unknown>;
    entries.push({
      name,
      url: typeof entry.url === "string" ? entry.url : undefined,
      command: typeof entry.command === "string" ? entry.command : undefined,
    });
  }
  if (entries.length === 0) {
    throw new AdHocScanError("Config contains no server entries", "empty-config");
  }
  return entries;
}

async function scanConfigInput(
  rawConfig: string,
  scanEngine: ScanEngine,
): Promise<AdHocScanResult> {
  const entries = parseConfig(rawConfig);
  const remote = entries.filter((e) => e.url);
  const stdio = entries.filter((e) => !e.url);

  const unscannable_stdio = stdio.map((e) => ({
    name: e.name,
    reason: e.command
      ? "Local stdio server — runs via a shell command, not reachable over the network. Use the mcp-sentinel CLI to scan it locally."
      : "No URL — only remote (HTTP/SSE) MCP servers can be scanned here.",
  }));

  if (remote.length === 0) {
    throw new AdHocScanError(
      "Config has no remote (URL-based) MCP servers — only local stdio servers, which cannot be scanned here.",
      "no-remote-servers",
    );
  }

  const toScan = remote.slice(0, MAX_CONFIG_SERVERS);
  const warnings: string[] = [];
  if (remote.length > MAX_CONFIG_SERVERS) {
    warnings.push(
      `Config has ${remote.length} remote servers; only the first ${MAX_CONFIG_SERVERS} were scanned.`,
    );
  }

  const servers: ScannedServer[] = [];
  for (const entry of toScan) {
    try {
      const url = await assertSafe(entry.url as string);
      const scanned = await scanLiveEndpoint(url.toString(), scanEngine, entry.name);
      servers.push(scanned);
      if (!scanned.connection_success) {
        warnings.push(
          `"${entry.name}": ` +
            describeConnectionFailure(entry.name, scanned.connection_error).message,
        );
      }
    } catch (err) {
      warnings.push(
        `Skipped "${entry.name}": ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  if (servers.filter((s) => s.connection_success).length === 0) {
    throw new AdHocScanError(
      "None of the remote servers in the config could be reached.",
      "all-connections-failed",
    );
  }

  return {
    input_type: "config",
    rules_version: scanEngine.rulesVersion,
    servers,
    unscannable_stdio,
    warnings,
  };
}

// ─── Source input ────────────────────────────────────────────────────────────

interface ResolvedSourceRef {
  github_url: string | null;
  npm_package: string | null;
  pypi_package: string | null;
  display_name: string;
}

/**
 * Resolve a source reference into a GitHub URL plus package identity.
 * Accepts: a github.com URL, `npm:<pkg>`, `pypi:<pkg>`, or a bare name
 * (tried as an npm package, then PyPI). Throws when nothing resolves to a
 * fetchable GitHub repository.
 */
async function resolveSourceRef(ref: string): Promise<ResolvedSourceRef> {
  const trimmed = ref.trim();

  if (/github\.com/i.test(trimmed)) {
    return {
      github_url: trimmed.startsWith("http") ? trimmed : `https://${trimmed}`,
      npm_package: null,
      pypi_package: null,
      display_name: trimmed.replace(/^https?:\/\//, "").replace(/^github\.com\//, ""),
    };
  }

  const npmMatch = trimmed.match(/^npm:(.+)$/i);
  const pypiMatch = trimmed.match(/^pypi:(.+)$/i);

  if (pypiMatch) {
    const pkg = pypiMatch[1].trim();
    const gh = await resolvePypiRepo(pkg);
    return { github_url: gh, npm_package: null, pypi_package: pkg, display_name: pkg };
  }

  const npmName = npmMatch ? npmMatch[1].trim() : trimmed;
  const ghFromNpm = await resolveNpmRepo(npmName);
  if (ghFromNpm) {
    return { github_url: ghFromNpm, npm_package: npmName, pypi_package: null, display_name: npmName };
  }
  // Bare name with no npm hit — try PyPI as a fallback.
  if (!npmMatch) {
    const ghFromPypi = await resolvePypiRepo(npmName);
    if (ghFromPypi) {
      return { github_url: ghFromPypi, npm_package: null, pypi_package: npmName, display_name: npmName };
    }
  }
  throw new AdHocScanError(
    `Could not resolve "${ref}" to a GitHub repository. Provide a github.com URL, or an npm/PyPI package that links to its source.`,
    "unresolvable-ref",
  );
}

/** Look up an npm package's source repository. Registry host is fixed (no SSRF). */
async function resolveNpmRepo(pkg: string): Promise<string | null> {
  if (!/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i.test(pkg)) {
    return null;
  }
  try {
    const resp = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg).replace("%40", "@")}`, {
      signal: AbortSignal.timeout(10_000),
      headers: { Accept: "application/json" },
    });
    if (!resp.ok) return null;
    const data = (await resp.json()) as Record<string, unknown>;
    const repo = data.repository as { url?: string } | string | undefined;
    const repoUrl = typeof repo === "string" ? repo : repo?.url;
    if (repoUrl && /github\.com/i.test(repoUrl)) {
      return normalizeGitHubUrl(repoUrl);
    }
  } catch {
    /* fall through */
  }
  return null;
}

/** Look up a PyPI package's source repository. Registry host is fixed (no SSRF). */
async function resolvePypiRepo(pkg: string): Promise<string | null> {
  if (!/^[A-Za-z0-9._-]+$/.test(pkg)) return null;
  try {
    const resp = await fetch(`https://pypi.org/pypi/${encodeURIComponent(pkg)}/json`, {
      signal: AbortSignal.timeout(10_000),
      headers: { Accept: "application/json" },
    });
    if (!resp.ok) return null;
    const data = (await resp.json()) as { info?: Record<string, unknown> };
    const info = data.info ?? {};
    const candidates: string[] = [];
    const projectUrls = info.project_urls as Record<string, string> | undefined;
    if (projectUrls) candidates.push(...Object.values(projectUrls));
    if (typeof info.home_page === "string") candidates.push(info.home_page);
    for (const c of candidates) {
      if (/github\.com/i.test(c)) return normalizeGitHubUrl(c);
    }
  } catch {
    /* fall through */
  }
  return null;
}

function normalizeGitHubUrl(raw: string): string {
  const cleaned = raw
    .replace(/^git\+/, "")
    .replace(/\.git$/, "")
    .replace(/^git:\/\//, "https://")
    .replace(/^ssh:\/\/git@/, "https://");
  const match = cleaned.match(/github\.com[/:]([^/]+)\/([^/#?]+)/i);
  if (match) return `https://github.com/${match[1]}/${match[2]}`;
  return cleaned;
}

async function scanSourceInput(
  ref: string,
  scanEngine: ScanEngine,
): Promise<AdHocScanResult> {
  const resolved = await resolveSourceRef(ref);
  if (!resolved.github_url) {
    throw new AdHocScanError(
      `No source repository found for "${ref}".`,
      "unresolvable-ref",
    );
  }

  const fetcher = new SourceFetcher();
  const auditor = new DependencyAuditor();
  const fetched = await fetcher.fetchFromGitHub(resolved.github_url);

  if (!fetched.source_code) {
    throw new AdHocScanError(
      `Could not fetch source code from ${resolved.github_url}: ${fetched.error ?? "no recognised entry-point files"}`,
      "source-fetch-failed",
    );
  }

  const enrichedDeps =
    fetched.raw_dependencies.length > 0
      ? await auditor.audit(fetched.raw_dependencies)
      : [];

  const context: AnalysisContext = {
    server: {
      id: "ad-hoc-source",
      name: resolved.display_name,
      description: null,
      github_url: resolved.github_url,
    },
    tools: [],
    source_code: fetched.source_code,
    source_files: fetched.source_files,
    dependencies: enrichedDeps.map((d) => ({
      name: d.name,
      version: d.version,
      has_known_cve: d.has_known_cve,
      cve_ids: d.cve_ids,
      last_updated: d.last_updated,
    })),
    connection_metadata: null,
  };

  const scanned = analyzeContext(context, scanEngine, {
    name: resolved.display_name,
    endpoint: null,
    github_url: resolved.github_url,
    npm_package: resolved.npm_package,
    pypi_package: resolved.pypi_package,
    connection_success: true,
    connection_error: null,
    server_version: null,
  });

  return {
    input_type: "source",
    rules_version: scanEngine.rulesVersion,
    servers: [scanned],
    unscannable_stdio: [],
    warnings: [],
  };
}

// ─── Live-endpoint scanning ──────────────────────────────────────────────────

/**
 * Connect to a live MCP endpoint (initialize + tools/list only — ADR-007),
 * build the analysis context, and run the rule engine. The caller must
 * have already passed the URL through `assertSafe()`.
 */
async function scanLiveEndpoint(
  endpoint: string,
  scanEngine: ScanEngine,
  displayName?: string,
): Promise<ScannedServer> {
  const connector = new MCPConnector({ timeout: CONNECT_TIMEOUT_MS });
  const enumeration = await connector.enumerate("ad-hoc-scan", endpoint);

  let hostname = endpoint;
  try {
    hostname = parseAndValidate(endpoint).hostname;
  } catch {
    /* keep raw */
  }
  const name = displayName ?? hostname;

  if (!enumeration.connection_success) {
    // A failed connection still produces a (degraded) ScannedServer so the
    // caller can decide how to surface it.
    const context = emptyContext(name);
    return analyzeContext(context, scanEngine, {
      name,
      endpoint,
      github_url: null,
      npm_package: null,
      pypi_package: null,
      connection_success: false,
      connection_error: enumeration.connection_error,
      server_version: null,
    });
  }

  const context: AnalysisContext = {
    server: { id: "ad-hoc-scan", name, description: null, github_url: null },
    tools: enumeration.tools.map((t) => ({
      name: t.name,
      description: t.description ?? null,
      input_schema: (t.input_schema as Record<string, unknown> | null) ?? null,
      annotations:
        (t as { annotations?: AnalysisContext["tools"][number]["annotations"] })
          .annotations ?? null,
    })),
    source_code: null,
    dependencies: [],
    connection_metadata: {
      auth_required: false,
      transport:
        endpoint.endsWith("/sse") || endpoint.includes("?sse=")
          ? "sse"
          : "streamable-http",
      response_time_ms: enumeration.response_time_ms ?? 0,
    },
    initialize_metadata: {
      server_version: enumeration.server_version ?? null,
      server_instructions: enumeration.server_instructions ?? null,
    },
    resources: (enumeration.resources ?? []).map((r) => ({
      uri: r.uri,
      name: r.name,
      description: r.description ?? null,
      mimeType: r.mimeType ?? null,
    })),
    prompts: (enumeration.prompts ?? []).map((p) => ({
      name: p.name,
      description: p.description ?? null,
      arguments: (p.arguments ?? []).map((a) => ({
        name: a.name,
        description: a.description ?? null,
        required: a.required ?? false,
      })),
    })),
    roots: enumeration.roots ?? [],
    declared_capabilities: enumeration.declared_capabilities ?? null,
  };

  return analyzeContext(context, scanEngine, {
    name,
    endpoint,
    github_url: null,
    npm_package: null,
    pypi_package: null,
    connection_success: true,
    connection_error: null,
    server_version: enumeration.server_version ?? null,
  });
}

function emptyContext(name: string): AnalysisContext {
  return {
    server: { id: "ad-hoc-scan", name, description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}

interface ServerIdentity {
  name: string;
  endpoint: string | null;
  github_url: string | null;
  npm_package: string | null;
  pypi_package: string | null;
  connection_success: boolean;
  connection_error: string | null;
  server_version: string | null;
}

/** Run the engine on an assembled context and shape the result. */
function analyzeContext(
  context: AnalysisContext,
  scanEngine: ScanEngine,
  identity: ServerIdentity,
): ScannedServer {
  const profileResult = scanEngine.engine.analyzeWithProfile(context);
  const scored = profileResult.scored_findings;

  const coverageForScorer = {
    had_source_code: profileResult.coverage.had_source_code,
    had_connection: profileResult.coverage.had_connection,
    had_dependencies: profileResult.coverage.had_dependencies,
    coverage_ratio: profileResult.coverage.coverage_ratio,
    confidence_band: profileResult.coverage.confidence_band,
    techniques_run: profileResult.coverage.techniques_run,
    rules_executed: profileResult.coverage.rules_executed,
    rules_skipped_no_data: profileResult.coverage.rules_skipped_no_data,
  };

  const score = computeScore(
    scored as Parameters<typeof computeScore>[0],
    scanEngine.ruleCategories,
    coverageForScorer,
    scanEngine.ruleEngineV2,
  );

  const findings: AdHocFinding[] = scored.map((f) => {
    const raw = f as unknown as Record<string, unknown>;
    return {
      rule_id: f.rule_id,
      severity: f.severity as AdHocFinding["severity"],
      evidence: f.evidence,
      remediation: f.remediation,
      owasp_category: (f.owasp_category as string | null) ?? null,
      mitre_technique: (f.mitre_technique as string | null) ?? null,
      confidence: typeof raw.confidence === "number" ? raw.confidence : 1.0,
      evidence_chain: raw.evidence_chain ?? null,
    };
  });

  logger.info(
    {
      server: identity.name,
      findings: findings.length,
      score: score.total_score,
      band: profileResult.coverage.confidence_band,
    },
    "Ad-hoc scan complete",
  );

  return {
    name: identity.name,
    endpoint: identity.endpoint,
    github_url: identity.github_url,
    npm_package: identity.npm_package,
    pypi_package: identity.pypi_package,
    connection_success: identity.connection_success,
    connection_error: identity.connection_error,
    server_version: identity.server_version,
    tool_count: context.tools.length,
    tools: context.tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.input_schema,
    })),
    score,
    findings,
    coverage: profileResult.coverage,
    profile: {
      attack_surfaces: profileResult.profile.attack_surfaces,
      capabilities: profileResult.profile.capabilities
        .filter((c) => c.confidence >= 0.5)
        .map((c) => ({
          capability: c.capability,
          confidence: Math.round(c.confidence * 100) / 100,
        })),
      threats: profileResult.threats.map((t) => t.id),
      raw_findings: profileResult.all_annotated.length,
      filtered_findings:
        profileResult.all_annotated.length - profileResult.scored_findings.length,
    },
  };
}
