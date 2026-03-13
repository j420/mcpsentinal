/**
 * @mcp-sentinel/scanner
 * Public API for the MCP Sentinel scan pipeline.
 *
 * Use ScanPipeline programmatically if you need to embed scanning
 * in another service. For CLI usage, run: pnpm scan
 */

export { ScanPipeline, type PipelineConfig } from "./pipeline.js";
export { SourceFetcher, type FetchedSource } from "./fetcher.js";
export { DependencyAuditor } from "./auditor.js";
export type {
  ScanOptions,
  ScanRunStats,
  ScanServerResult,
  ScanStages,
  RawDependency,
  EnrichedDependency,
} from "./types.js";
