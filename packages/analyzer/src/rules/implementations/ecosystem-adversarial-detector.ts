/**
 * Ecosystem & Adversarial Remaining — F2-F4, F5, F6, G6, H1, H3
 *
 * F2: High-Risk Capability Profile
 * F3: Data Flow Risk Source→Sink
 * F4: MCP Spec Non-Compliance
 * F5: Official Namespace Squatting (Levenshtein)
 * F6: Circular Data Loop (already partially in f1, this covers YAML fallback)
 * G6: Rug Pull / Tool Behavior Drift (historical diff)
 * H1: MCP OAuth 2.0 Insecure Implementation
 * H3: Multi-Agent Propagation Risk
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { buildCapabilityGraph } from "../analyzers/capability-graph.js";
import { damerauLevenshtein } from "../analyzers/similarity.js";
import { EvidenceChainBuilder } from "../../evidence.js";
import { computeToolSignals, computeCodeSignals } from "../../confidence-signals.js";

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }
function lineNum(s: string, i: number) { return s.substring(0, i).split("\n").length; }

// F2 and F3 are already handled by f1-lethal-trifecta.ts (graph-based implementation)
// F4 migrated to f4-mcp-spec-non-compliance/ in Phase 1 Chunk 1.26.

// F5 migrated to f5-official-namespace-squatting/ in Phase 1 Chunk 1.26.

// G6 migrated to g6-rug-pull-tool-drift/ in Phase 1 Chunk 1.26.

// H1 migrated to h1-oauth-insecure-implementation/ in Phase 1 Chunk 1.26.

// H3 migrated to h3-multi-agent-propagation-risk/ in Phase 1 Chunk 1.26.
