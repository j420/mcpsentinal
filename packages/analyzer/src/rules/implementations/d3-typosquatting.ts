/**
 * D3 — Typosquatting Detection (Multi-Algorithm)
 *
 * REPLACES the YAML composite rule with multi-algorithm similarity analysis.
 *
 * Old behavior: Single Levenshtein distance with fixed 0.85 threshold.
 * New behavior: 5 complementary algorithms, each catching different typo classes,
 * with weighted combination, attack classification, and confidence intervals.
 *
 * Algorithm weights (tuned for npm/PyPI package names):
 * - Jaro-Winkler (0.30) — prefix-sensitive, optimal for short identifiers
 * - Damerau-Levenshtein (0.25) — catches transpositions (most common human typo)
 * - Levenshtein (0.20) — general edit distance
 * - Keyboard proximity (0.15) — catches adjacent-key substitutions
 * - Normalized (0.10) — catches delimiter variations (fast-mcp vs fastmcp)
 *
 * Attack classification:
 * - transposition: "axois" → "axios"
 * - keyboard_proximity: "reakt" → "react"
 * - repetition: "expresss" → "express"
 * - delimiter_variation: "fast-mcp" → "fastmcp"
 * - homoglyph: "lоdash" (Cyrillic о) → "lodash"
 * - prefix_suffix: "my-express" → "express"
 * - vowel_swap: "babel" → "bobel"
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { computeSimilarity, normalizeName, type SimilarityResult } from "../analyzers/similarity.js";
import { normalizeConfusables } from "../analyzers/unicode.js";

/** Known legitimate packages in the MCP ecosystem */
const KNOWN_PACKAGES: string[] = [
  // MCP SDK packages
  "@modelcontextprotocol/sdk",
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/server-postgres",
  "@modelcontextprotocol/server-slack",
  "@modelcontextprotocol/server-memory",
  "@modelcontextprotocol/server-puppeteer",
  "@modelcontextprotocol/server-brave-search",
  "@modelcontextprotocol/server-google-maps",
  "@modelcontextprotocol/server-fetch",
  "@modelcontextprotocol/server-everart",
  "@modelcontextprotocol/server-sequential-thinking",
  "@modelcontextprotocol/server-everything",
  // Popular MCP packages
  "fastmcp",
  "mcp-framework",
  "mcp-server",
  "mcp-client",
  // Core ecosystem packages
  "express",
  "fastify",
  "next",
  "react",
  "vue",
  "angular",
  "lodash",
  "axios",
  "zod",
  "prisma",
  "drizzle-orm",
  "typescript",
  "eslint",
  "prettier",
  "vitest",
  "jest",
  "webpack",
  "vite",
  "esbuild",
  "turbo",
  "pnpm",
  // Python ecosystem
  "flask",
  "django",
  "fastapi",
  "pydantic",
  "requests",
  "httpx",
  "numpy",
  "pandas",
  "langchain",
  "openai",
  "anthropic",
];

/** Threshold for flagging as potential typosquat */
const SIMILARITY_THRESHOLD = 0.75;
/** Threshold for high confidence typosquat */
const HIGH_CONFIDENCE_THRESHOLD = 0.85;

class TyposquattingRule implements TypedRule {
  readonly id = "D3";
  readonly name = "Typosquatting Detection (Multi-Algorithm)";

  analyze(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];

    for (const dep of context.dependencies) {
      // Skip exact matches
      if (KNOWN_PACKAGES.includes(dep.name)) continue;

      // Check against all known packages
      let bestMatch: {
        known: string;
        result: SimilarityResult;
      } | null = null;

      for (const known of KNOWN_PACKAGES) {
        // Skip if names are identical
        if (dep.name === known) continue;

        // Quick pre-filter: skip if length difference is too large
        const normDep = normalizeName(dep.name);
        const normKnown = normalizeName(known);
        if (
          Math.abs(normDep.length - normKnown.length) > 3 &&
          normDep.length > 3 &&
          normKnown.length > 3
        ) continue;

        const result = computeSimilarity(dep.name, known);

        if (
          result.score >= SIMILARITY_THRESHOLD &&
          (!bestMatch || result.score > bestMatch.result.score)
        ) {
          bestMatch = { known, result };
        }
      }

      // Also check for homoglyph attacks
      const normalizedDep = normalizeConfusables(dep.name);
      if (normalizedDep !== dep.name) {
        // The name contains confusable characters — check if normalized version matches anything
        for (const known of KNOWN_PACKAGES) {
          if (normalizedDep === known || normalizeName(normalizedDep) === normalizeName(known)) {
            findings.push({
              rule_id: "D3",
              severity: "critical",
              evidence:
                `Dependency "${dep.name}" uses Unicode confusable characters to impersonate ` +
                `"${known}". After normalization: "${normalizedDep}". ` +
                `Attack class: homoglyph. Confidence: 99%.`,
              remediation:
                `Replace "${dep.name}" with the legitimate package "${known}". ` +
                `This package uses visually similar characters from non-Latin Unicode scripts ` +
                `to impersonate a known package — a supply chain attack.`,
              owasp_category: "MCP10-supply-chain",
              mitre_technique: "AML.T0054",
              confidence: 0.99,
              metadata: {
                analysis_type: "homoglyph",
                original: dep.name,
                normalized: normalizedDep,
                target: known,
              },
            });
            break;
          }
        }
      }

      if (!bestMatch) continue;

      const { known, result } = bestMatch;
      const isHighConfidence = result.score >= HIGH_CONFIDENCE_THRESHOLD;

      findings.push({
        rule_id: "D3",
        severity: isHighConfidence ? "critical" : "high",
        evidence:
          `Dependency "${dep.name}" is ${(result.score * 100).toFixed(1)}% similar to ` +
          `known package "${known}" — possible typosquat. ` +
          `Attack class: ${result.attack_class}. ` +
          `Algorithm scores: ` +
          `Jaro-Winkler=${(result.algorithms.jaro_winkler * 100).toFixed(0)}%, ` +
          `Damerau-Levenshtein=${(result.algorithms.damerau_levenshtein * 100).toFixed(0)}%, ` +
          `Levenshtein=${(result.algorithms.levenshtein * 100).toFixed(0)}%, ` +
          `Keyboard=${(result.algorithms.keyboard_distance * 100).toFixed(0)}%, ` +
          `Normalized=${(result.algorithms.normalized * 100).toFixed(0)}%. ` +
          `Edit operations: ${result.edit_operations
            .map(
              (op) =>
                `${op.type}${op.from_char ? `(${op.from_char}→${op.to_char || ""})` : `(${op.to_char || ""})`}@${op.position}`
            )
            .join(", ")}.`,
        remediation:
          `Verify that "${dep.name}" is the intended package, not a typosquat of "${known}". ` +
          `Check the package's npm/PyPI page for: download count, publish date, author reputation. ` +
          `If this is a typosquat, replace with "${known}".`,
        owasp_category: "MCP10-supply-chain",
        mitre_technique: "AML.T0054",
        confidence: result.confidence,
        metadata: {
          analysis_type: "multi_algorithm",
          target_package: known,
          composite_score: result.score,
          attack_class: result.attack_class,
          algorithm_scores: result.algorithms,
          edit_operations: result.edit_operations,
        },
      });
    }

    return findings;
  }
}

registerTypedRule(new TyposquattingRule());
