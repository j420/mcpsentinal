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
import { EvidenceChainBuilder } from "../../evidence.js";

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
            const homoglyphChain = new EvidenceChainBuilder()
              .source({
                source_type: "external-content",
                location: `dependency: "${dep.name}" (version ${dep.version || "unknown"})`,
                observed: `Package name "${dep.name}" contains Unicode confusable characters that visually impersonate "${known}"`,
                rationale:
                  "Dependency names in package manifests are external content resolved from public registries. " +
                  "A package using Unicode confusable characters (e.g., Cyrillic 'о' instead of Latin 'o') is " +
                  "visually indistinguishable from the legitimate package but resolves to attacker-controlled code.",
              })
              .propagation({
                propagation_type: "direct-pass",
                location: "package manager resolution / build pipeline",
                observed:
                  `Package manager resolves "${dep.name}" (with confusable characters) from the registry. ` +
                  `After Unicode normalization, this resolves to "${normalizedDep}" which matches "${known}", ` +
                  `but the registry treats it as a distinct package controlled by the attacker.`,
              })
              .sink({
                sink_type: "config-modification",
                location: "node_modules or site-packages / build environment",
                observed:
                  `Malicious package "${dep.name}" replaces the intended "${known}" in the dependency tree. ` +
                  `Attack class: homoglyph — Unicode confusable characters make the package visually identical to the target.`,
              })
              .mitigation({
                mitigation_type: "input-validation",
                present: false,
                location: "package manifest / registry",
                detail:
                  "No Unicode normalization is applied to package names before resolution. Most package managers " +
                  "treat visually identical names with different Unicode codepoints as distinct packages, enabling this attack.",
              })
              .impact({
                impact_type: "remote-code-execution",
                scope: "server-host",
                exploitability: "trivial",
                scenario:
                  "An attacker publishes a package with a name that uses Unicode confusable characters to impersonate " +
                  "a popular legitimate package. Developers who copy-paste or autocomplete the name install attacker-controlled " +
                  "code that executes during installation or at runtime, giving the attacker full code execution on the host.",
              })
              .factor(
                "homoglyph_exact_match",
                0.2,
                `After Unicode normalization, "${dep.name}" becomes "${normalizedDep}" which exactly matches "${known}" — this is a deliberate impersonation, not an accidental typo`
              )
              .factor(
                "unicode_confusable_characters",
                0.15,
                "Package name contains characters from non-Latin Unicode scripts that are visually indistinguishable from Latin characters"
              )
              .reference({
                id: "CWE-1104",
                title: "Use of Unmaintained Third Party Components",
                url: "https://cwe.mitre.org/data/definitions/1104.html",
                year: 2023,
                relevance:
                  "Homoglyph-based typosquatting is a supply chain attack that exploits developers' inability to " +
                  "visually distinguish Unicode confusable characters. Several real npm incidents (ua-parser-js, event-stream) " +
                  "demonstrated that malicious packages execute arbitrary code upon installation.",
              })
              .verification({
                step_type: "check-dependency",
                instruction:
                  `Inspect the Unicode codepoints in the package name "${dep.name}" by running: ` +
                  `echo -n "${dep.name}" | xxd | head -5. Compare each character's codepoint against the ` +
                  `legitimate package name "${known}". Look for Cyrillic, Greek, or Mathematical Alphanumeric ` +
                  `characters that are visually identical to Latin letters.`,
                target: `package name: "${dep.name}" vs legitimate: "${known}"`,
                expected_observation:
                  `One or more characters in "${dep.name}" have different Unicode codepoints than the corresponding ` +
                  `characters in "${known}", despite being visually identical. After normalization: "${normalizedDep}".`,
              })
              .verification({
                step_type: "compare-baseline",
                instruction:
                  `Search the npm or PyPI registry for "${dep.name}" and compare its metadata with "${known}". ` +
                  `Check the author, publish date, download count, and package contents. Homoglyph typosquats are ` +
                  `almost always recently published, have very few downloads, and may contain obfuscated code or ` +
                  `postinstall scripts that exfiltrate environment variables.`,
                target: `registry pages for "${dep.name}" and "${known}"`,
                expected_observation:
                  `Package "${dep.name}" has a different author, far fewer downloads, a more recent publish date, ` +
                  `and suspicious contents compared to the legitimate "${known}" package.`,
              })
              .build();

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
                evidence_chain: homoglyphChain,
              },
            });
            break;
          }
        }
      }

      if (!bestMatch) continue;

      const { known, result } = bestMatch;
      const isHighConfidence = result.score >= HIGH_CONFIDENCE_THRESHOLD;

      const chain = new EvidenceChainBuilder()
        .source({
          source_type: "external-content",
          location: `dependency: "${dep.name}" (version ${dep.version || "unknown"})`,
          observed: `Package name "${dep.name}" is ${(result.score * 100).toFixed(1)}% similar to "${known}"`,
          rationale:
            "Package names in dependency manifests are external content sourced from public registries. " +
            "A typosquatted package name causes the build system to install attacker-controlled code " +
            "instead of the intended legitimate package.",
        })
        .propagation({
          propagation_type: "direct-pass",
          location: "package manager install / build pipeline",
          observed:
            `Package manager resolves "${dep.name}" from the registry and installs it into node_modules or site-packages. ` +
            `The attacker's code runs during installation (postinstall hooks) or at import time.`,
        })
        .sink({
          sink_type: "command-execution",
          location: "build environment / runtime",
          observed:
            `Malicious package "${dep.name}" executes attacker code in the build environment or server runtime — ` +
            `attack class: ${result.attack_class}`,
        })
        .mitigation({
          mitigation_type: "input-validation",
          present: false,
          location: "package manifest / lockfile",
          detail:
            "No package name verification against known-good packages. Lockfiles prevent version drift but not initial typosquat installation.",
        })
        .impact({
          impact_type: "remote-code-execution",
          scope: "server-host",
          exploitability: "trivial",
          scenario:
            "A developer installs a typosquatted package that executes malicious code during installation " +
            "or at runtime. The attacker gains code execution in the build environment or production server, " +
            "enabling credential theft, backdoor installation, or supply chain compromise of downstream users.",
        })
        .factor(
          "multi_algorithm_match",
          0.1,
          `5-algorithm weighted similarity score: ${(result.score * 100).toFixed(1)}% (threshold: ${SIMILARITY_THRESHOLD * 100}%)`
        )
        .factor(
          isHighConfidence ? "high_confidence_match" : "moderate_confidence_match",
          isHighConfidence ? 0.15 : 0.0,
          isHighConfidence
            ? `Score ${(result.score * 100).toFixed(1)}% exceeds high-confidence threshold (${HIGH_CONFIDENCE_THRESHOLD * 100}%)`
            : `Score ${(result.score * 100).toFixed(1)}% is above threshold but below high-confidence level`
        )
        .factor(
          "attack_class_identified",
          0.05,
          `Attack classification: ${result.attack_class} — edit operations: ${result.edit_operations.map((op) => op.type).join(", ")}`
        )
        .reference({
          id: "Alex Birsan 2021",
          title: "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies",
          url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
          year: 2021,
          relevance:
            "Typosquatting is a core technique in dependency confusion attacks. " +
            "Birsan demonstrated that typosquatted and namespace-confused packages are installed " +
            "automatically by package managers, achieving RCE in corporate build environments.",
        })
        .verification({
          step_type: "check-dependency",
          instruction:
            `Compute the Levenshtein distance and Damerau-Levenshtein distance between "${dep.name}" and "${known}". ` +
            `Verify the edit operations: ${result.edit_operations.map((op) => `${op.type}(${op.from_char || ""}→${op.to_char || ""})@${op.position}`).join(", ")}. ` +
            `Check whether the edits correspond to common typo patterns (adjacent key substitution, transposition, extra/missing character).`,
          target: `package name: "${dep.name}" vs legitimate: "${known}"`,
          expected_observation:
            `Similarity score of ${(result.score * 100).toFixed(1)}% with attack class "${result.attack_class}". ` +
            `Algorithm breakdown: Jaro-Winkler=${(result.algorithms.jaro_winkler * 100).toFixed(0)}%, ` +
            `Damerau-Levenshtein=${(result.algorithms.damerau_levenshtein * 100).toFixed(0)}%.`,
        })
        .verification({
          step_type: "compare-baseline",
          instruction:
            `Check the npm or PyPI registry page for "${dep.name}": verify the author, publish date, download count, ` +
            `and README content. Compare against the legitimate package "${known}". Typosquatted packages typically have ` +
            `very low download counts, recent publish dates, unknown authors, and sparse or copied README content. ` +
            `Also check if the package has postinstall scripts that execute code during installation.`,
          target: `registry page for "${dep.name}" (npm/PyPI)`,
          expected_observation:
            `Package "${dep.name}" has significantly fewer downloads, a more recent publish date, and a different author ` +
            `compared to "${known}" — consistent with a typosquatting attack.`,
        })
        .build();

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
          evidence_chain: chain,
        },
      });
    }

    return findings;
  }
}

registerTypedRule(new TyposquattingRule());
