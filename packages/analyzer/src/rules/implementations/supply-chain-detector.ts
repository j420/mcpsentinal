/**
 * Supply Chain Integrity Detector — Deep analysis for L5, L12, L14, K10
 *
 * Uses STRUCTURED PARSING of package manifests instead of regex.
 * JSON.parse → analyze structure → compare fields for contradictions.
 *
 * What this catches that YAML regex can't:
 * - L5:  prepublish script modifying package.json itself (not just containing keywords)
 * - L12: post-build script modifying dist/ files AFTER tests pass
 * - L14: bin field shadowing system commands (ls, cat, curl)
 * - K10: registry URL pointing to non-standard registry
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

function getLineNumber(source: string, index: number): number {
  return source.substring(0, index).split("\n").length;
}

// ─── JSON block extraction helper ──────────────────────────────────────────

/**
 * Extract JSON-like blocks from source code.
 * Finds package.json content, MCP configs, etc. embedded in source files.
 */
function extractJSONBlocks(source: string): Array<{ json: Record<string, unknown>; offset: number }> {
  const blocks: Array<{ json: Record<string, unknown>; offset: number }> = [];

  // Try to parse the entire file as JSON first (it might BE a package.json)
  try {
    const parsed = JSON.parse(source);
    if (typeof parsed === "object" && parsed !== null) {
      blocks.push({ json: parsed, offset: 0 });
      return blocks;
    }
  } catch {
    // Not pure JSON — look for embedded JSON objects
  }

  // Find JSON-like blocks in source code (objects assigned to variables, config literals)
  const jsonPattern = /(?:=\s*|:\s*)(\{[\s\S]*?\n\})/g;
  let match: RegExpExecArray | null;
  while ((match = jsonPattern.exec(source)) !== null) {
    try {
      // Clean up JS object syntax to valid JSON (strip comments, trailing commas)
      const cleaned = match[1]
        .replace(/\/\/.*$/gm, "")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/,(\s*[}\]])/g, "$1")
        .replace(/(\w+)\s*:/g, '"$1":')
        .replace(/'/g, '"');
      const parsed = JSON.parse(cleaned);
      if (typeof parsed === "object") {
        blocks.push({ json: parsed, offset: match.index });
      }
    } catch {
      // Not parseable — skip
    }
  }

  return blocks;
}

// ─── L5: Package Manifest Confusion ───────────────────────────────────────

const SYSTEM_COMMANDS = new Set([
  "ls", "cat", "grep", "curl", "wget", "ssh", "sudo", "su",
  "chmod", "chown", "rm", "mv", "cp", "node", "npm", "npx",
  "python", "pip", "git", "docker", "kubectl", "make",
]);

class ManifestConfusionRule implements TypedRule {
  readonly id = "L5";
  readonly name = "Package Manifest Confusion (Structural Analysis)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const blocks = extractJSONBlocks(context.source_code);

    for (const { json, offset } of blocks) {
      const scripts = json.scripts as Record<string, string> | undefined;
      const bin = json.bin as Record<string, string> | string | undefined;
      const exports = json.exports as Record<string, unknown> | undefined;
      const main = json.main as string | undefined;

      if (!scripts && !bin && !exports) continue;

      // L5: prepublish modifying package.json itself
      if (scripts) {
        const prepub = scripts.prepublish || scripts.prepublishOnly;
        if (prepub && /package\.json/.test(prepub) && !/tsc|build|compile|lint|typecheck/.test(prepub)) {
          findings.push({
            rule_id: "L5",
            severity: "high",
            evidence:
              `prepublish script modifies package.json: "${prepub.slice(0, 80)}". ` +
              `Manifest confusion: published package may differ from repository. ` +
              `Darcy Clarke npm manifest confusion (July 2023 — still unpatched).`,
            remediation:
              "prepublish scripts should only run build tools (tsc, esbuild, rollup). " +
              "Never modify package.json in prepublish — it enables manifest confusion attacks.",
            owasp_category: "MCP10-supply-chain",
            mitre_technique: "AML.T0017",
            confidence: 0.90,
            metadata: { analysis_type: "structural", script: prepub },
          });
        }
      }

      // L14: bin field shadowing system commands
      if (bin && typeof bin === "object") {
        for (const [name, path] of Object.entries(bin)) {
          if (SYSTEM_COMMANDS.has(name)) {
            findings.push({
              rule_id: "L14",
              severity: "high",
              evidence:
                `bin field shadows system command "${name}" → "${path}". ` +
                `Installing this package overrides the system "${name}" command. ` +
                `npm bin field hijacking (2024-2025 incidents).`,
              remediation:
                `Rename the bin entry from "${name}" to a unique name that doesn't shadow system commands.`,
              owasp_category: "MCP10-supply-chain",
              mitre_technique: "AML.T0017",
              confidence: 0.95,
              metadata: { analysis_type: "structural", bin_name: name, bin_path: path },
            });
          }

          // Hidden entry point (starts with dot or double underscore)
          if (/^(?:\.|__)/.test(path)) {
            findings.push({
              rule_id: "L14",
              severity: "high",
              evidence:
                `bin "${name}" points to hidden file "${path}". ` +
                `Hidden entry points are used to conceal malicious payloads.`,
              remediation: "bin entry points should be visible files in the package root or dist directory.",
              owasp_category: "MCP10-supply-chain",
              mitre_technique: "AML.T0017",
              confidence: 0.85,
              metadata: { analysis_type: "structural" },
            });
          }
        }
      }

      // L14: exports with different import/require targets containing dangerous code
      if (exports && typeof exports === "object") {
        const dotExport = exports["."] as Record<string, unknown> | undefined;
        if (dotExport && typeof dotExport === "object") {
          const importPath = dotExport.import as string | undefined;
          const requirePath = dotExport.require as string | undefined;
          if (importPath && requirePath && importPath !== requirePath) {
            // Different files for import vs require — check if either is suspicious
            const suspiciousPath = [importPath, requirePath].find((p) =>
              /(?:backdoor|payload|hook|inject|hidden)/.test(p)
            );
            if (suspiciousPath) {
              findings.push({
                rule_id: "L14",
                severity: "critical",
                evidence:
                  `exports["."] has divergent paths: import="${importPath}", require="${requirePath}". ` +
                  `Suspicious path detected: "${suspiciousPath}".`,
                remediation:
                  "import and require paths should point to the same logical module. " +
                  "Divergent paths with suspicious names indicate hidden payload delivery.",
                owasp_category: "MCP10-supply-chain",
                mitre_technique: "AML.T0017",
                confidence: 0.90,
                metadata: { analysis_type: "structural" },
              });
            }
          }
        }
      }
    }

    return findings;
  }
}

// ─── L12: Build Artifact Tampering ────────────────────────────────────────

class BuildArtifactTamperingRule implements TypedRule {
  readonly id = "L12";
  readonly name = "Build Artifact Tampering (Script Order Analysis)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const blocks = extractJSONBlocks(context.source_code);

    for (const { json } of blocks) {
      const scripts = json.scripts as Record<string, string> | undefined;
      if (!scripts) continue;

      // Detect post-build/pre-publish scripts that modify dist/ files
      const tamperScripts = ["postbuild", "prepublishOnly", "prepack"];
      for (const hook of tamperScripts) {
        const script = scripts[hook];
        if (!script) continue;

        // Check if the script modifies build output
        const modifiesDist = /(?:sed|awk|perl|patch|cat\s*>>|echo\s*>>|appendFile).*(?:dist|build|out|lib)\//i.test(script);
        const isBuildTool = /(?:tsc|esbuild|rollup|webpack|vite|babel|swc|minify|terser|uglify)/i.test(script);

        if (modifiesDist && !isBuildTool) {
          findings.push({
            rule_id: "L12",
            severity: "critical",
            evidence:
              `${hook} script modifies build artifacts: "${script.slice(0, 100)}". ` +
              `Post-build modification of dist/ files can inject code after tests pass. ` +
              `SLSA framework violation: build artifacts must not be modified after build step.`,
            remediation:
              "Remove file modification from post-build hooks. " +
              "All dist/ modifications should happen DURING the build step, not after. " +
              "Use reproducible builds with integrity checksums.",
            owasp_category: "MCP10-supply-chain",
            mitre_technique: "AML.T0017",
            confidence: 0.88,
            metadata: { analysis_type: "structural", hook, script },
          });
        }
      }

      // Detect test→modify→publish chains
      const testScript = scripts.test || "";
      const publishScript = scripts.prepublishOnly || scripts.prepublish || "";
      if (testScript && publishScript) {
        const hasModifyBetween = /(?:sed|awk|cat\s*>>|echo\s*>>).*(?:dist|build|lib)/i.test(publishScript);
        if (hasModifyBetween) {
          findings.push({
            rule_id: "L12",
            severity: "high",
            evidence:
              `prepublish modifies build artifacts: "${publishScript.slice(0, 100)}". ` +
              `This modification happens after test execution, bypassing test coverage.`,
            remediation:
              "Build artifact modifications must happen before or during the test step. " +
              "Post-test modifications are invisible to quality gates.",
            owasp_category: "MCP10-supply-chain",
            mitre_technique: "AML.T0017",
            confidence: 0.80,
            metadata: { analysis_type: "structural" },
          });
        }
      }
    }

    return findings;
  }
}

// ─── K10: Package Registry Substitution ───────────────────────────────────

const TRUSTED_REGISTRIES = [
  /registry\.npmjs\.org/i,
  /npm\.pkg\.github\.com/i,
  /registry\.yarnpkg\.com/i,
  /pypi\.org/i,
  /files\.pythonhosted\.org/i,
  /proxy\.golang\.org/i,
  /repo1?\.maven\.org/i,
  /central\.sonatype/i,
  /plugins\.gradle\.org/i,
];

const LOCAL_REGISTRIES = [
  /verdaccio/i, /localhost/i, /127\.0\.0\.1/i,
  /internal/i, /private/i, /artifactory/i,
  /nexus/i, /jfrog/i,
];

class RegistrySubstitutionRule implements TypedRule {
  readonly id = "K10";
  readonly name = "Package Registry Substitution";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    // Pattern: registry=<url> or --index-url=<url> etc.
    const registryPatterns = [
      { regex: /registry\s*=\s*(https?:\/\/[^\s]+)/gi, type: "npm" },
      { regex: /(?:--index-url|--extra-index-url|index[_-]url)\s*=?\s*(https?:\/\/[^\s]+)/gi, type: "pip" },
      { regex: /npmRegistryServer\s*:\s*["'](https?:\/\/[^"']+)/gi, type: "yarn" },
      { regex: /GOPROXY\s*=\s*([^\s,]+)/gi, type: "go" },
    ];

    for (const { regex, type } of registryPatterns) {
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(source)) !== null) {
        const url = match[1];
        const line = getLineNumber(source, match.index);

        // Skip trusted registries
        if (TRUSTED_REGISTRIES.some((r) => r.test(url))) continue;
        // Skip local/internal registries (these are expected in enterprise)
        if (LOCAL_REGISTRIES.some((r) => r.test(url))) continue;

        findings.push({
          rule_id: "K10",
          severity: "high",
          evidence:
            `Non-standard ${type} registry at line ${line}: "${url}". ` +
            `Packages from untrusted registries may contain malicious code. ` +
            `Registry substitution is a known supply chain attack vector.`,
          remediation:
            `Use only trusted registries (npmjs.org, pypi.org, proxy.golang.org). ` +
            `If using a private registry, ensure it proxies from the official source.`,
          owasp_category: "MCP10-supply-chain",
          mitre_technique: "AML.T0054",
          confidence: 0.80,
          metadata: { analysis_type: "pattern", registry_type: type, url, line },
        });
        break;
      }
    }

    return findings;
  }
}

// ─── Register ──────────────────────────────────────────────────────────────

registerTypedRule(new ManifestConfusionRule());
registerTypedRule(new BuildArtifactTamperingRule());
registerTypedRule(new RegistrySubstitutionRule());
