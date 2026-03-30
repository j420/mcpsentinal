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
import { EvidenceChainBuilder } from "../../evidence.js";

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
          const l5Chain = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: "package.json → scripts.prepublish(Only)",
              observed: prepub.slice(0, 100),
              rationale:
                "The prepublish(Only) lifecycle script references package.json itself. npm executes " +
                "prepublish before `npm publish`, meaning this script can modify the package manifest " +
                "between what exists in the repository and what gets published to the registry. This is " +
                "the core mechanism of manifest confusion attacks — the published package.json differs " +
                "from the source-controlled version, hiding modified dependencies or entry points.",
            })
            .propagation({
              propagation_type: "function-call",
              location: "npm lifecycle: prepublish → pack → publish",
              observed: `Script: ${prepub.slice(0, 60)}`,
            })
            .sink({
              sink_type: "config-modification",
              location: "package.json (published artifact)",
              observed: "package.json modified during publish lifecycle — published manifest diverges from repository",
            })
            .mitigation({
              mitigation_type: "sanitizer-function",
              present: false,
              location: "npm publish pipeline",
              detail:
                "npm does NOT validate that the published package.json matches the repository version. " +
                "There is no integrity check between the prepublish script output and the original manifest. " +
                "This is a known, unpatched npm vulnerability (Darcy Clarke, July 2023).",
            })
            .impact({
              impact_type: "config-poisoning",
              scope: "connected-services",
              exploitability: "moderate",
              scenario:
                "The prepublish script modifies package.json before `npm pack` creates the tarball. " +
                "The published package can have different dependencies, entry points, or bin fields than " +
                "what reviewers see in the repository. A reviewer audits the clean repository version while " +
                "consumers install the modified version. This enables: (1) dependency injection — adding " +
                "malicious dependencies not visible in the repo, (2) entry point swap — redirecting `main` " +
                "or `exports` to a backdoored file, (3) bin field hijacking — overriding system commands.",
            })
            .factor("structural_confirmed", 0.1, "Structural analysis confirmed prepublish script references package.json with non-build commands")
            .reference({
              id: "npm-manifest-confusion-2023",
              title: "Darcy Clarke: npm Manifest Confusion (July 2023)",
              year: 2023,
              relevance:
                "Darcy Clarke (former npm CLI lead) disclosed that npm allows published packages to have " +
                "arbitrary manifest content that differs from the repository. npm install trusts the registry " +
                "manifest, not the tarball's package.json. Still unpatched as of 2026.",
            })
            .reference({
              id: "CWE-345",
              title: "Insufficient Verification of Data Authenticity",
              relevance:
                "npm's failure to verify manifest integrity between publish-time and install-time " +
                "matches CWE-345 — the registry-served manifest is not authenticated against source.",
            })
            .verification({
              step_type: "inspect-source",
              instruction:
                `Review the prepublish script: "${prepub.slice(0, 60)}". Determine exactly what ` +
                `modifications it makes to package.json. Check if it changes: (1) dependencies or ` +
                `devDependencies, (2) main/module/exports entry points, (3) bin field entries, ` +
                `(4) scripts section, (5) name or version fields.`,
              target: "package.json → scripts.prepublish(Only)",
              expected_observation:
                "prepublish script modifies package.json fields that affect what consumers install.",
            })
            .verification({
              step_type: "compare-baseline",
              instruction:
                "Compare the repository package.json with the published package.json by running: " +
                "`npm pack --dry-run` then inspecting the tarball contents. Alternatively, compare " +
                "`npm view <pkg> --json` with the repository file. Any divergence in dependencies, " +
                "entry points, or bin fields confirms manifest confusion.",
              target: "repository package.json vs published package.json",
              expected_observation:
                "Published manifest differs from repository — manifest confusion confirmed.",
            })
            .build();

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
            metadata: { analysis_type: "structural", script: prepub, evidence_chain: l5Chain },
          });
        }
      }

      // L14: bin field shadowing system commands
      if (bin && typeof bin === "object") {
        for (const [name, path] of Object.entries(bin)) {
          if (SYSTEM_COMMANDS.has(name)) {
            const binChain = new EvidenceChainBuilder()
              .source({
                source_type: "file-content",
                location: `package.json → bin.${name}`,
                observed: `"${name}": "${path}"`,
                rationale:
                  `The package declares a bin entry named "${name}" which is an existing system command. ` +
                  `When this package is installed globally (npm install -g) or linked, the bin entry is ` +
                  `symlinked into the user's PATH. This causes the package's script to execute instead ` +
                  `of the real system command "${name}" — a PATH hijack via npm's bin mechanism.`,
              })
              .propagation({
                propagation_type: "direct-pass",
                location: "npm install → bin symlink creation",
                observed: `npm creates symlink: node_modules/.bin/${name} → ${path}`,
              })
              .sink({
                sink_type: "command-execution",
                location: `PATH precedence: node_modules/.bin/${name} overrides /usr/bin/${name}`,
                observed: `System command "${name}" is shadowed by package bin entry`,
              })
              .mitigation({
                mitigation_type: "sanitizer-function",
                present: false,
                location: "npm bin installation",
                detail:
                  "npm does not warn when a bin entry shadows an existing system command. The PATH " +
                  "hijack occurs silently during installation. No confirmation is requested from the user.",
              })
              .impact({
                impact_type: "remote-code-execution",
                scope: "server-host",
                exploitability: "moderate",
                scenario:
                  `After installation, any script or user invoking "${name}" will execute the ` +
                  `package's code instead of the real system command. In CI/CD pipelines, build ` +
                  `scripts, and Makefiles that call "${name}", the attacker's code runs with the ` +
                  `user's full privileges. This is especially dangerous for commands like "curl", ` +
                  `"git", "ssh", and "sudo" which are used in security-sensitive contexts.`,
              })
              .factor("structural_confirmed", 0.1, `Structural analysis confirmed bin entry "${name}" matches known system command`)
              .reference({
                id: "CWE-426",
                title: "Untrusted Search Path",
                relevance:
                  "CWE-426 covers PATH-based command hijacking. npm's bin mechanism modifies the " +
                  "effective search path, causing attacker-controlled code to execute when system " +
                  "commands are invoked by name.",
              })
              .verification({
                step_type: "inspect-source",
                instruction:
                  `Examine the bin entry's target file "${path}". Determine: (1) does it proxy to ` +
                  `the real "${name}" command after running its own code (stealth hijack), (2) does ` +
                  `it replace the command entirely, (3) does it have a legitimate purpose that ` +
                  `justifies the name collision (e.g., a wrapper with additional features)?`,
                target: `bin entry: "${name}" → "${path}"`,
                expected_observation:
                  `Package's "${name}" binary replaces or wraps the system command without user awareness.`,
              })
              .verification({
                step_type: "check-config",
                instruction:
                  "Check if the package is intended for global installation (has a `preferGlobal` field " +
                  "or README instructs `npm install -g`). Global installation makes the PATH hijack " +
                  "system-wide. Also check if any CI/CD scripts or Makefiles invoke the shadowed command.",
                target: "installation scope and downstream command usage",
                expected_observation:
                  `Package shadows "${name}" — any downstream invocation of "${name}" executes attacker code.`,
              })
              .build();

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
              metadata: { analysis_type: "structural", bin_name: name, bin_path: path, evidence_chain: binChain },
            });
          }

          // Hidden entry point (starts with dot or double underscore)
          if (/^(?:\.|__)/.test(path)) {
            const hiddenChain = new EvidenceChainBuilder()
              .source({
                source_type: "file-content",
                location: `package.json → bin.${name}`,
                observed: `"${name}": "${path}"`,
                rationale:
                  `The bin entry points to a hidden file (path starts with "." or "__"). Hidden files ` +
                  `are not shown by default in directory listings (ls, file explorers) and are commonly ` +
                  `used by malware authors to conceal malicious payloads in npm packages. Legitimate ` +
                  `bin entries point to visible files in the package root or dist/ directory.`,
              })
              .sink({
                sink_type: "command-execution",
                location: `hidden file: ${path}`,
                observed: `bin "${name}" → hidden entry point "${path}"`,
              })
              .mitigation({
                mitigation_type: "sanitizer-function",
                present: false,
                location: "package review process",
                detail:
                  "npm does not flag bin entries pointing to hidden files. Manual package review " +
                  "typically skips hidden files, making this an effective concealment technique.",
              })
              .impact({
                impact_type: "remote-code-execution",
                scope: "server-host",
                exploitability: "moderate",
                scenario:
                  "The hidden file executes when the bin command is invoked. Because the file is hidden, " +
                  "it evades casual code review and directory listing during security audits. The file " +
                  "could contain a backdoor, data exfiltration logic, or reverse shell.",
              })
              .factor("structural_confirmed", 0.05, "Structural analysis confirmed bin entry points to hidden file path")
              .reference({
                id: "CWE-506",
                title: "Embedded Malicious Code",
                relevance:
                  "Hidden entry points are a concealment technique for embedded malicious code (CWE-506). " +
                  "Multiple npm malware campaigns used dot-prefixed files to hide payloads.",
              })
              .verification({
                step_type: "inspect-source",
                instruction:
                  `Examine the hidden file "${path}" to determine its contents. Check if it contains ` +
                  `legitimate application logic or suspicious patterns (network requests, eval, exec, ` +
                  `encoded strings, obfuscated code).`,
                target: `file: ${path}`,
                expected_observation: "Hidden file contains concealed executable code.",
              })
              .build();

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
              metadata: { analysis_type: "structural", evidence_chain: hiddenChain },
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
              const exportChain = new EvidenceChainBuilder()
                .source({
                  source_type: "file-content",
                  location: 'package.json → exports["."]',
                  observed: `import: "${importPath}", require: "${requirePath}"`,
                  rationale:
                    "The package's exports map declares different files for ESM (import) and CJS (require) " +
                    "consumers. While dual-format packages legitimately have different entry points, the " +
                    "divergent path contains a suspicious filename indicating a hidden payload. This allows " +
                    "the package to serve different code depending on how it's consumed — the clean module " +
                    "to reviewers (who typically check one format) and the backdoored module to consumers.",
                })
                .propagation({
                  propagation_type: "direct-pass",
                  location: "Node.js module resolution → conditional exports",
                  observed: `Consumers using ${importPath === suspiciousPath ? "import" : "require"} get suspicious file: ${suspiciousPath}`,
                })
                .sink({
                  sink_type: "code-evaluation",
                  location: `file: ${suspiciousPath}`,
                  observed: `Suspicious entry point: "${suspiciousPath}" loaded via conditional exports`,
                })
                .mitigation({
                  mitigation_type: "sanitizer-function",
                  present: false,
                  location: "Node.js module loader",
                  detail:
                    "Node.js does not validate or inspect the content of conditional export targets. " +
                    "The module loader trusts the exports map and loads whichever file matches the " +
                    "consumer's module system (ESM or CJS) without additional security checks.",
                })
                .impact({
                  impact_type: "remote-code-execution",
                  scope: "connected-services",
                  exploitability: "moderate",
                  scenario:
                    "The conditional exports field serves a clean module to one consumer type and a " +
                    `backdoored module ("${suspiciousPath}") to the other. If the reviewer checks the ` +
                    `import path but the victim's bundler uses require (or vice versa), the malicious ` +
                    "code executes undetected. This is a dual-format supply chain attack.",
                })
                .factor("structural_confirmed", 0.1, "Structural analysis confirmed divergent exports paths with suspicious filename")
                .reference({
                  id: "CWE-506",
                  title: "Embedded Malicious Code",
                  relevance:
                    "Divergent conditional exports with suspicious filenames are a code concealment " +
                    "technique — the malicious payload is delivered selectively based on module format.",
                })
                .verification({
                  step_type: "inspect-source",
                  instruction:
                    `Compare the two entry points: import="${importPath}" vs require="${requirePath}". ` +
                    `The suspicious path is "${suspiciousPath}". Examine its contents for: (1) obfuscated ` +
                    `code, (2) network requests, (3) eval/exec calls, (4) file system access not present ` +
                    `in the other entry point.`,
                  target: `files: ${importPath} and ${requirePath}`,
                  expected_observation:
                    "Divergent entry points — suspicious path contains code not present in the clean path.",
                })
                .verification({
                  step_type: "compare-baseline",
                  instruction:
                    "Diff the import and require entry points to identify divergent code. Legitimate " +
                    "dual-format packages have functionally equivalent modules (ESM wrapper around CJS " +
                    "or vice versa). Material differences in functionality indicate payload delivery.",
                  target: `diff: ${importPath} vs ${requirePath}`,
                  expected_observation:
                    "Entry points have materially different functionality — not just ESM/CJS wrappers.",
                })
                .build();

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
                metadata: { analysis_type: "structural", evidence_chain: exportChain },
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
          const l12Chain = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `package.json → scripts.${hook}`,
              observed: script.slice(0, 100),
              rationale:
                `The "${hook}" lifecycle script runs AFTER the build step completes. It uses file ` +
                `modification tools (sed, awk, patch, echo >>) to alter files in the build output ` +
                `directory (dist/, build/, out/, lib/). This means the published artifacts differ ` +
                `from what the build step produced — and critically, from what the test suite validated.`,
            })
            .propagation({
              propagation_type: "function-call",
              location: `npm lifecycle: build → test → ${hook} → pack → publish`,
              observed: `${hook} modifies dist/ files after test execution`,
            })
            .sink({
              sink_type: "config-modification",
              location: "build output directory (dist/, build/, out/, lib/)",
              observed: `Post-build file modification: ${script.slice(0, 60)}`,
            })
            .mitigation({
              mitigation_type: "sanitizer-function",
              present: false,
              location: "build pipeline integrity",
              detail:
                "No integrity checksum or reproducible build verification between the build step " +
                "output and the published artifact. The post-build modification is invisible to the " +
                "test suite and any CI/CD quality gates that ran before this hook.",
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "connected-services",
              exploitability: "moderate",
              scenario:
                `The "${hook}" script modifies compiled JavaScript in the dist/ directory after tests ` +
                "pass. This creates a gap between what was tested and what gets published: (1) injected " +
                "code is never tested, (2) code reviewers see the source, not the modified dist, " +
                "(3) SLSA provenance claims are invalidated because the artifact is tampered post-build. " +
                "An attacker can insert a backdoor, data exfiltration hook, or dependency override " +
                "that exists only in the published artifact.",
            })
            .factor("structural_confirmed", 0.1, `Structural analysis confirmed ${hook} script modifies dist/ files with non-build tools`)
            .reference({
              id: "SLSA-Build-L2",
              title: "SLSA Framework: Build Integrity Requirements",
              year: 2024,
              relevance:
                "SLSA Level 2 requires that build artifacts are produced by a defined build process " +
                "without post-build modification. Post-build file tampering violates SLSA build " +
                "integrity and invalidates any provenance attestation.",
            })
            .reference({
              id: "CWE-494",
              title: "Download of Code Without Integrity Check",
              relevance:
                "Consumers install the modified artifact without verifying it matches the tested build " +
                "output — the post-build modification creates an integrity gap.",
            })
            .verification({
              step_type: "inspect-source",
              instruction:
                `Review the "${hook}" script: "${script.slice(0, 60)}". Determine exactly what ` +
                `modifications are made to dist/ files. Check if the modification: (1) injects new ` +
                `code not present in source, (2) modifies existing function behavior, (3) adds ` +
                `import/require statements, (4) changes configuration or environment references.`,
              target: `package.json → scripts.${hook}`,
              expected_observation:
                "Post-build script modifies compiled output files with non-build tools.",
            })
            .verification({
              step_type: "compare-baseline",
              instruction:
                "Run the build step in isolation (npm run build), hash the dist/ output, then run " +
                `the ${hook} step and hash again. Compare the hashes to identify exactly which files ` +
                "were modified and what changed. Any modification confirms build artifact tampering.",
              target: "dist/ directory before and after post-build hook",
              expected_observation:
                "File hashes differ — dist/ contents modified after build step completed.",
            })
            .build();

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
            metadata: { analysis_type: "structural", hook, script, evidence_chain: l12Chain },
          });
        }
      }

      // Detect test→modify→publish chains
      const testScript = scripts.test || "";
      const publishScript = scripts.prepublishOnly || scripts.prepublish || "";
      if (testScript && publishScript) {
        const hasModifyBetween = /(?:sed|awk|cat\s*>>|echo\s*>>).*(?:dist|build|lib)/i.test(publishScript);
        if (hasModifyBetween) {
          const l12PubChain = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: "package.json → scripts.prepublish(Only)",
              observed: publishScript.slice(0, 100),
              rationale:
                "The prepublish script contains file modification commands (sed, awk, cat >>, echo >>) " +
                "targeting the build output directory. npm's lifecycle ordering runs test → prepublish → " +
                "pack, meaning this modification happens AFTER tests pass but BEFORE the package is packed " +
                "for publishing. The tested code and the published code diverge.",
            })
            .propagation({
              propagation_type: "function-call",
              location: "npm lifecycle: test → prepublish → pack",
              observed: `prepublish modifies dist/ after test: ${publishScript.slice(0, 60)}`,
            })
            .sink({
              sink_type: "config-modification",
              location: "build output (dist/, build/, lib/)",
              observed: "Build artifacts modified between test execution and package publishing",
            })
            .mitigation({
              mitigation_type: "sanitizer-function",
              present: false,
              location: "npm publish pipeline",
              detail:
                "No post-test integrity verification. npm does not compare the tested build output " +
                "with the published artifact — any modification in prepublish is invisible to CI/CD.",
            })
            .impact({
              impact_type: "remote-code-execution",
              scope: "connected-services",
              exploitability: "moderate",
              scenario:
                "Build artifacts are modified after tests pass, creating an untested code path in the " +
                "published package. This test-coverage gap can conceal injected backdoors, modified " +
                "dependencies, or altered function behavior that would have been caught by the test suite.",
            })
            .factor("structural_confirmed", 0.05, "Structural analysis confirmed prepublish modifies dist/ with non-build tools")
            .reference({
              id: "SLSA-Build-L2",
              title: "SLSA Framework: Build Integrity",
              year: 2024,
              relevance: "Post-test artifact modification violates SLSA build integrity requirements.",
            })
            .verification({
              step_type: "inspect-source",
              instruction:
                `Review the prepublish script: "${publishScript.slice(0, 60)}". Identify which dist/ ` +
                `files are modified and what changes are applied. Determine if the modification has a ` +
                `legitimate purpose (e.g., version stamping) or introduces untested code.`,
              target: "package.json → scripts.prepublish(Only)",
              expected_observation: "prepublish modifies build output after test execution.",
            })
            .build();

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
            metadata: { analysis_type: "structural", evidence_chain: l12PubChain },
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

        const k10Chain = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${line}`,
            observed: `${type} registry: ${url}`,
            rationale:
              `A non-standard ${type} package registry URL is configured. Package managers (npm, pip, ` +
              `go) resolve and download dependencies from this URL instead of the official registry. ` +
              `If the registry is attacker-controlled, every package installed from it can contain ` +
              `arbitrary malicious code that executes during installation or at runtime.`,
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `${type} package resolution`,
            observed: `Package manager resolves dependencies from: ${url}`,
          })
          .sink({
            sink_type: "code-evaluation",
            location: "dependency installation",
            observed: `Packages downloaded and installed from non-standard registry: ${url}`,
          })
          .mitigation({
            mitigation_type: "auth-check",
            present: false,
            location: `${type} registry configuration`,
            detail:
              `No package signature verification or hash pinning configured for the non-standard ` +
              `registry. The ${type} package manager trusts whatever the registry returns without ` +
              `independent verification against the official registry.`,
          })
          .impact({
            impact_type: "remote-code-execution",
            scope: "connected-services",
            exploitability: "trivial",
            scenario:
              "An attacker controlling the registry URL can serve modified versions of any package. " +
              "The attack is transparent — `npm install` or `pip install` behaves normally, but every " +
              "package may contain injected backdoors, credential stealers, or reverse shells. " +
              "Alex Birsan's dependency confusion research (2021) demonstrated this attack against " +
              "Apple, Microsoft, and PayPal by publishing packages to a controlled registry.",
          })
          .factor("structural_confirmed", 0.05, `Registry URL does not match any known trusted ${type} registry`)
          .reference({
            id: "dependency-confusion-2021",
            title: "Alex Birsan: Dependency Confusion (February 2021)",
            year: 2021,
            relevance:
              "Birsan demonstrated that non-standard registry configurations enable supply chain attacks " +
              "at scale. Companies using private registries without proper scoping were vulnerable to " +
              "dependency confusion — the public registry version took precedence.",
          })
          .reference({
            id: "CWE-829",
            title: "Inclusion of Functionality from Untrusted Control Sphere",
            relevance:
              "Installing packages from an untrusted registry includes code from an uncontrolled " +
              "source — matching CWE-829's definition of untrusted functionality inclusion.",
          })
          .verification({
            step_type: "inspect-source",
            instruction:
              `Review the registry URL at line ${line}: "${url}". Determine: (1) is this a known ` +
              `enterprise registry (Artifactory, Nexus, Verdaccio) or an unknown external URL? ` +
              `(2) does the URL use HTTPS? (3) is there a corresponding scope configuration ` +
              `(@company:registry=...) that limits which packages come from this registry? ` +
              `(4) is the registry URL in a committed config file (.npmrc, pip.conf) or injected at ` +
              `runtime via environment variable?`,
            target: `source_code:${line}`,
            expected_observation:
              `Non-standard ${type} registry URL configured — packages resolved from untrusted source.`,
          })
          .verification({
            step_type: "check-config",
            instruction:
              "Check if package integrity verification is configured: (1) npm — package-lock.json " +
              "with integrity hashes, (2) pip — --require-hashes flag, (3) go — go.sum file. " +
              "Also check if the registry is scoped (applies only to specific package namespaces) " +
              "or global (applies to ALL package resolution).",
            target: "package manager integrity verification and registry scoping",
            expected_observation:
              "No integrity verification — packages from non-standard registry accepted without hash checks.",
          })
          .build();

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
          metadata: { analysis_type: "pattern", registry_type: type, url, line, evidence_chain: k10Chain },
        });
        break;
      }
    }

    return findings;
  }
}

// ─── Register ──────────────────────────────────────────────────────────────

// L14 findings are emitted by L5 (ManifestConfusionRule) during entry point analysis.
// Register stub so the engine doesn't warn about missing implementation.
class L14Stub implements TypedRule {
  readonly id = "L14";
  readonly name = "Hidden Entry Point Mismatch (via L5)";
  analyze(): TypedFinding[] { return []; }
}

registerTypedRule(new ManifestConfusionRule());
registerTypedRule(new L14Stub());
registerTypedRule(new BuildArtifactTamperingRule());
registerTypedRule(new RegistrySubstitutionRule());
