import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "MCP Sentinel Scanner — Scan Any MCP Server",
  description:
    "Use mcp-sentinel-scanner to analyze any MCP server against 177 security detection rules. Setup guide, expected results, and configuration examples.",
};

export default function ScannerPage() {
  return (
    <div className="scanner-page">
      {/* ── Hero ──────────────────────────────── */}
      <section className="scanner-hero">
        <div className="scanner-hero-badge">MCP Server</div>
        <h1 className="scanner-hero-title">mcp-sentinel-scanner</h1>
        <p className="scanner-hero-sub">
          Scan any MCP server against 177 security detection rules — directly from Claude, Cursor, or any MCP client.
        </p>
        <div className="scanner-install-box">
          <code className="scanner-install-cmd">npx mcp-sentinel-scanner</code>
        </div>
      </section>

      {/* ── Quick Setup ──────────────────────── */}
      <section className="scanner-section">
        <h2 className="scanner-section-title">Quick Setup</h2>
        <div className="scanner-steps">
          <div className="scanner-step">
            <div className="scanner-step-num">1</div>
            <div className="scanner-step-content">
              <h3 className="scanner-step-title">Add to Claude Desktop</h3>
              <p className="scanner-step-desc">
                Open your Claude Desktop config and add the scanner as an MCP server:
              </p>
              <pre className="scanner-code">{`{
  "mcpServers": {
    "mcp-sentinel-scanner": {
      "command": "npx",
      "args": ["-y", "mcp-sentinel-scanner"]
    }
  }
}`}</pre>
            </div>
          </div>

          <div className="scanner-step">
            <div className="scanner-step-num">2</div>
            <div className="scanner-step-content">
              <h3 className="scanner-step-title">Ask Claude to scan</h3>
              <p className="scanner-step-desc">
                Just ask in natural language. The scanner exposes three tools that Claude can call:
              </p>
              <div className="scanner-examples">
                <div className="scanner-example">
                  <span className="scanner-example-label">Scan a live endpoint</span>
                  <span className="scanner-example-text">&ldquo;Scan the MCP server at https://api.example.com/mcp for security issues&rdquo;</span>
                </div>
                <div className="scanner-example">
                  <span className="scanner-example-label">Analyze server metadata</span>
                  <span className="scanner-example-text">&ldquo;Check this MCP server&apos;s tools for prompt injection risks&rdquo;</span>
                </div>
                <div className="scanner-example">
                  <span className="scanner-example-label">List detection rules</span>
                  <span className="scanner-example-text">&ldquo;What security rules does the scanner check for?&rdquo;</span>
                </div>
              </div>
            </div>
          </div>

          <div className="scanner-step">
            <div className="scanner-step-num">3</div>
            <div className="scanner-step-content">
              <h3 className="scanner-step-title">Get actionable results</h3>
              <p className="scanner-step-desc">
                Every finding includes evidence (what triggered it) and remediation (how to fix it).
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── Tools ────────────────────────────── */}
      <section className="scanner-section">
        <h2 className="scanner-section-title">Available Tools</h2>
        <div className="scanner-tools-grid">
          <div className="scanner-tool-card">
            <h3 className="scanner-tool-name">scan_server</h3>
            <p className="scanner-tool-desc">
              Analyze server metadata without a live connection. Pass tools, descriptions, source code, and dependencies. Returns findings + score.
            </p>
            <div className="scanner-tool-meta">
              <span className="scanner-tool-badge scanner-tool-badge-input">Input: tools, source code, dependencies</span>
              <span className="scanner-tool-badge scanner-tool-badge-output">Output: findings + 0-100 score</span>
            </div>
          </div>

          <div className="scanner-tool-card">
            <h3 className="scanner-tool-name">scan_endpoint</h3>
            <p className="scanner-tool-desc">
              Connect to a live MCP server endpoint. Enumerates tools via <code>initialize</code> + <code>tools/list</code> (safe, read-only), then runs all 177 detection rules.
            </p>
            <div className="scanner-tool-meta">
              <span className="scanner-tool-badge scanner-tool-badge-input">Input: endpoint URL</span>
              <span className="scanner-tool-badge scanner-tool-badge-output">Output: findings + score + connection info</span>
            </div>
          </div>

          <div className="scanner-tool-card">
            <h3 className="scanner-tool-name">list_rules</h3>
            <p className="scanner-tool-desc">
              List all available detection rules. Filter by category or severity to explore specific rule sets.
            </p>
            <div className="scanner-tool-meta">
              <span className="scanner-tool-badge scanner-tool-badge-input">Input: optional category/severity filter</span>
              <span className="scanner-tool-badge scanner-tool-badge-output">Output: rule list with IDs, names, categories</span>
            </div>
          </div>
        </div>
      </section>

      {/* ── Example Output ────────────────────── */}
      <section className="scanner-section">
        <h2 className="scanner-section-title">Example Output</h2>
        <p className="scanner-section-sub">What a scan result looks like:</p>
        <pre className="scanner-code scanner-code-lg">{`{
  "server_name": "my-mcp-server",
  "total_score": 62,
  "rating": "Moderate",
  "findings_count": 3,
  "findings": [
    {
      "rule_id": "A1",
      "severity": "critical",
      "evidence": "Tool description contains injection pattern:
        'ignore all previous instructions'",
      "remediation": "Remove instruction-like language from
        tool descriptions. Use factual, concise descriptions."
    },
    {
      "rule_id": "C5",
      "severity": "high",
      "evidence": "Hardcoded API key pattern detected:
        sk-proj-abc123...",
      "remediation": "Move secrets to environment variables.
        Never hardcode API keys in source code."
    },
    {
      "rule_id": "B1",
      "severity": "medium",
      "evidence": "Parameter 'query' has type string with
        no maxLength, pattern, or enum constraint.",
      "remediation": "Add maxLength, pattern, or enum
        constraints to string parameters."
    }
  ],
  "score_breakdown": {
    "total_score": 62,
    "code_score": 85,
    "deps_score": 100,
    "config_score": 92,
    "description_score": 50,
    "behavior_score": 100
  }
}`}</pre>
      </section>

      {/* ── Score Interpretation ───────────────── */}
      <section className="scanner-section">
        <h2 className="scanner-section-title">Score Interpretation</h2>
        <div className="scanner-score-grid">
          <div className="scanner-score-item scanner-score-good">
            <span className="scanner-score-range">80-100</span>
            <span className="scanner-score-label">Good</span>
            <span className="scanner-score-desc">Low risk. Minor or no findings.</span>
          </div>
          <div className="scanner-score-item scanner-score-moderate">
            <span className="scanner-score-range">60-79</span>
            <span className="scanner-score-label">Moderate</span>
            <span className="scanner-score-desc">Some issues found. Review recommended.</span>
          </div>
          <div className="scanner-score-item scanner-score-poor">
            <span className="scanner-score-range">40-59</span>
            <span className="scanner-score-label">Poor</span>
            <span className="scanner-score-desc">Significant issues. Fix before deploying.</span>
          </div>
          <div className="scanner-score-item scanner-score-critical">
            <span className="scanner-score-range">0-39</span>
            <span className="scanner-score-label">Critical</span>
            <span className="scanner-score-desc">Severe vulnerabilities. Do not use in production.</span>
          </div>
        </div>
      </section>

      {/* ── Detection Coverage ────────────────── */}
      <section className="scanner-section">
        <h2 className="scanner-section-title">Detection Coverage</h2>
        <p className="scanner-section-sub">177 rules across 17 categories</p>
        <div className="scanner-coverage-grid">
          {[
            { cat: "A", name: "Description Analysis", count: 9, example: "Prompt injection, unicode attacks" },
            { cat: "B", name: "Schema Analysis", count: 7, example: "Missing validation, dangerous defaults" },
            { cat: "C", name: "Code Analysis", count: 16, example: "Command injection, SSRF, secrets" },
            { cat: "D", name: "Dependency Analysis", count: 7, example: "CVEs, typosquatting, malicious packages" },
            { cat: "E", name: "Behavioral Analysis", count: 4, example: "Auth, transport, response time" },
            { cat: "F", name: "Ecosystem Context", count: 7, example: "Lethal trifecta, exfiltration chains" },
            { cat: "G", name: "Adversarial AI", count: 7, example: "Indirect injection, rug pull" },
            { cat: "H", name: "2026 Attack Surface", count: 3, example: "OAuth, initialize injection" },
            { cat: "I", name: "Protocol Surface", count: 16, example: "Annotations, sampling, elicitation" },
            { cat: "J", name: "Threat Intelligence", count: 7, example: "CVE-backed: git injection, schema poisoning" },
            { cat: "K", name: "Compliance", count: 20, example: "NIST, ISO 27001, EU AI Act" },
            { cat: "L-Q", name: "Advanced Detection", count: 74, example: "Supply chain, AI runtime, data privacy" },
          ].map((c) => (
            <div key={c.cat} className="scanner-coverage-item">
              <span className="scanner-coverage-cat">{c.cat}</span>
              <div className="scanner-coverage-info">
                <span className="scanner-coverage-name">{c.name}</span>
                <span className="scanner-coverage-example">{c.example}</span>
              </div>
              <span className="scanner-coverage-count">{c.count}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ── Safety ────────────────────────────── */}
      <section className="scanner-section">
        <h2 className="scanner-section-title">Safety</h2>
        <div className="scanner-safety-box">
          <p>
            The scanner <strong>never invokes tools</strong> on target servers. It only calls <code>initialize</code> and <code>tools/list</code> for enumeration. All analysis is deterministic — no LLM calls, no false positives from probabilistic models.
          </p>
        </div>
      </section>

      {/* ── Other Clients ─────────────────────── */}
      <section className="scanner-section">
        <h2 className="scanner-section-title">Other MCP Clients</h2>
        <p className="scanner-section-sub">Works with any MCP-compatible client:</p>
        <div className="scanner-clients-grid">
          {[
            { name: "Cursor", config: "Settings → MCP → Add Server" },
            { name: "VS Code (Copilot)", config: ".vscode/mcp.json" },
            { name: "Windsurf", config: "~/.codeium/windsurf/mcp_config.json" },
            { name: "Claude Code", config: "claude mcp add mcp-sentinel-scanner" },
          ].map((c) => (
            <div key={c.name} className="scanner-client-card">
              <span className="scanner-client-name">{c.name}</span>
              <code className="scanner-client-config">{c.config}</code>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
