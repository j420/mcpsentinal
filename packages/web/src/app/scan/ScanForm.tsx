"use client";

/**
 * ScanForm — the ad-hoc "Scan your MCP server" input form.
 *
 * Three tabbed input modes (URL / pasted config / GitHub-npm ref). On submit
 * it POSTs to /api/v1/scan, receives a job id, and navigates to /scan/:id
 * where the result page polls for completion.
 */

import { useState } from "react";
import { useRouter } from "next/navigation";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

type Tab = "url" | "config" | "source";

const TABS: Array<{ id: Tab; label: string; hint: string }> = [
  { id: "url", label: "Live URL", hint: "A remote MCP server endpoint (HTTP / SSE)." },
  { id: "config", label: "Config JSON", hint: "Paste your MCP client config — remote entries are scanned." },
  { id: "source", label: "GitHub / npm", hint: "A github.com URL or an npm / PyPI package name." },
];

export default function ScanForm() {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>("url");
  const [url, setUrl] = useState("");
  const [config, setConfig] = useState("");
  const [ref, setRef] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);

    let body: Record<string, string>;
    if (tab === "url") {
      if (!url.trim()) return setError("Enter an MCP server URL.");
      body = { kind: "url", url: url.trim() };
    } else if (tab === "config") {
      if (!config.trim()) return setError("Paste an MCP client config.");
      body = { kind: "config", config: config.trim() };
    } else {
      if (!ref.trim()) return setError("Enter a GitHub URL or package name.");
      body = { kind: "source", ref: ref.trim() };
    }

    setSubmitting(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (res.status === 202) {
        const data = await res.json();
        router.push(`/scan/${data.id}`);
        return;
      }
      if (res.status === 429) {
        setError("Scan limit reached — at most 5 scans per hour. Please try again later.");
      } else if (res.status === 400) {
        setError("That input could not be read. Check the URL, config, or package name.");
      } else {
        setError("The scan could not be started. Please try again.");
      }
    } catch {
      setError("Could not reach the scanner. Check your connection and try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="scan-form">
      <div className="scan-tabs" role="tablist" aria-label="Scan input type">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={`scan-tab${tab === t.id ? " scan-tab-active" : ""}`}
            onClick={() => {
              setTab(t.id);
              setError(null);
            }}
            type="button"
          >
            {t.label}
          </button>
        ))}
      </div>

      <p className="scan-tab-hint">{TABS.find((t) => t.id === tab)?.hint}</p>

      {tab === "url" && (
        <input
          className="scan-input"
          type="url"
          placeholder="https://your-mcp-server.example.com/mcp"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          spellCheck={false}
          autoComplete="off"
        />
      )}

      {tab === "config" && (
        <textarea
          className="scan-textarea"
          placeholder={'{\n  "mcpServers": {\n    "my-server": { "url": "https://..." }\n  }\n}'}
          value={config}
          onChange={(e) => setConfig(e.target.value)}
          spellCheck={false}
          rows={10}
        />
      )}

      {tab === "source" && (
        <input
          className="scan-input"
          type="text"
          placeholder="github.com/owner/repo  ·  npm:package-name  ·  pypi:package-name"
          value={ref}
          onChange={(e) => setRef(e.target.value)}
          spellCheck={false}
          autoComplete="off"
        />
      )}

      {error && <p className="scan-error" role="alert">{error}</p>}

      <div className="scan-form-footer">
        <button
          className="btn-primary"
          type="button"
          onClick={submit}
          disabled={submitting}
        >
          {submitting ? "Starting scan…" : "Scan this server"}
        </button>
        <span className="scan-form-note">
          Read-only — MCP Sentinel only calls <code>initialize</code> and{" "}
          <code>tools/list</code>. It never invokes your tools.
        </span>
      </div>
    </div>
  );
}
