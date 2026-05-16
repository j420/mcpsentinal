import type { Metadata } from "next";
import ScanForm from "./ScanForm";

export const metadata: Metadata = {
  title: "Scan Your MCP Server — MCP Sentinel",
  description:
    "Scan any MCP server against 164 deterministic security detection rules. Paste a URL, an MCP client config, or a GitHub/npm reference and get a security report in seconds.",
};

export default function ScanPage() {
  return (
    <div className="scan-page">
      <section className="scan-hero">
        <div className="hero-eyebrow">
          <span className="hero-eyebrow-mark" aria-hidden="true">AD-HOC SCAN</span>
          <span aria-hidden="true">·</span>
          <span>Scan any MCP server</span>
        </div>
        <h1 className="scan-hero-title">Scan your MCP server</h1>
        <p className="scan-hero-sub">
          Run a live security scan against 164 deterministic detection rules.
          Submit a URL, paste your MCP client config, or point at a GitHub repo
          or npm package. Every successful scan is added to the public registry.
        </p>
      </section>

      <ScanForm />

      <section className="scan-explain">
        <h2 className="scan-explain-title">What gets checked</h2>
        <div className="scan-explain-grid">
          <div className="scan-explain-item">
            <h3>Live URL &amp; config</h3>
            <p>
              Connects over MCP, enumerates tools, resources and prompts, and
              runs the description, schema, protocol-surface and adversarial-AI
              rule families (~60–80 rules).
            </p>
          </div>
          <div className="scan-explain-item">
            <h3>GitHub / npm source</h3>
            <p>
              Fetches the source and dependency manifest, unlocking the full
              164-rule suite — including code-analysis, dependency and
              supply-chain rules. Takes a little longer.
            </p>
          </div>
          <div className="scan-explain-item">
            <h3>Honest coverage</h3>
            <p>
              Every report carries a confidence band so a metadata-only URL
              scan is never mistaken for a full source-backed analysis.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
