import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Responsible Disclosure Policy",
  description: "MCP Sentinel responsible disclosure policy for reporting security vulnerabilities in MCP servers discovered through our scanning infrastructure.",
};

export default function ResponsibleDisclosurePage() {
  return (
    <div className="disclosure-page">
      <h1 className="disclosure-title">Responsible Disclosure Policy</h1>
      <p className="disclosure-updated">Last updated: March 2026</p>

      <section className="disclosure-section">
        <h2>Scope</h2>
        <p>
          This policy covers security vulnerabilities discovered by MCP Sentinel&apos;s automated scanning
          infrastructure across the MCP server ecosystem. We scan 21,000+ servers against 177 detection rules
          covering prompt injection, command injection, data exfiltration, supply chain attacks, and more.
        </p>
      </section>

      <section className="disclosure-section">
        <h2>Our Commitment</h2>
        <ul>
          <li>We will <strong>not</strong> publicly disclose specific vulnerabilities with exploitable detail until the server author has been notified and given reasonable time to remediate.</li>
          <li>We publish <strong>aggregate statistics</strong> (e.g., &ldquo;23% of servers have prompt injection risks&rdquo;) without identifying individual servers.</li>
          <li>We display <strong>findings on server detail pages</strong> with remediation guidance — this is intended to help, not shame.</li>
          <li>Server authors can <strong>dispute findings</strong> they believe are false positives by contacting us.</li>
        </ul>
      </section>

      <section className="disclosure-section">
        <h2>Disclosure Timeline</h2>
        <div className="disclosure-timeline">
          <div className="disclosure-timeline-item">
            <span className="disclosure-timeline-day">Day 0</span>
            <span className="disclosure-timeline-desc">Vulnerability discovered by automated scan</span>
          </div>
          <div className="disclosure-timeline-item">
            <span className="disclosure-timeline-day">Day 1-7</span>
            <span className="disclosure-timeline-desc">Finding published on MCP Sentinel registry with remediation guidance</span>
          </div>
          <div className="disclosure-timeline-item">
            <span className="disclosure-timeline-day">Day 7-14</span>
            <span className="disclosure-timeline-desc">For critical/high severity: attempt to contact server author via GitHub issues or npm contact</span>
          </div>
          <div className="disclosure-timeline-item">
            <span className="disclosure-timeline-day">Day 90</span>
            <span className="disclosure-timeline-desc">Finding included in quarterly &ldquo;State of MCP Security&rdquo; report (aggregated, anonymized)</span>
          </div>
        </div>
      </section>

      <section className="disclosure-section">
        <h2>What We Scan</h2>
        <p>MCP Sentinel&apos;s scanner performs <strong>passive analysis only</strong>:</p>
        <ul>
          <li>Tool descriptions and parameter schemas (no tool invocation)</li>
          <li>Source code from public GitHub repositories</li>
          <li>Package dependencies from npm/PyPI manifests</li>
          <li>MCP protocol metadata via <code>initialize</code> + <code>tools/list</code> (read-only)</li>
        </ul>
        <p>
          We <strong>never invoke tools</strong> on scanned servers. We never send test payloads,
          make authenticated requests, or interact with server-side resources.
        </p>
      </section>

      <section className="disclosure-section">
        <h2>Dispute a Finding</h2>
        <p>
          If you believe a finding on your server is a false positive, please open an issue on our
          GitHub repository with the server slug and finding details. We will review and update
          the finding status within 7 days.
        </p>
      </section>

      <section className="disclosure-section">
        <h2>Report a Vulnerability in MCP Sentinel</h2>
        <p>
          If you discover a security vulnerability in MCP Sentinel itself (our scanner, website, or API),
          please report it via GitHub Security Advisories on our repository. Do not open a public issue
          for security vulnerabilities.
        </p>
      </section>
    </div>
  );
}
