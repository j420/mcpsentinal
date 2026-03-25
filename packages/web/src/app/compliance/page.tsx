import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Compliance & Governance",
  description: "MCP Sentinel maps 177 detection rules to 9 security frameworks: OWASP MCP Top 10, OWASP Agentic Top 10, MITRE ATLAS, NIST AI RMF, ISO 27001, ISO 42001, EU AI Act, CoSAI MCP Security, and MAESTRO.",
};

const FRAMEWORKS = [
  {
    id: "owasp-mcp",
    name: "OWASP MCP Top 10",
    desc: "The definitive security risk taxonomy for MCP servers. 10 categories covering prompt injection, tool poisoning, command injection, data exfiltration, privilege escalation, and more.",
    ruleCount: 177,
    color: "#B91C1C",
    categories: [
      { id: "MCP01", name: "Prompt Injection", rules: 14 },
      { id: "MCP02", name: "Tool Poisoning", rules: 9 },
      { id: "MCP03", name: "Command Injection", rules: 6 },
      { id: "MCP04", name: "Data Exfiltration", rules: 6 },
      { id: "MCP05", name: "Privilege Escalation", rules: 7 },
      { id: "MCP06", name: "Excessive Permissions", rules: 7 },
      { id: "MCP07", name: "Insecure Configuration", rules: 11 },
      { id: "MCP08", name: "Dependency Vulnerabilities", rules: 7 },
      { id: "MCP09", name: "Logging & Monitoring", rules: 2 },
      { id: "MCP10", name: "Supply Chain", rules: 8 },
    ],
  },
  {
    id: "owasp-agentic",
    name: "OWASP Agentic Top 10",
    desc: "Security risks specific to agentic AI applications. MCP Sentinel is the first tool to map detection rules to both MCP and Agentic Top 10 frameworks.",
    ruleCount: 82,
    color: "#C2410C",
    categories: [
      { id: "ASI01", name: "Agent Goal Hijack", rules: 10 },
      { id: "ASI02", name: "Tool Misuse", rules: 9 },
      { id: "ASI03", name: "Identity & Privilege Abuse", rules: 5 },
      { id: "ASI04", name: "Agentic Supply Chain", rules: 7 },
      { id: "ASI05", name: "Unexpected Code Execution", rules: 6 },
      { id: "ASI06", name: "Memory & Context Poisoning", rules: 8 },
      { id: "ASI07", name: "Insecure Inter-Agent Communication", rules: 5 },
    ],
  },
  {
    id: "mitre",
    name: "MITRE ATLAS",
    desc: "Adversarial Threat Landscape for AI Systems. ATLAS techniques mapped to MCP-specific detection patterns covering LLM prompt injection, data leakage, context poisoning, and agent manipulation.",
    ruleCount: 148,
    color: "#7C3AED",
    categories: [
      { id: "AML.T0054", name: "LLM Prompt Injection", rules: 14 },
      { id: "AML.T0057", name: "LLM Data Leakage", rules: 6 },
      { id: "AML.T0058", name: "AI Agent Context Poisoning", rules: 6 },
      { id: "AML.T0059", name: "Memory Manipulation", rules: 3 },
      { id: "AML.T0060", name: "Modify AI Agent Configuration", rules: 1 },
      { id: "AML.T0061", name: "Thread Injection", rules: 3 },
    ],
  },
  {
    id: "nist",
    name: "NIST AI RMF",
    desc: "The NIST AI Risk Management Framework provides standards for trustworthy AI. MCP Sentinel covers GOVERN and MEASURE functions through audit trail and human oversight rules.",
    ruleCount: 4,
    color: "#1D4ED8",
    categories: [
      { id: "GOVERN 1.7", name: "Human Override Mechanisms", rules: 2 },
      { id: "MEASURE 2.6", name: "Audit Evidence & Logging", rules: 2 },
    ],
  },
  {
    id: "iso27k",
    name: "ISO 27001",
    desc: "Information security management standard. MCP Sentinel maps to 10 Annex A controls covering audit logging, access control, cryptography, supplier relationships, and system security.",
    ruleCount: 11,
    color: "#4338CA",
    categories: [
      { id: "A.5.14", name: "Information Transfer", rules: 1 },
      { id: "A.5.15", name: "Access Control", rules: 1 },
      { id: "A.5.17", name: "Authentication Information", rules: 1 },
      { id: "A.5.20", name: "Addressing Security in Supplier Agreements", rules: 1 },
      { id: "A.5.21", name: "Managing ICT Supply Chain", rules: 1 },
      { id: "A.8.15", name: "Logging", rules: 4 },
      { id: "A.8.22", name: "Segregation of Networks", rules: 1 },
      { id: "A.8.24", name: "Use of Cryptography", rules: 1 },
    ],
  },
  {
    id: "iso42k",
    name: "ISO 42001",
    desc: "AI Management System standard. MCP Sentinel covers human-in-the-loop requirements and AI transparency controls.",
    ruleCount: 3,
    color: "#6D28D9",
    categories: [
      { id: "A.8.1", name: "AI System Transparency", rules: 1 },
      { id: "A.9.1", name: "Human Control of AI Systems", rules: 1 },
      { id: "A.9.2", name: "Human Override", rules: 1 },
    ],
  },
  {
    id: "eu-ai",
    name: "EU AI Act",
    desc: "European regulation on artificial intelligence. MCP Sentinel covers Article 12 (record-keeping), Article 14 (human oversight), and Article 15 (robustness and cybersecurity).",
    ruleCount: 5,
    color: "#0D9488",
    categories: [
      { id: "Art. 12", name: "Record-keeping (Logging)", rules: 1 },
      { id: "Art. 14", name: "Human Oversight", rules: 2 },
      { id: "Art. 15", name: "Accuracy, Robustness, Cybersecurity", rules: 2 },
    ],
  },
  {
    id: "cosai",
    name: "CoSAI MCP Security",
    desc: "Coalition for Secure AI threat model for MCP. MCP Sentinel covers 9 of 12 threat categories including authentication, authorization, tool safety, and supply chain integrity.",
    ruleCount: 36,
    color: "#0D7C5F",
    categories: [
      { id: "MCP-T1/T2", name: "Authentication & Authorization", rules: 6 },
      { id: "MCP-T4", name: "Tool Output Safety", rules: 2 },
      { id: "MCP-T5", name: "Cross-Trust-Boundary Data Flow", rules: 1 },
      { id: "MCP-T6/T11", name: "Supply Chain Integrity", rules: 6 },
      { id: "MCP-T8", name: "Runtime Sandbox", rules: 1 },
      { id: "MCP-T9", name: "Multi-Agent Collusion", rules: 1 },
      { id: "MCP-T10", name: "Availability & Resilience", rules: 2 },
      { id: "MCP-T12", name: "Audit & Monitoring", rules: 4 },
    ],
  },
  {
    id: "maestro",
    name: "MAESTRO",
    desc: "Multi-Agent Evaluation and Security Testing for Robust Operations. Layered security model for AI agent systems covering trust, isolation, observability, and governance.",
    ruleCount: 12,
    color: "#B45309",
    categories: [
      { id: "L3", name: "Agent Layer — Integrity", rules: 2 },
      { id: "L4", name: "Deployment Layer — Isolation", rules: 3 },
      { id: "L5", name: "Observability Layer — Logging", rules: 4 },
      { id: "L7", name: "Ecosystem Layer — Trust", rules: 3 },
    ],
  },
];

export default function CompliancePage() {
  return (
    <div className="compliance-page">
      <section className="compliance-hero">
        <div className="scanner-hero-badge">Layer 6</div>
        <h1 className="compliance-hero-title">Compliance & Governance</h1>
        <p className="compliance-hero-sub">
          177 detection rules mapped to 9 security frameworks. Every finding traces back to specific controls,
          articles, and techniques — making compliance audits data-driven, not guesswork.
        </p>
      </section>

      <section className="compliance-grid">
        {FRAMEWORKS.map((fw) => (
          <div key={fw.id} className="compliance-card" style={{ borderTopColor: fw.color }}>
            <div className="compliance-card-header">
              <h2 className="compliance-card-name" style={{ color: fw.color }}>{fw.name}</h2>
              <span className="compliance-card-count" style={{ color: fw.color, borderColor: fw.color }}>
                {fw.ruleCount} rules
              </span>
            </div>
            <p className="compliance-card-desc">{fw.desc}</p>
            <div className="compliance-card-categories">
              {fw.categories.map((cat) => (
                <div key={cat.id} className="compliance-cat-row">
                  <span className="compliance-cat-id">{cat.id}</span>
                  <span className="compliance-cat-name">{cat.name}</span>
                  <span className="compliance-cat-rules">{cat.rules}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </section>

      <section className="compliance-cta">
        <h2 className="compliance-cta-title">Scan your MCP servers for compliance</h2>
        <p className="compliance-cta-desc">
          Use mcp-sentinel-scanner to check any server against all 9 frameworks. Every finding includes
          the framework control it maps to, evidence of the violation, and remediation steps.
        </p>
        <a href="/scanner" className="compliance-cta-btn">Get started with MCP Scanner</a>
      </section>
    </div>
  );
}
