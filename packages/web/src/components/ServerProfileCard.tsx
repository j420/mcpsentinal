/**
 * ServerProfileCard — Displays server capability classification, attack surfaces, and threats.
 *
 * Renders the profiler's output: what the server does (capabilities with confidence bars),
 * what attack surfaces those capabilities create, data flow pairs between tools,
 * and which threat categories are applicable.
 *
 * Server component — no client-side state needed. Data passed from parent.
 * Gracefully renders nothing if profile is null/undefined (pre-API).
 */

// ─── Types ───────────────────────────────────────────────────────────────────

interface CapabilityEvidence {
  source: string;
  tool_name: string | null;
  detail: string;
  weight: number;
}

interface Capability {
  capability: string;
  confidence: number;
  evidence: CapabilityEvidence[];
}

interface DataFlowPair {
  source_tool: string;
  sink_tool: string;
  flow_type: string;
}

interface Threat {
  id: string;
  name: string;
  description: string;
  rule_ids: string[];
}

export interface ServerProfileData {
  profile_type: string;
  capabilities: Capability[];
  attack_surfaces: string[];
  data_flow_pairs: DataFlowPair[];
  threats: Threat[];
  summary: string;
  has_source_code: boolean;
  has_connection: boolean;
  has_dependencies: boolean;
  tool_count: number;
}

// ─── Constants ───────────────────────────────────────────────────────────────

/** Human-readable capability labels. Unknown capabilities fall back to title-casing the raw key. */
const CAPABILITY_LABELS: Record<string, string> = {
  "reads-private-data": "Reads Private Data",
  "reads-public-data": "Reads Public Data",
  "writes-filesystem": "Writes Filesystem",
  "writes-database": "Writes Database",
  "executes-code": "Executes Code",
  "sends-network": "Sends Network",
  "ingests-untrusted": "Ingests Untrusted Content",
  "manages-credentials": "Manages Credentials",
  "modifies-config": "Modifies Config",
  "destructive-ops": "Destructive Operations",
  "cross-agent-comm": "Cross-Agent Comms",
  "privileged-system": "Privileged System Access",
  "user-interaction": "User Interaction",
};

/** Map capabilities to CSS color modifier class. */
const CAPABILITY_COLORS: Record<string, string> = {
  "reads-private-data": "sp-cap-read",
  "reads-public-data": "sp-cap-read",
  "writes-filesystem": "sp-cap-write",
  "writes-database": "sp-cap-write",
  "executes-code": "sp-cap-exec",
  "sends-network": "sp-cap-net",
  "ingests-untrusted": "sp-cap-ingest",
  "manages-credentials": "sp-cap-cred",
  "modifies-config": "sp-cap-write",
  "destructive-ops": "sp-cap-exec",
  "cross-agent-comm": "sp-cap-net",
  "privileged-system": "sp-cap-exec",
  "user-interaction": "sp-cap-read",
};

/** Human-readable attack surface labels. */
const SURFACE_LABELS: Record<string, string> = {
  "code-execution": "Code Execution",
  "data-exfiltration": "Data Exfiltration",
  "prompt-injection": "Prompt Injection",
  "credential-theft": "Credential Theft",
  "supply-chain": "Supply Chain",
  "privilege-escalation": "Privilege Escalation",
  "denial-of-service": "Denial of Service",
  "config-poisoning": "Config Poisoning",
  "cross-agent-attack": "Cross-Agent Attack",
};

/** SVG icons per attack surface. Inline SVG keeps bundle dependency-free. */
const SURFACE_ICONS: Record<string, string> = {
  "code-execution": "M4 3h8l4 4v9a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2zm4 7v4m-2-2h4",
  "data-exfiltration": "M12 19V5m0 0l-4 4m4-4l4 4M4 15h16",
  "prompt-injection": "M8 2v4m0 12v4M2 8h4m12 0h4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83",
  "credential-theft": "M12 2a4 4 0 014 4v2H8V6a4 4 0 014-4zM6 8h12v10a2 2 0 01-2 2H8a2 2 0 01-2-2V8z",
  "supply-chain": "M4 6h16M4 12h16M4 18h16",
  "privilege-escalation": "M13 7l5 5-5 5M6 7l5 5-5 5",
  "denial-of-service": "M18.364 5.636a9 9 0 010 12.728M5.636 5.636a9 9 0 000 12.728M12 8v4m0 4h.01",
  "config-poisoning": "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37a1.724 1.724 0 002.573-1.066z",
  "cross-agent-attack": "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z",
};

const FLOW_TYPE_LABELS: Record<string, string> = {
  "data-read-to-send": "Read \u2192 Send",
  "ingest-to-execute": "Ingest \u2192 Execute",
  "credential-to-network": "Credential \u2192 Network",
  "config-write-read": "Config Write \u2192 Read",
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function capLabel(capability: string): string {
  return CAPABILITY_LABELS[capability] ?? capability.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function confidenceLevel(c: number): "high" | "medium" | "low" {
  if (c >= 0.75) return "high";
  if (c >= 0.45) return "medium";
  return "low";
}

function pct(n: number): string {
  return `${Math.round(n * 100)}%`;
}

// ─── Component ───────────────────────────────────────────────────────────────

export default function ServerProfileCard({ profile }: { profile: ServerProfileData | null | undefined }) {
  if (!profile) return null;

  // Sort capabilities by confidence descending
  const sortedCaps = [...profile.capabilities].sort((a, b) => b.confidence - a.confidence);

  // Split into high-confidence (show expanded) and low-confidence (collapsed)
  const primaryCaps = sortedCaps.filter((c) => c.confidence >= 0.4);
  const secondaryCaps = sortedCaps.filter((c) => c.confidence < 0.4);

  return (
    <section className="sd-section sp-section">
      <h2 className="sd-section-title">
        Server Profile
        <span className="sp-profile-type">{profile.profile_type}</span>
      </h2>
      <p className="sd-section-sub">{profile.summary}</p>

      {/* ── Capabilities ─────────────────────────────────────── */}
      <div className="sp-grid">
        <div className="sp-col">
          <h3 className="sp-col-title">Capabilities</h3>
          <div className="sp-caps">
            {primaryCaps.map((cap) => (
              <div key={cap.capability} className={`sp-cap ${CAPABILITY_COLORS[cap.capability] ?? ""}`}>
                <div className="sp-cap-header">
                  <span className="sp-cap-name">{capLabel(cap.capability)}</span>
                  <span className={`sp-cap-conf sp-cap-conf-${confidenceLevel(cap.confidence)}`}>
                    {pct(cap.confidence)}
                  </span>
                </div>
                <div className="sp-cap-bar-track">
                  <div
                    className={`sp-cap-bar-fill sp-cap-bar-${confidenceLevel(cap.confidence)}`}
                    style={{ width: pct(cap.confidence) }}
                  />
                </div>
                {cap.evidence.length > 0 && (
                  <div className="sp-cap-evidence">
                    {cap.evidence.slice(0, 3).map((e, i) => (
                      <span key={i} className="sp-cap-ev-item" title={e.detail}>
                        {e.tool_name ? `${e.tool_name}: ` : ""}{e.detail.slice(0, 60)}{e.detail.length > 60 ? "\u2026" : ""}
                      </span>
                    ))}
                    {cap.evidence.length > 3 && (
                      <span className="sp-cap-ev-more">+{cap.evidence.length - 3} more</span>
                    )}
                  </div>
                )}
              </div>
            ))}
            {secondaryCaps.length > 0 && (
              <div className="sp-secondary">
                <span className="sp-secondary-label">Low confidence ({secondaryCaps.length})</span>
                <div className="sp-secondary-list">
                  {secondaryCaps.map((cap) => (
                    <span key={cap.capability} className="sp-secondary-chip">
                      {capLabel(cap.capability)} <span className="sp-secondary-pct">{pct(cap.confidence)}</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── Attack Surfaces ─────────────────────────────────── */}
        <div className="sp-col">
          <h3 className="sp-col-title">Attack Surfaces</h3>
          {profile.attack_surfaces.length === 0 ? (
            <p className="sp-empty">No attack surfaces identified</p>
          ) : (
            <div className="sp-surfaces">
              {profile.attack_surfaces.map((surface) => (
                <div key={surface} className="sp-surface">
                  <svg className="sp-surface-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d={SURFACE_ICONS[surface] ?? "M12 2v20M2 12h20"} />
                  </svg>
                  <span className="sp-surface-name">{SURFACE_LABELS[surface] ?? surface}</span>
                </div>
              ))}
            </div>
          )}

          {/* ── Data Flow Pairs ─────────────────────────────────── */}
          {profile.data_flow_pairs.length > 0 && (
            <>
              <h3 className="sp-col-title sp-col-title-sub">Data Flow Pairs</h3>
              <div className="sp-flows">
                {profile.data_flow_pairs.map((flow, i) => (
                  <div key={i} className="sp-flow">
                    <span className="sp-flow-tool">{flow.source_tool}</span>
                    <span className="sp-flow-arrow">\u2192</span>
                    <span className="sp-flow-tool">{flow.sink_tool}</span>
                    <span className="sp-flow-type">{FLOW_TYPE_LABELS[flow.flow_type] ?? flow.flow_type}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── Applicable Threats ─────────────────────────────────── */}
      {profile.threats.length > 0 && (
        <div className="sp-threats">
          <h3 className="sp-col-title">Applicable Threats <span className="sp-threat-count">{profile.threats.length}</span></h3>
          <div className="sp-threats-grid">
            {profile.threats.map((threat) => (
              <div key={threat.id} className="sp-threat">
                <div className="sp-threat-header">
                  <span className="sp-threat-id">{threat.id}</span>
                  <span className="sp-threat-name">{threat.name}</span>
                </div>
                <p className="sp-threat-desc">{threat.description}</p>
                <div className="sp-threat-rules">
                  {threat.rule_ids.slice(0, 8).map((rid) => (
                    <span key={rid} className="sp-threat-rule">{rid}</span>
                  ))}
                  {threat.rule_ids.length > 8 && (
                    <span className="sp-threat-rule sp-threat-rule-more">+{threat.rule_ids.length - 8}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Analysis Coverage ──────────────────────────────────── */}
      <div className="sp-coverage">
        <span className={`sp-cov-badge ${profile.has_source_code ? "sp-cov-yes" : "sp-cov-no"}`}>
          {profile.has_source_code ? "\u2713" : "\u2717"} Source Code
        </span>
        <span className={`sp-cov-badge ${profile.has_connection ? "sp-cov-yes" : "sp-cov-no"}`}>
          {profile.has_connection ? "\u2713" : "\u2717"} Live Connection
        </span>
        <span className={`sp-cov-badge ${profile.has_dependencies ? "sp-cov-yes" : "sp-cov-no"}`}>
          {profile.has_dependencies ? "\u2713" : "\u2717"} Dependencies
        </span>
        <span className="sp-cov-badge sp-cov-neutral">
          {profile.tool_count} Tools Analyzed
        </span>
      </div>
    </section>
  );
}
