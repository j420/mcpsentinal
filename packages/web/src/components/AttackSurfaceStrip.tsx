/**
 * AttackSurfaceStrip — capability-domain cards between hero and tabs.
 *
 * Groups tools by their `capability_tags` enum into domain cards. Each card's
 * top border maps to the matching --cap-* CSS var from globals.css. Tool-level
 * poisoning indicators are derived client-side from findings whose rule_id is
 * in the documented tool-poisoning set (per agent_docs/detection-rules.md
 * OWASP MCP02 + MCP01 mappings).
 *
 * Domains shown only when count > 0. No "Database" card — `accesses-database`
 * is not in the CapabilityTag enum.
 */

import React from "react";

interface Tool {
  name: string;
  capability_tags: string[];
}

interface Finding {
  rule_id: string;
  evidence: string;
  severity: string;
}

interface Props {
  tools: Tool[];
  findings: Finding[];
}

// Tool-poisoning rule set: OWASP MCP02 (Tool Poisoning) + MCP01 (Prompt Injection)
// rules that specifically target tool-level metadata. See agent_docs/detection-rules.md.
const POISONING_RULES = new Set([
  "A1", "A2", "A4", "A6", "A7", "A8", "A9",
  "B5", "B7",
  "F1", "F5",
  "I1", "I2",
  "J3", "J5", "J6",
]);

interface DomainSpec {
  key: string;
  label: string;
  borderVar: string;
  match: (tags: Set<string>) => boolean;
}

// Domain specs ordered by descending risk. A tool may match multiple domains.
const DOMAINS: DomainSpec[] = [
  {
    key: "shell",
    label: "Shell / Code Execution",
    borderVar: "--cap-exec-border",
    match: (t) => t.has("executes-code"),
  },
  {
    key: "creds",
    label: "Credentials & Secrets",
    borderVar: "--cap-cred-border",
    match: (t) => t.has("manages-credentials"),
  },
  {
    key: "network",
    label: "Network",
    borderVar: "--cap-net-border",
    match: (t) => t.has("sends-network"),
  },
  {
    key: "fs-write",
    label: "Filesystem (Write)",
    borderVar: "--cap-write-border",
    match: (t) => t.has("accesses-filesystem") && t.has("writes-data"),
  },
  {
    key: "fs-read",
    label: "Filesystem (Read)",
    borderVar: "--cap-read-border",
    match: (t) =>
      t.has("accesses-filesystem") && t.has("reads-data") && !t.has("writes-data"),
  },
  {
    key: "other",
    label: "Other / Data Handling",
    borderVar: "--border-strong",
    match: (t) =>
      t.size > 0 &&
      !t.has("executes-code") &&
      !t.has("manages-credentials") &&
      !t.has("sends-network") &&
      !t.has("accesses-filesystem"),
  },
];

function findingsTouchingTool(toolName: string, findings: Finding[]): Finding[] {
  // Conservative: a poisoning rule fires somewhere on this server, attribute
  // it to the named tool if its evidence references the name. If no name is
  // referenced, fall back to all tools in the matching domain.
  return findings.filter(
    (f) => POISONING_RULES.has(f.rule_id) && (f.evidence ?? "").includes(toolName),
  );
}

function unattributedPoisonings(findings: Finding[]): Finding[] {
  return findings.filter(
    (f) => POISONING_RULES.has(f.rule_id),
  );
}

export default function AttackSurfaceStrip({ tools, findings }: Props) {
  if (!tools || tools.length === 0) return null;

  const cards: Array<{
    spec: DomainSpec;
    tools: Tool[];
    poisonedTools: Set<string>;
    domainHasUnattributed: boolean;
  }> = [];

  const allPoisonings = unattributedPoisonings(findings);
  const hasAnyAttributed = allPoisonings.some((f) =>
    tools.some((t) => (f.evidence ?? "").includes(t.name)),
  );

  for (const spec of DOMAINS) {
    const matched = tools.filter((t) => spec.match(new Set(t.capability_tags ?? [])));
    if (matched.length === 0) continue;

    const poisoned = new Set<string>();
    for (const t of matched) {
      if (findingsTouchingTool(t.name, findings).length > 0) {
        poisoned.add(t.name);
      }
    }
    // If any poisoning fires but is not attributable to a specific tool name,
    // mark the whole domain conservatively (per the prompt's "attribute to all").
    const domainHasUnattributed = !hasAnyAttributed && allPoisonings.length > 0;

    cards.push({ spec, tools: matched, poisonedTools: poisoned, domainHasUnattributed });
  }

  if (cards.length === 0) return null;

  return (
    <section className="ass-strip" aria-label="Attack surface by capability domain">
      <h2 className="ass-title">Attack surface</h2>
      <div className="ass-grid">
        {cards.map(({ spec, tools: domainTools, poisonedTools, domainHasUnattributed }) => {
          const hasPoison = poisonedTools.size > 0 || domainHasUnattributed;
          return (
            <div
              key={spec.key}
              className="ass-card"
              style={{ borderTopColor: `var(${spec.borderVar})` }}
            >
              <div className="ass-card-head">
                <span className="ass-card-label">{spec.label}</span>
                <span className="ass-card-count">
                  {domainTools.length} tool{domainTools.length === 1 ? "" : "s"}
                </span>
              </div>
              <ul className="ass-tool-list">
                {domainTools.map((t) => {
                  const poisoned = poisonedTools.has(t.name) || domainHasUnattributed;
                  return (
                    <li key={t.name} className="ass-tool-row">
                      {poisoned && (
                        <span
                          className="ass-poison-dot"
                          title="Tool referenced by a poisoning-class finding"
                          aria-label="poisoning indicator"
                        />
                      )}
                      <span className="ass-tool-name">{t.name}</span>
                    </li>
                  );
                })}
              </ul>
              {hasPoison && (
                <div className="ass-card-warn">
                  ⚠ poisoning indicators detected
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
