/**
 * VersionHistoryTab — score history timeline.
 *
 * Reframed from "server release versions" (which we don't track) to
 * "scan history" — fetches /api/v1/servers/:slug/history and renders a
 * timeline strip + drop-detection alert + table. Drops > 10 points
 * trigger an amber banner. Rule-set version changes are surfaced as
 * "engine update" badges so a regression isn't conflated with a real
 * server regression.
 *
 * The G6 (rug-pull) tool-fingerprint diff is acknowledged as a future
 * enhancement — the tool-fingerprint module exists in packages/analyzer
 * but is not yet exposed via the API.
 */

import React from "react";
import { scoreBand } from "@/components/EvidenceSummaryHero";

interface HistoryEntry {
  score: number;
  findings_count: number;
  rules_version: string | null;
  recorded_at: string;
}

interface Props {
  slug: string;
  apiUrl: string;
}

async function fetchHistory(apiUrl: string, slug: string): Promise<HistoryEntry[]> {
  try {
    const res = await fetch(
      `${apiUrl}/api/v1/servers/${encodeURIComponent(slug)}/history`,
      { signal: AbortSignal.timeout(4000) },
    );
    if (!res.ok) return [];
    const json = await res.json();
    const list = (json.data ?? json) as HistoryEntry[];
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function fmtShortDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      month: "short", day: "numeric", year: "numeric",
    });
  } catch {
    return iso;
  }
}

export default async function VersionHistoryTab({ slug, apiUrl }: Props) {
  const raw = await fetchHistory(apiUrl, slug);
  // Sort ascending for the strip, descending for the table
  const asc = [...raw].sort((a, b) =>
    new Date(a.recorded_at).getTime() - new Date(b.recorded_at).getTime(),
  );
  const desc = [...raw].sort((a, b) =>
    new Date(b.recorded_at).getTime() - new Date(a.recorded_at).getTime(),
  );

  if (raw.length === 0) {
    return (
      <section className="vht-empty">
        <p className="vht-empty-msg">No scan history available for this server yet.</p>
      </section>
    );
  }

  // Detect score regressions > 10 points between consecutive scans (asc)
  const drops: Array<{ from: HistoryEntry; to: HistoryEntry; delta: number }> = [];
  for (let i = 1; i < asc.length; i++) {
    const delta = asc[i]!.score - asc[i - 1]!.score;
    if (delta < -10) {
      drops.push({ from: asc[i - 1]!, to: asc[i]!, delta });
    }
  }

  return (
    <section className="vht-section">
      <p className="vht-intro">
        Each segment below is one scan run. Score changes between runs may reflect
        new findings, fixed findings, or a rules-engine update — engine updates are
        marked separately so a rule-driven shift is not confused with a server change.
      </p>

      {/* ── Timeline strip ─────────────────────────────────────────── */}
      <div className="vht-strip" role="list" aria-label="Scan history timeline">
        {asc.map((h, i) => {
          const band = scoreBand(h.score);
          return (
            <div
              key={i}
              role="listitem"
              className="vht-segment"
              style={{ background: `var(--${band})` }}
              title={`${h.score}/100 · ${fmtShortDate(h.recorded_at)} · rules ${h.rules_version ?? "—"}`}
            >
              <span className="vht-segment-score">{h.score}</span>
            </div>
          );
        })}
      </div>

      {/* ── Drop alerts ────────────────────────────────────────────── */}
      {drops.length > 0 && (
        <div className="vht-alert" role="alert">
          <div className="vht-alert-head">Score regression detected</div>
          <ul className="vht-alert-list">
            {drops.map((d, i) => {
              const enginedChanged = d.from.rules_version !== d.to.rules_version;
              return (
                <li key={i} className="vht-alert-row">
                  <span className="vht-alert-mono">
                    {fmtShortDate(d.to.recorded_at)}
                  </span>
                  : {d.from.score} → {d.to.score} (Δ{d.delta})
                  {enginedChanged && (
                    <span className="vht-alert-engine">
                      rules {d.from.rules_version ?? "—"} → {d.to.rules_version ?? "—"}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
          <p className="vht-alert-foot">
            A drop may stem from a rules update, a tool-set change, or a real regression.
            Tool-fingerprint diff (G6) coming in a follow-up.
          </p>
        </div>
      )}

      {/* ── Table ──────────────────────────────────────────────────── */}
      <table className="vht-table">
        <thead>
          <tr>
            <th>Score</th>
            <th>Findings</th>
            <th>Recorded</th>
            <th>Rules</th>
            <th>Δ</th>
          </tr>
        </thead>
        <tbody>
          {desc.map((h, i) => {
            const prev = desc[i + 1];
            const delta = prev ? h.score - prev.score : null;
            const engineChanged = prev ? prev.rules_version !== h.rules_version : false;
            const band = scoreBand(h.score);
            return (
              <tr key={i}>
                <td>
                  <span
                    className="vht-row-chip"
                    style={{ background: `var(--${band})` }}
                    aria-hidden="true"
                  />
                  <span className="vht-row-score">{h.score}</span>
                </td>
                <td className="vht-row-mono">{h.findings_count}</td>
                <td>{fmtShortDate(h.recorded_at)}</td>
                <td className="vht-row-mono">{h.rules_version ?? "—"}</td>
                <td>
                  {delta == null ? (
                    <span className="vht-row-mute">—</span>
                  ) : (
                    <span
                      className="vht-row-mono"
                      style={{
                        color: delta > 0
                          ? "var(--good)"
                          : delta < 0
                          ? "var(--critical)"
                          : "var(--text-3)",
                      }}
                    >
                      {delta > 0 ? "+" : ""}{delta}
                    </span>
                  )}
                  {engineChanged && (
                    <span className="vht-row-engine">engine update</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
