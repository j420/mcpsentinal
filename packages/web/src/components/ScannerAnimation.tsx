"use client";

import { useState, useEffect } from "react";

/* Reads CSS tokens at runtime so the animation always tracks the active theme. */
const SCAN_STEPS = [
  { label: "Connecting", detail: "initialize + tools/list", color: "var(--accent)" },
  { label: "Enumerating", detail: "12 tools found", color: "var(--accent)" },
  { label: "Analyzing", detail: "164 rules running...", color: "var(--sev-medium)" },
  { label: "Finding", detail: "Prompt Injection in description", color: "var(--sev-critical)", severity: "critical" },
  { label: "Finding", detail: "Hardcoded API key detected", color: "var(--sev-high)", severity: "high" },
  { label: "Finding", detail: "Missing input validation", color: "var(--sev-medium)", severity: "medium" },
  { label: "Scoring", detail: "Score: 62/100 — Moderate", color: "var(--sev-medium)" },
  { label: "Complete", detail: "3 findings · 62/100", color: "var(--sev-low)" },
];

export default function ScannerAnimation() {
  const [step, setStep] = useState(0);
  const [visible, setVisible] = useState<number[]>([]);

  useEffect(() => {
    const timer = setInterval(() => {
      setStep((prev) => {
        const next = (prev + 1) % SCAN_STEPS.length;
        if (next === 0) {
          setVisible([]);
        }
        return next;
      });
    }, 1400);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    setVisible((prev) => [...prev, step]);
  }, [step]);

  return (
    <div className="scanner-anim">
      <div className="scanner-anim-header">
        <div className="scanner-anim-dots">
          <span className="scanner-dot scanner-dot-red" />
          <span className="scanner-dot scanner-dot-yellow" />
          <span className="scanner-dot scanner-dot-green" />
        </div>
        <span className="scanner-anim-title">mcp-sentinel-scanner</span>
      </div>
      <div className="scanner-anim-body">
        {visible.map((idx) => {
          const s = SCAN_STEPS[idx];
          if (!s) return null;
          return (
            <div key={idx} className="scanner-line scanner-line-in">
              <span className="scanner-label" style={{ color: s.color }}>
                {s.severity ? `[${s.severity.toUpperCase()}]` : `[${s.label}]`}
              </span>
              <span className="scanner-detail">{s.detail}</span>
            </div>
          );
        })}
        <span className="scanner-cursor" />
      </div>
      <a href="/scanner" className="scanner-anim-cta">
        Learn how to use →
      </a>
    </div>
  );
}
