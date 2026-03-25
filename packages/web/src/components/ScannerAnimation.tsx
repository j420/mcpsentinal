"use client";

import { useState, useEffect } from "react";

const SCAN_STEPS = [
  { label: "Connecting", detail: "initialize + tools/list", color: "#10B981" },
  { label: "Enumerating", detail: "12 tools found", color: "#10B981" },
  { label: "Analyzing", detail: "177 rules running...", color: "#F59E0B" },
  { label: "Finding", detail: "A1 Prompt Injection in description", color: "#EF4444", severity: "critical" },
  { label: "Finding", detail: "C5 Hardcoded API key detected", color: "#EF4444", severity: "high" },
  { label: "Finding", detail: "B1 Missing input validation", color: "#F59E0B", severity: "medium" },
  { label: "Scoring", detail: "Score: 62/100 — Moderate", color: "#F59E0B" },
  { label: "Complete", detail: "3 findings · 62/100", color: "#10B981" },
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
