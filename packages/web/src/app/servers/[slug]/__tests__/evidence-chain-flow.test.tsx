import React from "react";
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import EvidenceChainFlow from "../evidence-chain-flow";

afterEach(() => cleanup());

describe("EvidenceChainFlow", () => {
  it("falls back to prose when chain is null", () => {
    render(<EvidenceChainFlow chain={null} fallbackEvidence="exec() at line 42" />);
    expect(screen.getByText("exec() at line 42")).toBeInTheDocument();
    expect(
      screen.getByText(/Structured evidence chain not on file/i),
    ).toBeInTheDocument();
  });

  it("falls back to prose when chain.links is empty", () => {
    render(
      <EvidenceChainFlow
        chain={{ links: [], confidence: 0.9, confidence_factors: [] }}
        fallbackEvidence="prose"
      />,
    );
    expect(screen.getByText("prose")).toBeInTheDocument();
  });

  it("renders 5-link source → propagation → sink → mitigation → impact chain", () => {
    const chain = {
      links: [
        {
          type: "source",
          source_type: "user-parameter",
          location: { kind: "parameter", tool_name: "run", parameter_path: "cmd" },
          observed: "${user.input}",
          rationale: "AI fills from prompt",
        },
        {
          type: "propagation",
          propagation_type: "direct-pass",
          location: "src/run.ts:12",
          observed: "exec(cmd)",
        },
        {
          type: "sink",
          sink_type: "command-execution",
          location: { kind: "source", file: "src/run.ts", line: 12, col: 4 },
          observed: "child_process.exec(cmd)",
          cve_precedent: "CVE-2025-6514",
        },
        {
          type: "mitigation",
          mitigation_type: "sanitizer-function",
          present: false,
          location: "src/run.ts:12",
          detail: "no escapeShell call",
        },
        {
          type: "impact",
          impact_type: "remote-code-execution",
          scope: "server-host",
          exploitability: "trivial",
          scenario: "attacker injects $(curl …)",
        },
      ],
      confidence: 0.87,
      confidence_factors: [
        { factor: "taint-path-complete", adjustment: 0.4, rationale: "source→sink" },
      ],
      threat_reference: { id: "CVE-2025-6514", title: "mcp-remote RCE" },
    };
    const { container } = render(
      <EvidenceChainFlow chain={chain} fallbackEvidence="fallback" />,
    );
    // Every link rendered
    expect(container.querySelectorAll(".fv-chain-node")).toHaveLength(5);
    // Each kind class present
    expect(container.querySelector(".fv-chain-node-source")).toBeInTheDocument();
    expect(container.querySelector(".fv-chain-node-propagation")).toBeInTheDocument();
    expect(container.querySelector(".fv-chain-node-sink")).toBeInTheDocument();
    expect(container.querySelector(".fv-chain-node-mitigation")).toBeInTheDocument();
    expect(container.querySelector(".fv-chain-node-impact")).toBeInTheDocument();
    // CVE precedent shows on sink + threat ref — 2 references is correct
    expect(screen.getAllByText("CVE-2025-6514").length).toBeGreaterThanOrEqual(1);
    expect(container.querySelector(".fv-chain-node-cve")).toHaveTextContent(
      "CVE-2025-6514",
    );
    // Mitigation marked absent
    expect(screen.getByText("absent")).toBeInTheDocument();
    // Confidence rounded
    expect(screen.getByText("87%")).toBeInTheDocument();
  });

  it("renders verification steps strip above the chain when present", () => {
    const chain = {
      links: [
        {
          type: "source",
          source_type: "user-parameter",
          location: "tool run",
          observed: "x",
          rationale: "y",
        },
        {
          type: "sink",
          sink_type: "command-execution",
          location: "src/x.ts:1",
          observed: "exec(x)",
        },
      ],
      confidence: 0.9,
      confidence_factors: [],
      verification_steps: [
        {
          step_type: "inspect-source",
          instruction: "Open src/x.ts line 1",
          target: { kind: "source", file: "src/x.ts", line: 1 },
          expected_observation: "exec(x) call without sanitizer",
        },
      ],
    };
    render(<EvidenceChainFlow chain={chain} fallbackEvidence="f" />);
    expect(screen.getByText(/Open src\/x.ts line 1/)).toBeInTheDocument();
    expect(screen.getByText(/exec\(x\) call without sanitizer/)).toBeInTheDocument();
  });

  it("renders without a location safely (missing fields)", () => {
    const chain = {
      links: [{ type: "source", source_type: "external-content", observed: "x" }],
      confidence: null,
      confidence_factors: [],
    };
    expect(() =>
      render(<EvidenceChainFlow chain={chain} fallbackEvidence="f" />),
    ).not.toThrow();
  });

  it("renders prose fallback when every link is malformed (missing type)", () => {
    const chain = {
      links: [{ observed: "no type" }, { type: "not-a-real-kind", observed: "x" }],
      confidence: 0.5,
      confidence_factors: [],
    };
    render(<EvidenceChainFlow chain={chain} fallbackEvidence="prose-here" />);
    expect(screen.getByText("prose-here")).toBeInTheDocument();
  });

  it("anchors the chain with findingId when provided", () => {
    const { container } = render(
      <EvidenceChainFlow chain={null} fallbackEvidence="x" findingId="finding-abc" />,
    );
    expect(container.querySelector("#finding-abc")).toBeInTheDocument();
  });
});
