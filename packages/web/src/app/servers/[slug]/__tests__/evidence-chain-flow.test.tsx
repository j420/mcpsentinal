import React from "react";
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import EvidenceChainFlow from "../evidence-chain-flow";

afterEach(() => cleanup());

describe("EvidenceChainFlow — fallback states", () => {
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

  it("falls back to prose when every link is malformed (missing type)", () => {
    const chain = {
      links: [{ observed: "no type" }, { type: "not-a-real-kind", observed: "x" }],
      confidence: 0.5,
      confidence_factors: [],
    };
    render(<EvidenceChainFlow chain={chain} fallbackEvidence="prose-here" />);
    expect(screen.getByText("prose-here")).toBeInTheDocument();
  });
});

describe("EvidenceChainFlow — full chain rendering", () => {
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
    threat_reference: {
      id: "CVE-2025-6514",
      title: "mcp-remote RCE",
      year: 2025,
      relevance: "Same sink class.",
    },
  };

  it("renders every link kind as its own labeled block", () => {
    const { container } = render(
      <EvidenceChainFlow chain={chain} fallbackEvidence="fallback" />,
    );
    expect(container.querySelectorAll(".fv-ev-link")).toHaveLength(5);
    expect(container.querySelector(".fv-ev-link-source")).toBeInTheDocument();
    expect(container.querySelector(".fv-ev-link-propagation")).toBeInTheDocument();
    expect(container.querySelector(".fv-ev-link-sink")).toBeInTheDocument();
    expect(container.querySelector(".fv-ev-link-mitigation")).toBeInTheDocument();
    expect(container.querySelector(".fv-ev-link-impact")).toBeInTheDocument();
  });

  it("surfaces the kind label on every block", () => {
    render(<EvidenceChainFlow chain={chain} fallbackEvidence="x" />);
    expect(screen.getByText("Source")).toBeInTheDocument();
    expect(screen.getByText("Propagation")).toBeInTheDocument();
    expect(screen.getByText("Sink")).toBeInTheDocument();
    expect(screen.getByText("Mitigation")).toBeInTheDocument();
    expect(screen.getByText("Impact")).toBeInTheDocument();
  });

  it("surfaces every link field with a clear label", () => {
    render(<EvidenceChainFlow chain={chain} fallbackEvidence="x" />);
    // Field labels for each link kind
    expect(screen.getAllByText("Where").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("At")).toBeInTheDocument();
    expect(screen.getByText("Why untrusted")).toBeInTheDocument();
    expect(screen.getByText("Detail")).toBeInTheDocument();
    expect(screen.getByText("Scenario")).toBeInTheDocument();
    expect(screen.getByText("Scope")).toBeInTheDocument();
    expect(screen.getByText("Exploitability")).toBeInTheDocument();
    expect(screen.getByText("CVE precedent")).toBeInTheDocument();
  });

  it("renders a prominent ABSENT badge on the mitigation block", () => {
    const { container } = render(
      <EvidenceChainFlow chain={chain} fallbackEvidence="x" />,
    );
    const badge = container.querySelector(".fv-ev-mit-absent");
    expect(badge).toBeInTheDocument();
    expect(badge?.textContent).toMatch(/Absent/i);
  });

  it("surfaces the CVE precedent inside the sink block", () => {
    const { container } = render(
      <EvidenceChainFlow chain={chain} fallbackEvidence="x" />,
    );
    const cveChip = container.querySelector(".fv-ev-cve");
    expect(cveChip).toHaveTextContent("CVE-2025-6514");
  });

  it("renders confidence inline with the rounded percentage", () => {
    render(<EvidenceChainFlow chain={chain} fallbackEvidence="x" />);
    expect(screen.getByText("87%")).toBeInTheDocument();
    expect(screen.getByText("Confidence")).toBeInTheDocument();
    expect(screen.getByText("taint-path-complete")).toBeInTheDocument();
    expect(screen.getByText(/source.*sink/i)).toBeInTheDocument();
  });

  it("renders the real-world precedent card with title + relevance", () => {
    render(<EvidenceChainFlow chain={chain} fallbackEvidence="x" />);
    expect(screen.getByText("Real-world precedent")).toBeInTheDocument();
    expect(screen.getByText("mcp-remote RCE")).toBeInTheDocument();
    expect(screen.getByText("Same sink class.")).toBeInTheDocument();
  });
});

describe("EvidenceChainFlow — verification steps", () => {
  it("renders the 'How to verify' block above the confidence block", () => {
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
    expect(screen.getByText("How to verify this finding")).toBeInTheDocument();
    expect(screen.getByText("Open src/x.ts line 1")).toBeInTheDocument();
    expect(screen.getByText(/exec\(x\) call without sanitizer/)).toBeInTheDocument();
    expect(screen.getByText("inspect-source")).toBeInTheDocument();
  });
});

describe("EvidenceChainFlow — defensive rendering", () => {
  it("renders without throwing when fields are missing", () => {
    const chain = {
      links: [{ type: "source", source_type: "external-content", observed: "x" }],
      confidence: null,
      confidence_factors: [],
    };
    expect(() =>
      render(<EvidenceChainFlow chain={chain} fallbackEvidence="f" />),
    ).not.toThrow();
  });

  it("anchors the chain with findingId when provided", () => {
    const { container } = render(
      <EvidenceChainFlow
        chain={null}
        fallbackEvidence="x"
        findingId="finding-abc"
      />,
    );
    expect(container.querySelector("#finding-abc")).toBeInTheDocument();
  });
});
