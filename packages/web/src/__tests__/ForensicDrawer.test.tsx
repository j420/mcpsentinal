// @vitest-environment jsdom
/**
 * ForensicDrawer + ForensicTrigger behavioural tests.
 *
 * Guards:
 *   - Trigger writes ?finding=<id> to the URL (preserving other params).
 *   - Drawer renders nothing when ?finding is absent.
 *   - Drawer renders the matching rule + finding when ?finding is set.
 *   - Drawer renders a not-found state when ?finding doesn't match any
 *     finding in the payload.
 *   - Tabs switch between Evidence / Verify / Receipt panels.
 *   - Esc key closes (strips ?finding from URL).
 *   - Backdrop click closes; click inside the drawer does NOT.
 *   - Body scroll-lock applied while open, released on close.
 *   - Copy-as-audit-pack writes markdown to the clipboard.
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from "vitest";
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import ForensicDrawer from "../components/ForensicDrawer";
import ForensicTrigger from "../components/ForensicTrigger";
import type {
  DeepDiveCategory,
  DeepDiveFinding,
  DeepDiveProvenance,
} from "../lib/deep-dive";

// ── Router mocks ──────────────────────────────────────────────────────
let mockSearchParamsString = "";
const mockRouterReplace: Mock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: mockRouterReplace,
    refresh: vi.fn(),
    prefetch: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  }),
  usePathname: () => "/servers/demo",
  useSearchParams: () => new URLSearchParams(mockSearchParamsString),
}));

// EvidenceChainViz pulls in evidence rendering — we don't need to
// re-test that here. Stub to keep the drawer snapshot tight.
vi.mock("@/components/EvidenceChainViz", () => ({
  __esModule: true,
  default: ({ confidence }: { confidence: number }) => (
    <div data-testid="evidence-chain-viz">conf:{confidence}</div>
  ),
}));

const FINDING_ID = "11111111-2222-3333-4444-555555555555";

function makeFinding(overrides: Partial<DeepDiveFinding> = {}): DeepDiveFinding {
  return {
    id: FINDING_ID,
    severity: "critical",
    confidence: 0.92,
    evidence: "exec(req.body.cmd) at server.ts:42",
    evidence_chain: {
      verification_steps: [
        {
          step_type: "code-inspection",
          target: "server.ts:42",
          instruction: "Locate the exec() call",
        },
      ],
    },
    remediation: "Use execFile().",
    ...overrides,
  };
}

function makeCategories(
  finding: DeepDiveFinding = makeFinding(),
): DeepDiveCategory[] {
  return [
    {
      id: "code-vulns",
      title: "Code Vulnerabilities",
      summary: "",
      frameworks: [],
      counts: {
        rules_total: 1,
        rules_passed: 0,
        rules_with_findings: 1,
        rules_skipped: 0,
        finding_count: 1,
        severity_breakdown: {
          critical: 1,
          high: 0,
          medium: 0,
          low: 0,
          informational: 0,
        },
      },
      sub_categories: [
        {
          id: "command-injection",
          title: "Command Injection",
          summary: "",
          counts: {
            rules_total: 1,
            rules_passed: 0,
            rules_with_findings: 1,
            rules_skipped: 0,
            finding_count: 1,
            severity_breakdown: {
              critical: 1,
              high: 0,
              medium: 0,
              low: 0,
              informational: 0,
            },
          },
          rules: [
            {
              rule_id: "C1",
              name: "Command Injection",
              severity: "critical",
              category: "C",
              owasp: "MCP03",
              mitre: null,
              summary: "",
              framework_controls: [],
              methodology: {
                technique: "ast-taint",
                verified_edge_cases: [],
                edge_case_strategies: [],
                confidence_cap: 0.99,
              },
              backing: null,
              remediation: "Use execFile().",
              status: "findings",
              findings: [finding],
            },
          ],
        },
      ],
    },
  ];
}

function makeProvenance(): DeepDiveProvenance {
  return {
    scan_id: "scan-abc",
    scan_completed_at: "2026-04-30T08:00:00.000Z",
    rules_version: "2026-04-23",
    sentinel_version: "0.4.0",
    signing_key_id: "dev-key",
  };
}

beforeEach(() => {
  mockSearchParamsString = "";
  mockRouterReplace.mockReset();
  // Ensure body styles reset between tests.
  document.body.style.overflow = "";
});

afterEach(() => {
  cleanup();
  document.body.style.overflow = "";
});

// ── ForensicTrigger ───────────────────────────────────────────────────
describe("ForensicTrigger", () => {
  it("writes ?finding=<id> to the URL on click", () => {
    render(<ForensicTrigger findingId={FINDING_ID} />);
    fireEvent.click(screen.getByRole("button"));
    expect(mockRouterReplace).toHaveBeenCalledTimes(1);
    expect(mockRouterReplace.mock.calls[0]![0]).toBe(
      `/servers/demo?finding=${FINDING_ID}`,
    );
  });

  it("preserves other query params when adding ?finding=", () => {
    mockSearchParamsString = "lens=audit&view=forensic";
    render(<ForensicTrigger findingId={FINDING_ID} />);
    fireEvent.click(screen.getByRole("button"));
    const target = mockRouterReplace.mock.calls[0]![0] as string;
    expect(target).toContain("lens=audit");
    expect(target).toContain("view=forensic");
    expect(target).toContain(`finding=${FINDING_ID}`);
  });
});

// ── ForensicDrawer ────────────────────────────────────────────────────
describe("ForensicDrawer", () => {
  function renderDrawer(opts: { categories?: DeepDiveCategory[] } = {}) {
    return render(
      <ForensicDrawer
        serverSlug="demo-server"
        serverName="Demo Server"
        categories={opts.categories ?? makeCategories()}
        provenance={makeProvenance()}
        apiOrigin="https://api.example.test"
      />,
    );
  }

  it("renders nothing when no ?finding is in the URL", () => {
    const { container } = renderDrawer();
    expect(container.querySelector(".fdrawer")).toBeNull();
  });

  it("renders the drawer when ?finding= matches a finding in the payload", () => {
    mockSearchParamsString = `finding=${FINDING_ID}`;
    renderDrawer();
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(screen.getByText(/C1/)).toBeTruthy();
    expect(screen.getByText(/Command Injection/)).toBeTruthy();
  });

  it("renders the not-found state for an unknown finding id", () => {
    mockSearchParamsString = "finding=does-not-exist";
    const { container } = renderDrawer();
    expect(container.querySelector(".fdrawer")).toBeTruthy();
    expect(container.querySelector(".fdrawer-empty")).toBeTruthy();
  });

  it("opens on the Evidence tab by default", () => {
    mockSearchParamsString = `finding=${FINDING_ID}`;
    renderDrawer();
    const evidenceTab = screen.getByRole("tab", { name: /Evidence/ });
    expect(evidenceTab.getAttribute("aria-selected")).toBe("true");
    expect(screen.getByTestId("evidence-chain-viz")).toBeTruthy();
  });

  it("switches to the Verify tab and shows the checklist", () => {
    mockSearchParamsString = `finding=${FINDING_ID}`;
    renderDrawer();
    fireEvent.click(screen.getByRole("tab", { name: /Verify/ }));
    expect(screen.getByText(/Verification checklist/)).toBeTruthy();
    expect(screen.getByText(/Locate the exec\(\) call/)).toBeTruthy();
    expect(
      screen.getAllByRole("checkbox", { name: /Verification step/ }).length,
    ).toBe(1);
  });

  it("switches to the Receipt tab and shows the per-finding receipt URL + provenance", () => {
    mockSearchParamsString = `finding=${FINDING_ID}`;
    const { container } = renderDrawer();
    fireEvent.click(screen.getByRole("tab", { name: /Receipt/ }));
    expect(
      container.querySelector(".fdrawer-receipt-url")!.textContent,
    ).toContain(`/api/v1/findings/${FINDING_ID}/receipt`);
    expect(screen.getByText(/scan-abc/)).toBeTruthy();
    expect(screen.getByText(/2026-04-23/)).toBeTruthy();
  });

  it("Esc strips ?finding= from the URL", () => {
    mockSearchParamsString = `finding=${FINDING_ID}&lens=audit`;
    renderDrawer();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(mockRouterReplace).toHaveBeenCalled();
    const target = mockRouterReplace.mock.calls[0]![0] as string;
    expect(target).toBe("/servers/demo?lens=audit");
  });

  it("clicking the backdrop closes; clicking inside the drawer does NOT", () => {
    mockSearchParamsString = `finding=${FINDING_ID}`;
    const { container } = renderDrawer();
    const drawer = container.querySelector(".fdrawer")!;
    fireEvent.click(drawer);
    expect(mockRouterReplace).not.toHaveBeenCalled();
    fireEvent.click(container.querySelector(".fdrawer-backdrop")!);
    expect(mockRouterReplace).toHaveBeenCalled();
  });

  it("close (×) button strips ?finding=", () => {
    mockSearchParamsString = `finding=${FINDING_ID}`;
    renderDrawer();
    fireEvent.click(screen.getByLabelText("Close forensic view"));
    expect(mockRouterReplace).toHaveBeenCalled();
    const target = mockRouterReplace.mock.calls[0]![0] as string;
    expect(target).toBe("/servers/demo");
  });

  it("locks body scroll while open and releases on unmount", () => {
    mockSearchParamsString = `finding=${FINDING_ID}`;
    const { unmount } = renderDrawer();
    expect(document.body.style.overflow).toBe("hidden");
    unmount();
    expect(document.body.style.overflow).toBe("");
  });

  it("'Copy as audit pack' button calls navigator.clipboard.writeText with the markdown", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
      writable: true,
    });
    mockSearchParamsString = `finding=${FINDING_ID}`;
    renderDrawer();
    fireEvent.click(
      screen.getByRole("button", { name: /Copy as audit pack/ }),
    );
    // Allow microtask to flush
    await Promise.resolve();
    await Promise.resolve();
    expect(writeText).toHaveBeenCalledTimes(1);
    const md = writeText.mock.calls[0]![0] as string;
    expect(md).toContain("# Finding C1 — Command Injection");
    expect(md).toContain(FINDING_ID);
    expect(md).toContain("## How to verify");
    expect(md).toContain(
      "https://api.example.test/api/v1/findings/" + FINDING_ID + "/receipt",
    );
  });
});
