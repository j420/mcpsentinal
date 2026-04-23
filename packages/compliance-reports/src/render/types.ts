import type { FrameworkId, SignedComplianceReport } from "../types.js";

export type RendererFormat = "html" | "json" | "pdf";

/**
 * Contract implemented by each format × framework renderer. The renderer
 * receives a fully-signed report and decides where in the output the
 * attestation block lives — JSON renderers typically emit the envelope
 * as-is; PDF and HTML renderers emit the signature as a footer panel and
 * include a QR-linkable verifier URL.
 */
export interface ComplianceReportRenderer {
  format: RendererFormat;
  /** MIME content-type for HTTP Response.setHeader. */
  contentType: string;
  /** File extension without dot, e.g. "pdf" or "html". */
  filenameSuffix: string;
  render(signed: SignedComplianceReport): Buffer | string;
}

type RendererKey = `${RendererFormat}:${FrameworkId}`;
const registry = new Map<RendererKey, ComplianceReportRenderer>();

function key(format: RendererFormat, framework: FrameworkId): RendererKey {
  return `${format}:${framework}`;
}

export function registerRenderer(
  format: RendererFormat,
  framework: FrameworkId,
  r: ComplianceReportRenderer,
): void {
  if (r.format !== format) {
    throw new Error(
      `Renderer.format mismatch: expected ${format}, got ${r.format}`,
    );
  }
  registry.set(key(format, framework), r);
}

export function getRenderer(
  format: RendererFormat,
  framework: FrameworkId,
): ComplianceReportRenderer | undefined {
  return registry.get(key(format, framework));
}

export function getAllRenderers(): Array<{
  format: RendererFormat;
  framework: FrameworkId;
  renderer: ComplianceReportRenderer;
}> {
  const out: Array<{ format: RendererFormat; framework: FrameworkId; renderer: ComplianceReportRenderer }> = [];
  for (const [k, r] of registry.entries()) {
    const [format, framework] = k.split(":", 2) as [RendererFormat, FrameworkId];
    out.push({ format, framework, renderer: r });
  }
  return out;
}

/** Test-only hook — Agent 2 does not need this. */
export function __clearRendererRegistry(): void {
  registry.clear();
}
