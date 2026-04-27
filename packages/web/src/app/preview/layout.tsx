/**
 * Preview layout — owns the chrome for /preview/* routes only.
 *
 * Composition note: in Next.js App Router, child layouts nest *inside* the
 * root layout — they do not replace it. The root layout in
 * `packages/web/src/app/layout.tsx` renders `<header class="site-header">` /
 * `<footer class="site-footer">` around every page, so we hide both via a
 * scoped `<style>` block that only takes effect while this layout is mounted.
 *
 * That keeps the footprint additive: deleting `packages/web/src/app/preview/`
 * removes the override along with the rest of the preview tree. The root
 * layout is never edited.
 *
 * Server component — no client-side state, no hooks, no event handlers.
 */

import type { Metadata } from "next";
import PreviewBanner from "./_components/PreviewBanner";
import PreviewNav from "./_components/PreviewNav";
import PreviewFooter from "./_components/PreviewFooter";

export const metadata: Metadata = {
  title: {
    default: "Preview — MCP Sentinel",
    template: "%s — Preview · MCP Sentinel",
  },
  description:
    "Experimental information architecture for the MCP Sentinel registry. Not the live site.",
  robots: { index: false, follow: false },
};

export default function PreviewLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      {/*
       * Hide the root layout's chrome only while the preview tree is rendering.
       * Selectors are scoped to `body >` so they cannot leak into nested
       * surfaces. Removing this directory removes the override entirely.
       */}
      <style
        dangerouslySetInnerHTML={{
          __html: `
            body > header.site-header { display: none !important; }
            body > footer.site-footer { display: none !important; }
            body > main.site-main {
              padding: 0 !important;
              max-width: none !important;
            }
          `,
        }}
      />

      <PreviewBanner />
      <PreviewNav />

      <main
        style={{
          maxWidth: "1200px",
          margin: "0 auto",
          padding: "var(--s8) 24px var(--s10)",
          minHeight: "calc(100vh - 320px)",
        }}
      >
        {children}
      </main>

      <PreviewFooter />
    </>
  );
}
