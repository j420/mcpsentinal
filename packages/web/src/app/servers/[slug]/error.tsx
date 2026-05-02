"use client";
/**
 * /servers/[slug] — error boundary.
 *
 * Catches any render-time exception in the Deep Dive page tree and
 * surfaces a friendly fallback instead of Next's default 500 page. The
 * error digest is shown so an operator can correlate with server logs;
 * a "Try again" button calls Next's `reset()` to re-render the segment.
 *
 * Why a route-level error.tsx (not a try/catch in page.tsx):
 *   - Page.tsx is a server component; runtime exceptions in any of its
 *     children (server OR client) bubble up here.
 *   - The boundary survives the framework's automatic dev-vs-prod
 *     differences — in dev you see the stack inline, in prod the page
 *     stays usable instead of dying outright.
 *
 * The fallback is deliberately neutral: same layout chrome (no page
 * header / footer overrides) so the rest of the site still works while
 * the user is on this URL.
 */

import React, { useEffect } from "react";

interface ErrorPageProps {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function ServerDetailError({ error, reset }: ErrorPageProps) {
  useEffect(() => {
    // eslint-disable-next-line no-console
    console.error("Deep Dive render error:", error);
  }, [error]);

  return (
    <div className="dd-error">
      <h1 className="dd-error-title">We hit a snag rendering this server</h1>
      <p className="dd-error-msg">
        The Deep Dive could not be assembled. Per-section error boundaries
        catch most rendering issues and degrade just the failing block,
        but something at the page level threw before any of those caught
        it — most likely the data fetch returned something the page can't
        recover from. The underlying scan data is intact; only this view
        is affected.
      </p>
      {error.digest && (
        <p className="dd-error-digest">
          Reference: <code>{error.digest}</code>
        </p>
      )}
      {error.message && process.env.NODE_ENV !== "production" && (
        <pre className="dd-error-stack">{error.message}</pre>
      )}
      <div className="dd-error-actions">
        <button
          type="button"
          className="dd-error-retry"
          onClick={() => reset()}
        >
          Try again
        </button>
        <a className="dd-error-home" href="/servers">
          Back to all servers
        </a>
      </div>
      <p className="dd-error-help">
        This is not because the server hasn't been scanned — newly
        scanned data is not required. The page is meant to render any
        scan data on file; an exception here is a code-level issue we
        need to chase, not a data gap.
      </p>
    </div>
  );
}
