import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "404 — Page Not Found",
};

export default function NotFound() {
  return (
    <div className="notfound">
      <div className="notfound-code">404</div>
      <h1 className="notfound-title">Page not found</h1>
      <p className="notfound-sub">
        The page you&apos;re looking for doesn&apos;t exist or has been moved.
      </p>
      <div style={{ display: "flex", gap: "var(--s3)", flexWrap: "wrap", justifyContent: "center" }}>
        <a href="/" className="btn-primary">
          Browse registry
        </a>
        <a href="/dashboard" className="btn-secondary">
          Ecosystem dashboard
        </a>
      </div>
    </div>
  );
}
