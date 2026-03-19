"use client";

import { useState, useEffect, useCallback } from "react";

interface FeaturedOrg {
  name: string;
  org: string;
  slug: string;
  desc: string;
  color: string;
  initials: string;
}

const VISIBLE = 6;
const INTERVAL = 7000;

export default function FeaturedCarousel({ orgs }: { orgs: FeaturedOrg[] }) {
  const [offset, setOffset] = useState(0);
  const [paused, setPaused] = useState(false);

  const advance = useCallback(() => {
    setOffset((prev) => (prev + VISIBLE) % orgs.length);
  }, [orgs.length]);

  const goBack = useCallback(() => {
    setOffset((prev) => (prev - VISIBLE + orgs.length) % orgs.length);
  }, [orgs.length]);

  useEffect(() => {
    if (paused) return;
    const id = setInterval(advance, INTERVAL);
    return () => clearInterval(id);
  }, [paused, advance]);

  // Wrap around to always show VISIBLE cards
  const visible: FeaturedOrg[] = [];
  for (let i = 0; i < VISIBLE; i++) {
    visible.push(orgs[(offset + i) % orgs.length]);
  }

  const page = Math.floor(offset / VISIBLE) + 1;
  const totalPages = Math.ceil(orgs.length / VISIBLE);

  return (
    <div
      className="featured-carousel"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
    >
      <div className="featured-grid featured-grid-animated" key={offset}>
        {visible.map((org) => (
          <a
            key={org.slug}
            href={`/server/${org.slug}`}
            className="featured-card featured-card-branded"
            style={{
              background: org.color,
              borderColor: org.color,
            }}
          >
            <div className="featured-brand-row">
              <div
                className="featured-brand-icon"
                style={{
                  background: "rgba(255,255,255,0.2)",
                  border: "1px solid rgba(255,255,255,0.3)",
                  color: "#fff",
                }}
              >
                {org.initials}
              </div>
              <span className="featured-brand-label" style={{ color: "rgba(255,255,255,0.8)" }}>
                {org.org}
              </span>
            </div>
            <div className="featured-card-name" style={{ color: "#fff" }}>{org.name}</div>
            <div className="featured-card-desc" style={{ color: "rgba(255,255,255,0.75)" }}>
              {org.desc}
            </div>
          </a>
        ))}
      </div>
      <div className="featured-carousel-controls">
        <button
          type="button"
          className="featured-carousel-btn"
          onClick={goBack}
          aria-label="Previous servers"
        >
          ←
        </button>
        <span className="featured-carousel-page">
          {page} / {totalPages}
        </span>
        <button
          type="button"
          className="featured-carousel-btn"
          onClick={advance}
          aria-label="Next servers"
        >
          →
        </button>
      </div>
    </div>
  );
}
