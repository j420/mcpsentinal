import type { MetadataRoute } from "next";

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "https://mcp-sentinel.com";
const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

/* Fetch one page of server slugs */
async function fetchServerPage(
  page: number,
  limit: number
): Promise<{ slugs: string[]; total: number }> {
  try {
    const params = new URLSearchParams({
      limit: String(limit),
      page: String(page),
      sort: "score",
      order: "desc",
    });
    const res = await fetch(`${API_URL}/api/v1/servers?${params}`, {
      next: { revalidate: 3600 }, // re-generate sitemap every hour
    });
    if (!res.ok) return { slugs: [], total: 0 };
    const data = await res.json();
    const slugs: string[] = (data.data ?? []).map(
      (s: { slug: string }) => s.slug
    );
    const total: number = data.pagination?.total ?? 0;
    return { slugs, total };
  } catch {
    return { slugs: [], total: 0 };
  }
}

/* Fetch all server slugs in parallel batches of 50 requests */
async function getAllServerSlugs(): Promise<string[]> {
  const LIMIT = 100;
  const CONCURRENCY = 50;

  // Page 1 to get total count
  const first = await fetchServerPage(1, LIMIT);
  if (first.total === 0) return first.slugs;

  const totalPages = Math.ceil(first.total / LIMIT);
  const remainingPages = Array.from(
    { length: totalPages - 1 },
    (_, i) => i + 2
  );

  const allSlugs: string[] = [...first.slugs];

  // Fetch remaining pages in parallel batches
  for (let i = 0; i < remainingPages.length; i += CONCURRENCY) {
    const batch = remainingPages.slice(i, i + CONCURRENCY);
    const results = await Promise.all(
      batch.map((page) => fetchServerPage(page, LIMIT))
    );
    for (const r of results) allSlugs.push(...r.slugs);
  }

  return allSlugs;
}

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const now = new Date();

  // Static pages
  const staticRoutes: MetadataRoute.Sitemap = [
    {
      url: SITE_URL,
      lastModified: now,
      changeFrequency: "hourly",
      priority: 1.0,
    },
    {
      url: `${SITE_URL}/dashboard`,
      lastModified: now,
      changeFrequency: "hourly",
      priority: 0.9,
    },
    {
      url: `${SITE_URL}/about`,
      lastModified: now,
      changeFrequency: "monthly",
      priority: 0.6,
    },
  ];

  // Dynamic server pages
  const slugs = await getAllServerSlugs();
  const serverRoutes: MetadataRoute.Sitemap = slugs.map((slug) => ({
    url: `${SITE_URL}/server/${slug}`,
    lastModified: now,
    changeFrequency: "weekly" as const,
    priority: 0.7,
  }));

  return [...staticRoutes, ...serverRoutes];
}
