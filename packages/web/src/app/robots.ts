import type { MetadataRoute } from "next";

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "https://mcp-sentinel.com";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        // /preview/* is an experimental information-architecture sandbox.
        // Removing packages/web/src/app/preview/ also removes the need for
        // this rule — it becomes a no-op at that point.
        disallow: ["/api/", "/preview/"],
      },
    ],
    sitemap: `${SITE_URL}/sitemap.xml`,
    host: SITE_URL,
  };
}
