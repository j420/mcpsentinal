import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "MCP Sentinel — Security Intelligence Registry",
    short_name: "MCP Sentinel",
    description: "Security intelligence for Model Context Protocol servers. 177 detection rules.",
    start_url: "/",
    display: "standalone",
    background_color: "#0a0a0a",
    theme_color: "#34D399",
    icons: [
      { src: "/favicon.svg", sizes: "any", type: "image/svg+xml" },
    ],
  };
}
