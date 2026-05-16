import type { Metadata } from "next";
import ScanResultView from "./ScanResultView";

export const metadata: Metadata = {
  title: "Scan Result — MCP Sentinel",
  description: "Ad-hoc MCP server security scan result.",
  robots: { index: false },
};

export default async function ScanResultPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return (
    <div className="scan-page">
      <ScanResultView id={id} />
    </div>
  );
}
