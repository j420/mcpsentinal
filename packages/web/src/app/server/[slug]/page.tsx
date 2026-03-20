import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function LegacyServerDetailPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  redirect(`/servers/${encodeURIComponent(slug)}`);
}
