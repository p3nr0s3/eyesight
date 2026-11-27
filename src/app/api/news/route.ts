import { NextResponse } from "next/server";
import { asc } from "drizzle-orm";
import { getDb, schema } from "@/db";
import { enforceAuthGuard } from "@/lib/api-utils";
import { fetchAggregatedRssNews } from "@/lib/rss";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const { searchParams } = new URL(request.url);
    const q = searchParams.get("q")?.trim().toLowerCase() || "";
    const source = searchParams.get("source")?.trim() || "ALL";
    const refresh = searchParams.get("refresh") === "true";

    const db = await getDb();
    const feeds = await db
      .select()
      .from(schema.rssFeeds)
      .orderBy(asc(schema.rssFeeds.name));

    const agg = await fetchAggregatedRssNews(feeds, refresh);

    let articles = agg.articles;
    if (source !== "ALL") {
      articles = articles.filter((a) => a.sourceName === source);
    }
    if (q) {
      articles = articles.filter(
        (a) =>
          a.title.toLowerCase().includes(q) ||
          a.summary.toLowerCase().includes(q) ||
          a.sourceName.toLowerCase().includes(q) ||
          a.tags.some((t) => t.toLowerCase().includes(q)),
      );
    }

    return NextResponse.json({
      articles,
      feedStatuses: agg.feedStatuses,
      totalFeeds: feeds.length,
      enabledFeeds: feeds.filter((f) => f.enabled).length,
      fetchedAt: agg.fetchedAt,
    });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Failed to load news" },
      { status: 500 },
    );
  }
}
