import { NextResponse } from "next/server";
import { enforceAuthGuard } from "@/lib/api-utils";
import {
  getLiveGlobalBreachesSnapshot,
  searchCredentialLeaks,
} from "@/lib/credentials";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const { searchParams } = new URL(request.url);
    const mode = searchParams.get("mode") || "search";
    const refresh = searchParams.get("refresh") === "true";

    if (mode === "feed") {
      const recentBreaches = await getLiveGlobalBreachesSnapshot(refresh);
      return NextResponse.json(
        { recentBreaches: recentBreaches.slice(0, 80), fetchedAt: new Date().toISOString() },
        { headers: { "Cache-Control": "no-store" } },
      );
    }

    const q = searchParams.get("q")?.trim() || "";
    if (!q || q.length < 2) {
      return NextResponse.json(
        { error: "Query must be at least 2 characters (domain, email, or username)." },
        { status: 400 },
      );
    }

    const start = Number(searchParams.get("start") || 0);
    const limit = Number(searchParams.get("limit") || 50);

    const report = await searchCredentialLeaks(q, {
      start: Number.isFinite(start) ? start : 0,
      limit: Number.isFinite(limit) ? limit : 50,
      forceRefresh: refresh,
    });

    return NextResponse.json(report, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (err) {
    return NextResponse.json(
      {
        error:
          err instanceof Error
            ? err.message
            : "Failed to query credential leak intelligence",
      },
      { status: 500 },
    );
  }
}
