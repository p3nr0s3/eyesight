import { NextResponse } from "next/server";
import { enforceAuthGuard } from "@/lib/api-utils";
import { getDarkwebIntelSnapshot, searchDarkwebIntel } from "@/lib/darkweb";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const { searchParams } = new URL(request.url);
    const mode = searchParams.get("mode") || "dashboard";
    const q = searchParams.get("q")?.trim() || "";
    const refresh = searchParams.get("refresh") === "true";
    const hibpHeaderKey = request.headers.get("x-hibp-key")?.trim() || null;

    if (mode === "search" && q) {
      const result = await searchDarkwebIntel(q, hibpHeaderKey);
      return NextResponse.json({ mode: "search", ...result });
    }

    const snapshot = await getDarkwebIntelSnapshot(refresh);
    return NextResponse.json(
      {
        mode: "dashboard",
        victims: snapshot.victims,
        groups: snapshot.groups,
        markets: snapshot.markets,
        breaches: snapshot.breaches,
        leakedDomains: snapshot.leakedDomains.slice(0, 2000),
        infraStats: snapshot.infraStats,
        topGroups: snapshot.topGroups,
        topSectors: snapshot.topSectors,
        topCountries: snapshot.topCountries,
        stats: snapshot.stats,
        fetchedAt: snapshot.fetchedAt,
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch (err) {
    return NextResponse.json(
      {
        error:
          err instanceof Error
            ? err.message
            : "Failed to fetch darkweb monitoring intelligence",
      },
      { status: 500 },
    );
  }
}
