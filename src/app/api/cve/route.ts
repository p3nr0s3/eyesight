import { NextResponse } from "next/server";
import { enforceAuthGuard } from "@/lib/api-utils";
import { getCveDashboardData, searchCves } from "@/lib/cve";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const { searchParams } = new URL(request.url);
    const mode = searchParams.get("mode") || "dashboard";
    const q = searchParams.get("q")?.trim() || "";
    const severity = searchParams.get("severity")?.trim().toUpperCase() || "ALL";
    const kevOnly = searchParams.get("kevOnly") === "true";

    if (mode === "search" || q) {
      const results = await searchCves({
        query: q,
        severity,
        kevOnly,
      });
      return NextResponse.json({
        mode: "search",
        query: q,
        count: results.length,
        results,
      });
    }

    const dashboard = await getCveDashboardData();
    return NextResponse.json({
      mode: "dashboard",
      ...dashboard,
    });
  } catch (err) {
    return NextResponse.json(
      {
        error:
          err instanceof Error
            ? err.message
            : "Failed to fetch CVE intelligence",
      },
      { status: 500 },
    );
  }
}
