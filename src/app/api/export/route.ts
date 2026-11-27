import { NextResponse } from "next/server";
import { z } from "zod";
import { enforceAuthGuard } from "@/lib/api-utils";
import type { EnrichmentReport } from "@/lib/enrich";
import {
  exportReportsAsCsv,
  exportReportsAsJson,
  exportReportsAsStix,
} from "@/lib/export";

export const dynamic = "force-dynamic";

const exportSchema = z.object({
  format: z.enum(["json", "csv", "stix"]),
  reports: z.array(z.any()).min(1).max(200),
});

export async function POST(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const body = await request.json();
    const parsed = exportSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid export payload", issues: parsed.error.issues },
        { status: 400 },
      );
    }

    const reports = parsed.data.reports as EnrichmentReport[];
    const ts = new Date().toISOString().slice(0, 10);

    if (parsed.data.format === "csv") {
      const csv = exportReportsAsCsv(reports);
      return new NextResponse(csv, {
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": `attachment; filename="eyesight-export-${ts}.csv"`,
        },
      });
    }

    if (parsed.data.format === "stix") {
      const stix = exportReportsAsStix(reports);
      return new NextResponse(stix, {
        headers: {
          "Content-Type": "application/stix+json; charset=utf-8",
          "Content-Disposition": `attachment; filename="eyesight-stix21-${ts}.json"`,
        },
      });
    }

    const json = exportReportsAsJson(reports);
    return new NextResponse(json, {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Disposition": `attachment; filename="eyesight-export-${ts}.json"`,
      },
    });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Export failed" },
      { status: 500 },
    );
  }
}
