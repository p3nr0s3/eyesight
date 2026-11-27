import { NextResponse } from "next/server";
import { z } from "zod";
import { enforceAuthGuard } from "@/lib/api-utils";
import { parseBulkIocs } from "@/lib/ioc";

export const dynamic = "force-dynamic";

const bulkParseSchema = z.object({
  text: z.string().min(1).max(200_000),
  maxItems: z.number().int().min(1).max(200).optional().default(100),
});

export async function POST(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const body = await request.json();
    const parsed = bulkParseSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid bulk input", issues: parsed.error.issues },
        { status: 400 },
      );
    }

    const result = parseBulkIocs(parsed.data.text, parsed.data.maxItems);
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Failed to parse bulk IOCs" },
      { status: 500 },
    );
  }
}
