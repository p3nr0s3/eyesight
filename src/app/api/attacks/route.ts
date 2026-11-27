import { NextResponse } from "next/server";
import { enforceAuthGuard } from "@/lib/api-utils";
import { getLiveAttackIocsSnapshot } from "@/lib/attack-iocs";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const { searchParams } = new URL(request.url);
    const refresh = searchParams.get("refresh") === "true";
    const snapshot = await getLiveAttackIocsSnapshot(refresh);

    return NextResponse.json(snapshot, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (err) {
    return NextResponse.json(
      {
        error:
          err instanceof Error
            ? err.message
            : "Failed to fetch live attack IOC feeds",
      },
      { status: 500 },
    );
  }
}
