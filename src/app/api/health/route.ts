import { NextResponse } from "next/server";
import { getDb, getDbMode } from "@/db";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    await getDb();
    return NextResponse.json({
      status: "ok",
      service: "eyesight",
      dbMode: getDbMode(),
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    return NextResponse.json(
      {
        status: "error",
        error: err instanceof Error ? err.message : "Database unavailable",
      },
      { status: 500 },
    );
  }
}
