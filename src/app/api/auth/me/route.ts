import { NextResponse } from "next/server";
import { getAuthContext } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const ctx = await getAuthContext(request);
  return NextResponse.json(ctx);
}
