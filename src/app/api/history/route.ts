import { NextResponse } from "next/server";
import { and, desc, eq, ilike } from "drizzle-orm";
import { getDb, schema } from "@/db";
import { enforceAuthGuard } from "@/lib/api-utils";
import { canManageWorkspaceSettings } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  const { searchParams } = new URL(request.url);
  const q = searchParams.get("q")?.trim();
  const type = searchParams.get("type")?.trim();
  const verdict = searchParams.get("verdict")?.trim();
  const limit = Math.min(100, Math.max(1, Number(searchParams.get("limit") || 50)));

  const db = await getDb();
  const conditions = [];
  if (q) conditions.push(ilike(schema.lookupHistory.iocValue, `%${q}%`));
  if (type && type !== "all") conditions.push(eq(schema.lookupHistory.iocType, type));
  if (verdict && verdict !== "all") {
    conditions.push(eq(schema.lookupHistory.verdict, verdict));
  }

  const rows = await db
    .select()
    .from(schema.lookupHistory)
    .where(conditions.length ? and(...conditions) : undefined)
    .orderBy(desc(schema.lookupHistory.createdAt))
    .limit(limit);

  return NextResponse.json({ items: rows });
}

export async function DELETE(request: Request) {
  const { ctx, errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  if (!canManageWorkspaceSettings(ctx)) {
    return NextResponse.json(
      { error: "Admin privileges required to clear workspace history." },
      { status: 403 },
    );
  }

  const db = await getDb();
  await db.delete(schema.lookupHistory);
  return NextResponse.json({ cleared: true });
}
