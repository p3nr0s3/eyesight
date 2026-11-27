import { NextResponse } from "next/server";
import { and, eq } from "drizzle-orm";
import { getDb, schema } from "@/db";
import { getAuthContext } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function DELETE(
  request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const ctx = await getAuthContext(request);
  if (!ctx.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await context.params;
  const db = await getDb();
  await db
    .delete(schema.apiKeys)
    .where(and(eq(schema.apiKeys.id, id), eq(schema.apiKeys.userId, ctx.user.id)));

  return NextResponse.json({ deleted: true });
}
