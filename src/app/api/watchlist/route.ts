import { NextResponse } from "next/server";
import { desc, eq } from "drizzle-orm";
import { z } from "zod";
import { getDb, schema } from "@/db";
import { enforceAuthGuard } from "@/lib/api-utils";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  const db = await getDb();
  const items = await db
    .select()
    .from(schema.toolWatchlist)
    .orderBy(desc(schema.toolWatchlist.createdAt));

  return NextResponse.json({ items });
}

const createWatchlistSchema = z.object({
  name: z.string().min(2).max(80),
  category: z.string().min(2).max(40).default("THREAT INTEL"),
  status: z.enum(["MONITORING", "PLANNED", "INTEGRATED"]).default("MONITORING"),
  url: z.string().max(500).optional().nullable(),
  notes: z.string().max(300).optional().nullable(),
});

export async function POST(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const body = await request.json();
    const parsed = createWatchlistSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Provide a valid tool name, category, and status." },
        { status: 400 },
      );
    }

    const db = await getDb();
    const item = {
      id: crypto.randomUUID(),
      name: parsed.data.name.trim(),
      category: parsed.data.category.trim().toUpperCase(),
      status: parsed.data.status,
      url: parsed.data.url?.trim() || null,
      notes: parsed.data.notes?.trim() || null,
    };

    await db.insert(schema.toolWatchlist).values(item);
    return NextResponse.json({ item }, { status: 201 });
  } catch (err) {
    return NextResponse.json(
      {
        error:
          err instanceof Error
            ? err.message
            : "Failed to add tool to watchlist",
      },
      { status: 500 },
    );
  }
}

const patchWatchlistSchema = z.object({
  id: z.string().min(1),
  status: z.enum(["MONITORING", "PLANNED", "INTEGRATED"]),
});

export async function PATCH(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  const body = await request.json();
  const parsed = patchWatchlistSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid payload" }, { status: 400 });
  }

  const db = await getDb();
  await db
    .update(schema.toolWatchlist)
    .set({ status: parsed.data.status })
    .where(eq(schema.toolWatchlist.id, parsed.data.id));

  return NextResponse.json({ updated: true });
}

export async function DELETE(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  const { searchParams } = new URL(request.url);
  const id = searchParams.get("id")?.trim();
  if (!id) {
    return NextResponse.json({ error: "Missing watchlist id" }, { status: 400 });
  }

  const db = await getDb();
  await db.delete(schema.toolWatchlist).where(eq(schema.toolWatchlist.id, id));
  return NextResponse.json({ deleted: true });
}
