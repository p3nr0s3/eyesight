import { NextResponse } from "next/server";
import { desc, eq } from "drizzle-orm";
import { z } from "zod";
import { getDb, schema } from "@/db";
import { enforceAuthGuard } from "@/lib/api-utils";
import {
  evaluateTargetAgainstSnapshot,
  getDarkwebIntelSnapshot,
} from "@/lib/darkweb";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const db = await getDb();
    const [monitors, snapshot] = await Promise.all([
      db
        .select()
        .from(schema.darkwebMonitors)
        .orderBy(desc(schema.darkwebMonitors.createdAt)),
      getDarkwebIntelSnapshot(),
    ]);

    const evaluated = monitors.map((m) => ({
      ...m,
      evaluation: evaluateTargetAgainstSnapshot(m.target, snapshot),
    }));

    return NextResponse.json({ items: evaluated });
  } catch (err) {
    return NextResponse.json(
      {
        error:
          err instanceof Error
            ? err.message
            : "Failed to evaluate darkweb monitors",
      },
      { status: 500 },
    );
  }
}

const createMonitorSchema = z.object({
  target: z.string().min(2).max(150),
  targetType: z.enum(["DOMAIN", "BRAND", "EMAIL", "KEYWORD"]).default("DOMAIN"),
  notes: z.string().max(300).optional().nullable(),
});

export async function POST(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const body = await request.json();
    const parsed = createMonitorSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Provide a valid monitor target (2+ chars) and type." },
        { status: 400 },
      );
    }

    const db = await getDb();
    const item = {
      id: crypto.randomUUID(),
      target: parsed.data.target.trim(),
      targetType: parsed.data.targetType,
      notes: parsed.data.notes?.trim() || null,
    };

    await db.insert(schema.darkwebMonitors).values(item);
    return NextResponse.json({ item }, { status: 201 });
  } catch (err) {
    return NextResponse.json(
      {
        error:
          err instanceof Error
            ? err.message
            : "Failed to create darkweb monitor",
      },
      { status: 500 },
    );
  }
}

export async function DELETE(request: Request) {
  const { errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  const { searchParams } = new URL(request.url);
  const id = searchParams.get("id")?.trim();
  if (!id) {
    return NextResponse.json({ error: "Missing monitor id" }, { status: 400 });
  }

  const db = await getDb();
  await db
    .delete(schema.darkwebMonitors)
    .where(eq(schema.darkwebMonitors.id, id));
  return NextResponse.json({ deleted: true });
}
