import { NextResponse } from "next/server";
import { asc, eq } from "drizzle-orm";
import { z } from "zod";
import { getDb, schema } from "@/db";
import { enforceAuthGuard } from "@/lib/api-utils";
import { canManageWorkspaceSettings } from "@/lib/auth";
import { invalidateNewsCache, isSafeExternalFeedUrl } from "@/lib/rss";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { ctx, errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  const db = await getDb();
  const items = await db
    .select()
    .from(schema.rssFeeds)
    .orderBy(asc(schema.rssFeeds.name));

  return NextResponse.json({
    canManage: canManageWorkspaceSettings(ctx),
    items,
  });
}

const createFeedSchema = z.object({
  name: z.string().min(2).max(80),
  url: z.string().url().max(500),
  category: z.string().min(2).max(40).optional().default("CYBER NEWS"),
});

export async function POST(request: Request) {
  const { ctx, errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;
  if (!canManageWorkspaceSettings(ctx)) {
    return NextResponse.json(
      { error: "Admin privileges required to manage RSS feeds." },
      { status: 403 },
    );
  }

  try {
    const body = await request.json();
    const parsed = createFeedSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Provide a valid feed name and HTTP/HTTPS URL." },
        { status: 400 },
      );
    }

    if (!isSafeExternalFeedUrl(parsed.data.url)) {
      return NextResponse.json(
        { error: "RSS feed URL must be a public HTTP/HTTPS address." },
        { status: 400 },
      );
    }

    const db = await getDb();
    const existing = await db
      .select({ id: schema.rssFeeds.id })
      .from(schema.rssFeeds)
      .where(eq(schema.rssFeeds.url, parsed.data.url.trim()))
      .limit(1);

    if (existing.length > 0) {
      return NextResponse.json(
        { error: "This RSS feed URL is already configured." },
        { status: 409 },
      );
    }

    const item = {
      id: crypto.randomUUID(),
      name: parsed.data.name.trim(),
      url: parsed.data.url.trim(),
      category: parsed.data.category.trim().toUpperCase(),
      enabled: true,
    };

    await db.insert(schema.rssFeeds).values(item);
    invalidateNewsCache();
    return NextResponse.json({ item }, { status: 201 });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Failed to add RSS feed" },
      { status: 500 },
    );
  }
}

const patchFeedSchema = z.object({
  id: z.string().min(1),
  enabled: z.boolean(),
});

export async function PATCH(request: Request) {
  const { ctx, errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;
  if (!canManageWorkspaceSettings(ctx)) {
    return NextResponse.json(
      { error: "Admin privileges required to modify RSS feeds." },
      { status: 403 },
    );
  }

  const body = await request.json();
  const parsed = patchFeedSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid payload" }, { status: 400 });
  }

  const db = await getDb();
  await db
    .update(schema.rssFeeds)
    .set({ enabled: parsed.data.enabled })
    .where(eq(schema.rssFeeds.id, parsed.data.id));

  invalidateNewsCache();
  return NextResponse.json({ updated: true });
}

export async function DELETE(request: Request) {
  const { ctx, errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;
  if (!canManageWorkspaceSettings(ctx)) {
    return NextResponse.json(
      { error: "Admin privileges required to delete RSS feeds." },
      { status: 403 },
    );
  }

  const { searchParams } = new URL(request.url);
  const id = searchParams.get("id")?.trim();
  if (!id) {
    return NextResponse.json({ error: "Missing feed id" }, { status: 400 });
  }

  const db = await getDb();
  await db.delete(schema.rssFeeds).where(eq(schema.rssFeeds.id, id));
  invalidateNewsCache();
  return NextResponse.json({ deleted: true });
}
