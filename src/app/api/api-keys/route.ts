import { NextResponse } from "next/server";
import { desc, eq } from "drizzle-orm";
import { z } from "zod";
import { getDb, schema } from "@/db";
import { getAuthContext } from "@/lib/auth";
import { generateRestApiKey } from "@/lib/crypto";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const ctx = await getAuthContext(request);
  if (!ctx.user) {
    return NextResponse.json({ items: [] });
  }

  const db = await getDb();
  const rows = await db
    .select({
      id: schema.apiKeys.id,
      name: schema.apiKeys.name,
      keyPrefix: schema.apiKeys.keyPrefix,
      lastUsedAt: schema.apiKeys.lastUsedAt,
      createdAt: schema.apiKeys.createdAt,
    })
    .from(schema.apiKeys)
    .where(eq(schema.apiKeys.userId, ctx.user.id))
    .orderBy(desc(schema.apiKeys.createdAt));

  return NextResponse.json({ items: rows });
}

const createKeySchema = z.object({
  name: z.string().min(1).max(60),
});

export async function POST(request: Request) {
  const ctx = await getAuthContext(request);
  if (!ctx.user) {
    return NextResponse.json(
      { error: "Sign in to create personal REST API keys." },
      { status: 401 },
    );
  }

  const body = await request.json();
  const parsed = createKeySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Provide an API key name (1-60 chars)." },
      { status: 400 },
    );
  }

  const db = await getDb();
  const { rawKey, keyPrefix, keyHash } = generateRestApiKey();
  const id = crypto.randomUUID();

  await db.insert(schema.apiKeys).values({
    id,
    userId: ctx.user.id,
    name: parsed.data.name.trim(),
    keyPrefix,
    keyHash,
  });

  return NextResponse.json(
    {
      id,
      name: parsed.data.name.trim(),
      keyPrefix,
      rawKey, // Shown once!
    },
    { status: 201 },
  );
}
